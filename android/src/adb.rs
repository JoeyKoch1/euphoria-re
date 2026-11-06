use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use anyhow::{Context, Result, ensure};

use crate::app::parse_api_level;
use crate::process::{self, Output};

const SHORT_TIMEOUT: Duration = Duration::from_secs(5);
const QUERY_TIMEOUT: Duration = Duration::from_secs(15);
const INSTALL_TIMEOUT: Duration = Duration::from_secs(600);
const START_TIMEOUT: Duration = Duration::from_secs(60);
const PUSH_TIMEOUT: Duration = Duration::from_secs(120);
const WALLPAPER_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Clone, Debug)]
pub struct Adb {
    path: PathBuf,
}

impl Adb {
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }

    pub fn start_server(&self) -> Result<()> {
        let output = process::run_capture(&self.path, &["start-server"], QUERY_TIMEOUT)
            .context("cannot start the adb server")?;
        ensure!(
            output.success,
            "adb could not start its server: {}",
            output.combined()
        );
        Ok(())
    }

    pub fn devices(&self) -> Result<Vec<String>> {
        let output =
            process::run_capture(&self.path, &["devices"], QUERY_TIMEOUT).context("adb devices")?;
        ensure!(output.success, "adb devices failed: {}", output.combined());
        Ok(parse_devices(&output.stdout))
    }

    pub fn state(&self, serial: &str) -> Result<String> {
        validate_serial(serial)?;
        let output = process::run_capture(&self.path, &["-s", serial, "get-state"], SHORT_TIMEOUT)?;
        let text = output.combined().to_ascii_lowercase();
        for state in ["unauthorized", "offline", "bootloader"] {
            if text.contains(state) {
                return Ok((*state).to_owned());
            }
        }
        if text.contains("device") && output.success {
            return Ok("device".to_owned());
        }
        if text.contains("not found") || text.contains("does not exist") {
            return Ok("absent".to_owned());
        }
        Ok(if output.success {
            "unknown".to_owned()
        } else {
            "offline".to_owned()
        })
    }

    pub fn getprop(&self, serial: &str, key: &str) -> Result<String> {
        let output = self.shell(serial, &["getprop", key], SHORT_TIMEOUT)?;
        ensure!(
            output.success,
            "adb getprop {key} failed: {}",
            output.combined()
        );
        Ok(output.stdout.trim().to_owned())
    }

    pub fn device_info(&self, serial: &str) -> DeviceProperties {
        let get = |key: &str| self.getprop(serial, key).unwrap_or_default();
        DeviceProperties {
            model: get("ro.product.model"),
            api: parse_api_level(&get("ro.build.version.sdk")),
            release: get("ro.build.version.release"),
            abi_list: get("ro.product.cpu.abilist")
                .split(',')
                .map(str::trim)
                .filter(|abi| !abi.is_empty())
                .map(str::to_owned)
                .collect(),
            resolution: self
                .shell(serial, &["wm", "size"], SHORT_TIMEOUT)
                .ok()
                .filter(|output| output.success)
                .and_then(|output| parse_size(&output.stdout)),
            density: self
                .shell(serial, &["wm", "density"], SHORT_TIMEOUT)
                .ok()
                .filter(|output| output.success)
                .and_then(|output| parse_density(&output.stdout)),
        }
    }

    pub fn install(&self, serial: &str, apk: &Path, grant_permissions: bool) -> Result<Output> {
        validate_serial(serial)?;
        let mut args: Vec<OsString> = vec![
            "-s".into(),
            serial.into(),
            "install".into(),
            "-r".into(),
            "-t".into(),
        ];
        if grant_permissions {
            args.push("-g".into());
        }
        // The path is a single argv entry, never part of a shell string.
        args.push(apk.as_os_str().to_owned());
        process::run_capture(&self.path, &args, INSTALL_TIMEOUT)
            .with_context(|| format!("adb install {}", apk.display()))
    }

    pub fn uninstall(&self, serial: &str, package: &str) -> Result<Output> {
        validate_serial(serial)?;
        validate_shell_value(package)?;
        process::run_capture(
            &self.path,
            &["-s", serial, "uninstall", package],
            INSTALL_TIMEOUT,
        )
        .context("adb uninstall")
    }

    pub fn package_path(&self, serial: &str, package: &str) -> Result<String> {
        let output = self.shell(serial, &["pm", "path", package], QUERY_TIMEOUT)?;
        ensure!(
            output.success,
            "Android could not find the installed package {package}: {}",
            output.combined()
        );
        Ok(output.stdout.trim().to_owned())
    }

    pub fn force_stop(&self, serial: &str, package: &str) -> Result<()> {
        let output = self.shell(serial, &["am", "force-stop", package], QUERY_TIMEOUT)?;
        ensure!(
            output.success,
            "Android could not stop {package}: {}",
            output.combined()
        );
        Ok(())
    }

    // Resolves only when the manifest did not name a launcher. `cmd package` is missing on very
    // old images, so `pm` is a fallback.
    pub fn resolve_launcher(&self, serial: &str, package: &str) -> Result<Option<String>> {
        let commands: [&[&str]; 2] = [
            &[
                "cmd",
                "package",
                "resolve-activity",
                "--brief",
                "-c",
                "android.intent.category.LAUNCHER",
                package,
            ],
            &[
                "pm",
                "resolve-activity",
                "--brief",
                "-c",
                "android.intent.category.LAUNCHER",
                package,
            ],
        ];
        for command in commands {
            let Ok(output) = self.shell(serial, command, QUERY_TIMEOUT) else {
                continue;
            };
            if output.success
                && let Some(component) = parse_component(&output.stdout)
            {
                return Ok(Some(component));
            }
        }
        Ok(None)
    }

    pub fn start_activity(&self, serial: &str, component: &str) -> Result<Output> {
        validate_component(component)?;
        self.shell(
            serial,
            &["am", "start", "-W", "-n", component],
            START_TIMEOUT,
        )
    }

    pub fn monkey_launch(&self, serial: &str, package: &str) -> Result<Output> {
        self.shell(
            serial,
            &[
                "monkey",
                "-p",
                package,
                "-c",
                "android.intent.category.LAUNCHER",
                "1",
            ],
            START_TIMEOUT,
        )
    }

    pub fn clear_logcat(&self, serial: &str) -> Result<()> {
        validate_serial(serial)?;
        let output =
            process::run_capture(&self.path, &["-s", serial, "logcat", "-c"], QUERY_TIMEOUT)?;
        ensure!(
            output.success,
            "Android could not clear logcat: {}",
            output.combined()
        );
        Ok(())
    }

    pub fn reduce_animations(&self, serial: &str) {
        for key in [
            "window_animation_scale",
            "transition_animation_scale",
            "animator_duration_scale",
        ] {
            let _ = self.shell(
                serial,
                &["settings", "put", "global", key, "0"],
                SHORT_TIMEOUT,
            );
        }
    }

    // The system proxy is what apps that honour ProxySelector use. 10.0.2.2 is the emulator's
    // alias for the host loopback, which is where Euphoria's capture proxy listens.
    pub fn set_http_proxy(&self, serial: &str, host: &str, port: u16) -> Result<()> {
        ensure!(
            host.chars().all(|ch| ch.is_ascii_digit() || ch == '.'),
            "Invalid proxy host: {host}"
        );
        let value = format!("{host}:{port}");
        let output = self.shell(
            serial,
            &["settings", "put", "global", "http_proxy", &value],
            QUERY_TIMEOUT,
        )?;
        ensure!(
            output.success,
            "Android could not set the HTTP proxy: {}",
            output.combined()
        );
        Ok(())
    }

    pub fn clear_http_proxy(&self, serial: &str) {
        let _ = self.shell(
            serial,
            &["settings", "delete", "global", "http_proxy"],
            SHORT_TIMEOUT,
        );
    }

    pub fn push(&self, serial: &str, local: &Path, remote: &str) -> Result<Output> {
        validate_serial(serial)?;
        validate_remote_path(remote)?;
        let args: [OsString; 5] = [
            "-s".into(),
            serial.into(),
            "push".into(),
            local.as_os_str().to_owned(),
            remote.into(),
        ];
        process::run_capture(&self.path, &args, PUSH_TIMEOUT)
            .with_context(|| format!("adb push {}", local.display()))
    }

    pub fn remove_files(&self, serial: &str, files: &[&str]) -> Result<()> {
        let mut command = vec!["rm", "-f"];
        command.extend_from_slice(files);
        let output = self.shell(serial, &command, SHORT_TIMEOUT)?;
        ensure!(
            output.success,
            "Android could not remove the temporary files: {}",
            output.combined()
        );
        Ok(())
    }

    pub fn run_app_process(&self, serial: &str, dex: &str, image: &str) -> Result<Output> {
        let command = crate::wallpaper::command(dex, image);
        let args: Vec<&str> = command.iter().map(String::as_str).collect();
        self.shell(serial, &args, WALLPAPER_TIMEOUT)
    }

    pub fn emu_kill(&self, serial: &str) -> Result<()> {
        validate_serial(serial)?;
        let output =
            process::run_capture(&self.path, &["-s", serial, "emu", "kill"], QUERY_TIMEOUT)?;
        ensure!(output.success, "adb emu kill failed: {}", output.combined());
        Ok(())
    }

    pub(crate) fn logcat_command(&self, serial: &str) -> Result<Command> {
        validate_serial(serial)?;
        let mut command = Command::new(&self.path);
        command.args(["-s", serial, "logcat", "-v", "threadtime"]);
        Ok(command)
    }

    fn shell(&self, serial: &str, command: &[&str], timeout: Duration) -> Result<Output> {
        validate_serial(serial)?;
        let mut args: Vec<OsString> = vec!["-s".into(), serial.into(), "shell".into()];
        for value in command {
            validate_shell_value(value)?;
            args.push(escape_device_arg(value).into());
        }
        process::run_capture(&self.path, &args, timeout).context("adb shell")
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DeviceProperties {
    pub model: String,
    pub api: Option<u32>,
    pub release: String,
    pub abi_list: Vec<String>,
    pub resolution: Option<String>,
    pub density: Option<String>,
}

// adb's shell protocol joins arguments before the device shell sees them. Keep every value in a
// form the shell cannot interpret, as defense in depth on top of package validation.
fn validate_shell_value(value: &str) -> Result<()> {
    ensure!(
        !value.is_empty(),
        "Refusing to pass an empty value to adb shell."
    );
    ensure!(
        value.chars().all(|ch| {
            ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-' | '/' | ':' | '$' | '=')
        }),
        "Refusing to pass unsafe shell characters to the device: {value}"
    );
    Ok(())
}

fn validate_remote_path(path: &str) -> Result<()> {
    ensure!(
        path.starts_with("/data/local/tmp/")
            && path
                .chars()
                .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '/' | '.' | '-' | '_'))
            && path
                .trim_start_matches('/')
                .split('/')
                .all(|segment| !segment.is_empty() && segment != "." && segment != ".."),
        "Refusing to push to an unsafe device path: {path}"
    );
    Ok(())
}

// Inner-class names contain '$'. Prefix it with a backslash so the device shell treats it as a
// literal instead of a variable expansion; no other shell metacharacters survive validation.
fn escape_device_arg(value: &str) -> String {
    value.replace('$', "\\$")
}

fn validate_serial(serial: &str) -> Result<()> {
    ensure!(
        !serial.is_empty()
            && serial
                .chars()
                .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.' | ':')),
        "Invalid adb serial: {serial}"
    );
    Ok(())
}

fn validate_component(component: &str) -> Result<()> {
    let (package, class) = component
        .split_once('/')
        .context("an Android component must look like package/class")?;
    validate_shell_value(package)?;
    validate_shell_value(class)?;
    Ok(())
}

pub fn parse_devices(output: &str) -> Vec<String> {
    output
        .lines()
        .skip_while(|line| !line.starts_with("List of devices"))
        .skip(1)
        .filter_map(|line| {
            let mut parts = line.split_whitespace();
            let serial = parts.next()?;
            let state = parts.next()?;
            (!serial.starts_with('*') && matches!(state, "device" | "offline" | "unauthorized"))
                .then(|| serial.to_owned())
        })
        .collect()
}

pub fn parse_component(output: &str) -> Option<String> {
    output.lines().rev().find_map(|line| {
        let line = line.trim();
        if line.is_empty()
            || line.contains(' ')
            || line.contains('=')
            || line.starts_with("No activity")
            || line.starts_with("Error")
            || line.starts_with("Warning")
            || line.starts_with("priority")
        {
            return None;
        }
        let (package, class) = line.split_once('/')?;
        if package.is_empty() || class.is_empty() {
            return None;
        }
        Some(line.to_owned())
    })
}

pub fn parse_size(output: &str) -> Option<String> {
    parse_labeled_value(output, "Override size")
        .or_else(|| parse_labeled_value(output, "Physical size"))
}

pub fn parse_density(output: &str) -> Option<String> {
    parse_labeled_value(output, "Override density")
        .or_else(|| parse_labeled_value(output, "Physical density"))
}

fn parse_labeled_value(output: &str, label: &str) -> Option<String> {
    output
        .lines()
        .find_map(|line| line.trim().strip_prefix(label))
        .and_then(|rest| rest.trim().strip_prefix(':'))
        .and_then(|value| value.split_whitespace().next())
        .map(str::to_owned)
}

pub fn install_hint(text: &str) -> Option<&'static str> {
    let text = text.to_ascii_uppercase();
    let hints = [
        (
            "INSTALL_FAILED_NO_MATCHING_ABIS",
            "The APK contains native libraries that do not match the emulator's CPU architecture.",
        ),
        (
            "INSTALL_FAILED_OLDER_SDK",
            "The emulator's Android version is older than this APK requires.",
        ),
        (
            "INSTALL_FAILED_DEPRECATED_SDK_VERSION",
            "The emulator's Android version is not supported by this APK.",
        ),
        (
            "INSTALL_FAILED_INSUFFICIENT_STORAGE",
            "The emulator ran out of storage. Reset it or create an AVD with more space.",
        ),
        (
            "INSTALL_PARSE_FAILED_NO_CERTIFICATES",
            "The APK is not signed. Android only installs signed packages.",
        ),
        (
            "INSTALL_PARSE_FAILED_INCONSISTENT_CERTIFICATES",
            "The APK is signed inconsistently. Re-sign it before installing.",
        ),
        (
            "INSTALL_FAILED_UPDATE_INCOMPATIBLE",
            "A different build with the same package name is installed.",
        ),
        (
            "INSTALL_FAILED_INVALID_APK",
            "Android rejected the APK as invalid or corrupt.",
        ),
        (
            "INSTALL_FAILED_VERIFICATION_FAILURE",
            "Android's package verifier rejected this APK.",
        ),
        (
            "INSTALL_FAILED_CONFLICTING_PROVIDER",
            "Another installed app declares the same content provider.",
        ),
        (
            "INSTALL_PARSE_FAILED_MANIFEST_MALFORMED",
            "Android could not parse the APK's manifest.",
        ),
    ];
    hints
        .iter()
        .find(|(code, _)| text.contains(code))
        .map(|(_, hint)| *hint)
}

pub fn update_incompatible(text: &str) -> bool {
    text.to_ascii_uppercase()
        .contains("INSTALL_FAILED_UPDATE_INCOMPATIBLE")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_attached_devices_and_skips_daemon_noise() {
        let output = "* daemon not running; starting now\n\
                      * daemon started successfully\n\
                      List of devices attached\n\
                      emulator-5554\tdevice\n\
                      emulator-5556\toffline\n\
                      192.168.1.5:5555\tunauthorized\n";
        assert_eq!(
            parse_devices(output),
            ["emulator-5554", "emulator-5556", "192.168.1.5:5555"]
        );
    }

    #[test]
    fn reads_resolved_activity_components() {
        let brief = "priority=0 preferredOrder=0\ncom.example/.MainActivity\n";
        assert_eq!(
            parse_component(brief).as_deref(),
            Some("com.example/.MainActivity")
        );
        assert_eq!(parse_component("No activity found\n").as_deref(), None);
        assert_eq!(parse_component("com.example.MainActivity").as_deref(), None);
    }

    #[test]
    fn maps_install_failures_to_advice() {
        assert!(
            install_hint("Failure [INSTALL_FAILED_NO_MATCHING_ABIS: ...]")
                .unwrap()
                .contains("CPU architecture")
        );
        assert!(
            install_hint("Failure [INSTALL_PARSE_FAILED_NO_CERTIFICATES]")
                .unwrap()
                .contains("not signed")
        );
        assert!(install_hint("Success").is_none());
        assert!(update_incompatible("INSTALL_FAILED_UPDATE_INCOMPATIBLE"));
        assert!(!update_incompatible("Success"));
    }

    #[test]
    fn reads_display_override_before_physical_size() {
        let output = "Physical size: 1080x2400\nOverride size: 720x1280\n";
        assert_eq!(parse_size(output).as_deref(), Some("720x1280"));
        assert_eq!(
            parse_size("Physical size: 1080x2400\n").as_deref(),
            Some("1080x2400")
        );
        assert_eq!(
            parse_density("Physical density: 420\n").as_deref(),
            Some("420")
        );
    }

    #[test]
    fn shell_values_cannot_escape_into_the_device_shell() {
        assert!(validate_shell_value("com.example.app").is_ok());
        assert!(validate_shell_value("com.example/.MainActivity").is_ok());
        assert!(validate_shell_value("com.example; rm -rf /").is_err());
        assert!(validate_shell_value("$(reboot)").is_err());
        assert!(validate_shell_value("a b").is_err());
        assert!(validate_shell_value("`id`").is_err());
        assert!(validate_shell_value("").is_err());
        assert!(validate_shell_value("-Djava.class.path=/data/local/tmp/wp.dex").is_ok());
        assert_eq!(
            escape_device_arg("com.example/.Main$1"),
            "com.example/.Main\\$1"
        );
    }

    #[test]
    fn pushes_stay_inside_the_device_temp_directory() {
        assert!(validate_remote_path("/data/local/tmp/euphoria-wallpaper.dex").is_ok());
        assert!(validate_remote_path("/sdcard/evil").is_err());
        assert!(validate_remote_path("/data/local/tmp/../evil").is_err());
        assert!(validate_remote_path("/data/local/tmp/a b").is_err());
    }
}
