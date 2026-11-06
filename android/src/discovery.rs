use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::config::AndroidConfig;
use crate::process;

const ACCEL_TIMEOUT: Duration = Duration::from_secs(20);

pub const SETUP_HELP: &str = "\
Euphoria runs the APK in the official Android Emulator and can install the missing tools for you.
1. Press \"Set up automatically\" to download the Android command-line tools, platform-tools,
   emulator, a system image, an AVD, and scrcpy. Downloads start only after you confirm, come from
   Google and the official scrcpy releases, and need Java 17 or newer.
2. You can also install Android Studio, or the command-line tools with platform-tools, emulator,
   and a system image such as system-images;android-34;google_apis;x86_64, then create one AVD:
   avdmanager create avd -n euphoria -k \"system-images;android-34;google_apis;x86_64\" -d pixel_5
3. Install scrcpy for the screen, keyboard, and mouse. Without it Euphoria can still boot the
   emulator and fall back to the emulator's own window.
4. Enable hardware virtualization: WHPX on Windows, KVM on Linux, Hypervisor.framework on macOS.
5. Set the SDK path below or in android.json, next to config.json in the Euphoria settings folder.";

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Acceleration {
    Available(String),
    Unavailable(String),
    Unknown(String),
}

impl Acceleration {
    pub fn is_available(&self) -> bool {
        matches!(self, Self::Available(_))
    }

    pub fn summary(&self) -> &str {
        match self {
            Self::Available(text) | Self::Unavailable(text) | Self::Unknown(text) => text,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Avd {
    pub name: String,
    pub display_name: String,
    pub path: PathBuf,
    pub api: Option<u32>,
    pub abi: Option<String>,
    pub tag: String,
    pub width: Option<u32>,
    pub height: Option<u32>,
    pub density: Option<u32>,
    pub play_store: bool,
    pub error: Option<String>,
}

impl Avd {
    pub fn release(&self) -> String {
        self.api
            .map(|api| android_release(api).to_owned())
            .unwrap_or_default()
    }

    pub fn label(&self) -> String {
        let mut label = self.name.clone();
        if let Some(api) = self.api {
            label.push_str(&format!(" — API {api}"));
            let release = self.release();
            if !release.is_empty() {
                label.push_str(&format!(" ({release})"));
            }
        }
        if let Some(abi) = &self.abi {
            label.push_str(&format!(", {abi}"));
        }
        if self.play_store {
            label.push_str(", Play Store");
        }
        label
    }

    // x86_64 images normally run x86 code too; ARM images also contain 32-bit ARM support.
    pub fn abi_family(&self) -> Vec<String> {
        match self.abi.as_deref() {
            Some("x86_64") => vec!["x86_64".into(), "x86".into()],
            Some("arm64-v8a") => vec!["arm64-v8a".into(), "armeabi-v7a".into(), "armeabi".into()],
            Some(other) => vec![other.to_owned()],
            None => Vec::new(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct Environment {
    pub sdk_root: Option<PathBuf>,
    pub emulator: Option<PathBuf>,
    pub adb: Option<PathBuf>,
    pub scrcpy: Option<PathBuf>,
    pub avds: Vec<Avd>,
    pub acceleration: Acceleration,
    pub notes: Vec<String>,
}

impl Default for Environment {
    fn default() -> Self {
        Self {
            sdk_root: None,
            emulator: None,
            adb: None,
            scrcpy: None,
            avds: Vec::new(),
            acceleration: Acceleration::Unknown("Android tools have not been checked yet.".into()),
            notes: Vec::new(),
        }
    }
}

impl Environment {
    // This spawns adb/emulator probes, so callers run it on a worker thread.
    pub fn discover(config: &AndroidConfig) -> Self {
        let mut notes = Vec::new();
        let sdk_root = find_sdk_root(config, &mut notes);
        let emulator = resolve_tool(
            &config.emulator_path,
            "emulator",
            sdk_root.as_deref().map(|sdk| sdk.join("emulator")),
            &mut notes,
        );
        let adb = resolve_tool(
            &config.adb_path,
            "adb",
            sdk_root.as_deref().map(|sdk| sdk.join("platform-tools")),
            &mut notes,
        );
        let scrcpy = resolve_tool(&config.scrcpy_path, "scrcpy", None, &mut notes);
        let avds = discover_avds();
        if avds.is_empty() {
            notes.push(
                "No AVD was found in ANDROID_AVD_HOME, ANDROID_USER_HOME, or ~/.android/avd."
                    .to_owned(),
            );
        }
        let acceleration = match &emulator {
            Some(emulator) => detect_acceleration(emulator),
            None => Acceleration::Unknown(
                "Virtualization could not be checked because the Android Emulator was not found."
                    .to_owned(),
            ),
        };
        if !config.avd.trim().is_empty() && !avds.iter().any(|avd| avd.name == config.avd.trim()) {
            notes.push(format!(
                "The configured AVD '{}' was not found; Euphoria will pick a compatible one.",
                config.avd.trim()
            ));
        }

        Self {
            sdk_root,
            emulator,
            adb,
            scrcpy,
            avds,
            acceleration,
            notes,
        }
    }

    pub fn blocker(&self, allow_software_accel: bool) -> Option<String> {
        if self.emulator.is_none() {
            return Some(
                "The Android Emulator was not found. Install the emulator component and set the \
                 Android SDK path."
                    .to_owned(),
            );
        }
        if self.adb.is_none() {
            return Some(
                "adb was not found. Install Android platform-tools and set the Android SDK path."
                    .to_owned(),
            );
        }
        if !self.avds.iter().any(|avd| avd.error.is_none()) {
            return Some(
                "No usable Android Virtual Device (AVD) was found. Create one with avdmanager or \
                 Android Studio's Device Manager."
                    .to_owned(),
            );
        }
        if !allow_software_accel && let Acceleration::Unavailable(text) = &self.acceleration {
            return Some(format!(
                "Hardware virtualization is not available: {text}\nEnable WHPX (Windows), KVM \
                 (Linux), or Hypervisor.framework (macOS). Software emulation can be allowed in \
                 the emulator settings, but it is very slow."
            ));
        }
        None
    }

    pub fn ready(&self, allow_software_accel: bool) -> bool {
        self.blocker(allow_software_accel).is_none()
    }

    pub fn avd(&self, name: &str) -> Option<&Avd> {
        self.avds.iter().find(|avd| avd.name == name)
    }

    pub fn summary(&self) -> Vec<String> {
        let describe = |path: &Option<PathBuf>| {
            path.as_ref()
                .map_or_else(|| "not found".to_owned(), |path| path.display().to_string())
        };
        vec![
            format!("SDK: {}", describe(&self.sdk_root)),
            format!("Emulator: {}", describe(&self.emulator)),
            format!("adb: {}", describe(&self.adb)),
            format!("scrcpy: {}", describe(&self.scrcpy)),
            format!("AVDs: {}", self.avds.len()),
            format!("Virtualization: {}", self.acceleration.summary()),
        ]
    }
}

pub fn android_release(api: u32) -> &'static str {
    match api {
        21 => "5.0",
        22 => "5.1",
        23 => "6",
        24 => "7",
        25 => "7.1",
        26 => "8",
        27 => "8.1",
        28 => "9",
        29 => "10",
        30 => "11",
        31 => "12",
        32 => "12L",
        33 => "13",
        34 => "14",
        35 => "15",
        36 => "16",
        _ => "",
    }
}

fn find_sdk_root(config: &AndroidConfig, notes: &mut Vec<String>) -> Option<PathBuf> {
    let mut candidates = Vec::new();
    let configured = expand_home(config.sdk_root.trim());
    if !config.sdk_root.trim().is_empty() {
        if configured.is_dir() {
            candidates.push(configured.clone());
        } else {
            notes.push(format!(
                "The configured SDK path {} does not exist.",
                configured.display()
            ));
        }
    }
    for variable in ["ANDROID_SDK_ROOT", "ANDROID_HOME"] {
        if let Some(value) = env::var_os(variable) {
            let path = PathBuf::from(value);
            if path.is_dir() {
                candidates.push(path);
            }
        }
    }
    if cfg!(windows) {
        if let Some(base) = env::var_os("LOCALAPPDATA") {
            candidates.push(PathBuf::from(base).join("Android").join("Sdk"));
        }
    } else if cfg!(target_os = "macos") {
        if let Some(home) = home_dir() {
            candidates.push(home.join("Library/Android/sdk"));
        }
    } else {
        if let Some(home) = home_dir() {
            candidates.push(home.join("Android/Sdk"));
            candidates.push(home.join("android-sdk"));
        }
        candidates.push(PathBuf::from("/opt/android-sdk"));
        candidates.push(PathBuf::from("/usr/lib/android-sdk"));
    }

    // A directly configured emulator or adb also reveals the SDK root.
    for tool in [&config.emulator_path, &config.adb_path] {
        let path = expand_home(tool.trim());
        if path.is_file()
            && let Some(root) = path.parent().and_then(Path::parent)
            && root.is_dir()
        {
            candidates.push(root.to_owned());
        }
    }

    candidates.into_iter().find(|path| {
        path.join("emulator").is_dir()
            || path.join("platform-tools").is_dir()
            || path.join("cmdline-tools").is_dir()
    })
}

fn resolve_tool(
    configured: &str,
    name: &str,
    sdk_dir: Option<PathBuf>,
    notes: &mut Vec<String>,
) -> Option<PathBuf> {
    let configured = configured.trim();
    if !configured.is_empty() {
        let path = expand_home(configured);
        if path.is_file() {
            return Some(path);
        }
        if path.is_dir() {
            let candidate = path.join(executable_name(name));
            if candidate.is_file() {
                return Some(candidate);
            }
        }
        notes.push(format!(
            "The configured {name} path {} does not exist.",
            path.display()
        ));
    }

    if let Some(dir) = sdk_dir {
        let candidate = dir.join(executable_name(name));
        if candidate.is_file() {
            return Some(candidate);
        }
    }

    find_on_path(name)
}

fn executable_name(name: &str) -> String {
    if cfg!(windows) {
        format!("{name}.exe")
    } else {
        name.to_owned()
    }
}

fn find_on_path(name: &str) -> Option<PathBuf> {
    let path = env::var_os("PATH")?;
    let executable = executable_name(name);
    env::split_paths(&path)
        .map(|dir| dir.join(&executable))
        .find(|candidate| candidate.is_file())
}

fn home_dir() -> Option<PathBuf> {
    env::var_os("HOME")
        .or_else(|| env::var_os("USERPROFILE"))
        .map(PathBuf::from)
}

fn expand_home(value: &str) -> PathBuf {
    if let Some(rest) = value.strip_prefix("~/")
        && let Some(home) = home_dir()
    {
        return home.join(rest);
    }
    PathBuf::from(value)
}

pub fn discover_avds() -> Vec<Avd> {
    let mut found: Vec<Avd> = Vec::new();
    for home in avd_homes() {
        let Ok(entries) = fs::read_dir(&home) else {
            continue;
        };
        let mut files: Vec<PathBuf> = entries
            .flatten()
            .map(|entry| entry.path())
            .filter(|path| {
                path.extension().is_some_and(|ext| ext == "ini")
                    && path.file_stem().is_some_and(|stem| stem != "config")
            })
            .collect();
        files.sort();
        for ini in files {
            let Some(avd) = avd_from_ini(&ini) else {
                continue;
            };
            if !found.iter().any(|existing| existing.name == avd.name) {
                found.push(avd);
            }
        }
    }
    found.sort_by_key(|avd| avd.name.to_ascii_lowercase());
    found
}

fn avd_homes() -> Vec<PathBuf> {
    let mut homes = Vec::new();
    if let Some(path) = env::var_os("ANDROID_AVD_HOME") {
        homes.push(PathBuf::from(path));
    }
    if let Some(path) = env::var_os("ANDROID_USER_HOME") {
        homes.push(PathBuf::from(path).join("avd"));
    }
    if let Some(home) = home_dir() {
        homes.push(home.join(".android").join("avd"));
    }
    if let Some(config) = env::var_os("XDG_CONFIG_HOME") {
        homes.push(PathBuf::from(config).join(".android").join("avd"));
    }
    homes
}

fn avd_from_ini(ini_path: &Path) -> Option<Avd> {
    let name = ini_path.file_stem()?.to_string_lossy().into_owned();
    let ini_text = fs::read_to_string(ini_path).unwrap_or_default();
    let ini = parse_ini(&ini_text);
    let directory = ini
        .get("path")
        .map(|path| {
            let path = PathBuf::from(path);
            if path.is_absolute() {
                path
            } else {
                match ini_path.parent() {
                    Some(parent) => parent.join(&path),
                    None => path,
                }
            }
        })
        .unwrap_or_else(|| ini_path.with_extension("avd"));

    let config_path = directory.join("config.ini");
    let config = fs::read_to_string(&config_path)
        .map(|text| parse_ini(&text))
        .unwrap_or_default();

    let display_name = config
        .get("avd.ini.displayname")
        .or_else(|| ini.get("avd.ini.displayname"))
        .cloned()
        .unwrap_or_else(|| name.clone());
    let sysdir = config.get("image.sysdir.1").cloned().unwrap_or_default();
    let api = api_from_sysdir(&sysdir)
        .or_else(|| ini.get("target").and_then(|target| api_from_sysdir(target)))
        .or_else(|| {
            config
                .get("target")
                .and_then(|target| api_from_sysdir(target))
        });
    let abi = config
        .get("abi.type")
        .filter(|value| !value.is_empty())
        .cloned()
        .or_else(|| abi_from_sysdir(&sysdir))
        .or_else(|| {
            config
                .get("hw.cpu.arch")
                .and_then(|arch| arch_to_abi(arch))
                .map(str::to_owned)
        });
    let tag = config
        .get("tag.id")
        .cloned()
        .or_else(|| tag_from_sysdir(&sysdir))
        .unwrap_or_default();
    let play_store = config
        .get("PlayStore.enabled")
        .is_some_and(|value| value.eq_ignore_ascii_case("true"))
        || tag.contains("playstore");

    let error = if !config_path.is_file() {
        Some(format!(
            "{} is missing; the AVD is incomplete.",
            config_path.display()
        ))
    } else {
        None
    };

    Some(Avd {
        name,
        display_name,
        path: directory,
        api,
        abi,
        tag,
        width: number(&config, "hw.lcd.width"),
        height: number(&config, "hw.lcd.height"),
        density: number(&config, "hw.lcd.density"),
        play_store,
        error,
    })
}

fn parse_ini(text: &str) -> BTreeMap<String, String> {
    let mut values = BTreeMap::new();
    for line in text.trim_start_matches('\u{feff}').lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if let Some((key, value)) = line.split_once('=') {
            values.insert(key.trim().to_owned(), value.trim().to_owned());
        }
    }
    values
}

fn split_sysdir(sysdir: &str) -> Vec<&str> {
    sysdir
        .split([';', '/', '\\'])
        .map(str::trim)
        .filter(|part| !part.is_empty())
        .collect()
}

fn api_from_sysdir(sysdir: &str) -> Option<u32> {
    split_sysdir(sysdir)
        .iter()
        .find_map(|part| part.strip_prefix("android-"))
        .and_then(|level| level.parse().ok())
}

fn abi_from_sysdir(sysdir: &str) -> Option<String> {
    split_sysdir(sysdir)
        .last()
        .and_then(|abi| arch_to_abi(abi).map(str::to_owned))
}

fn tag_from_sysdir(sysdir: &str) -> Option<String> {
    let parts = split_sysdir(sysdir);
    parts.get(2).map(|tag| (*tag).to_owned())
}

fn arch_to_abi(arch: &str) -> Option<&'static str> {
    match arch.trim() {
        "x86_64" => Some("x86_64"),
        "x86" => Some("x86"),
        "arm64" | "arm64-v8a" => Some("arm64-v8a"),
        "arm" | "armeabi-v7a" => Some("armeabi-v7a"),
        "armeabi" => Some("armeabi"),
        _ => None,
    }
}

fn number(config: &BTreeMap<String, String>, key: &str) -> Option<u32> {
    config.get(key).and_then(|value| value.parse().ok())
}

pub fn detect_acceleration(emulator: &Path) -> Acceleration {
    let output = match process::run_capture(emulator, &["-accel-check"], ACCEL_TIMEOUT) {
        Ok(output) => output,
        Err(error) => {
            return Acceleration::Unknown(format!("Running emulator -accel-check failed: {error}"));
        }
    };
    let text = output.combined();

    // On Linux the emulator cannot accelerate without the KVM device, whatever adb reports.
    if cfg!(target_os = "linux") && !Path::new("/dev/kvm").exists() {
        return Acceleration::Unavailable(
            "KVM is not available because /dev/kvm does not exist. Load the kvm module, enable \
             virtualization in the firmware, and make sure your user can access /dev/kvm."
                .to_owned(),
        );
    }
    classify_acceleration(&text, output.success)
}

fn classify_acceleration(text: &str, success: bool) -> Acceleration {
    let lower = text.to_ascii_lowercase();
    let summary: String = text
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .chars()
        .take(500)
        .collect();
    let summary = if summary.is_empty() {
        "the emulator returned no explanation".to_owned()
    } else {
        summary
    };

    if lower.contains("is installed and usable") {
        return Acceleration::Available(summary);
    }
    let unavailable = [
        "not installed",
        "not usable",
        "not supported",
        "not enabled",
        "disabled",
        "failed",
        "cannot",
        "requires",
        "no accelerator",
        "unavailable",
        "does not exist",
    ];
    if unavailable.iter().any(|needle| lower.contains(needle)) {
        return Acceleration::Unavailable(summary);
    }
    if success {
        Acceleration::Available(summary)
    } else {
        Acceleration::Unavailable(summary)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_platform_acceleration_messages() {
        assert!(matches!(
            classify_acceleration("WHPX(10.0.19041) is installed and usable.", true),
            Acceleration::Available(_)
        ));
        assert!(matches!(
            classify_acceleration("KVM is installed and usable.", true),
            Acceleration::Available(_)
        ));
        assert!(matches!(
            classify_acceleration("HVF is installed and usable.", true),
            Acceleration::Available(_)
        ));
        assert!(matches!(
            classify_acceleration(
                "WHPX is either not installed or not enabled. Please enable it.",
                false
            ),
            Acceleration::Unavailable(_)
        ));
        assert!(matches!(
            classify_acceleration("HAXM is not installed.", false),
            Acceleration::Unavailable(_)
        ));
        assert!(matches!(
            classify_acceleration("KVM requires a CPU that supports vmx or svm.", false),
            Acceleration::Unavailable(_)
        ));
    }

    #[test]
    fn reads_avd_metadata_from_an_ini_pair() {
        let base = env::temp_dir().join(format!("euphoria-android-avd-{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        let directory = base.join("euphoria.avd");
        fs::create_dir_all(&directory).unwrap();
        fs::write(
            base.join("euphoria.ini"),
            "avd.ini.encoding=UTF-8\npath=euphoria.avd\ntarget=android-34\n",
        )
        .unwrap();
        fs::write(
            directory.join("config.ini"),
            "AvdId=euphoria\navd.ini.displayname=Euphoria Test\n\
             image.sysdir.1=system-images;android-34;google_apis;x86_64/\n\
             abi.type=x86_64\nhw.lcd.width=1080\nhw.lcd.height=2400\nhw.lcd.density=420\n",
        )
        .unwrap();

        let avd = avd_from_ini(&base.join("euphoria.ini")).unwrap();
        assert_eq!(avd.display_name, "Euphoria Test");
        assert_eq!(avd.api, Some(34));
        assert_eq!(avd.abi.as_deref(), Some("x86_64"));
        assert_eq!(avd.tag, "google_apis");
        assert_eq!(avd.width, Some(1080));
        assert_eq!(avd.height, Some(2400));
        assert_eq!(avd.density, Some(420));
        assert!(!avd.play_store);
        assert!(avd.error.is_none());
        assert_eq!(avd.abi_family(), ["x86_64", "x86"]);
        assert_eq!(avd.release(), "14");

        fs::remove_dir_all(&base).unwrap();
    }

    #[test]
    fn parses_old_and_new_system_image_paths() {
        assert_eq!(
            api_from_sysdir("system-images;android-34;google_apis;x86_64/"),
            Some(34)
        );
        assert_eq!(
            api_from_sysdir(r"system-images\android-30\google_apis\x86_64\"),
            Some(30)
        );
        assert_eq!(
            abi_from_sysdir("system-images;android-34;google_apis;arm64-v8a/").as_deref(),
            Some("arm64-v8a")
        );
        assert_eq!(api_from_sysdir("not-an-api"), None);
    }

    #[test]
    fn ini_values_are_trimmed_and_comments_skipped() {
        let parsed = parse_ini("# comment\npath = C:\\avd\\test.avd\n; other\n\nabi.type=x86\n");
        assert_eq!(
            parsed.get("path").map(String::as_str),
            Some("C:\\avd\\test.avd")
        );
        assert_eq!(parsed.get("abi.type").map(String::as_str), Some("x86"));
    }
}
