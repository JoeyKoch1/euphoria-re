use std::collections::VecDeque;
use std::env;
use std::fs::{self, File};
use std::io::{self, Read};
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Sender};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail, ensure};

use crate::config::{AndroidConfig, settings_dir};
use crate::discovery::discover_avds;
use crate::emulator::validate_avd_name;
use crate::process::{Output, ProcessGuard};

const REPOSITORY_BASE: &str = "https://dl.google.com/android/repository/";
const REPOSITORIES: [&str; 2] = [
    "https://dl.google.com/android/repository/repository2-3.xml",
    "https://dl.google.com/android/repository/repository2-1.xml",
];
const SCRCPY_LATEST: &str = "https://api.github.com/repos/Genymobile/scrcpy/releases/latest";
const SYSTEM_IMAGE_API: u32 = 34;
const AVD_NAME: &str = "Euphoria_API_34";
const LICENSE_TIMEOUT: Duration = Duration::from_secs(600);
const INSTALL_TIMEOUT: Duration = Duration::from_secs(7200);
const AVD_TIMEOUT: Duration = Duration::from_secs(300);
const MAX_EXTRACTED_BYTES: u64 = 8 * 1024 * 1024 * 1024;
const OUTPUT_TAIL_LINES: usize = 240;
const POLL: Duration = Duration::from_millis(200);
const DOWNLOAD_STALL: Duration = Duration::from_secs(180);

pub const SOURCES: &str = "\
Downloads come only from Google's official SDK repository (dl.google.com) and the official \
scrcpy releases on GitHub (github.com/Genymobile/scrcpy). Euphoria checks the published SHA-1 \
or SHA-256 value whenever the source publishes one. Installing needs Java 17 or newer, which \
Android Studio also provides.";

const JAVA_HELP: &str = "\
Android's command-line tools need Java 17 or newer. Install a JDK (for example Temurin, Microsoft \
OpenJDK, or zulu), or install Android Studio which bundles one, then run setup again. If Java is \
installed in a nonstandard place, set JAVA_HOME to its folder.";

// Google publishes arm64 system images for macOS and Linux, but the Windows emulator uses x86_64.
#[cfg(all(any(target_os = "macos", target_os = "linux"), target_arch = "aarch64"))]
const HOST_ABI: &str = "arm64-v8a";
#[cfg(not(all(any(target_os = "macos", target_os = "linux"), target_arch = "aarch64")))]
const HOST_ABI: &str = "x86_64";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SetupOutcome {
    pub sdk_root: PathBuf,
    pub avd: Option<String>,
    pub scrcpy: Option<PathBuf>,
    pub notes: Vec<String>,
}

#[derive(Debug)]
pub enum SetupUpdate {
    Progress { detail: String, percent: Option<u8> },
    Finished(SetupOutcome),
    Canceled,
    Failed(String),
}

// The requested folder for the managed SDK. A configured SDK root is respected, so setup repairs
// an existing installation instead of creating a second one.
pub fn planned_root(config: &AndroidConfig) -> PathBuf {
    let configured = config.sdk_root.trim();
    if configured.is_empty() {
        settings_dir().join("android-sdk")
    } else {
        expand_home(configured)
    }
}

// The installer runs on its own thread so downloads and sdkmanager never block the UI. It owns a
// job object so Java and curl cannot outlive Euphoria even when the window is closed mid-setup.
pub fn spawn(config: AndroidConfig, sender: Sender<SetupUpdate>, cancel: Arc<AtomicBool>) {
    thread::spawn(move || {
        let guard = ProcessGuard::new();
        let update = match run(&config, &sender, &cancel, &guard) {
            Ok(outcome) => SetupUpdate::Finished(outcome),
            Err(error) if is_canceled(&error) => SetupUpdate::Canceled,
            Err(error) => SetupUpdate::Failed(format!("{error:#}")),
        };
        let _ = sender.send(update);
    });
}

fn run(
    config: &AndroidConfig,
    sender: &Sender<SetupUpdate>,
    cancel: &AtomicBool,
    guard: &ProcessGuard,
) -> Result<SetupOutcome> {
    let root = planned_root(config);
    fs::create_dir_all(&root).with_context(|| format!("cannot create {}", root.display()))?;
    let downloads = tempfile::Builder::new()
        .prefix("euphoria-android-")
        .tempdir()
        .context("cannot create a temporary download folder")?;

    let mut reporter = Reporter::new(sender);
    let mut installer = Installer {
        root: root.clone(),
        downloads: downloads.path().to_path_buf(),
        guard,
        cancel,
        reporter: &mut reporter,
        notes: Vec::new(),
    };

    check_cancel(cancel)?;
    // Check Java before the large download so a missing JDK fails in seconds, not gigabytes.
    let java = find_java()?;
    installer
        .reporter
        .set(format!("Using Java at {}.", java.display()), None);

    installer
        .reporter
        .set("Checking the Android command-line tools...", None);
    let tools = root.join("cmdline-tools").join("latest").join("lib");
    if !tools.is_dir() {
        installer.install_tools()?;
    }

    let need_adb = !root.join("platform-tools").join(exe_name("adb")).is_file();
    let need_emulator = !root.join("emulator").join(exe_name("emulator")).is_file();
    let compatible = discover_avds()
        .into_iter()
        .any(|avd| avd.error.is_none() && avd.abi_family().iter().any(|abi| abi == HOST_ABI));
    let image = system_image();
    let image_path = root
        .join("system-images")
        .join(format!("android-{SYSTEM_IMAGE_API}"))
        .join("google_apis")
        .join(HOST_ABI);
    let need_image = !compatible && !image_path.is_dir();

    let mut packages = Vec::new();
    if need_adb {
        packages.push("platform-tools".to_owned());
    }
    if need_emulator {
        packages.push("emulator".to_owned());
    }
    if need_image {
        packages.push(image.clone());
    }
    if !packages.is_empty() {
        installer.accept_licenses(&java)?;
        installer.install_packages(&java, &packages)?;
    }

    let avd = if compatible {
        None
    } else {
        installer.create_avd(&java, &image)?;
        Some(AVD_NAME.to_owned())
    };

    let mut scrcpy = None;
    match find_scrcpy(config, &root) {
        // A managed copy is recorded in the settings so discovery finds it next time.
        Some(path) if path.starts_with(root.join("scrcpy")) => scrcpy = Some(path),
        Some(_) => {}
        None if cfg!(windows) => match installer.install_scrcpy() {
            Ok(path) => {
                installer
                    .notes
                    .push(format!("scrcpy was installed at {}.", path.display()));
                scrcpy = Some(path);
            }
            Err(error) if is_canceled(&error) => return Err(error),
            Err(error) => installer.notes.push(format!(
                "scrcpy could not be installed ({}). Euphoria will use the emulator's own window \
                 instead.",
                one_line(&error)
            )),
        },
        None => installer.notes.push(
            "Install scrcpy with your package manager (for example `brew install scrcpy` or \
             `sudo apt install scrcpy`). Until then Euphoria uses the emulator's own window."
                .to_owned(),
        ),
    }

    installer
        .reporter
        .set("Android setup is complete.", Some(100));
    Ok(SetupOutcome {
        sdk_root: root,
        avd,
        scrcpy,
        notes: installer.notes,
    })
}

struct Installer<'a> {
    root: PathBuf,
    downloads: PathBuf,
    guard: &'a ProcessGuard,
    cancel: &'a AtomicBool,
    reporter: &'a mut Reporter,
    notes: Vec<String>,
}

impl Installer<'_> {
    fn check(&self) -> Result<()> {
        check_cancel(self.cancel)
    }

    fn install_tools(&mut self) -> Result<()> {
        self.reporter
            .set("Finding the official Android command-line tools...", None);
        let archive = self.repository_archive()?;
        let zip = self.downloads.join("commandlinetools.zip");
        self.reporter
            .set("Downloading the Android command-line tools...", None);
        self.download(
            &archive.url,
            &zip,
            archive.size,
            archive.sha1.as_deref(),
            "the Android command-line tools",
        )?;

        self.reporter
            .set("Unpacking the Android command-line tools...", None);
        let tools = self.root.join("cmdline-tools");
        fs::create_dir_all(&tools)?;
        let staging = tools.join(format!(".installing-{}", std::process::id()));
        self.extract(&zip, &staging, &tools.join("latest"))?;
        self.reporter
            .set("The Android command-line tools are ready.", None);
        Ok(())
    }

    fn repository_archive(&mut self) -> Result<Archive> {
        let host = host_os();
        let mut last = "no repository was reachable".to_owned();
        for url in REPOSITORIES {
            self.check()?;
            match fetch_text(url) {
                Ok(text) => {
                    if let Some(archive) = cmdline_tools_archive(&text, host) {
                        return Ok(archive);
                    }
                    last = format!("{url} did not list cmdline-tools;latest for {host}");
                }
                Err(error) => last = format!("{error:#}"),
            }
        }
        bail!("Could not find the official Android command-line tools. {last}");
    }

    fn accept_licenses(&mut self, java: &Path) -> Result<()> {
        self.reporter
            .set("Accepting the Android SDK licenses...", None);
        let input = b"y\n".repeat(128);
        self.sdkmanager(java, &["--licenses".to_owned()], &input, LICENSE_TIMEOUT)?;
        Ok(())
    }

    fn install_packages(&mut self, java: &Path, packages: &[String]) -> Result<()> {
        if packages.is_empty() {
            return Ok(());
        }
        self.reporter
            .set(format!("Installing {}...", packages.join(", ")), None);
        let mut extra = vec!["--install".to_owned()];
        extra.extend(packages.iter().cloned());
        let input = b"y\n".repeat(128);
        self.sdkmanager(java, &extra, &input, INSTALL_TIMEOUT)?;
        Ok(())
    }

    fn create_avd(&mut self, java: &Path, image: &str) -> Result<()> {
        validate_avd_name(AVD_NAME)?;
        self.reporter.set(
            format!("Creating the disposable virtual device {AVD_NAME}..."),
            None,
        );
        let input = b"no\n".repeat(16);
        let base = vec![
            "create".to_owned(),
            "avd".to_owned(),
            "-n".to_owned(),
            AVD_NAME.to_owned(),
            "-k".to_owned(),
            image.to_owned(),
        ];

        let mut with_device = base.clone();
        with_device.extend(["-d".to_owned(), "pixel_5".to_owned(), "--force".to_owned()]);
        let first = self.avdmanager(java, &with_device, &input)?;
        if !first.success {
            let mut plain = base;
            plain.push("--force".to_owned());
            let second = self.avdmanager(java, &plain, &input)?;
            ensure!(
                second.success,
                "Could not create an AVD.\n{}\n{}",
                tail_text(&first),
                tail_text(&second)
            );
        }

        ensure!(
            discover_avds().into_iter().any(|avd| avd.name == AVD_NAME),
            "avdmanager reported success, but the AVD {AVD_NAME} was not found."
        );
        Ok(())
    }

    fn install_scrcpy(&mut self) -> Result<PathBuf> {
        self.reporter
            .set("Looking up the latest scrcpy release...", None);
        let json = fetch_text(SCRCPY_LATEST)?;
        let release: Release =
            serde_json::from_str(&json).context("the scrcpy release list could not be read")?;
        let asset = select_scrcpy_asset(&release.assets)?;
        let digest = asset
            .digest
            .as_deref()
            .and_then(|digest| digest.strip_prefix("sha256:"));

        let zip = self.downloads.join("scrcpy.zip");
        self.reporter.set("Downloading scrcpy...", None);
        self.download(
            &asset.browser_download_url,
            &zip,
            asset.size,
            None,
            "scrcpy",
        )?;
        if let Some(expected) = digest {
            ensure!(
                sha256_file(&zip)?.eq_ignore_ascii_case(expected),
                "The scrcpy download did not match GitHub's published SHA-256 digest."
            );
        }

        self.reporter.set("Unpacking scrcpy...", None);
        let staging = self
            .root
            .join(format!(".scrcpy-installing-{}", std::process::id()));
        let final_dir = self.root.join("scrcpy");
        self.extract(&zip, &staging, &final_dir)?;
        let executable = final_dir.join(exe_name("scrcpy"));
        ensure!(
            executable.is_file(),
            "The scrcpy archive did not contain scrcpy.exe."
        );
        Ok(executable)
    }

    fn sdkmanager(
        &mut self,
        java: &Path,
        extra: &[String],
        input: &[u8],
        timeout: Duration,
    ) -> Result<Output> {
        let args = self.java_args(
            "com.android.sdklib.tool.sdkmanager.SdkManagerCli",
            extra,
            true,
        );
        let output = self.java(java, &args, input, timeout)?;
        ensure!(
            output.success,
            "The Android SDK manager failed.\n{}",
            tail_text(&output)
        );
        Ok(output)
    }

    fn avdmanager(&mut self, java: &Path, extra: &[String], input: &[u8]) -> Result<Output> {
        let args = self.java_args("com.android.sdklib.tool.AvdManagerCli", extra, false);
        self.java(java, &args, input, AVD_TIMEOUT)
    }

    fn java_args(&self, class: &str, extra: &[String], sdk_root: bool) -> Vec<String> {
        let tools = self.root.join("cmdline-tools").join("latest");
        let lib = tools.join("lib");
        let mut args = vec![
            // The .bat wrappers set this, and avdmanager refuses to start without it.
            format!("-Dcom.android.sdkmanager.toolsdir={}", tools.display()),
            "-classpath".to_owned(),
            format!("{}{}*", lib.display(), std::path::MAIN_SEPARATOR),
            class.to_owned(),
        ];
        if sdk_root {
            args.push(format!("--sdk_root={}", self.root.display()));
        }
        args.extend(extra.iter().cloned());
        args
    }

    fn java(
        &mut self,
        java: &Path,
        args: &[String],
        input: &[u8],
        timeout: Duration,
    ) -> Result<Output> {
        let vars = [
            ("ANDROID_SDK_ROOT", self.root.as_path()),
            ("ANDROID_HOME", self.root.as_path()),
        ];
        run_streaming(
            java,
            args,
            &vars,
            input,
            timeout,
            self.guard,
            self.cancel,
            self.reporter,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn download(
        &mut self,
        url: &str,
        destination: &Path,
        expected_size: Option<u64>,
        expected_sha1: Option<&str>,
        label: &str,
    ) -> Result<()> {
        self.check()?;
        let (program, args) = download_command(url, destination)?;
        let _ = fs::remove_file(destination);

        let mut child = Command::new(&program)
            .args(&args)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .with_context(|| format!("cannot start {}", program.display()))?;
        self.guard.assign(&child);
        let errors = child
            .stderr
            .take()
            .map(|stderr| thread::spawn(move || read_text(stderr)));

        let mut last_bytes = 0;
        let mut last_change = Instant::now();
        let status = loop {
            if self.cancel.load(Ordering::Relaxed) {
                let _ = child.kill();
                let _ = child.wait();
                let _ = fs::remove_file(destination);
                let _ = errors.map(|reader| reader.join());
                bail!(Canceled);
            }
            if let Some(status) = child.try_wait()? {
                break status;
            }
            let bytes = fs::metadata(destination).map_or(0, |meta| meta.len());
            if bytes != last_bytes {
                last_bytes = bytes;
                last_change = Instant::now();
            } else if last_change.elapsed() > DOWNLOAD_STALL {
                let _ = child.kill();
                let _ = child.wait();
                let _ = fs::remove_file(destination);
                let _ = errors.map(|reader| reader.join());
                bail!(
                    "Downloading {label} stalled at {} MB for {} seconds. Check the network \
                     connection and try again.",
                    bytes / 1_048_576,
                    DOWNLOAD_STALL.as_secs()
                );
            }
            let (detail, percent) = match expected_size.filter(|size| *size > 0) {
                Some(total) => {
                    let percent = ((bytes.saturating_mul(100) / total).min(99)) as u8;
                    (format!("Downloading {label}... {percent}%"), Some(percent))
                }
                None => (
                    format!("Downloading {label}... {} MB", bytes / 1_048_576),
                    None,
                ),
            };
            self.reporter.set(detail, percent);
            thread::sleep(POLL);
        };

        let stderr = errors
            .map(|reader| reader.join().unwrap_or_default())
            .unwrap_or_default();
        if !status.success() {
            let _ = fs::remove_file(destination);
            bail!("Downloading {label} failed ({status}). {}", stderr.trim());
        }
        if let Some(expected) = expected_size.filter(|size| *size > 0) {
            let actual = fs::metadata(destination).map_or(0, |meta| meta.len());
            ensure!(
                actual == expected,
                "The {label} download is incomplete: expected {expected} bytes, got {actual}."
            );
        }
        if let Some(expected) = expected_sha1 {
            ensure!(
                sha1_file(destination)?.eq_ignore_ascii_case(expected),
                "The {label} download did not match Google's published SHA-1 checksum."
            );
        }
        self.reporter.set(format!("Downloaded {label}."), None);
        Ok(())
    }

    fn extract(&mut self, zip: &Path, staging: &Path, final_dir: &Path) -> Result<()> {
        if staging.exists() {
            fs::remove_dir_all(staging)
                .with_context(|| format!("cannot clear {}", staging.display()))?;
        }
        fs::create_dir_all(staging)?;
        if let Err(error) = extract_zip(zip, staging, self.cancel) {
            let _ = fs::remove_dir_all(staging);
            return Err(error);
        }
        if final_dir.exists() {
            fs::remove_dir_all(final_dir)
                .with_context(|| format!("cannot replace {}", final_dir.display()))?;
        }
        fs::rename(staging, final_dir).with_context(|| {
            format!("cannot move the extracted files to {}", final_dir.display())
        })?;
        Ok(())
    }
}

struct Reporter {
    sender: Sender<SetupUpdate>,
    detail: String,
    percent: Option<u8>,
}

impl Reporter {
    fn new(sender: &Sender<SetupUpdate>) -> Self {
        Self {
            sender: sender.clone(),
            detail: String::new(),
            percent: None,
        }
    }

    fn set(&mut self, detail: impl Into<String>, percent: Option<u8>) {
        let detail = detail.into();
        if detail == self.detail && percent == self.percent {
            return;
        }
        self.detail = detail.clone();
        self.percent = percent;
        let _ = self.sender.send(SetupUpdate::Progress { detail, percent });
    }

    fn line(&mut self, line: &str) {
        if let Some(percent) = parse_percent(line) {
            let detail = if self.detail.is_empty() {
                "Installing Android components...".to_owned()
            } else {
                self.detail.clone()
            };
            self.set(detail, Some(percent.min(99)));
        } else if let Some(text) = interesting(line) {
            self.set(text, None);
        }
    }
}

// A long-lived command whose output drives progress. Line readers feed a channel so the wait loop
// can poll for cancellation and a timeout at the same time.
#[allow(clippy::too_many_arguments)]
fn run_streaming(
    program: &Path,
    args: &[String],
    vars: &[(&str, &Path)],
    input: &[u8],
    timeout: Duration,
    guard: &ProcessGuard,
    cancel: &AtomicBool,
    reporter: &mut Reporter,
) -> Result<Output> {
    let mut command = Command::new(program);
    command
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (key, value) in vars {
        command.env(key, value);
    }

    let mut child = command
        .spawn()
        .with_context(|| format!("cannot start {}", program.display()))?;
    guard.assign(&child);

    if let Some(mut stdin) = child.stdin.take() {
        let _ = io::Write::write_all(&mut stdin, input);
    }

    let (line_sender, lines) = mpsc::channel();
    if let Some(stdout) = child.stdout.take() {
        let sender = line_sender.clone();
        thread::spawn(move || pump(stdout, sender, false));
    }
    if let Some(stderr) = child.stderr.take() {
        thread::spawn(move || pump(stderr, line_sender, true));
    }

    let deadline = Instant::now() + timeout;
    let mut stdout = VecDeque::new();
    let mut stderr = VecDeque::new();

    let status = loop {
        if cancel.load(Ordering::Relaxed) {
            let _ = child.kill();
            let _ = child.wait();
            bail!(Canceled);
        }
        while let Ok((is_error, line)) = lines.try_recv() {
            reporter.line(&line);
            let tail = if is_error { &mut stderr } else { &mut stdout };
            if tail.len() == OUTPUT_TAIL_LINES {
                tail.pop_front();
            }
            tail.push_back(line);
        }
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            bail!(
                "{} did not finish within {} seconds.",
                program.display(),
                timeout.as_secs()
            );
        }
        thread::sleep(Duration::from_millis(50));
    };

    while let Ok((is_error, line)) = lines.try_recv() {
        reporter.line(&line);
        let tail = if is_error { &mut stderr } else { &mut stdout };
        if tail.len() == OUTPUT_TAIL_LINES {
            tail.pop_front();
        }
        tail.push_back(line);
    }

    Ok(Output {
        success: status.success(),
        stdout: stdout.into_iter().collect::<Vec<_>>().join("\n"),
        stderr: stderr.into_iter().collect::<Vec<_>>().join("\n"),
    })
}

fn pump(mut reader: impl Read, sender: Sender<(bool, String)>, is_error: bool) {
    let mut buffer = Vec::new();
    let mut chunk = [0u8; 8192];
    loop {
        let read = match reader.read(&mut chunk) {
            Ok(0) => break,
            Ok(read) => read,
            Err(_) => break,
        };
        for &byte in &chunk[..read] {
            if byte == b'\n' || byte == b'\r' {
                if !buffer.is_empty() {
                    let line = String::from_utf8_lossy(&buffer).trim().to_owned();
                    buffer.clear();
                    if sender.send((is_error, line)).is_err() {
                        return;
                    }
                }
            } else if buffer.len() < 8192 {
                buffer.push(byte);
            }
        }
    }
    if !buffer.is_empty() {
        let line = String::from_utf8_lossy(&buffer).trim().to_owned();
        let _ = sender.send((is_error, line));
    }
}

fn read_text(mut reader: impl Read) -> String {
    let mut text = String::new();
    let _ = reader.read_to_string(&mut text);
    text
}

fn check_cancel(cancel: &AtomicBool) -> Result<()> {
    if cancel.load(Ordering::Relaxed) {
        bail!(Canceled);
    }
    Ok(())
}

#[derive(Debug)]
struct Canceled;

impl std::fmt::Display for Canceled {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("setup was canceled")
    }
}

impl std::error::Error for Canceled {}

fn is_canceled(error: &anyhow::Error) -> bool {
    error.downcast_ref::<Canceled>().is_some()
}

fn tail_text(output: &Output) -> String {
    let mut text = output.stdout.trim().to_owned();
    let stderr = output.stderr.trim();
    if !stderr.is_empty() {
        if !text.is_empty() {
            text.push('\n');
        }
        text.push_str(stderr);
    }
    if text.trim().is_empty() {
        "The tool printed no details.".to_owned()
    } else {
        text
    }
}

fn one_line(error: &anyhow::Error) -> String {
    let text = format!("{error:#}");
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn fetch_text(url: &str) -> Result<String> {
    let mut last = None;
    if let Some(curl) = find_program("curl") {
        let args = ["-fsSL", "--max-time", "60", url];
        match crate::process::run_capture(&curl, &args, Duration::from_secs(75)) {
            Ok(output) if output.success && !output.stdout.trim().is_empty() => {
                return Ok(output.stdout);
            }
            Ok(output) => last = Some(output.combined()),
            Err(error) => last = Some(format!("{error:#}")),
        }
    }
    if let Some(wget) = find_program("wget") {
        let args = ["-q", "-O", "-", url];
        match crate::process::run_capture(&wget, &args, Duration::from_secs(75)) {
            Ok(output) if output.success && !output.stdout.trim().is_empty() => {
                return Ok(output.stdout);
            }
            Ok(output) => last = Some(output.combined()),
            Err(error) => last = Some(format!("{error:#}")),
        }
    }
    bail!(
        "Could not download {url}. {}",
        last.unwrap_or_else(|| "Install curl or wget first.".to_owned())
    )
}

fn download_command(url: &str, destination: &Path) -> Result<(PathBuf, Vec<String>)> {
    let target = destination.display().to_string();
    if let Some(curl) = find_program("curl") {
        let args = vec![
            "-L".to_owned(),
            "--fail".to_owned(),
            "--silent".to_owned(),
            "--show-error".to_owned(),
            "--retry".to_owned(),
            "3".to_owned(),
            "--connect-timeout".to_owned(),
            "30".to_owned(),
            "--output".to_owned(),
            target,
            url.to_owned(),
        ];
        return Ok((curl, args));
    }
    if let Some(wget) = find_program("wget") {
        let args = vec!["-q".to_owned(), "-O".to_owned(), target, url.to_owned()];
        return Ok((wget, args));
    }
    bail!("Downloading the Android tools needs curl or wget, and neither was found on PATH.");
}

fn find_program(name: &str) -> Option<PathBuf> {
    let executable = exe_name(name);
    let path = env::var_os("PATH")?;
    env::split_paths(&path)
        .map(|directory| directory.join(&executable))
        .find(|candidate| candidate.is_file())
}

// sdkmanager refuses to start on old Java, and the same JDK must also run avdmanager.
fn find_java() -> Result<PathBuf> {
    let mut seen: Vec<PathBuf> = Vec::new();
    let mut older = Vec::new();
    let mut unreadable = None;
    for candidate in java_candidates() {
        if !candidate.is_file() || seen.contains(&candidate) {
            continue;
        }
        seen.push(candidate.clone());
        match java_major(&candidate) {
            Some(major) if major >= 17 => return Ok(candidate),
            Some(major) => older.push(format!("{} (Java {major})", candidate.display())),
            None => {
                unreadable.get_or_insert(candidate);
            }
        }
    }
    if let Some(candidate) = unreadable {
        return Ok(candidate);
    }
    if older.is_empty() {
        bail!("{JAVA_HELP}");
    }
    bail!(
        "{JAVA_HELP}\nFound these older versions: {}.",
        older.join(", ")
    )
}

fn java_major(java: &Path) -> Option<u32> {
    let output = crate::process::run_capture(java, &["-version"], Duration::from_secs(10)).ok()?;
    let text = output.combined();
    let start = text.find("version \"")? + "version \"".len();
    let rest = &text[start..];
    let end = rest.find('"')?;
    let mut parts = rest[..end].split(['.', '_', '-']);
    let first: u32 = parts.next()?.parse().ok()?;
    if first == 1 {
        parts.next()?.parse().ok()
    } else {
        Some(first)
    }
}

fn java_candidates() -> Vec<PathBuf> {
    let mut candidates = Vec::new();
    if let Some(home) = env::var_os("JAVA_HOME") {
        candidates.push(PathBuf::from(home).join("bin").join(exe_name("java")));
    }
    if let Some(java) = find_program("java") {
        candidates.push(java);
    }
    if cfg!(windows) {
        for base in ["ProgramFiles", "ProgramW6432", "LOCALAPPDATA"] {
            if let Some(directory) = env::var_os(base) {
                let directory = PathBuf::from(directory);
                candidates.push(
                    directory
                        .join("Android")
                        .join("Android Studio")
                        .join("jbr")
                        .join("bin")
                        .join("java.exe"),
                );
                candidates.push(
                    directory
                        .join("Programs")
                        .join("Android Studio")
                        .join("jbr")
                        .join("bin")
                        .join("java.exe"),
                );
            }
        }
    } else if cfg!(target_os = "macos") {
        candidates.push(PathBuf::from(
            "/Applications/Android Studio.app/Contents/jbr/Contents/Home/bin/java",
        ));
    } else {
        candidates.push(PathBuf::from("/opt/android-studio/jbr/bin/java"));
        if let Some(home) = home_dir() {
            candidates.push(
                home.join("android-studio")
                    .join("jbr")
                    .join("bin")
                    .join("java"),
            );
        }
    }
    candidates
}

fn find_scrcpy(config: &AndroidConfig, root: &Path) -> Option<PathBuf> {
    let configured = expand_home(config.scrcpy_path.trim());
    if !config.scrcpy_path.trim().is_empty() {
        if configured.is_file() {
            return Some(configured);
        }
        let candidate = configured.join(exe_name("scrcpy"));
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    let installed = root.join("scrcpy").join(exe_name("scrcpy"));
    if installed.is_file() {
        return Some(installed);
    }
    find_program("scrcpy")
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

fn exe_name(name: &str) -> String {
    format!("{name}{}", env::consts::EXE_SUFFIX)
}

fn host_os() -> &'static str {
    if cfg!(windows) {
        "windows"
    } else if cfg!(target_os = "macos") {
        "macosx"
    } else {
        "linux"
    }
}

fn system_image() -> String {
    format!("system-images;android-{SYSTEM_IMAGE_API};google_apis;{HOST_ABI}")
}

fn parse_percent(line: &str) -> Option<u8> {
    let bytes = line.as_bytes();
    for (index, &byte) in bytes.iter().enumerate() {
        if byte != b'%' {
            continue;
        }
        let mut start = index;
        while start > 0 && bytes[start - 1].is_ascii_digit() {
            start -= 1;
        }
        if start < index {
            return line[start..index]
                .parse()
                .ok()
                .filter(|percent| *percent <= 100);
        }
    }
    None
}

fn interesting(line: &str) -> Option<String> {
    let trimmed = line.trim();
    if trimmed.len() < 8 {
        return None;
    }
    let lower = trimmed.to_ascii_lowercase();
    const KEYS: [&str; 5] = [
        "downloading",
        "unzipping",
        "installing",
        "preparing",
        "fetching",
    ];
    if KEYS.iter().any(|key| lower.contains(key)) {
        Some(trimmed.chars().take(160).collect())
    } else {
        None
    }
}

fn sha1_file(path: &Path) -> Result<String> {
    use sha1::Digest;
    let mut hasher = sha1::Sha1::new();
    let mut file = File::open(path)?;
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hex(&hasher.finalize()))
}

fn sha256_file(path: &Path) -> Result<String> {
    use sha2::Digest;
    let mut hasher = sha2::Sha256::new();
    let mut file = File::open(path)?;
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hex(&hasher.finalize()))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn extract_zip(zip: &Path, destination: &Path, cancel: &AtomicBool) -> Result<()> {
    let file = File::open(zip).with_context(|| format!("cannot open {}", zip.display()))?;
    let mut archive =
        zip::ZipArchive::new(file).context("the downloaded archive is not a valid zip file")?;
    let mut total = 0u64;
    for index in 0..archive.len() {
        if index % 64 == 0 {
            check_cancel(cancel)?;
        }
        let mut entry = archive.by_index(index)?;
        if entry.is_symlink() {
            continue;
        }
        let Some(name) = entry.enclosed_name() else {
            continue;
        };
        let relative: PathBuf = name
            .components()
            .filter_map(|component| match component {
                Component::Normal(part) => Some(part),
                _ => None,
            })
            // The archives wrap everything in one top-level folder.
            .skip(1)
            .collect();
        if relative.as_os_str().is_empty() {
            continue;
        }
        let target = destination.join(&relative);
        ensure!(
            target.starts_with(destination),
            "the archive contains an unsafe path"
        );
        if entry.is_dir() {
            fs::create_dir_all(&target)?;
            continue;
        }
        total = total.saturating_add(entry.size());
        ensure!(
            total <= MAX_EXTRACTED_BYTES,
            "the archive expands past the {} GB safety limit",
            MAX_EXTRACTED_BYTES / (1024 * 1024 * 1024)
        );
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent)?;
        }
        let mut out =
            File::create(&target).with_context(|| format!("cannot write {}", target.display()))?;
        io::copy(&mut entry, &mut out)?;
    }
    Ok(())
}

#[derive(Debug, PartialEq, Eq)]
struct Archive {
    url: String,
    sha1: Option<String>,
    size: Option<u64>,
}

fn cmdline_tools_archive(xml: &str, host: &str) -> Option<Archive> {
    let mut rest = xml;
    while let Some(start) = rest.find("<remotePackage ") {
        let block = &rest[start..];
        let open_end = block.find('>')?;
        let open_tag = &block[..open_end];
        let close = block.find("</remotePackage>")?;
        if open_tag.contains(r#"path="cmdline-tools;latest""#) {
            return select_archive(&block[open_end..close], host);
        }
        rest = &block[close + "</remotePackage>".len()..];
    }
    None
}

fn select_archive(xml: &str, host: &str) -> Option<Archive> {
    let mut rest = xml;
    let mut fallback = None;
    while let Some(start) = rest.find("<archive>") {
        let block = &rest[start + "<archive>".len()..];
        let end = block.find("</archive>")?;
        let entry = &block[..end];
        rest = &block[end + "</archive>".len()..];

        let Some(path) = element_text(entry, "url") else {
            continue;
        };
        let archive = Archive {
            url: format!("{REPOSITORY_BASE}{path}"),
            sha1: element_text(entry, "checksum").filter(|text| !text.is_empty()),
            size: element_text(entry, "size").and_then(|text| text.parse().ok()),
        };
        match element_text(entry, "host-os") {
            Some(found) if found == host => return Some(archive),
            Some(_) => {}
            None => {
                fallback.get_or_insert(archive);
            }
        }
    }
    fallback
}

fn element_text(xml: &str, name: &str) -> Option<String> {
    let open = format!("<{name}");
    let start = xml.find(&open)?;
    let after = &xml[start + open.len()..];
    let content_start = after.find('>')? + 1;
    let close = after.find(&format!("</{name}>"))?;
    let text = after[content_start..close].trim();
    if text.is_empty() {
        None
    } else {
        Some(decode_entities(text))
    }
}

fn decode_entities(text: &str) -> String {
    text.replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
}

#[derive(serde::Deserialize)]
struct Release {
    #[serde(default)]
    assets: Vec<Asset>,
}

#[derive(serde::Deserialize)]
struct Asset {
    name: String,
    browser_download_url: String,
    #[serde(default)]
    size: Option<u64>,
    #[serde(default)]
    digest: Option<String>,
}

fn select_scrcpy_asset(assets: &[Asset]) -> Result<&Asset> {
    assets
        .iter()
        .find(|asset| asset.name.contains("win64") && asset.name.ends_with(".zip"))
        .ok_or_else(|| anyhow!("The latest scrcpy release has no Windows 64-bit zip."))
}

#[cfg(test)]
mod tests {
    use super::*;

    const REPOSITORY: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<r:sdk-repository>
  <remotePackage path="emulator">
    <revision><major>35</major></revision>
  </remotePackage>
  <remotePackage path="cmdline-tools;latest">
    <revision><major>19</major><minor>0</minor></revision>
    <archives>
      <archive>
        <complete>
          <size>148513981</size>
          <checksum type="sha1">aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa</checksum>
          <url>commandlinetools-win-13114758_latest.zip</url>
        </complete>
        <host-os>windows</host-os>
      </archive>
      <archive>
        <complete>
          <size>131851864</size>
          <checksum type="sha1">bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb</checksum>
          <url>commandlinetools-mac-13114758_latest.zip</url>
        </complete>
        <host-os>macosx</host-os>
      </archive>
      <archive>
        <complete>
          <size>131000000</size>
          <checksum type="sha1">cccccccccccccccccccccccccccccccccccccccc</checksum>
          <url>commandlinetools-linux-13114758_latest.zip</url>
        </complete>
        <host-os>linux</host-os>
      </archive>
    </archives>
  </remotePackage>
</r:sdk-repository>"#;

    #[test]
    fn selects_the_command_line_tools_for_each_host() {
        let windows = cmdline_tools_archive(REPOSITORY, "windows").unwrap();
        assert!(
            windows
                .url
                .ends_with("commandlinetools-win-13114758_latest.zip")
        );
        assert_eq!(windows.size, Some(148513981));
        assert_eq!(
            windows.sha1.as_deref(),
            Some("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
        );

        let mac = cmdline_tools_archive(REPOSITORY, "macosx").unwrap();
        assert!(
            mac.url
                .ends_with("commandlinetools-mac-13114758_latest.zip")
        );
        let linux = cmdline_tools_archive(REPOSITORY, "linux").unwrap();
        assert!(
            linux
                .url
                .ends_with("commandlinetools-linux-13114758_latest.zip")
        );
        assert!(cmdline_tools_archive(REPOSITORY, "beos").is_none());
    }

    #[test]
    fn reads_sdkmanager_progress() {
        assert_eq!(parse_percent("[=====      ] 45% Downloading"), Some(45));
        assert_eq!(parse_percent("100% Unzipping..."), Some(100));
        assert_eq!(parse_percent("Loading package information..."), None);
        assert_eq!(parse_percent("150% nothing"), None);
        assert_eq!(
            interesting("Downloading platform-tools"),
            Some("Downloading platform-tools".to_owned())
        );
        assert_eq!(interesting("x"), None);
    }

    #[test]
    fn java_commands_set_the_tools_directory() {
        let (sender, _updates) = std::sync::mpsc::channel();
        let mut reporter = Reporter::new(&sender);
        let guard = ProcessGuard::new();
        let cancel = AtomicBool::new(false);
        let installer = Installer {
            root: PathBuf::from("sdk"),
            downloads: PathBuf::from("downloads"),
            guard: &guard,
            cancel: &cancel,
            reporter: &mut reporter,
            notes: Vec::new(),
        };

        let args = installer.java_args("com.android.sdklib.tool.AvdManagerCli", &[], false);
        assert_eq!(
            args[0],
            format!(
                "-Dcom.android.sdkmanager.toolsdir={}",
                Path::new("sdk")
                    .join("cmdline-tools")
                    .join("latest")
                    .display()
            )
        );
        assert_eq!(args[1], "-classpath");
        assert_eq!(args[3], "com.android.sdklib.tool.AvdManagerCli");
    }

    #[test]
    fn system_image_matches_the_host() {
        assert_eq!(
            system_image(),
            format!("system-images;android-34;google_apis;{HOST_ABI}")
        );
        assert!(matches!(HOST_ABI, "x86_64" | "arm64-v8a"));
    }

    #[test]
    fn picks_the_windows_scrcpy_archive() {
        let assets = vec![
            Asset {
                name: "scrcpy-win64-v3.zip.sha256".to_owned(),
                browser_download_url: "ignored".to_owned(),
                size: None,
                digest: None,
            },
            Asset {
                name: "scrcpy-win64-v3.zip".to_owned(),
                browser_download_url: "https://example.invalid/scrcpy-win64-v3.zip".to_owned(),
                size: Some(42),
                digest: Some("sha256:abc".to_owned()),
            },
        ];
        let selected = select_scrcpy_asset(&assets).unwrap();
        assert_eq!(selected.name, "scrcpy-win64-v3.zip");
    }

    #[test]
    fn extraction_stays_inside_the_target() {
        let base = env::temp_dir().join(format!("euphoria-setup-zip-{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        fs::create_dir_all(&base).unwrap();
        let zip_path = base.join("sample.zip");
        {
            let file = File::create(&zip_path).unwrap();
            let mut writer = zip::ZipWriter::new(file);
            let options = zip::write::SimpleFileOptions::default();
            writer.start_file("tools/bin/tool.txt", options).unwrap();
            io::Write::write_all(&mut writer, b"hello").unwrap();
            writer.start_file("../escape.txt", options).unwrap();
            io::Write::write_all(&mut writer, b"nope").unwrap();
            writer.finish().unwrap();
        }

        let destination = base.join("out");
        fs::create_dir_all(&destination).unwrap();
        extract_zip(&zip_path, &destination, &AtomicBool::new(false)).unwrap();

        assert_eq!(
            fs::read_to_string(destination.join("bin/tool.txt")).unwrap(),
            "hello"
        );
        assert!(!base.join("escape.txt").exists());
        fs::remove_dir_all(&base).unwrap();
    }

    #[test]
    fn planned_root_uses_the_settings_folder_by_default() {
        let config = AndroidConfig {
            sdk_root: String::new(),
            ..AndroidConfig::default()
        };
        assert_eq!(planned_root(&config), settings_dir().join("android-sdk"));

        let config = AndroidConfig {
            sdk_root: "  /opt/euphoria-sdk ".to_owned(),
            ..AndroidConfig::default()
        };
        assert_eq!(planned_root(&config), PathBuf::from("/opt/euphoria-sdk"));
    }
}
