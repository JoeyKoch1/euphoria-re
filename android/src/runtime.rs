use std::collections::VecDeque;
use std::path::{Path, PathBuf};
use std::process::Child;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, Sender, TryRecvError};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Result, bail};

use crate::adb::{self, Adb, DeviceProperties};
use crate::app::{self, AppInfo, Staging};
use crate::capture::{CaptureEvent, CaptureServer};
use crate::config::AndroidConfig;
use crate::discovery::{Acceleration, Avd, Environment, SETUP_HELP};
use crate::emulator;
use crate::logcat::Logcat;
use crate::process::{self, Output, ProcessGuard};
use crate::setup::{self, SetupUpdate};
use crate::wallpaper;

const MAX_LOGCAT_LINES: usize = 2000;
const MAX_CAPTURE_ENTRIES: usize = 500;
const MIN_BOOT_TIMEOUT_SECS: u64 = 30;
const STOP_TIMEOUT: Duration = Duration::from_secs(10);
const HOST_LOOPBACK: &str = "10.0.2.2";

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Phase {
    #[default]
    Idle,
    NotConfigured,
    Starting,
    Booting,
    Installing,
    Launching,
    Running,
    Stopping,
    Error,
}

impl Phase {
    pub fn label(self) -> &'static str {
        match self {
            Self::Idle => "Idle",
            Self::NotConfigured => "Setup needed",
            Self::Starting => "Starting",
            Self::Booting => "Booting",
            Self::Installing => "Installing",
            Self::Launching => "Launching",
            Self::Running => "Running",
            Self::Stopping => "Stopping",
            Self::Error => "Error",
        }
    }

    pub fn is_active(self) -> bool {
        matches!(
            self,
            Self::Starting
                | Self::Booting
                | Self::Installing
                | Self::Launching
                | Self::Running
                | Self::Stopping
        )
    }

    pub fn is_running(self) -> bool {
        self == Self::Running
    }

    pub fn is_busy(self) -> bool {
        matches!(
            self,
            Self::Starting | Self::Booting | Self::Installing | Self::Launching | Self::Stopping
        )
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DeviceInfo {
    pub serial: String,
    pub avd: String,
    pub port: u16,
    pub model: String,
    pub api: Option<u32>,
    pub release: String,
    pub abi_list: Vec<String>,
    pub resolution: Option<String>,
    pub density: Option<String>,
    pub package: String,
    pub component: Option<String>,
}

impl DeviceInfo {
    pub fn android_text(&self) -> String {
        match (self.api, self.release.is_empty()) {
            (Some(api), false) => format!("Android {} (API {api})", self.release),
            (Some(api), true) => format!("API {api}"),
            (None, false) => format!("Android {}", self.release),
            (None, true) => "Android".to_owned(),
        }
    }
}

enum Command {
    Stop,
    Restart,
    Reset,
    StopApp,
    RelaunchApp,
    ShowDisplay,
}

enum Update {
    Phase(Phase, String),
    Device(Box<DeviceInfo>),
    Environment(Box<Environment>),
    Notice(String),
    Error(String),
    Logcat(Vec<String>),
    Capture(Vec<CaptureEvent>),
    Finished,
}

struct Scan {
    receiver: Receiver<Environment>,
}

struct Session {
    commands: Sender<Command>,
    updates: Receiver<Update>,
}

struct SetupJob {
    updates: Receiver<SetupUpdate>,
    cancel: Arc<AtomicBool>,
}

pub struct AndroidRuntime {
    config: AndroidConfig,
    phase: Phase,
    detail: String,
    error: Option<String>,
    notice: Option<String>,
    device: Option<DeviceInfo>,
    environment: Option<Environment>,
    scan: Option<Scan>,
    session: Option<Session>,
    setup: Option<SetupJob>,
    setup_detail: String,
    setup_percent: Option<u8>,
    setup_message: Option<String>,
    setup_error: Option<String>,
    logcat: VecDeque<String>,
    logcat_visible: bool,
    capture: VecDeque<CaptureEvent>,
    capture_visible: bool,
    finished: bool,
}

impl Default for AndroidRuntime {
    fn default() -> Self {
        Self::new()
    }
}

impl AndroidRuntime {
    pub fn new() -> Self {
        Self {
            config: AndroidConfig::load(),
            phase: Phase::Idle,
            detail: "Android tools have not been checked yet.".to_owned(),
            error: None,
            notice: None,
            device: None,
            environment: None,
            scan: None,
            session: None,
            setup: None,
            setup_detail: String::new(),
            setup_percent: None,
            setup_message: None,
            setup_error: None,
            logcat: VecDeque::new(),
            logcat_visible: true,
            capture: VecDeque::new(),
            capture_visible: true,
            finished: false,
        }
    }

    pub fn poll(&mut self) -> bool {
        let mut changed = false;
        let scan_result = self.scan.as_ref().map(|scan| scan.receiver.try_recv());
        match scan_result {
            Some(Ok(environment)) => {
                self.scan = None;
                self.apply_environment(environment);
                changed = true;
            }
            Some(Err(TryRecvError::Disconnected)) => {
                self.scan = None;
                changed = true;
            }
            Some(Err(TryRecvError::Empty)) | None => {}
        }

        let mut setup_updates = Vec::new();
        let mut setup_gone = false;
        if let Some(job) = &self.setup {
            loop {
                match job.updates.try_recv() {
                    Ok(update) => setup_updates.push(update),
                    Err(TryRecvError::Empty) => break,
                    Err(TryRecvError::Disconnected) => {
                        setup_gone = true;
                        break;
                    }
                }
            }
        }
        for update in setup_updates {
            self.apply_setup(update);
            changed = true;
        }
        if setup_gone && self.setup.is_some() {
            self.setup = None;
            self.setup_percent = None;
            self.setup_error = Some(
                "The Android setup worker stopped unexpectedly. Close Euphoria, remove any \
                 partial download, and try again."
                    .to_owned(),
            );
            changed = true;
        }

        let mut updates = Vec::new();
        let mut disconnected = false;
        if let Some(session) = &self.session {
            loop {
                match session.updates.try_recv() {
                    Ok(update) => updates.push(update),
                    Err(TryRecvError::Empty) => break,
                    Err(TryRecvError::Disconnected) => {
                        disconnected = true;
                        break;
                    }
                }
            }
        }
        for update in updates {
            self.apply(update);
            changed = true;
        }

        if self.finished {
            self.finished = false;
            self.session = None;
            changed = true;
        }
        if disconnected && self.session.is_some() {
            self.session = None;
            if !matches!(self.phase, Phase::Idle | Phase::Error) {
                self.phase = Phase::Error;
                self.error = Some(
                    "The Android runtime worker stopped unexpectedly. The emulator may still be \
                     running; restart Euphoria if it does not exit."
                        .to_owned(),
                );
            }
            changed = true;
        }
        changed
    }

    pub fn ensure_scanned(&mut self) {
        if self.environment.is_none()
            && self.scan.is_none()
            && self.session.is_none()
            && self.setup.is_none()
        {
            self.start_scan();
        }
    }

    pub fn refresh(&mut self) {
        if self.session.is_some() || self.setup.is_some() {
            return;
        }
        self.environment = None;
        self.scan = None;
        if !self.phase.is_active() && self.phase != Phase::Error {
            self.phase = Phase::Idle;
            self.detail = "Android tools have not been checked yet.".to_owned();
        }
        self.start_scan();
    }

    // One worker owns the emulator, adb installs, scrcpy, and logcat, so a second Start can never
    // race a first one. The session lives until the worker sends Finished.
    pub fn run(&mut self, app: AppInfo) -> Result<()> {
        if self.setup.is_some() {
            bail!("Android setup is still running. Wait for it to finish before running an APK.");
        }
        if self.session.is_some() {
            bail!(
                "The Android emulator runtime is already active. Stop it before starting another \
                 run."
            );
        }
        self.scan = None;
        self.error = None;
        self.notice = None;
        self.device = None;
        self.logcat.clear();
        self.capture.clear();
        self.phase = Phase::Starting;
        self.detail = "Preparing the Android runtime...".to_owned();

        let (command_sender, command_receiver) = mpsc::channel();
        let (update_sender, update_receiver) = mpsc::channel();
        self.session = Some(Session {
            commands: command_sender,
            updates: update_receiver,
        });
        let config = self.config.clone();
        thread::spawn(move || run_worker(config, app, update_sender, command_receiver));
        Ok(())
    }

    pub fn stop(&mut self) -> bool {
        if self.session.is_none() {
            return false;
        }
        if !self.send(Command::Stop) {
            return false;
        }
        self.phase = Phase::Stopping;
        self.detail = "Stopping the emulator...".to_owned();
        true
    }

    pub fn restart(&mut self) -> bool {
        if self.session.is_none() {
            return false;
        }
        if !self.send(Command::Restart) {
            return false;
        }
        self.phase = Phase::Stopping;
        self.detail = "Restarting the emulator...".to_owned();
        true
    }

    pub fn reset(&mut self) -> bool {
        if self.session.is_none() {
            return false;
        }
        if !self.send(Command::Reset) {
            return false;
        }
        self.phase = Phase::Stopping;
        self.detail = "Resetting the emulator and wiping its data...".to_owned();
        true
    }

    pub fn stop_app(&mut self) -> bool {
        self.send(Command::StopApp)
    }

    pub fn relaunch_app(&mut self) -> bool {
        self.send(Command::RelaunchApp)
    }

    pub fn show_display(&mut self) -> bool {
        self.send(Command::ShowDisplay)
    }

    // Called when Euphoria closes. Stop is asynchronous, so wait briefly for the worker to take
    // the emulator down instead of leaving an orphan on platforms without a job object.
    pub fn shutdown(&mut self) {
        if self.setup.is_some() {
            self.cancel_setup();
            let deadline = Instant::now() + Duration::from_secs(5);
            while self.setup.is_some() && Instant::now() < deadline {
                self.poll();
                if self.setup.is_some() {
                    thread::sleep(Duration::from_millis(50));
                }
            }
        }
        if self.session.is_none() {
            return;
        }
        let _ = self.send(Command::Stop);
        let deadline = Instant::now() + Duration::from_secs(30);
        while self.session.is_some() && Instant::now() < deadline {
            self.poll();
            if self.session.is_some() {
                thread::sleep(Duration::from_millis(50));
            }
        }
    }

    pub fn save_config(&mut self) -> Result<()> {
        self.config.save()?;
        if self.session.is_none() {
            self.scan = None;
            self.start_scan();
        }
        Ok(())
    }

    pub fn config(&self) -> &AndroidConfig {
        &self.config
    }

    pub fn config_mut(&mut self) -> &mut AndroidConfig {
        &mut self.config
    }

    pub fn phase(&self) -> Phase {
        self.phase
    }

    pub fn detail(&self) -> &str {
        &self.detail
    }

    pub fn error(&self) -> Option<&str> {
        self.error.as_deref()
    }

    pub fn notice(&self) -> Option<&str> {
        self.notice.as_deref()
    }

    pub fn clear_notice(&mut self) {
        self.notice = None;
    }

    pub fn set_notice(&mut self, text: impl Into<String>) {
        self.notice = Some(text.into());
    }

    pub fn clear_error(&mut self) {
        self.error = None;
        if self.phase == Phase::Error {
            self.phase = Phase::Idle;
            self.detail = "Android runtime idle.".to_owned();
        }
    }

    pub fn device(&self) -> Option<&DeviceInfo> {
        self.device.as_ref()
    }

    pub fn environment(&self) -> Option<&Environment> {
        self.environment.as_ref()
    }

    pub fn avds(&self) -> &[Avd] {
        self.environment
            .as_ref()
            .map_or(&[], |environment| environment.avds.as_slice())
    }

    pub fn is_scanning(&self) -> bool {
        self.scan.is_some()
    }

    pub fn is_active(&self) -> bool {
        self.phase.is_active()
    }

    pub fn is_busy(&self) -> bool {
        self.phase.is_busy()
    }

    pub fn can_run(&self) -> bool {
        self.session.is_none() && self.setup.is_none()
    }

    pub fn is_setting_up(&self) -> bool {
        self.setup.is_some()
    }

    // Setup can replace missing tools, but it cannot enable hardware virtualization.
    pub fn setup_available(&self) -> bool {
        let Some(environment) = &self.environment else {
            return false;
        };
        environment.sdk_root.is_none()
            || environment.emulator.is_none()
            || environment.adb.is_none()
            || !environment.avds.iter().any(|avd| avd.error.is_none())
    }

    pub fn setup_root(&self) -> PathBuf {
        setup::planned_root(&self.config)
    }

    pub fn start_setup(&mut self) -> bool {
        if self.setup.is_some() || self.session.is_some() {
            return false;
        }
        let (sender, receiver) = mpsc::channel();
        let cancel = Arc::new(AtomicBool::new(false));
        setup::spawn(self.config.clone(), sender, Arc::clone(&cancel));
        self.setup = Some(SetupJob {
            updates: receiver,
            cancel,
        });
        self.setup_detail = "Preparing the Android SDK installer...".to_owned();
        self.setup_percent = None;
        self.setup_message = None;
        self.setup_error = None;
        self.notice = None;
        self.scan = None;
        true
    }

    pub fn cancel_setup(&mut self) {
        if let Some(job) = &self.setup {
            job.cancel.store(true, Ordering::Relaxed);
            self.setup_detail = "Cancelling setup...".to_owned();
        }
    }

    pub fn setup_detail(&self) -> &str {
        &self.setup_detail
    }

    pub fn setup_percent(&self) -> Option<u8> {
        self.setup_percent
    }

    pub fn setup_message(&self) -> Option<&str> {
        self.setup_message.as_deref()
    }

    pub fn setup_error(&self) -> Option<&str> {
        self.setup_error.as_deref()
    }

    pub fn clear_setup_message(&mut self) {
        self.setup_message = None;
    }

    pub fn clear_setup_error(&mut self) {
        self.setup_error = None;
    }

    pub fn blocker(&self) -> Option<String> {
        self.environment
            .as_ref()
            .and_then(|environment| environment.blocker(self.config.allow_software_accel))
    }

    pub fn logcat(&self) -> &VecDeque<String> {
        &self.logcat
    }

    pub fn logcat_visible(&self) -> bool {
        self.logcat_visible
    }

    pub fn set_logcat_visible(&mut self, visible: bool) {
        self.logcat_visible = visible;
    }

    pub fn clear_logcat(&mut self) {
        self.logcat.clear();
    }

    pub fn capture(&self) -> &VecDeque<CaptureEvent> {
        &self.capture
    }

    pub fn capture_visible(&self) -> bool {
        self.capture_visible
    }

    pub fn set_capture_visible(&mut self, visible: bool) {
        self.capture_visible = visible;
    }

    pub fn clear_capture(&mut self) {
        self.capture.clear();
    }

    fn send(&self, command: Command) -> bool {
        self.session
            .as_ref()
            .is_some_and(|session| session.commands.send(command).is_ok())
    }

    fn start_scan(&mut self) {
        let (sender, receiver) = mpsc::channel();
        self.scan = Some(Scan { receiver });
        let config = self.config.clone();
        thread::spawn(move || {
            let _ = sender.send(Environment::discover(&config));
        });
    }

    fn apply_environment(&mut self, environment: Environment) {
        let blocker = environment.blocker(self.config.allow_software_accel);
        self.environment = Some(environment);
        if matches!(self.phase, Phase::Idle | Phase::NotConfigured) {
            if blocker.is_some() {
                self.phase = Phase::NotConfigured;
                self.detail = "Android tools need setup.".to_owned();
            } else {
                self.phase = Phase::Idle;
                self.detail = "Ready to run an APK.".to_owned();
            }
        }
    }

    fn apply_setup(&mut self, update: SetupUpdate) {
        match update {
            SetupUpdate::Progress { detail, percent } => {
                self.setup_detail = detail;
                self.setup_percent = percent;
            }
            SetupUpdate::Finished(outcome) => {
                self.setup = None;
                self.setup_percent = Some(100);
                self.setup_detail = "Android setup is complete.".to_owned();
                self.config.sdk_root = outcome.sdk_root.display().to_string();
                if let Some(avd) = &outcome.avd {
                    self.config.avd = avd.clone();
                }
                if let Some(scrcpy) = &outcome.scrcpy {
                    self.config.scrcpy_path = scrcpy.display().to_string();
                }
                let mut message =
                    format!("Android tools are ready in {}.", outcome.sdk_root.display());
                for note in &outcome.notes {
                    message.push_str("\n- ");
                    message.push_str(note);
                }
                if let Err(error) = self.config.save() {
                    message.push_str(&format!(
                        "\nThe Android settings could not be saved: {error:#}"
                    ));
                }
                self.setup_message = Some(message);
                self.setup_error = None;
                self.error = None;
                self.notice = None;
                self.device = None;
                self.environment = None;
                self.scan = None;
                self.phase = Phase::Idle;
                self.detail = "Checking the newly installed Android tools...".to_owned();
                self.start_scan();
            }
            SetupUpdate::Canceled => {
                self.setup = None;
                self.setup_percent = None;
                self.setup_detail = "Setup was canceled.".to_owned();
                self.setup_message = Some(
                    "Setup was canceled. Incomplete downloads were removed; anything that was \
                     already installed stays in place."
                        .to_owned(),
                );
                self.setup_error = None;
            }
            SetupUpdate::Failed(error) => {
                self.setup = None;
                self.setup_percent = None;
                self.setup_detail = "Setup did not finish.".to_owned();
                self.setup_error = Some(error);
            }
        }
    }

    fn apply(&mut self, update: Update) {
        match update {
            Update::Phase(phase, detail) => {
                self.phase = phase;
                self.detail = detail;
                if phase == Phase::Idle {
                    self.device = None;
                }
            }
            Update::Device(device) => self.device = Some(*device),
            Update::Environment(environment) => self.apply_environment(*environment),
            Update::Notice(text) => self.notice = Some(text),
            Update::Error(text) => {
                self.error = Some(text);
                self.phase = Phase::Error;
                self.detail = "The Android runtime failed.".to_owned();
            }
            Update::Logcat(lines) => {
                for line in lines {
                    if self.logcat.len() >= MAX_LOGCAT_LINES {
                        self.logcat.pop_front();
                    }
                    self.logcat.push_back(line);
                }
            }
            Update::Capture(events) => {
                for event in events {
                    // A TLS tunnel is reported when it opens and again when it closes; the
                    // second report replaces the first so one destination is one row.
                    if let Some(existing) = self
                        .capture
                        .iter_mut()
                        .find(|existing| existing.id == event.id)
                    {
                        *existing = event;
                        continue;
                    }
                    if self.capture.len() >= MAX_CAPTURE_ENTRIES {
                        self.capture.pop_front();
                    }
                    self.capture.push_back(event);
                }
            }
            Update::Finished => self.finished = true,
        }
    }
}

impl Drop for AndroidRuntime {
    fn drop(&mut self) {
        self.shutdown();
    }
}

fn run_worker(
    config: AndroidConfig,
    app: AppInfo,
    sender: Sender<Update>,
    commands: Receiver<Command>,
) {
    let guard = ProcessGuard::new();
    match session(&guard, &sender, &commands, &config, &app) {
        Ok(()) => {}
        Err(End::Stopped) => send_phase(&sender, Phase::Idle, "Stopped."),
        Err(End::Failed(message)) => {
            let _ = sender.send(Update::Error(message));
        }
    }
    let _ = sender.send(Update::Finished);
}

fn session(
    guard: &ProcessGuard,
    sender: &Sender<Update>,
    commands: &Receiver<Command>,
    config: &AndroidConfig,
    app: &AppInfo,
) -> Result<(), End> {
    send_phase(sender, Phase::Starting, "Checking Android tools...");
    let environment = Environment::discover(config);
    let _ = sender.send(Update::Environment(Box::new(environment.clone())));
    if let Some(blocker) = environment.blocker(config.allow_software_accel) {
        return Err(End::Failed(format!("{blocker}\n\n{SETUP_HELP}")));
    }

    let emulator_path = environment
        .emulator
        .clone()
        .ok_or_else(|| End::Failed("The Android Emulator was not found.".to_owned()))?;
    let adb_path = environment
        .adb
        .clone()
        .ok_or_else(|| End::Failed("adb was not found.".to_owned()))?;
    let avd = app::select_avd(&environment.avds, &config.avd, app)?.clone();
    let issues = app::compatibility(&avd, app);
    if !issues.errors.is_empty() {
        return Err(End::Failed(issues.errors.join("\n")));
    }
    for warning in issues.warnings {
        let _ = sender.send(Update::Notice(warning));
    }

    let adb = Adb::new(adb_path);
    adb.start_server()?;
    let capture = if config.capture_network {
        match CaptureServer::start() {
            Ok(server) => Some(server),
            Err(error) => {
                let _ = sender.send(Update::Notice(format!(
                    "Network capture is unavailable: {error:#}"
                )));
                None
            }
        }
    } else {
        None
    };
    send_phase(
        sender,
        Phase::Starting,
        format!("Staging {}...", app.file_name),
    );
    let staging = Staging::new()?;
    let staged = staging.stage_apk(app)?;

    let mut wipe = false;
    loop {
        if matches!(drain_control(commands), Control::Stop) {
            return Err(End::Stopped);
        }
        send_phase(
            sender,
            Phase::Starting,
            format!("Starting AVD {}...", avd.name),
        );
        emulator::validate_avd_name(&avd.name)?;
        let port = emulator::allocate_port(&adb)?;
        let serial = format!("emulator-{port}");
        let show_window = config.show_emulator_window || environment.scrcpy.is_none();
        let accel_available = !matches!(environment.acceleration, Acceleration::Unavailable(_));
        let args =
            emulator::build_args(config, &avd.name, port, show_window, wipe, accel_available);
        let emulator_log = staging.dir().join(format!("emulator-{port}.log"));
        let mut child = process::spawn_logged(&emulator_path, &args, &emulator_log)?;
        guard.assign(&child);
        let _ = sender.send(Update::Device(Box::new(DeviceInfo {
            serial: serial.clone(),
            avd: avd.name.clone(),
            port,
            ..DeviceInfo::default()
        })));

        let mut windows = Windows::default();
        send_phase(sender, Phase::Booting, format!("Waiting for {serial}..."));
        match wait_for_boot(
            guard,
            &adb,
            &serial,
            &mut child,
            config,
            commands,
            sender,
            app,
            &environment,
            &staging,
            &emulator_log,
            capture.as_ref(),
            &mut windows,
        ) {
            Ok(()) => {}
            Err(Interrupt::Stop) => {
                stop_emulator(&adb, &serial, &mut child);
                return Err(End::Stopped);
            }
            Err(Interrupt::Restart { wipe: next }) => {
                stop_emulator(&adb, &serial, &mut child);
                wipe = next;
                continue;
            }
            Err(Interrupt::Failed(message)) => {
                stop_emulator(&adb, &serial, &mut child);
                return Err(End::Failed(message));
            }
        }

        let cycle = run_cycle(
            guard,
            sender,
            commands,
            config,
            app,
            &avd,
            &environment,
            &adb,
            &serial,
            port,
            &mut child,
            &staging,
            &staged,
            &emulator_log,
            capture.as_ref(),
            &mut windows,
        );
        match cycle {
            Cycle::Next { wipe: next } => {
                send_phase(
                    sender,
                    Phase::Starting,
                    if next {
                        "Resetting the emulator..."
                    } else {
                        "Restarting the emulator..."
                    },
                );
                stop_emulator(&adb, &serial, &mut child);
                wipe = next;
            }
            Cycle::Stop => {
                stop_emulator(&adb, &serial, &mut child);
                return Err(End::Stopped);
            }
            Cycle::Failed(message) => {
                stop_emulator(&adb, &serial, &mut child);
                return Err(End::Failed(message));
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn run_cycle(
    guard: &ProcessGuard,
    sender: &Sender<Update>,
    commands: &Receiver<Command>,
    config: &AndroidConfig,
    app: &AppInfo,
    avd: &Avd,
    environment: &Environment,
    adb: &Adb,
    serial: &str,
    port: u16,
    child: &mut Child,
    staging: &Staging,
    staged: &Path,
    emulator_log: &Path,
    capture: Option<&CaptureServer>,
    windows: &mut Windows,
) -> Cycle {
    if let Some(control) = interrupted(commands) {
        return control;
    }
    if let Some(capture) = capture {
        if let Err(error) = adb.set_http_proxy(serial, HOST_LOOPBACK, capture.port()) {
            let _ = sender.send(Update::Notice(format!(
                "The device HTTP proxy could not be set, so network capture will stay empty: \
                 {error:#}"
            )));
        }
    } else {
        // Remove a proxy left behind by a previous session or a hard emulator exit.
        adb.clear_http_proxy(serial);
    }
    drain_capture(capture, sender);
    if config.apply_wallpaper {
        // Cosmetic and best effort: a wallpaper failure must never keep the APK from running.
        if let Err(error) = wallpaper::apply(adb, serial, staging.dir()) {
            let _ = sender.send(Update::Notice(format!(
                "The Euphoria wallpaper could not be applied; the app still runs: {error:#}"
            )));
        }
    }
    if let Some(control) = interrupted(commands) {
        return control;
    }
    send_phase(
        sender,
        Phase::Installing,
        format!("Installing {}...", app.file_name),
    );
    let installed = match adb.install(serial, staged, config.grant_permissions) {
        Ok(output) => output,
        Err(error) => {
            return Cycle::Failed(format!(
                "Could not run adb install: {error:#}\n\n{}",
                process::tail(emulator_log, 8)
            ));
        }
    };
    if !installed.success {
        let text = installed.combined();
        if adb::update_incompatible(&text) {
            let _ = adb.uninstall(serial, &app.package);
            match adb.install(serial, staged, config.grant_permissions) {
                Ok(retry) if retry.success => {}
                Ok(retry) => return install_failure(&app.package, &retry, emulator_log),
                Err(error) => {
                    return Cycle::Failed(format!(
                        "Could not run adb install after uninstalling the old build: {error:#}"
                    ));
                }
            }
        } else {
            return install_failure(&app.package, &installed, emulator_log);
        }
    }
    if let Some(control) = interrupted(commands) {
        return control;
    }

    let properties = adb.device_info(serial);
    if let Some(warning) = app::device_abi_warning(app, &properties.abi_list) {
        let _ = sender.send(Update::Notice(warning));
    }
    if config.reduce_animations {
        adb.reduce_animations(serial);
    }

    let component = match app.component() {
        Some(component) => Some(component),
        None => match adb.resolve_launcher(serial, &app.package) {
            Ok(component) => component,
            Err(error) => {
                let _ = sender.send(Update::Notice(format!(
                    "Could not ask Android for the launcher activity: {error:#}"
                )));
                None
            }
        },
    };
    send_device(
        sender,
        serial,
        avd,
        port,
        &properties,
        &app.package,
        component.clone(),
    );

    let _ = adb.clear_logcat(serial);
    match Logcat::start(adb, serial) {
        Ok(logcat) => windows.logcat = Some(logcat),
        Err(error) => {
            let _ = sender.send(Update::Notice(format!(
                "Live logcat is unavailable: {error:#}"
            )));
        }
    }
    if use_scrcpy(config, environment) && windows.scrcpy.is_none() {
        let scrcpy = environment
            .scrcpy
            .as_deref()
            .expect("checked by use_scrcpy");
        let scrcpy_log = scrcpy_log_path(staging, serial);
        match spawn_scrcpy(guard, scrcpy, config, serial, &app.package, &scrcpy_log) {
            Ok(spawned) => windows.scrcpy = Some(spawned),
            Err(error) => {
                let _ = sender.send(Update::Notice(format!(
                    "scrcpy could not open, but the emulator is running: {error:#}. Enable \
                     \"Show the emulator's own window\" in Settings and Restart to use the \
                     emulator window."
                )));
            }
        }
    }

    if let Some(control) = interrupted(commands) {
        return control;
    }
    send_phase(
        sender,
        Phase::Launching,
        format!("Starting {}...", app.package),
    );
    match launch_app(adb, serial, app, component.as_deref()) {
        Ok(detail) => send_phase(sender, Phase::Running, detail),
        Err(error) => {
            return Cycle::Failed(format!("{error:#}\n\n{}", process::tail(emulator_log, 8)));
        }
    }
    let _ = sender.send(Update::Notice(if windows.scrcpy.is_some() {
        format!(
            "{} is running. Use the scrcpy window for keyboard and mouse input.",
            app.package
        )
    } else {
        format!("{} is running in the Android Emulator window.", app.package)
    }));

    monitor(
        guard,
        sender,
        commands,
        config,
        app,
        environment,
        adb,
        serial,
        child,
        emulator_log,
        staging,
        capture,
        windows,
        component.as_deref(),
    )
}

fn use_scrcpy(config: &AndroidConfig, environment: &Environment) -> bool {
    environment.scrcpy.is_some() && !config.show_emulator_window
}

fn drain_capture(capture: Option<&CaptureServer>, sender: &Sender<Update>) {
    let Some(capture) = capture else {
        return;
    };
    let events = capture.drain();
    if !events.is_empty() {
        let _ = sender.send(Update::Capture(events));
    }
}

fn scrcpy_log_path(staging: &Staging, serial: &str) -> PathBuf {
    staging.dir().join(format!("scrcpy-{serial}.log"))
}

fn scrcpy_closed_message(staging: &Staging, serial: &str, next: &str) -> String {
    let log = process::tail(&scrcpy_log_path(staging, serial), 4);
    if log.trim().is_empty() {
        format!("The scrcpy window closed. {next}")
    } else {
        format!("The scrcpy window closed. {next}\n{}", log.trim_end())
    }
}

fn spawn_scrcpy(
    guard: &ProcessGuard,
    scrcpy: &Path,
    config: &AndroidConfig,
    serial: &str,
    package: &str,
    log_path: &Path,
) -> Result<Child> {
    let args = emulator::build_scrcpy_args(config, serial, package);
    let child = process::spawn_logged(scrcpy, &args, log_path)?;
    guard.assign(&child);
    Ok(child)
}

#[derive(Default)]
struct Windows {
    scrcpy: Option<Child>,
    logcat: Option<Logcat>,
}

impl Windows {
    fn stop(&mut self) {
        if let Some(mut scrcpy) = self.scrcpy.take() {
            let _ = scrcpy.kill();
            let _ = scrcpy.wait();
        }
        self.logcat = None;
    }
}

impl Drop for Windows {
    fn drop(&mut self) {
        self.stop();
    }
}

#[allow(clippy::too_many_arguments)]
fn monitor(
    guard: &ProcessGuard,
    sender: &Sender<Update>,
    commands: &Receiver<Command>,
    config: &AndroidConfig,
    app: &AppInfo,
    environment: &Environment,
    adb: &Adb,
    serial: &str,
    child: &mut Child,
    emulator_log: &Path,
    staging: &Staging,
    capture: Option<&CaptureServer>,
    windows: &mut Windows,
    component: Option<&str>,
) -> Cycle {
    loop {
        drain_capture(capture, sender);
        loop {
            match commands.try_recv() {
                Ok(Command::Stop) => return Cycle::Stop,
                Ok(Command::Restart) => return Cycle::Next { wipe: false },
                Ok(Command::Reset) => return Cycle::Next { wipe: true },
                Ok(Command::StopApp) => match adb.force_stop(serial, &app.package) {
                    Ok(()) => send_phase(
                        sender,
                        Phase::Running,
                        format!("{} was stopped. Relaunch it from the toolbar.", app.package),
                    ),
                    Err(error) => {
                        let _ = sender.send(Update::Notice(format!(
                            "Android could not stop {}: {error:#}",
                            app.package
                        )));
                    }
                },
                Ok(Command::RelaunchApp) => {
                    send_phase(
                        sender,
                        Phase::Launching,
                        format!("Starting {} again...", app.package),
                    );
                    match launch_app(adb, serial, app, component) {
                        Ok(detail) => send_phase(sender, Phase::Running, detail),
                        Err(error) => {
                            send_phase(sender, Phase::Running, "The app is not running.");
                            let _ =
                                sender.send(Update::Notice(format!("Relaunch failed: {error:#}")));
                        }
                    }
                }
                Ok(Command::ShowDisplay) => {
                    show_display(
                        guard,
                        sender,
                        config,
                        app,
                        environment,
                        serial,
                        staging,
                        windows,
                    );
                }
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => return Cycle::Stop,
            }
        }

        match child.try_wait() {
            Ok(Some(status)) => {
                return Cycle::Failed(format!(
                    "The Android Emulator stopped unexpectedly ({status}).\n{}",
                    process::tail(emulator_log, 12)
                ));
            }
            Ok(None) => {}
            Err(error) => {
                return Cycle::Failed(format!("Cannot watch the emulator process: {error}"));
            }
        }

        let mut logcat_done = false;
        if let Some(logcat) = windows.logcat.as_mut() {
            if let Some(lines) = logcat.try_recv() {
                let _ = sender.send(Update::Logcat(lines));
            }
            logcat_done = logcat.exited().is_some();
        }
        if logcat_done {
            windows.logcat = None;
            let _ = sender.send(Update::Notice(
                "Live logcat ended. The app is still running; Restart the emulator to read logs \
                 again."
                    .to_owned(),
            ));
        }

        let mut scrcpy_done = false;
        if let Some(scrcpy) = windows.scrcpy.as_mut() {
            scrcpy_done = matches!(scrcpy.try_wait(), Ok(Some(_)));
        }
        if scrcpy_done {
            windows.scrcpy = None;
            let _ = sender.send(Update::Notice(scrcpy_closed_message(
                staging,
                serial,
                "The emulator is still running; use Show display to reopen it.",
            )));
        }

        thread::sleep(Duration::from_millis(150));
    }
}

#[allow(clippy::too_many_arguments)]
fn show_display(
    guard: &ProcessGuard,
    sender: &Sender<Update>,
    config: &AndroidConfig,
    app: &AppInfo,
    environment: &Environment,
    serial: &str,
    staging: &Staging,
    windows: &mut Windows,
) {
    if windows.scrcpy.is_some() {
        let _ = sender.send(Update::Notice(
            "The display window is already open.".to_owned(),
        ));
        return;
    }
    let Some(scrcpy) = environment.scrcpy.as_deref() else {
        let message = if config.show_emulator_window || environment.scrcpy.is_none() {
            "The Android Emulator's own window is showing the device."
        } else {
            "scrcpy was not found, so Euphoria cannot open a separate display window."
        };
        let _ = sender.send(Update::Notice(message.to_owned()));
        return;
    };
    let log = scrcpy_log_path(staging, serial);
    match spawn_scrcpy(guard, scrcpy, config, serial, &app.package, &log) {
        Ok(child) => {
            windows.scrcpy = Some(child);
            let _ = sender.send(Update::Notice(
                "Opened the device display with scrcpy.".to_owned(),
            ));
        }
        Err(error) => {
            let _ = sender.send(Update::Notice(format!("scrcpy could not start: {error:#}")));
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn wait_for_boot(
    guard: &ProcessGuard,
    adb: &Adb,
    serial: &str,
    child: &mut Child,
    config: &AndroidConfig,
    commands: &Receiver<Command>,
    sender: &Sender<Update>,
    app: &AppInfo,
    environment: &Environment,
    staging: &Staging,
    emulator_log: &Path,
    capture: Option<&CaptureServer>,
    windows: &mut Windows,
) -> Result<(), Interrupt> {
    let timeout = config.boot_timeout_secs.max(MIN_BOOT_TIMEOUT_SECS);
    let started = Instant::now();
    let deadline = started + Duration::from_secs(timeout);
    let mut last_detail = String::new();
    let mut scrcpy_tried = false;
    loop {
        drain_capture(capture, sender);
        let mut show_display_requested = false;
        while let Ok(command) = commands.try_recv() {
            match command {
                Command::Stop => return Err(Interrupt::Stop),
                Command::Restart => return Err(Interrupt::Restart { wipe: false }),
                Command::Reset => return Err(Interrupt::Restart { wipe: true }),
                Command::ShowDisplay => show_display_requested = true,
                Command::StopApp | Command::RelaunchApp => {}
            }
        }

        match child.try_wait() {
            Ok(Some(status)) => {
                return Err(Interrupt::Failed(format!(
                    "The Android Emulator stopped while booting ({status}).\n{}",
                    process::tail(emulator_log, 12)
                )));
            }
            Ok(None) => {}
            Err(error) => {
                return Err(Interrupt::Failed(format!(
                    "Cannot watch the emulator process: {error}"
                )));
            }
        }

        let state = adb.state(serial).unwrap_or_else(|_| "absent".to_owned());
        let booted = state == "device"
            && adb
                .getprop(serial, "sys.boot_completed")
                .is_ok_and(|value| value.trim() == "1");
        if booted && adb.package_path(serial, "android").is_ok() {
            return Ok(());
        }

        // SurfaceFlinger is enough for scrcpy, so the user can watch Android boot instead of
        // staring at an empty screen until the APK is installed and launched.
        let display_up = state == "device"
            && adb
                .getprop(serial, "init.svc.surfaceflinger")
                .is_ok_and(|value| value.trim() == "running");
        if show_display_requested {
            show_display(
                guard,
                sender,
                config,
                app,
                environment,
                serial,
                staging,
                windows,
            );
        } else if display_up
            && windows.scrcpy.is_none()
            && !scrcpy_tried
            && use_scrcpy(config, environment)
        {
            scrcpy_tried = true;
            let scrcpy = environment
                .scrcpy
                .as_deref()
                .expect("checked by use_scrcpy");
            let scrcpy_log = scrcpy_log_path(staging, serial);
            match spawn_scrcpy(guard, scrcpy, config, serial, &app.package, &scrcpy_log) {
                Ok(spawned) => {
                    windows.scrcpy = Some(spawned);
                    let _ = sender.send(Update::Notice(
                        "The device display is open. Android continues booting in the scrcpy \
                         window."
                            .to_owned(),
                    ));
                }
                Err(error) => {
                    let _ = sender.send(Update::Notice(format!(
                        "scrcpy could not open yet ({error:#}). Euphoria will try again after \
                         Android finishes booting."
                    )));
                }
            }
        }
        if windows
            .scrcpy
            .as_mut()
            .is_some_and(|scrcpy| matches!(scrcpy.try_wait(), Ok(Some(_))))
        {
            windows.scrcpy = None;
            let _ = sender.send(Update::Notice(scrcpy_closed_message(
                staging,
                serial,
                "The emulator is still booting; use Show display to reopen it.",
            )));
        }

        let detail = match state.as_str() {
            "device" if booted => "Android is finishing startup...",
            "device" => "Android is starting...",
            "unauthorized" => "The emulator is unauthorized; the AVD image may be damaged.",
            "offline" => "The emulator is still starting...",
            _ => "Waiting for the emulator to appear...",
        };
        let elapsed = started.elapsed().as_secs();
        let detail = if elapsed >= 5 {
            format!("{detail} ({}:{:02})", elapsed / 60, elapsed % 60)
        } else {
            detail.to_owned()
        };
        if detail != last_detail {
            send_phase(sender, Phase::Booting, detail.clone());
            last_detail = detail;
        }
        if Instant::now() >= deadline {
            return Err(Interrupt::Failed(format!(
                "Android did not finish booting within {timeout} seconds.\n{}",
                process::tail(emulator_log, 12)
            )));
        }
        thread::sleep(Duration::from_secs(1));
    }
}

fn launch_app(adb: &Adb, serial: &str, app: &AppInfo, component: Option<&str>) -> Result<String> {
    if let Some(component) = component {
        let output = adb.start_activity(serial, component)?;
        if started(&output) {
            return Ok(format!("{component} is running."));
        }
        let first = output.combined();
        let monkey = adb.monkey_launch(serial, &app.package)?;
        if started(&monkey) {
            return Ok(format!(
                "{} is running (launched with monkey).",
                app.package
            ));
        }
        bail!(
            "Android could not start {component}.\nam start:\n{first}\nmonkey:\n{}",
            monkey.combined()
        );
    }

    let monkey = adb.monkey_launch(serial, &app.package)?;
    if started(&monkey) {
        return Ok(format!(
            "{} is running (launched with monkey).",
            app.package
        ));
    }
    bail!(
        "Android could not find a launcher activity for {}.\n{}",
        app.package,
        monkey.combined()
    )
}

fn started(output: &Output) -> bool {
    if !output.success {
        return false;
    }
    let text = output.combined().to_ascii_lowercase();
    !["error", "exception", "does not exist", "aborted"]
        .iter()
        .any(|needle| text.contains(needle))
}

fn install_failure(package: &str, output: &Output, emulator_log: &Path) -> Cycle {
    let text = output.combined();
    let mut message = format!("Android could not install {package}.\n{text}");
    if let Some(hint) = adb::install_hint(&text) {
        message.push_str(&format!("\n{hint}"));
    }
    let tail = process::tail(emulator_log, 8);
    if !tail.is_empty() {
        message.push_str(&format!("\n\nEmulator log:\n{tail}"));
    }
    Cycle::Failed(message)
}

fn send_device(
    sender: &Sender<Update>,
    serial: &str,
    avd: &Avd,
    port: u16,
    properties: &DeviceProperties,
    package: &str,
    component: Option<String>,
) {
    let device = DeviceInfo {
        serial: serial.to_owned(),
        avd: avd.name.clone(),
        port,
        model: properties.model.clone(),
        api: properties.api,
        release: properties.release.clone(),
        abi_list: properties.abi_list.clone(),
        resolution: properties.resolution.clone(),
        density: properties.density.clone(),
        package: package.to_owned(),
        component,
    };
    let _ = sender.send(Update::Device(Box::new(device)));
}

fn send_phase(sender: &Sender<Update>, phase: Phase, detail: impl Into<String>) {
    let _ = sender.send(Update::Phase(phase, detail.into()));
}

fn stop_emulator(adb: &Adb, serial: &str, child: &mut Child) {
    // The proxy setting lives in the AVD's data, so remove it before the device disappears.
    adb.clear_http_proxy(serial);
    let _ = adb.emu_kill(serial);
    if process::wait_for_exit(child, STOP_TIMEOUT).is_none() {
        let _ = child.kill();
        let _ = child.wait();
    }
}

enum Control {
    Continue,
    Stop,
    Restart { wipe: bool },
}

fn drain_control(commands: &Receiver<Command>) -> Control {
    let mut control = Control::Continue;
    while let Ok(command) = commands.try_recv() {
        match command {
            Command::Stop => control = Control::Stop,
            Command::Restart => control = Control::Restart { wipe: false },
            Command::Reset => control = Control::Restart { wipe: true },
            Command::StopApp | Command::RelaunchApp | Command::ShowDisplay => {}
        }
    }
    control
}

fn interrupted(commands: &Receiver<Command>) -> Option<Cycle> {
    match drain_control(commands) {
        Control::Stop => Some(Cycle::Stop),
        Control::Restart { wipe } => Some(Cycle::Next { wipe }),
        Control::Continue => None,
    }
}

enum Cycle {
    Next { wipe: bool },
    Stop,
    Failed(String),
}

enum End {
    Stopped,
    Failed(String),
}

impl From<anyhow::Error> for End {
    fn from(error: anyhow::Error) -> Self {
        Self::Failed(format!("{error:#}"))
    }
}

enum Interrupt {
    Stop,
    Restart { wipe: bool },
    Failed(String),
}

impl From<anyhow::Error> for Interrupt {
    fn from(error: anyhow::Error) -> Self {
        Self::Failed(format!("{error:#}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn phases_describe_their_role() {
        assert!(!Phase::Idle.is_active());
        assert!(!Phase::Error.is_active());
        assert!(Phase::Booting.is_active());
        assert!(Phase::Running.is_running());
        assert!(Phase::Installing.is_busy());
        assert!(!Phase::Running.is_busy());
    }

    #[test]
    fn android_text_handles_missing_properties() {
        let device = DeviceInfo {
            api: Some(34),
            release: "14".to_owned(),
            ..DeviceInfo::default()
        };
        assert_eq!(device.android_text(), "Android 14 (API 34)");
        assert_eq!(DeviceInfo::default().android_text(), "Android");
    }

    #[test]
    fn logcat_is_capped() {
        let mut runtime = AndroidRuntime::new();
        runtime.apply(Update::Logcat(
            (0..MAX_LOGCAT_LINES + 50).map(|i| i.to_string()).collect(),
        ));
        assert_eq!(runtime.logcat().len(), MAX_LOGCAT_LINES);
        assert_eq!(runtime.logcat().front().unwrap(), "50");
    }

    fn captured(id: u64) -> CaptureEvent {
        CaptureEvent {
            id,
            scheme: "https",
            method: "CONNECT".to_owned(),
            host: "example.com".to_owned(),
            path: String::new(),
            status: None,
            request_bytes: 0,
            response_bytes: 0,
            millis: 0,
            content_type: String::new(),
            preview: String::new(),
            note: String::new(),
        }
    }

    #[test]
    fn capture_updates_replace_tunnels_and_stay_bounded() {
        let mut runtime = AndroidRuntime::new();
        runtime.apply(Update::Capture(vec![captured(1)]));
        runtime.apply(Update::Capture(vec![CaptureEvent {
            request_bytes: 9,
            response_bytes: 4,
            ..captured(1)
        }]));
        assert_eq!(runtime.capture().len(), 1);
        assert_eq!(runtime.capture()[0].request_bytes, 9);

        runtime.apply(Update::Capture(
            (0..MAX_CAPTURE_ENTRIES as u64 + 10).map(captured).collect(),
        ));
        assert_eq!(runtime.capture().len(), MAX_CAPTURE_ENTRIES);
        assert_eq!(runtime.capture().front().unwrap().id, 10);
    }

    #[test]
    fn setup_is_offered_only_when_it_can_help() {
        let mut runtime = AndroidRuntime::new();
        assert!(!runtime.setup_available());

        let mut environment = Environment {
            sdk_root: Some(PathBuf::from("/opt/android")),
            emulator: Some(PathBuf::from("/opt/android/emulator/emulator")),
            adb: Some(PathBuf::from("/opt/android/platform-tools/adb")),
            ..Environment::default()
        };
        runtime.environment = Some(environment.clone());
        assert!(runtime.setup_available(), "no AVD yet");

        environment.avds.push(Avd {
            name: "euphoria".to_owned(),
            display_name: "Euphoria".to_owned(),
            path: PathBuf::from("/avd/euphoria.avd"),
            api: Some(34),
            abi: Some("x86_64".to_owned()),
            tag: "google_apis".to_owned(),
            width: None,
            height: None,
            density: None,
            play_store: false,
            error: None,
        });
        runtime.environment = Some(environment);
        assert!(!runtime.setup_available());
        assert!(!runtime.is_setting_up());
        assert!(runtime.can_run());
    }

    #[test]
    fn commands_collapse_to_the_last_request() {
        let (sender, receiver) = mpsc::channel();
        sender.send(Command::Stop).unwrap();
        sender.send(Command::Reset).unwrap();
        assert!(matches!(
            drain_control(&receiver),
            Control::Restart { wipe: true }
        ));

        sender.send(Command::StopApp).unwrap();
        assert!(matches!(drain_control(&receiver), Control::Continue));
    }
}
