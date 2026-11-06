use std::path::PathBuf;
use std::sync::mpsc::{self, Receiver};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use eframe::egui::{self, RichText, Ui};
use euphoria_debugger::live::{self, LiveModule, LiveProcess, ProcessInfo, Region, ThreadContext};
use euphoria_engine::euphp;

use crate::debug_view::parse_bytes;
use crate::tabs::Action;
use crate::{Project, theme, tools};

const MAX_PROCESS_ROWS: usize = 400;
const MAX_MODULE_ROWS: usize = 600;
const MAX_REGION_ROWS: usize = 400;
const MAX_PATCH_BYTES: usize = 64 * 1024;
const PREVIEW_BYTES: usize = 16;
const STACK_BYTES: usize = 128;
const LIVE_MEMORY_BYTES: usize = 256;

pub enum LogoAction {
    None,
    Browse,
    Tour,
}

#[derive(Clone, Debug)]
pub struct LiveLoad {
    pub pid: u32,
    pub path: PathBuf,
    pub base: u64,
    pub module: String,
}

#[derive(Clone, Copy, PartialEq, Eq, Default)]
enum LivePane {
    #[default]
    Modules,
    Stack,
    Memory,
}

impl LivePane {
    const ALL: [(&'static str, Self); 3] = [
        ("Modules", Self::Modules),
        ("Stack", Self::Stack),
        ("Memory", Self::Memory),
    ];
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Confirm {
    Apply,
    Restore,
    Kill,
}

#[derive(Default)]
pub struct AttachState {
    picker: bool,
    filter: String,
    scan: Option<Receiver<Vec<ProcessInfo>>>,
    processes: Vec<ProcessInfo>,
    selected: Option<u32>,
    scan_error: Option<String>,
    live: Option<LiveSession>,
    confirm: Option<Confirm>,
    notice: Option<String>,
    patch_requested: bool,
    pending_load: Option<LiveLoad>,
}

struct LiveSession {
    process: LiveProcess,
    threads: Vec<u32>,
    handles: Option<u32>,
    regions: Vec<Region>,
    selected_module: Option<usize>,
    dll_job: Option<Receiver<DllScan>>,
    dll_result: Option<DllScan>,
    suspended: Option<bool>,
    patch: PatchDraft,
    contexts: Option<Vec<ThreadContext>>,
    context_error: Option<String>,
    selected_thread: Option<u32>,
    stack: Option<(u64, Vec<u8>)>,
    memory: Option<(u64, Vec<u8>)>,
    memory_address: String,
    pane: LivePane,
}

type DllScan = (String, Vec<(ProcessInfo, LiveModule)>);

#[derive(Default)]
struct PatchDraft {
    address: String,
    replacement: String,
    note: String,
    entries: Vec<Staged>,
    error: Option<String>,
}

#[derive(Debug)]
struct Staged {
    address: u64,
    module: String,
    offset: u64,
    original: Vec<u8>,
    patched: Vec<u8>,
    note: String,
    applied: bool,
}

impl LiveSession {
    fn new(process: LiveProcess) -> Self {
        let mut session = Self {
            process,
            threads: Vec::new(),
            handles: None,
            regions: Vec::new(),
            selected_module: None,
            dll_job: None,
            dll_result: None,
            suspended: None,
            patch: PatchDraft::default(),
            contexts: None,
            context_error: None,
            selected_thread: None,
            stack: None,
            memory: None,
            memory_address: String::new(),
            pane: LivePane::default(),
        };
        session.refresh();
        session
    }

    fn refresh(&mut self) {
        self.process.refresh_modules();
        self.threads = self.process.threads();
        self.handles = self.process.handle_count();
        self.regions = self.process.regions();
        self.dll_job = None;
        self.dll_result = None;
        self.selected_module = None;
    }

    fn lookup_users(&mut self, name: String, ctx: &egui::Context) {
        if self.dll_job.is_some() {
            return;
        }
        let (sender, receiver) = mpsc::channel();
        let ctx = ctx.clone();
        thread::spawn(move || {
            let users = live::dll_users(&name);
            let _ = sender.send((name, users));
            ctx.request_repaint();
        });
        self.dll_job = Some(receiver);
        self.dll_result = None;
    }

    fn total(&self, keep: impl Fn(&Region) -> bool) -> u64 {
        self.regions
            .iter()
            .filter(|region| region.committed() && keep(region))
            .map(|region| region.size)
            .sum()
    }

    fn primary_load(&self, pid: u32) -> Option<LiveLoad> {
        let modules = self.process.modules();
        let index = select_primary(modules, self.process.path(), self.process.name())?;
        let module = &modules[index];
        if module.path.is_empty() {
            return None;
        }
        Some(LiveLoad {
            pid,
            path: PathBuf::from(&module.path),
            base: module.base,
            module: module.name.clone(),
        })
    }
}

// The process path is the surest way to find the main module; a service or launcher can have
// several `*.exe` modules, so the ordering alone is not enough.
fn select_primary(modules: &[LiveModule], path: &str, name: &str) -> Option<usize> {
    modules
        .iter()
        .position(|module| !module.path.is_empty() && module.path.eq_ignore_ascii_case(path))
        .or_else(|| {
            modules
                .iter()
                .position(|module| module.name.eq_ignore_ascii_case(name))
        })
        .or_else(|| (!modules.is_empty()).then_some(0))
}

fn read_stack(session: &LiveSession, context: &ThreadContext) -> Option<(u64, Vec<u8>)> {
    if context.sp == 0 {
        return None;
    }
    let bytes = session.process.read(context.sp, STACK_BYTES);
    (!bytes.is_empty()).then_some((context.sp, bytes))
}

impl AttachState {
    pub fn is_attached(&self) -> bool {
        self.live.is_some()
    }

    pub fn label(&self) -> Option<String> {
        self.live
            .as_ref()
            .map(|session| format!("{} (pid {})", session.process.name(), session.process.pid()))
    }

    pub fn open_picker(&mut self, ctx: &egui::Context) {
        self.picker = true;
        self.scan_error = None;
        self.start_scan(ctx);
    }

    fn start_scan(&mut self, ctx: &egui::Context) {
        if self.scan.is_some() {
            return;
        }
        let (sender, receiver) = mpsc::channel();
        let ctx = ctx.clone();
        thread::spawn(move || {
            let _ = sender.send(live::processes());
            ctx.request_repaint();
        });
        self.scan = Some(receiver);
    }

    fn attach(&mut self, pid: u32) -> Result<(), String> {
        let process = LiveProcess::open(pid)?;
        let session = LiveSession::new(process);
        self.pending_load = session.primary_load(pid);
        self.live = Some(session);
        self.picker = false;
        self.scan_error = None;
        Ok(())
    }

    pub fn detach(&mut self) -> Option<String> {
        let session = self.live.take()?;
        self.pending_load = None;
        Some(format!(
            "Detached from {} (pid {})",
            session.process.name(),
            session.process.pid()
        ))
    }

    pub fn take_load_request(&mut self) -> Option<LiveLoad> {
        self.pending_load.take()
    }

    // Reads registers from every thread, pausing each one just for the copy.
    pub fn capture_contexts(&mut self) -> Option<String> {
        let session = self.live.as_mut()?;
        let contexts = session.process.contexts();
        if contexts.is_empty() {
            session.contexts = None;
            session.context_error =
                Some("Windows did not return registers for this process.".to_owned());
            return Some("Could not read any thread registers".to_owned());
        }
        let failed = contexts
            .iter()
            .filter(|context| context.error.is_some())
            .count();
        let first = contexts
            .iter()
            .find(|context| session.selected_thread == Some(context.id))
            .or(contexts.first());
        session.selected_thread = first.map(|context| context.id);
        session.stack = first.and_then(|context| read_stack(session, context));
        session.context_error = (failed == contexts.len())
            .then(|| "Windows refused access to every thread context.".to_owned());
        session.contexts = Some(contexts);
        Some(format!(
            "Captured {} thread register(s){}",
            session.contexts.as_ref().map_or(0, Vec::len),
            if failed == 0 {
                String::new()
            } else {
                format!(", {failed} unavailable")
            }
        ))
    }

    fn select_thread(&mut self, id: u32) {
        let Some(session) = self.live.as_mut() else {
            return;
        };
        session.selected_thread = Some(id);
        let stack = session
            .contexts
            .as_ref()
            .and_then(|contexts| contexts.iter().find(|context| context.id == id))
            .and_then(|context| read_stack(session, context));
        if stack.is_some() {
            session.stack = stack;
        }
    }

    fn read_memory(&mut self, address: u64) {
        let Some(session) = self.live.as_mut() else {
            return;
        };
        let bytes = session.process.read(address, LIVE_MEMORY_BYTES);
        if bytes.is_empty() {
            self.notice = Some(format!("Could not read memory at {address:#x}"));
            return;
        }
        session.memory_address = format!("{address:#x}");
        session.memory = Some((address, bytes));
    }

    fn inspect_module(&mut self, index: usize) {
        let Some(session) = &self.live else {
            return;
        };
        let Some(module) = session.process.modules().get(index) else {
            return;
        };
        if module.path.is_empty() {
            self.notice = Some(format!("Windows did not report a path for {}", module.name));
            return;
        }
        let path = PathBuf::from(&module.path);
        if !path.is_file() {
            self.notice = Some(format!("{} is no longer on disk", module.path));
            return;
        }
        self.pending_load = Some(LiveLoad {
            pid: session.process.pid(),
            path,
            base: module.base,
            module: module.name.clone(),
        });
    }

    pub fn suspend(&mut self) -> Option<String> {
        let session = self.live.as_mut()?;
        match session.process.suspend() {
            Ok(count) => {
                session.suspended = Some(true);
                session.threads = session.process.threads();
                session.contexts = None;
                session.context_error = None;
                session.stack = None;
                Some(format!(
                    "Suspended {count} thread(s) of {} (pid {})",
                    session.process.name(),
                    session.process.pid()
                ))
            }
            Err(error) => Some(error),
        }
    }

    pub fn resume(&mut self) -> Option<String> {
        let session = self.live.as_mut()?;
        match session.process.resume() {
            Ok(count) => {
                session.suspended = Some(false);
                session.contexts = None;
                session.context_error = None;
                session.stack = None;
                Some(format!(
                    "Resumed {count} thread(s) of {} (pid {})",
                    session.process.name(),
                    session.process.pid()
                ))
            }
            Err(error) => Some(error),
        }
    }

    pub fn request_kill(&mut self) {
        if self.live.is_some() {
            self.confirm = Some(Confirm::Kill);
        } else {
            self.notice = Some("No process is attached".to_owned());
        }
    }

    pub fn take_notice(&mut self) -> Option<String> {
        self.notice.take()
    }

    pub fn take_patch_request(&mut self) -> bool {
        std::mem::take(&mut self.patch_requested)
    }

    pub fn poll(&mut self, ctx: &egui::Context) {
        if let Some(receiver) = &self.scan {
            match receiver.try_recv() {
                Ok(list) => {
                    self.processes = list;
                    self.scan = None;
                }
                Err(mpsc::TryRecvError::Empty) => {
                    ctx.request_repaint_after(Duration::from_millis(100));
                }
                Err(mpsc::TryRecvError::Disconnected) => self.scan = None,
            }
        }

        let mut exited = None;
        if let Some(session) = &mut self.live {
            if let Some(receiver) = &session.dll_job {
                match receiver.try_recv() {
                    Ok(result) => {
                        session.dll_result = Some(result);
                        session.dll_job = None;
                    }
                    Err(mpsc::TryRecvError::Empty) => {
                        ctx.request_repaint_after(Duration::from_millis(100));
                    }
                    Err(mpsc::TryRecvError::Disconnected) => session.dll_job = None,
                }
            }
            if session.process.is_alive() {
                ctx.request_repaint_after(Duration::from_millis(1000));
            } else {
                exited = Some(session.process.name().to_owned());
            }
        }
        if let Some(name) = exited {
            self.live = None;
            self.pending_load = None;
            self.notice = Some(format!("{name} exited, so Euphoria detached"));
        }
    }

    // Returns a status line when a process was just attached.
    pub fn dialog(&mut self, ctx: &egui::Context) -> Option<String> {
        let mut message = None;
        if self.picker {
            let mut attach = None;
            let mut close = false;
            egui::Modal::new(egui::Id::unique("attach_process")).show(ctx, |ui| {
                ui.set_max_width(640.0);
                ui.label(RichText::new("Attach to a live process").size(16.0));
                ui.add_space(6.0);
                ui.label(
                    "Euphoria opens the process so it can list its modules and read its memory, \
                     and change bytes when Windows lets it. The program keeps running. Only \
                     attach to programs you own or are allowed to inspect; nothing is written \
                     until you press Apply in the Patch File tab.",
                );
                ui.add_space(10.0);
                ui.horizontal(|ui| {
                    ui.label(RichText::new("Filter").color(theme::MUTED));
                    ui.add(
                        egui::TextEdit::singleline(&mut self.filter)
                            .hint_text("process name or pid")
                            .desired_width(240.0),
                    );
                    if ui
                        .add_enabled(self.scan.is_none(), egui::Button::new("Refresh"))
                        .clicked()
                    {
                        self.scan = None;
                        self.start_scan(ctx);
                    }
                    if let Some(session) = &self.live {
                        ui.label(
                            RichText::new(format!(
                                "Replacing the attachment to {}",
                                session.process.name()
                            ))
                            .color(theme::MUTED),
                        );
                    }
                });
                if let Some(error) = &self.scan_error {
                    ui.label(RichText::new(error).color(theme::ERROR));
                }
                if self.scan.is_some() {
                    ui.horizontal(|ui| {
                        ui.spinner();
                        ui.label(RichText::new("Listing processes...").color(theme::MUTED));
                    });
                } else {
                    egui::ScrollArea::vertical()
                        .id_salt("attach_processes")
                        .max_height(340.0)
                        .show(ui, |ui| {
                            let filter = self.filter.trim().to_ascii_lowercase();
                            let mut shown = 0;
                            for process in &self.processes {
                                let matches = filter.is_empty()
                                    || process.name.to_ascii_lowercase().contains(&filter)
                                    || process.pid.to_string().contains(&filter);
                                if !matches {
                                    continue;
                                }
                                shown += 1;
                                if shown > MAX_PROCESS_ROWS {
                                    break;
                                }
                                let selected = self.selected == Some(process.pid);
                                let response = ui.selectable_label(
                                    selected,
                                    RichText::new(format!("{:>6}  {}", process.pid, process.name))
                                        .font(theme::mono()),
                                );
                                if response.clicked() {
                                    self.selected = Some(process.pid);
                                }
                                if response.double_clicked() {
                                    attach = Some(process.pid);
                                }
                            }
                            if shown == 0 {
                                ui.label(
                                    RichText::new("No processes matched that filter.")
                                        .color(theme::MUTED),
                                );
                            }
                        });
                }
                ui.add_space(10.0);
                ui.horizontal(|ui| {
                    if ui
                        .add_enabled(
                            self.selected.is_some() && self.scan.is_none(),
                            egui::Button::new("Attach"),
                        )
                        .clicked()
                        && let Some(pid) = self.selected
                    {
                        attach = Some(pid);
                    }
                    if ui.button("Cancel").clicked() {
                        close = true;
                    }
                });
            });

            if close {
                self.picker = false;
            }
            if let Some(pid) = attach {
                match self.attach(pid) {
                    Ok(()) => {
                        message = Some(format!(
                            "Attached to {}",
                            self.label().unwrap_or_else(|| format!("pid {pid}"))
                        ));
                    }
                    Err(error) => self.scan_error = Some(error),
                }
            }
        }

        if self.confirm.is_some() {
            self.confirm_dialog(ctx);
        }
        message
    }

    fn confirm_dialog(&mut self, ctx: &egui::Context) {
        let Some(confirm) = self.confirm else {
            return;
        };
        let Some((name, pid, pending, applied)) = self.live.as_ref().map(|session| {
            (
                session.process.name().to_owned(),
                session.process.pid(),
                session
                    .patch
                    .entries
                    .iter()
                    .filter(|entry| !entry.applied)
                    .count(),
                session
                    .patch
                    .entries
                    .iter()
                    .filter(|entry| entry.applied)
                    .count(),
            )
        }) else {
            self.confirm = None;
            return;
        };

        let mut decision = None;
        let response = egui::Modal::new(egui::Id::unique("attach_write")).show(ctx, |ui| {
            ui.set_max_width(480.0);
            let (title, detail, verb) = match confirm {
                Confirm::Kill => (
                    format!("Stop {name} (pid {pid})?"),
                    format!(
                        "Euphoria terminates the process and releases its handle. Anything it \
                         has not saved is lost, and {pending} staged edit(s) are discarded. This \
                         cannot be undone."
                    ),
                    "Stop process",
                ),
                Confirm::Restore => (
                    format!("Restore the original bytes in {name}?"),
                    format!(
                        "Euphoria writes the {applied} edit(s) that were applied back to the \
                         bytes it read before. The process keeps running but may crash if the \
                         patched code already ran."
                    ),
                    "Restore",
                ),
                Confirm::Apply => (
                    format!("Write {pending} edit(s) into {name}?"),
                    "Euphoria changes the running process immediately. Nothing is saved to disk \
                     yet. The original bytes stay listed, so they can be restored or saved into a \
                     .euphp file."
                        .to_owned(),
                    "Apply",
                ),
            };
            ui.label(RichText::new(title).size(16.0));
            ui.add_space(8.0);
            ui.label(detail);
            ui.add_space(12.0);
            ui.horizontal(|ui| {
                let button = if confirm == Confirm::Kill {
                    egui::Button::new(RichText::new(verb).color(theme::ERROR))
                } else {
                    egui::Button::new(verb)
                };
                if ui.add(button).clicked() {
                    decision = Some(true);
                }
                if ui.button("Cancel").clicked() {
                    decision = Some(false);
                }
            });
        });
        if response.should_close() && decision.is_none() {
            decision = Some(false);
        }

        match decision {
            Some(true) => {
                if confirm == Confirm::Kill {
                    if let Some(session) = self.live.take() {
                        match session.process.kill() {
                            Ok(()) => {
                                self.notice = Some(format!("Stopped {name} (pid {pid})"));
                            }
                            Err(error) => {
                                self.live = Some(session);
                                self.notice = Some(error);
                            }
                        }
                    }
                } else if let Some(session) = &mut self.live {
                    let message = apply_edits(session, confirm == Confirm::Restore);
                    self.notice = Some(message);
                }
                self.confirm = None;
            }
            Some(false) => self.confirm = None,
            None => {}
        }
    }

    pub fn resources(&mut self, ui: &mut Ui) -> Option<Action> {
        let mut action = None;
        let mut detach = false;
        let mut suspend = false;
        let mut resume = false;
        let mut kill = false;
        let Some(session) = &mut self.live else {
            return action;
        };

        tools::card(ui, |ui| {
            ui.horizontal(|ui| {
                ui.label(RichText::new("Attached process").strong());
                ui.label(
                    RichText::new(format!(
                        "{} (pid {})",
                        session.process.name(),
                        session.process.pid()
                    ))
                    .color(theme::ACCENT)
                    .font(theme::mono()),
                );
                match session.suspended {
                    Some(true) => {
                        ui.label(RichText::new("suspended").color(theme::NUMBER))
                            .on_hover_text("Every thread was suspended from the Debugger tab.");
                    }
                    Some(false) => {
                        ui.label(RichText::new("running").color(theme::ACCENT));
                    }
                    None => {}
                }
                if !session.process.writable() {
                    ui.label(RichText::new("read-only").color(theme::ERROR))
                        .on_hover_text(
                            "Windows did not grant write access, so memory cannot be edited.",
                        );
                }
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui.button("Detach").clicked() {
                        detach = true;
                    }
                    if ui.button("Refresh").clicked() {
                        session.refresh();
                    }
                    ui.separator();
                    if ui
                        .add(egui::Button::new(RichText::new("Kill").color(theme::ERROR)))
                        .on_hover_text("Ctrl+F9 - terminate this process")
                        .clicked()
                    {
                        kill = true;
                    }
                    if ui
                        .button("Resume")
                        .on_hover_text("Shift+F3 - let the threads run again")
                        .clicked()
                    {
                        resume = true;
                    }
                    if ui
                        .button("Suspend")
                        .on_hover_text("F3 - freeze every thread")
                        .clicked()
                    {
                        suspend = true;
                    }
                });
            });
            if !session.process.path().is_empty() {
                ui.label(
                    RichText::new(session.process.path())
                        .font(theme::mono())
                        .color(theme::MUTED)
                        .size(11.5),
                );
            }

            ui.horizontal_wrapped(|ui| {
                for (label, value) in [
                    ("Threads", session.threads.len().to_string()),
                    (
                        "Handles",
                        session
                            .handles
                            .map_or_else(|| "unknown".to_owned(), |count| count.to_string()),
                    ),
                    ("Modules", session.process.modules().len().to_string()),
                    ("Committed", size_label(session.total(|_| true))),
                    (
                        "Private",
                        size_label(session.total(|region| region.private())),
                    ),
                    ("Image", size_label(session.total(|region| region.image()))),
                    (
                        "Executable",
                        size_label(session.total(|region| region.executable())),
                    ),
                ] {
                    ui.add_space(10.0);
                    ui.label(RichText::new(label).color(theme::MUTED).size(11.5));
                    ui.label(RichText::new(value).font(theme::mono()).size(11.5));
                }
            });

            ui.add_space(8.0);
            ui.label(RichText::new("Loaded modules").color(theme::MUTED));
            let mut lookup = None;
            egui::ScrollArea::vertical()
                .id_salt("live_modules")
                .max_height(240.0)
                .show(ui, |ui| {
                    let modules = session.process.modules();
                    if modules.is_empty() {
                        ui.label(
                            RichText::new(
                                "No modules could be listed. Windows may not allow access to \
                                 this process.",
                            )
                            .color(theme::MUTED),
                        );
                    }
                    for (index, module) in modules.iter().take(MAX_MODULE_ROWS).enumerate() {
                        let selected = session.selected_module == Some(index);
                        let response = ui.selectable_label(
                            selected,
                            RichText::new(format!(
                                "{:012x}  {:>10}  {}",
                                module.base,
                                size_label(module.size),
                                module.name
                            ))
                            .font(theme::mono()),
                        );
                        if !module.path.is_empty() {
                            response.clone().on_hover_text(&module.path);
                        }
                        if response.clicked() {
                            session.selected_module = Some(index);
                            if module.name.to_ascii_lowercase().ends_with(".dll") {
                                lookup = Some(module.name.clone());
                            } else {
                                session.dll_result = None;
                                session.dll_job = None;
                            }
                        }
                    }
                });
            if let Some(name) = lookup {
                session.lookup_users(name, ui.ctx());
            }

            ui.add_space(8.0);
            let committed = session
                .regions
                .iter()
                .filter(|region| region.committed())
                .count();
            egui::CollapsingHeader::new(
                RichText::new(format!("Memory map ({committed})")).color(theme::MUTED),
            )
            .id_salt("live_memory_map")
            .show(ui, |ui| {
                egui::ScrollArea::vertical()
                    .id_salt("live_regions")
                    .max_height(220.0)
                    .show(ui, |ui| {
                        egui::Grid::new("live_region_grid")
                            .num_columns(4)
                            .spacing([16.0, 2.0])
                            .show(ui, |ui| {
                                for title in ["Base", "Size", "Protection", "Kind"] {
                                    ui.label(RichText::new(title).color(theme::MUTED).size(11.0));
                                }
                                ui.end_row();
                                for region in session
                                    .regions
                                    .iter()
                                    .filter(|region| region.committed())
                                    .take(MAX_REGION_ROWS)
                                {
                                    ui.label(
                                        RichText::new(format!("{:012x}", region.base))
                                            .font(theme::mono())
                                            .size(11.5),
                                    );
                                    ui.label(
                                        RichText::new(size_label(region.size))
                                            .font(theme::mono())
                                            .size(11.5),
                                    );
                                    let color = if region.guard() {
                                        theme::ERROR
                                    } else if region.executable() {
                                        theme::NUMBER
                                    } else {
                                        theme::MUTED
                                    };
                                    ui.label(
                                        RichText::new(if region.guard() {
                                            "guard"
                                        } else {
                                            region.protection()
                                        })
                                        .color(color)
                                        .font(theme::mono())
                                        .size(11.5),
                                    );
                                    ui.label(
                                        RichText::new(region_kind(region))
                                            .color(theme::MUTED)
                                            .size(11.5),
                                    );
                                    ui.end_row();
                                }
                            });
                    });
            });

            if let Some((name, users)) = &session.dll_result {
                ui.add_space(8.0);
                ui.label(RichText::new(format!("Processes using {name}")).color(theme::MUTED));
                if users.is_empty() {
                    ui.label(
                        RichText::new("No process currently has this module loaded.")
                            .color(theme::MUTED),
                    );
                }
                egui::ScrollArea::vertical()
                    .id_salt("dll_users")
                    .max_height(160.0)
                    .show(ui, |ui| {
                        for (process, module) in users {
                            let label = format!(
                                "{:>6}  {}  {}",
                                process.pid,
                                process.name,
                                size_label(module.size)
                            );
                            let response = ui
                                .label(RichText::new(label).font(theme::mono()).color(theme::TEXT));
                            if !module.path.is_empty() {
                                response.on_hover_text(&module.path);
                            }
                        }
                    });
            } else if session.dll_job.is_some() {
                ui.horizontal(|ui| {
                    ui.spinner();
                    ui.label(
                        RichText::new("Looking through running processes...").color(theme::MUTED),
                    );
                });
            } else if session.selected_module.is_some() {
                ui.label(
                    RichText::new("Pick a .dll in the list to see which processes loaded it.")
                        .color(theme::MUTED),
                );
            }
        });

        if detach && let Some(message) = self.detach() {
            action = Some(Action::Status(message));
        }
        if suspend && let Some(message) = self.suspend() {
            action = Some(Action::Status(message));
        }
        if resume && let Some(message) = self.resume() {
            action = Some(Action::Status(message));
        }
        if kill {
            self.request_kill();
        }
        action
    }

    // The Debugger tab while a process is attached. Everything here reads memory; the only
    // interruptions are the brief per-thread pause used by Capture registers.
    pub fn live_debugger(&mut self, ui: &mut Ui, project: Option<&mut Project>) -> Option<Action> {
        let mut action = None;
        let mut capture = false;
        let mut suspend = false;
        let mut resume = false;
        let mut detach = false;
        let mut kill = false;
        let mut inspect = None;
        let mut selection = None;
        let mut read_at: Option<u64> = None;
        let mut follow = None;
        let mut decompile = None;
        let mut memory_error = None;

        {
            let Some(session) = self.live.as_mut() else {
                ui.centered_and_justified(|ui| {
                    ui.label(
                        RichText::new("Attach to a process from the Euphoria menu")
                            .color(theme::MUTED),
                    );
                });
                return action;
            };

            let selected_context = session.selected_thread.and_then(|id| {
                session
                    .contexts
                    .as_ref()?
                    .iter()
                    .find(|context| context.id == id)
            });
            let ip = selected_context.map(|context| context.ip);

            egui::Frame::new()
                .fill(theme::SURFACE)
                .inner_margin(egui::Margin::symmetric(10, 6))
                .show(ui, |ui| {
                    ui.horizontal(|ui| {
                        ui.label(
                            RichText::new(format!(
                                "{} (pid {})",
                                session.process.name(),
                                session.process.pid()
                            ))
                            .strong(),
                        );
                        match session.suspended {
                            Some(true) => {
                                ui.label(RichText::new("suspended").color(theme::NUMBER));
                            }
                            Some(false) => {
                                ui.label(RichText::new("running").color(theme::ACCENT));
                            }
                            None => {
                                ui.label(RichText::new("live").color(theme::ACCENT));
                            }
                        }
                        if !session.process.writable() {
                            ui.label(RichText::new("read-only").color(theme::ERROR))
                                .on_hover_text(
                                    "Windows did not grant write access, so memory edits and \
                                     patches are unavailable.",
                                );
                        }
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            if ui.button("Detach").clicked() {
                                detach = true;
                            }
                            if ui
                                .add(egui::Button::new(RichText::new("Kill").color(theme::ERROR)))
                                .on_hover_text("Ctrl+F9 - terminate this process")
                                .clicked()
                            {
                                kill = true;
                            }
                            if ui
                                .button("Resume")
                                .on_hover_text("Shift+F3 - let every thread run")
                                .clicked()
                            {
                                resume = true;
                            }
                            if ui
                                .button("Suspend")
                                .on_hover_text("F3 - freeze every thread")
                                .clicked()
                            {
                                suspend = true;
                            }
                            if ui
                                .button("Capture registers")
                                .on_hover_text(
                                    "Pauses each thread for a moment to copy its registers, \
                                         then resumes it. Suspend first for a still snapshot.",
                                )
                                .clicked()
                            {
                                capture = true;
                            }
                            if let Some(ip) = ip {
                                if ui.button("Decompile at IP").clicked() {
                                    decompile = Some(ip);
                                }
                                if ui.button("Go to IP").clicked() {
                                    follow = Some(ip);
                                }
                            }
                        });
                    });
                    if let Some(error) = &session.context_error {
                        ui.label(RichText::new(error).color(theme::ERROR));
                    }
                });

            egui::Panel::bottom("live_debug_bottom")
                .exact_size(250.0)
                .frame(egui::Frame::new().fill(theme::SURFACE).inner_margin(8))
                .show(ui, |ui| {
                    ui.horizontal(|ui| {
                        for (name, value) in LivePane::ALL {
                            if ui.selectable_label(session.pane == value, name).clicked() {
                                session.pane = value;
                            }
                        }
                    });
                    ui.separator();
                    match session.pane {
                        LivePane::Modules => {
                            egui::ScrollArea::vertical()
                                .id_salt("live_debug_module_list")
                                .auto_shrink(false)
                                .show(ui, |ui| {
                                    egui::Grid::new("live_debug_module_grid")
                                        .num_columns(3)
                                        .spacing([16.0, 2.0])
                                        .show(ui, |ui| {
                                            for title in ["Base", "Size", "Module"] {
                                                ui.label(
                                                    RichText::new(title)
                                                        .color(theme::MUTED)
                                                        .size(11.0),
                                                );
                                            }
                                            ui.end_row();
                                            for (index, module) in session
                                                .process
                                                .modules()
                                                .iter()
                                                .take(MAX_MODULE_ROWS)
                                                .enumerate()
                                            {
                                                let selected =
                                                    session.selected_module == Some(index);
                                                let response = ui.selectable_label(
                                                    selected,
                                                    RichText::new(format!("{:012x}", module.base))
                                                        .font(theme::mono())
                                                        .size(11.5),
                                                );
                                                if !module.path.is_empty() {
                                                    response.clone().on_hover_text(&module.path);
                                                }
                                                if response.clicked() {
                                                    session.selected_module = Some(index);
                                                }
                                                if response.double_clicked() {
                                                    inspect = Some(index);
                                                }
                                                ui.label(
                                                    RichText::new(size_label(module.size))
                                                        .font(theme::mono())
                                                        .size(11.5),
                                                );
                                                let label = ui.selectable_label(
                                                    false,
                                                    RichText::new(&module.name)
                                                        .font(theme::mono())
                                                        .size(11.5),
                                                );
                                                if label.clicked() {
                                                    session.selected_module = Some(index);
                                                }
                                                if label.double_clicked() {
                                                    inspect = Some(index);
                                                }
                                                ui.end_row();
                                            }
                                        });
                                });
                            ui.add_space(6.0);
                            if let Some(index) = session.selected_module {
                                let module = session.process.modules().get(index);
                                let label = module.map_or_else(
                                    || "Inspect module".to_owned(),
                                    |module| format!("Inspect {}", module.name),
                                );
                                if ui
                                    .button(label)
                                    .on_hover_text(
                                        "Reads this module from disk and its bytes from the \
                                         process, then opens it in the listing and decompiler.",
                                    )
                                    .clicked()
                                {
                                    inspect = Some(index);
                                }
                            } else {
                                ui.label(
                                    RichText::new(
                                        "Pick a module, then Inspect it to list and decompile its \
                                         code at the live addresses.",
                                    )
                                    .color(theme::MUTED)
                                    .size(11.5),
                                );
                            }
                        }
                        LivePane::Stack => {
                            if let Some((sp, bytes)) = &session.stack {
                                ui.label(
                                    RichText::new(format!("Stack at {sp:#x}")).color(theme::MUTED),
                                );
                                egui::ScrollArea::vertical()
                                    .id_salt("live_debug_stack")
                                    .auto_shrink(false)
                                    .show(ui, |ui| {
                                        for (index, word) in
                                            bytes.as_chunks::<8>().0.iter().enumerate()
                                        {
                                            let address = sp.wrapping_add((index * 8) as u64);
                                            let value = u64::from_le_bytes(*word);
                                            let response = ui.selectable_label(
                                                false,
                                                RichText::new(format!(
                                                    "{address:012x}  {value:016x}"
                                                ))
                                                .font(theme::mono())
                                                .size(11.5),
                                            );
                                            if response.clicked() {
                                                read_at = Some(value);
                                            }
                                        }
                                    });
                            } else {
                                ui.label(
                                    RichText::new(
                                        "Capture registers to read the selected thread's stack.",
                                    )
                                    .color(theme::MUTED),
                                );
                            }
                        }
                        LivePane::Memory => {
                            ui.horizontal(|ui| {
                                ui.label(RichText::new("Address").color(theme::MUTED));
                                ui.add(
                                    egui::TextEdit::singleline(&mut session.memory_address)
                                        .font(theme::mono())
                                        .desired_width(170.0),
                                );
                                if ui.button("Read").clicked() {
                                    match live::parse_hex(&session.memory_address) {
                                        Ok(address) => read_at = Some(address),
                                        Err(error) => memory_error = Some(error),
                                    }
                                }
                            });
                            if let Some(error) = &memory_error {
                                ui.label(RichText::new(error).color(theme::ERROR));
                            }
                            if let Some((base, bytes)) = &session.memory {
                                ui.add_space(4.0);
                                egui::ScrollArea::vertical()
                                    .id_salt("live_debug_memory")
                                    .auto_shrink(false)
                                    .show(ui, |ui| {
                                        live_hex(ui, *base, bytes, |address| {
                                            read_at = Some(address);
                                        });
                                    });
                            } else {
                                ui.label(
                                    RichText::new("Enter an address to read up to 256 live bytes.")
                                        .color(theme::MUTED),
                                );
                            }
                        }
                    }
                });

            egui::Panel::left("live_debug_threads")
                .exact_size(320.0)
                .frame(egui::Frame::new().fill(theme::SURFACE).inner_margin(8))
                .show(ui, |ui| {
                    ui.label(RichText::new("Threads").strong());
                    egui::ScrollArea::vertical()
                        .id_salt("live_debug_thread_list")
                        .max_height(180.0)
                        .auto_shrink(false)
                        .show(ui, |ui| {
                            for &id in &session.threads {
                                let context = session.contexts.as_ref().and_then(|contexts| {
                                    contexts.iter().find(|context| context.id == id)
                                });
                                let text = context.map_or_else(
                                    || format!("{id:>6}"),
                                    |context| format!("{id:>6}  {:012x}", context.ip),
                                );
                                let failed = context.is_some_and(|context| context.error.is_some());
                                let color = if failed { theme::ERROR } else { theme::TEXT };
                                if ui
                                    .selectable_label(
                                        session.selected_thread == Some(id),
                                        RichText::new(text)
                                            .font(theme::mono())
                                            .color(color)
                                            .size(11.5),
                                    )
                                    .clicked()
                                {
                                    selection = Some(id);
                                }
                            }
                        });
                    ui.separator();
                    match selected_context {
                        Some(context) => {
                            ui.label(
                                RichText::new(format!("Registers (thread {})", context.id))
                                    .strong(),
                            );
                            if let Some(error) = &context.error {
                                ui.label(RichText::new(error).color(theme::ERROR));
                            }
                            egui::ScrollArea::vertical()
                                .id_salt("live_debug_registers")
                                .auto_shrink(false)
                                .show(ui, |ui| {
                                    ui.spacing_mut().item_spacing.y = 0.0;
                                    for &(name, value) in &context.registers {
                                        let response = ui.selectable_label(
                                            false,
                                            RichText::new(format!("{name:<6}  {value:016x}"))
                                                .font(theme::mono())
                                                .size(11.5),
                                        );
                                        let response =
                                            response.on_hover_text(format!("{name} = {value:#x}"));
                                        response.context_menu(|ui| {
                                            if ui.button("Copy value").clicked() {
                                                ui.ctx().copy_text(format!("{value:016x}"));
                                                ui.close();
                                            }
                                        });
                                    }
                                });
                        }
                        None => {
                            ui.label(
                                RichText::new(
                                    "Capture registers to see each thread's instruction pointer \
                                     and registers.",
                                )
                                .color(theme::MUTED),
                            );
                        }
                    }
                });

            let mut code_action = None;
            if let Some(project) = project {
                if let Some(ip) = ip {
                    // `row_at` rounds down, so confirm the row actually covers the pointer.
                    let inside = project.listing.row_at(ip).and_then(|row| {
                        let line = project
                            .listing
                            .render(&project.analysis.data, row..row + 1)
                            .pop()?;
                        (ip < line.va + line.bytes.len() as u64).then_some(row)
                    });
                    if let Some(row) = inside {
                        let start = row.saturating_sub(12);
                        let end = (row + 13).min(project.listing.rows.len());
                        let lines = project.listing.render(&project.analysis.data, start..end);
                        egui::ScrollArea::vertical()
                            .id_salt("live_debug_code")
                            .auto_shrink(false)
                            .show(ui, |ui| {
                                ui.spacing_mut().item_spacing.y = 0.0;
                                for (index, line) in (start..end).zip(lines) {
                                    let text = line
                                        .tokens
                                        .iter()
                                        .map(|token| token.text.as_str())
                                        .collect::<Vec<_>>()
                                        .join(" ");
                                    let at_ip = index == row;
                                    let response = ui.selectable_label(
                                        at_ip,
                                        RichText::new(format!("{:012x}  {text}", line.va))
                                            .font(theme::mono())
                                            .size(11.5),
                                    );
                                    if response.clicked() && !at_ip {
                                        code_action = Some(Action::Focus(line.va));
                                    }
                                    if at_ip {
                                        response.on_hover_text(format!(
                                            "The selected thread is here ({ip:#x})."
                                        ));
                                    }
                                }
                            });
                    } else {
                        ui.centered_and_justified(|ui| {
                            ui.label(
                                RichText::new(format!(
                                    "{ip:#x} is not inside the loaded module. Open the module \
                                     that owns it under Modules, then Inspect it."
                                ))
                                .color(theme::MUTED),
                            );
                        });
                    }
                } else {
                    ui.centered_and_justified(|ui| {
                        ui.label(
                            RichText::new(
                                "Capture registers to show live code at the selected thread.",
                            )
                            .color(theme::MUTED)
                            .size(16.0),
                        );
                    });
                }
            } else {
                ui.centered_and_justified(|ui| {
                    ui.label(
                        RichText::new(
                            "No live module is loaded yet. Euphoria is reading the process \
                             module; if that did not finish, pick a module under Modules and \
                             press Inspect.",
                        )
                        .color(theme::MUTED)
                        .size(16.0),
                    );
                });
            }
            if let Some(next) = code_action {
                action = Some(next);
            }
        }

        if let Some(thread) = selection {
            self.select_thread(thread);
        }
        if let Some(address) = read_at {
            self.read_memory(address);
        }
        if capture && let Some(message) = self.capture_contexts() {
            action = Some(Action::Status(message));
        }
        if suspend && let Some(message) = self.suspend() {
            action = Some(Action::Status(message));
        }
        if resume && let Some(message) = self.resume() {
            action = Some(Action::Status(message));
        }
        if let Some(index) = inspect {
            self.inspect_module(index);
        }
        if kill {
            self.request_kill();
        }
        if detach && let Some(message) = self.detach() {
            self.notice = Some(message);
        }
        if let Some(va) = decompile {
            action = Some(Action::Decompile(va));
        } else if let Some(va) = follow {
            action = Some(Action::Go(va));
        }
        action
    }

    pub fn patch_tab(&mut self, ui: &mut Ui) -> Option<Action> {
        let mut action = None;
        if self.live.is_none() {
            ui.add_space(40.0);
            ui.vertical_centered(|ui| {
                ui.label(RichText::new("No process attached").size(18.0));
                ui.add_space(6.0);
                ui.label(
                    RichText::new(
                        "Attach from the Euphoria menu to build a .euphp patch from a running \
                         process.",
                    )
                    .color(theme::MUTED),
                );
                ui.add_space(10.0);
                if ui.button("Attach to process...").clicked() {
                    self.open_picker(ui.ctx());
                }
            });
            return action;
        }

        let Some(session) = &mut self.live else {
            return action;
        };
        let mut request = None;

        tools::card(ui, |ui| {
            ui.horizontal(|ui| {
                ui.label(RichText::new("Make patch file").strong());
                ui.label(
                    RichText::new(format!(
                        "{} (pid {})",
                        session.process.name(),
                        session.process.pid()
                    ))
                    .font(theme::mono())
                    .color(theme::ACCENT),
                );
                if !session.process.writable() {
                    ui.label(RichText::new("read-only").color(theme::ERROR))
                        .on_hover_text(
                            "Windows did not grant write access, so edits can be saved but not \
                             applied.",
                        );
                }
            });
            if !session.process.path().is_empty() {
                ui.label(
                    RichText::new(session.process.path())
                        .font(theme::mono())
                        .color(theme::MUTED)
                        .size(11.5),
                );
            }
            ui.label(
                RichText::new(
                    "Edits are stored as module name plus offset, so they still line up when \
                     this build loads somewhere else.",
                )
                .color(theme::MUTED),
            );
        });

        tools::card(ui, |ui| {
            let draft = &mut session.patch;
            egui::Grid::new("patch_editor")
                .num_columns(2)
                .spacing([12.0, 6.0])
                .show(ui, |ui| {
                    ui.label(RichText::new("Address").color(theme::MUTED));
                    ui.add(
                        egui::TextEdit::singleline(&mut draft.address)
                            .hint_text("game.exe+0x1200 or 0x7ff6...")
                            .font(theme::mono())
                            .desired_width(380.0),
                    );
                    ui.end_row();

                    ui.label(RichText::new("New bytes").color(theme::MUTED));
                    ui.add(
                        egui::TextEdit::singleline(&mut draft.replacement)
                            .hint_text("75 10 becomes EB 10")
                            .font(theme::mono())
                            .desired_width(380.0),
                    );
                    ui.end_row();

                    ui.label(RichText::new("Note").color(theme::MUTED));
                    ui.add(
                        egui::TextEdit::singleline(&mut draft.note)
                            .hint_text("why this edit exists")
                            .desired_width(380.0),
                    );
                    ui.end_row();
                });

            let stage = ui.button("Stage edit").clicked();
            if let Some(error) = &draft.error {
                ui.label(RichText::new(error).color(theme::ERROR));
            }
            if stage {
                let outcome = plan_entry(
                    session.process.modules(),
                    &draft.address,
                    &draft.replacement,
                    &draft.note,
                    &draft.entries,
                    |address, length| session.process.read(address, length),
                );
                match outcome {
                    Ok(entry) => {
                        draft.entries.push(entry);
                        draft.error = None;
                    }
                    Err(error) => draft.error = Some(error),
                }
            }
        });

        let mut save = false;
        tools::card(ui, |ui| {
            let draft = &mut session.patch;
            ui.horizontal(|ui| {
                ui.label(RichText::new("Staged edits").strong());
                ui.label(RichText::new(format!("{}", draft.entries.len())).color(theme::MUTED));
            });
            if draft.entries.is_empty() {
                ui.label(
                    RichText::new("Nothing staged yet. Add an address and the bytes to put there.")
                        .color(theme::MUTED),
                );
            }

            let mut remove = None;
            egui::ScrollArea::vertical()
                .id_salt("patch_entries")
                .max_height(260.0)
                .show(ui, |ui| {
                    egui::Grid::new("patch_entries_grid")
                        .num_columns(5)
                        .spacing([16.0, 4.0])
                        .show(ui, |ui| {
                            for title in ["Target", "Original", "Patched", "Note", ""] {
                                ui.label(RichText::new(title).color(theme::MUTED).size(11.5));
                            }
                            ui.end_row();

                            for (index, entry) in draft.entries.iter().enumerate() {
                                let response = ui.label(
                                    RichText::new(format!(
                                        "{}+{:#x}  ({:#x})",
                                        entry.module, entry.offset, entry.address
                                    ))
                                    .font(theme::mono())
                                    .color(if entry.applied {
                                        theme::ACCENT
                                    } else {
                                        theme::TEXT
                                    }),
                                );
                                response.on_hover_text(if entry.applied {
                                    "Applied to the running process"
                                } else {
                                    "Staged, not written yet"
                                });
                                ui.label(
                                    RichText::new(hex_preview(&entry.original))
                                        .font(theme::mono())
                                        .color(theme::MUTED),
                                );
                                ui.label(
                                    RichText::new(hex_preview(&entry.patched))
                                        .font(theme::mono())
                                        .color(theme::NUMBER),
                                );
                                ui.label(RichText::new(&entry.note).color(theme::MUTED));
                                if !entry.applied && ui.small_button("×").clicked() {
                                    remove = Some(index);
                                }
                                ui.end_row();
                            }
                        });
                });
            if let Some(index) = remove {
                draft.entries.remove(index);
            }

            ui.add_space(4.0);
            ui.horizontal(|ui| {
                let pending = draft.entries.iter().any(|entry| !entry.applied);
                let applied = draft.entries.iter().any(|entry| entry.applied);
                let writable = session.process.writable();
                if ui
                    .add_enabled(
                        pending && writable && self.confirm.is_none(),
                        egui::Button::new("Apply pending"),
                    )
                    .on_hover_text("Write the staged bytes into the running process")
                    .clicked()
                {
                    request = Some(Confirm::Apply);
                }
                if ui
                    .add_enabled(applied && writable, egui::Button::new("Restore applied"))
                    .on_hover_text("Write the original bytes back into the process")
                    .clicked()
                {
                    request = Some(Confirm::Restore);
                }
                if ui
                    .add_enabled(!draft.entries.is_empty(), egui::Button::new("Save .euphp"))
                    .clicked()
                {
                    save = true;
                }
            });
            if !session.process.writable() {
                ui.label(
                    RichText::new(
                        "This attachment is read-only, so edits can be saved but not applied.",
                    )
                    .color(theme::MUTED),
                );
            }
        });
        if save {
            action = save_patch(session);
        }

        if let Some(confirm) = request {
            self.confirm = Some(confirm);
        }
        action
    }
}

pub fn logo_menu(
    ui: &mut Ui,
    texture: egui::TextureId,
    state: &mut AttachState,
) -> (LogoAction, egui::Rect) {
    let image = egui::Image::new((texture, egui::vec2(24.0, 24.0)));
    let response = ui
        .add(egui::Button::image(image).frame(false))
        .on_hover_text("Euphoria menu");
    let rect = response.rect;
    let mut action = LogoAction::None;

    egui::Popup::menu(&response).show(|ui| {
        ui.set_min_width(250.0);
        if let Some(label) = state.label() {
            ui.label(RichText::new(format!("Attached to {label}")).color(theme::ACCENT));
            if ui.button("Make patch file").clicked() {
                state.patch_requested = true;
                ui.close();
            }
            if ui.button("Detach").clicked() {
                if let Some(message) = state.detach() {
                    state.notice = Some(message);
                }
                ui.close();
            }
            ui.separator();
        }
        if ui.button("Attach to process...").clicked() {
            state.open_picker(ui.ctx());
            ui.close();
        }
        if ui.button("Open binary...").clicked() {
            action = LogoAction::Browse;
            ui.close();
        }
        if ui.button("Quick tour").clicked() {
            action = LogoAction::Tour;
            ui.close();
        }
    });

    (action, rect)
}

fn plan_entry(
    modules: &[LiveModule],
    address: &str,
    replacement: &str,
    note: &str,
    existing: &[Staged],
    read: impl FnOnce(u64, usize) -> Vec<u8>,
) -> Result<Staged, String> {
    let target = live::resolve_target(modules, address)?;
    let index = target
        .module
        .ok_or("That address is not inside a loaded module")?;
    let module = &modules[index];
    let patched = parse_bytes(replacement)?;
    if patched.len() > MAX_PATCH_BYTES {
        return Err(format!("Edits are limited to {MAX_PATCH_BYTES} bytes"));
    }
    if patched.is_empty() {
        return Err("Enter the bytes to write".to_owned());
    }
    let original = read(target.address, patched.len());
    if original.len() != patched.len() {
        return Err(format!(
            "Only {} of {} bytes are readable at {:#x}",
            original.len(),
            patched.len(),
            target.address
        ));
    }
    if original == patched {
        return Err("Those bytes already match, so there is nothing to change".to_owned());
    }
    if let Some(other) = existing.iter().find(|entry| {
        overlaps(
            entry.address,
            entry.original.len(),
            target.address,
            patched.len(),
        )
    }) {
        return Err(format!(
            "That overlaps the edit already staged at {}+{:#x}",
            other.module, other.offset
        ));
    }

    Ok(Staged {
        address: target.address,
        module: module.name.clone(),
        offset: target.address - module.base,
        original,
        patched,
        note: note.trim().to_owned(),
        applied: false,
    })
}

fn apply_edits(session: &mut LiveSession, restore: bool) -> String {
    let name = session.process.name().to_owned();
    let mut done = 0;
    let mut failure = None;
    for entry in &mut session.patch.entries {
        if entry.applied != restore {
            continue;
        }
        let bytes = if restore {
            &entry.original
        } else {
            &entry.patched
        };
        match session.process.write(entry.address, bytes) {
            Ok(()) => {
                entry.applied = !restore;
                done += 1;
            }
            Err(error) => {
                failure = Some(format!(
                    "{error}. {done} edit(s) were written before this one."
                ));
                break;
            }
        }
    }

    match failure {
        Some(error) => error,
        None if done == 0 => "Nothing to write".to_owned(),
        None if restore => format!("Restored {done} edit(s) in {name}"),
        None => format!("Applied {done} edit(s) to {name}"),
    }
}

fn save_patch(session: &LiveSession) -> Option<Action> {
    if session.patch.entries.is_empty() {
        return None;
    }
    let path = rfd::FileDialog::new()
        .set_title("Save Euphoria patch")
        .set_file_name(suggested_name(session.process.name()))
        .add_filter("Euphoria patch", &[euphp::EXTENSION])
        .save_file()?;

    let mut file = euphp::PatchFile::new(euphp::PatchTarget {
        name: session.process.name().to_owned(),
        path: session.process.path().to_owned(),
        pid: session.process.pid(),
    });
    file.created_at = unix_time();
    file.patches = session
        .patch
        .entries
        .iter()
        .map(|entry| euphp::PatchEntry {
            module: entry.module.clone(),
            offset: entry.offset,
            original: entry.original.clone(),
            patched: entry.patched.clone(),
            note: entry.note.clone(),
        })
        .collect();

    let outcome = file
        .encode()
        .map_err(|error| format!("{error:#}"))
        .and_then(|bytes| std::fs::write(&path, bytes).map_err(|error| error.to_string()));
    match outcome {
        Ok(()) => Some(Action::Status(format!(
            "Saved patch file to {}",
            path.display()
        ))),
        Err(error) => Some(Action::Status(format!(
            "Could not save the patch file: {error}"
        ))),
    }
}

fn unix_time() -> String {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs().to_string())
        .unwrap_or_default()
}

fn overlaps(left: u64, left_len: usize, right: u64, right_len: usize) -> bool {
    left < right.saturating_add(right_len as u64) && right < left.saturating_add(left_len as u64)
}

fn live_hex(ui: &mut Ui, base: u64, bytes: &[u8], mut on_click: impl FnMut(u64)) {
    ui.spacing_mut().item_spacing.y = 0.0;
    for (line, chunk) in bytes.chunks(16).enumerate() {
        let address = base.wrapping_add((line * 16) as u64);
        let hex = chunk
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<Vec<_>>()
            .join(" ");
        let ascii: String = chunk
            .iter()
            .map(|&byte| {
                if (0x20..0x7f).contains(&byte) {
                    byte as char
                } else {
                    '.'
                }
            })
            .collect();
        let text = format!("{address:012x}  {hex:<47}  {ascii}");
        let response = ui
            .selectable_label(false, RichText::new(text).font(theme::mono()).size(11.5))
            .on_hover_text("Read memory at this line");
        if response.clicked() {
            on_click(address);
        }
        response.context_menu(|ui| {
            if ui.button("Copy address").clicked() {
                ui.ctx().copy_text(format!("{address:012x}"));
                ui.close();
            }
        });
    }
}

fn hex_preview(bytes: &[u8]) -> String {
    let shown: Vec<String> = bytes
        .iter()
        .take(PREVIEW_BYTES)
        .map(|byte| format!("{byte:02x}"))
        .collect();
    let mut text = shown.join(" ");
    if bytes.len() > PREVIEW_BYTES {
        text.push_str(" …");
    }
    text
}

fn size_label(size: u64) -> String {
    if size >= 1 << 30 {
        format!("{:.2} GB", size as f64 / (1u64 << 30) as f64)
    } else if size >= 1 << 20 {
        format!("{:.1} MB", size as f64 / (1u64 << 20) as f64)
    } else if size >= 1024 {
        format!("{:.1} KB", size as f64 / 1024.0)
    } else {
        format!("{size} B")
    }
}

fn region_kind(region: &Region) -> &'static str {
    if region.image() {
        "image"
    } else if region.mapped() {
        "mapped"
    } else if region.private() {
        "private"
    } else {
        "other"
    }
}

fn suggested_name(file_name: &str) -> String {
    let stem = file_name
        .rsplit_once('.')
        .map_or(file_name, |(stem, _)| stem);
    format!("{stem}.{}", euphp::EXTENSION)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn modules() -> Vec<LiveModule> {
        vec![LiveModule {
            base: 0x1400_0000,
            size: 0x4000,
            name: "game.exe".into(),
            path: r"C:\Games\game.exe".into(),
        }]
    }

    fn staged(address: u64, length: usize) -> Staged {
        Staged {
            address,
            module: "game.exe".into(),
            offset: address - 0x1400_0000,
            original: vec![0x90; length],
            patched: vec![0xCC; length],
            note: String::new(),
            applied: false,
        }
    }

    #[test]
    fn picks_the_process_module_by_path_then_name() {
        let modules = vec![
            LiveModule {
                base: 0x1000_0000,
                size: 0x2000,
                name: "launcher.exe".into(),
                path: r"C:\Games\launcher.exe".into(),
            },
            LiveModule {
                base: 0x1400_0000,
                size: 0x4000,
                name: "game.exe".into(),
                path: r"C:\Games\game.exe".into(),
            },
        ];
        assert_eq!(
            select_primary(&modules, r"C:\Games\game.exe", "launcher.exe"),
            Some(1)
        );
        assert_eq!(select_primary(&modules, "", "launcher.exe"), Some(0));
        assert_eq!(select_primary(&modules, "", "missing.exe"), Some(0));
        assert_eq!(select_primary(&[], "", "game.exe"), None);
    }

    #[test]
    fn stages_an_edit_against_the_bytes_it_reads() {
        let entry = plan_entry(
            &modules(),
            "game.exe+0x120",
            "eb 10",
            "local branch",
            &[],
            |address, length| {
                assert_eq!(address, 0x1400_0120);
                assert_eq!(length, 2);
                vec![0x75, 0x10]
            },
        )
        .unwrap();
        assert_eq!(entry.address, 0x1400_0120);
        assert_eq!(entry.offset, 0x120);
        assert_eq!(entry.original, vec![0x75, 0x10]);
        assert_eq!(entry.patched, vec![0xEB, 0x10]);
        assert_eq!(entry.note, "local branch");
        assert!(!entry.applied);
    }

    #[test]
    fn rejects_overlapping_or_unreadable_edits() {
        let existing = [staged(0x1400_0100, 4)];
        let overlap = plan_entry(
            &modules(),
            "game.exe+0x102",
            "90 90",
            "",
            &existing,
            |_, length| vec![0; length],
        );
        assert!(overlap.unwrap_err().contains("overlaps"));

        let short = plan_entry(
            &modules(),
            "game.exe+0x200",
            "90 90 90 90",
            "",
            &[],
            |_, _| vec![0x90, 0x90],
        );
        assert!(short.unwrap_err().contains("Only 2 of 4 bytes"));

        let alike = plan_entry(&modules(), "game.exe+0x200", "90 90", "", &[], |_, _| {
            vec![0x90, 0x90]
        });
        assert!(alike.unwrap_err().contains("already match"));
    }

    #[test]
    fn refuses_addresses_outside_a_module() {
        let error = plan_entry(&modules(), "0x1000", "90", "", &[], |_, length| {
            vec![0; length]
        });
        assert!(error.unwrap_err().contains("not inside a loaded module"));
    }

    #[test]
    fn detects_overlapping_edits() {
        assert!(overlaps(0x1000, 4, 0x1002, 4));
        assert!(!overlaps(0x1000, 4, 0x1004, 4));
        assert!(!overlaps(0x1004, 4, 0x1000, 4));
    }

    #[test]
    fn previews_bytes_and_marks_the_rest() {
        assert_eq!(hex_preview(&[0x75, 0x10]), "75 10");
        assert!(hex_preview(&[0x90; 20]).ends_with('…'));
    }

    #[test]
    fn names_the_patch_file_after_the_program() {
        assert_eq!(suggested_name("game.exe"), "game.euphp");
        assert_eq!(suggested_name("sample"), "sample.euphp");
    }
}
