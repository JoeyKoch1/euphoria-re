use eframe::egui::{self, Color32, Rect, RichText, Sense, Ui};
use euphoria_debugger::{Command, Event, Launch, Session, Snapshot, StopReason, exception_name};
use euphoria_engine::{Analysis, Arch, dataset};

use crate::tabs::Action;
use crate::{Project, table, theme};

const MEMORY_BYTES: usize = 512;
const HEX_PER_LINE: usize = 16;
const LOG_LIMIT: usize = 2000;
const ROW: f32 = 22.0;
const REGISTER_WIDTH: f32 = 270.0;
const STACK_WIDTH: f32 = 470.0;
const BOTTOM_HEIGHT: f32 = 250.0;

#[derive(Clone, Copy, PartialEq)]
pub enum Intent {
    Run,
    Step,
}

#[derive(Clone, Copy, Default, PartialEq)]
enum Pane {
    #[default]
    Log,
    Breakpoints,
    Bookmarks,
    Memory,
    Modules,
    Threads,
}

pub enum Notice {
    Stopped { image_ip: u64, message: String },
    Message(String),
}

#[derive(Default)]
pub struct DebugState {
    session: Option<Session>,
    running: bool,
    snapshot: Option<Box<Snapshot>>,
    previous: Vec<(&'static str, u64)>,
    log: Vec<String>,
    asking: Option<Intent>,
    agreed_for: Option<String>,
    args: String,
    run_past_entry: bool,
    pane: Pane,
    memory_address: String,
    memory: Option<(u64, Vec<u8>)>,
    editor: Option<Editor>,
    jump: Option<JumpEdit>,
    // Byte ranges Euphoria wrote into the running process, merged and sorted.
    patched: Vec<(u64, u64)>,
}

#[derive(Clone)]
struct JumpEdit {
    address: u64,
    length: usize,
    target: String,
    error: Option<String>,
}

#[derive(Clone, Copy, PartialEq)]
enum EditMode {
    Register,
    Value,
    Bytes,
}

#[derive(Clone)]
struct Editor {
    title: String,
    mode: EditMode,
    register: Option<&'static str>,
    address: u64,
    width: usize,
    text: String,
    error: Option<String>,
    focus: bool,
}

impl Editor {
    fn register(name: &'static str, value: u64) -> Self {
        let width = register_width(name);
        Self {
            title: format!("Edit {name}"),
            mode: EditMode::Register,
            register: Some(name),
            address: 0,
            width,
            text: format!("{value:0width$x}", width = width * 2),
            error: None,
            focus: true,
        }
    }

    fn value(address: u64, value: u64, width: usize) -> Self {
        Self {
            title: format!("Edit {width}-byte value at {address:#x}"),
            mode: EditMode::Value,
            register: None,
            address,
            width,
            text: format!("{value:0width$x}", width = width * 2),
            error: None,
            focus: true,
        }
    }

    fn bytes(address: u64, bytes: &[u8]) -> Self {
        Self {
            title: format!("Edit memory at {address:#x}"),
            mode: EditMode::Bytes,
            register: None,
            address,
            width: bytes.len(),
            text: bytes
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<Vec<_>>()
                .join(" "),
            error: None,
            focus: true,
        }
    }

    fn command(&self) -> Result<Command, String> {
        match self.mode {
            EditMode::Register => {
                let name = self.register.ok_or("No register selected.")?;
                let value = parse_hex(&self.text)?;
                Ok(Command::WriteRegister {
                    name,
                    value: truncate(value, self.width),
                })
            }
            EditMode::Value => {
                let value = parse_hex(&self.text)?;
                Ok(Command::WriteMemory {
                    address: self.address,
                    bytes: value.to_le_bytes()[..self.width].to_vec(),
                })
            }
            EditMode::Bytes => Ok(Command::WriteMemory {
                address: self.address,
                bytes: parse_bytes(&self.text)?,
            }),
        }
    }
}

fn parse_hex(text: &str) -> Result<u64, String> {
    let digits: String = text
        .trim()
        .trim_start_matches("0x")
        .trim_start_matches("0X")
        .chars()
        .filter(|&c| c != '_')
        .collect();
    if digits.is_empty() {
        return Err("Enter a hexadecimal number.".to_owned());
    }
    u64::from_str_radix(&digits, 16).map_err(|_| format!("'{digits}' is not a hexadecimal number."))
}

fn jump_bytes(address: u64, length: usize, target: u64) -> Result<Vec<u8>, String> {
    if length < 5 {
        return Err("This line is shorter than a 5-byte jump.".to_owned());
    }
    let next = address.wrapping_add(5);
    let delta = i128::from(target) - i128::from(next);
    let delta =
        i32::try_from(delta).map_err(|_| "The target is farther than 2 GB away.".to_owned())?;
    let mut bytes = vec![0xE9];
    bytes.extend_from_slice(&delta.to_le_bytes());
    bytes.resize(length, 0x90);
    Ok(bytes)
}

pub(crate) fn parse_bytes(text: &str) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    for token in text.split_whitespace() {
        let digits = token.trim_start_matches("0x").trim_start_matches("0X");
        if digits.is_empty() || !digits.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(format!("'{token}' is not a hexadecimal byte."));
        }
        if digits.len() <= 2 {
            let byte = u8::from_str_radix(digits, 16)
                .map_err(|_| format!("'{token}' is not a hexadecimal byte."))?;
            bytes.push(byte);
            continue;
        }
        if digits.len() % 2 != 0 {
            return Err(format!("'{token}' has an odd number of digits."));
        }
        for pair in digits.as_bytes().as_chunks::<2>().0 {
            let pair = std::str::from_utf8(pair).unwrap_or("");
            let byte = u8::from_str_radix(pair, 16)
                .map_err(|_| format!("'{token}' is not a hexadecimal byte."))?;
            bytes.push(byte);
        }
    }
    if bytes.is_empty() {
        return Err("Enter at least one byte.".to_owned());
    }
    if bytes.len() > 1 << 16 {
        return Err("That is too many bytes to write at once.".to_owned());
    }
    Ok(bytes)
}

fn truncate(value: u64, width: usize) -> u64 {
    if width >= 8 {
        value
    } else {
        value & ((1u64 << (width * 8)) - 1)
    }
}

fn register_width(name: &str) -> usize {
    match name {
        "eflags" => 4,
        "rax" | "rbx" | "rcx" | "rdx" | "rsi" | "rdi" | "rbp" | "rsp" | "rip" | "r8" | "r9"
        | "r10" | "r11" | "r12" | "r13" | "r14" | "r15" => 8,
        _ => 4,
    }
}

fn pointer_width(snapshot: &Snapshot) -> usize {
    if snapshot.registers.iter().any(|(name, _)| *name == "rsp") {
        8
    } else {
        4
    }
}

fn launch_problem(analysis: &Analysis) -> Option<String> {
    if !cfg!(all(windows, target_arch = "x86_64")) {
        return Some("The debugger runs on 64-bit Windows for now.".to_owned());
    }
    if !analysis.is_pe || analysis.arch == Arch::Aarch64 {
        return Some("The debugger can only run x86 and x64 Windows programs.".to_owned());
    }
    let is_dataset = std::fs::read(&analysis.path)
        .ok()
        .is_none_or(|bytes| dataset::is_dataset(&bytes));
    if is_dataset {
        return Some("This is a saved dataset. Open the original .exe to debug it.".to_owned());
    }
    None
}

impl DebugState {
    pub fn is_active(&self) -> bool {
        self.session.is_some()
    }

    pub fn is_stopped(&self) -> bool {
        self.session.is_some() && !self.running && self.snapshot.is_some()
    }

    pub fn current_image_ip(&self) -> Option<u64> {
        let snapshot = self.snapshot.as_ref()?;
        self.is_stopped().then(|| snapshot.to_image(snapshot.ip))
    }

    fn write_log(&mut self, line: String) {
        if self.log.len() >= LOG_LIMIT {
            self.log.drain(..LOG_LIMIT / 4);
        }
        self.log.push(line);
    }

    pub fn toggle_breakpoint(&mut self, project: &mut Project, va: u64) {
        let adding = project.breakpoints.insert(va);
        if !adding {
            project.breakpoints.remove(&va);
        }
        if let Some(session) = &self.session {
            session.send(if adding {
                Command::AddBreakpoint(va)
            } else {
                Command::RemoveBreakpoint(va)
            });
        }
    }

    fn edit_register(&mut self, name: &'static str, value: u64) {
        self.editor = Some(Editor::register(name, value));
    }

    fn edit_value(&mut self, address: u64, value: u64, width: usize) {
        self.editor = Some(Editor::value(address, value, width));
    }

    pub fn edit_bytes(&mut self, address: u64, bytes: &[u8]) {
        self.editor = Some(Editor::bytes(address, bytes));
    }

    fn editor_dialog(&mut self, ctx: &egui::Context) {
        let mut command = None;
        let mut close = false;
        if let Some(editor) = &mut self.editor {
            egui::Modal::new(egui::Id::unique("debug_edit")).show(ctx, |ui| {
                ui.set_max_width(460.0);
                ui.label(RichText::new(&editor.title).size(16.0));
                ui.add_space(6.0);
                let hint = if editor.mode == EditMode::Bytes {
                    "Hex bytes"
                } else {
                    "Hexadecimal value"
                };
                ui.label(RichText::new(hint).color(theme::MUTED));
                let field = ui.add(
                    egui::TextEdit::singleline(&mut editor.text)
                        .font(theme::mono())
                        .desired_width(f32::INFINITY),
                );
                if editor.focus {
                    field.request_focus();
                    editor.focus = false;
                }
                if let Some(error) = &editor.error {
                    ui.label(RichText::new(error).color(theme::BREAKPOINT));
                }
                ui.add_space(10.0);
                let submitted = field.has_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
                ui.horizontal(|ui| {
                    if ui.button("Write").clicked() || submitted {
                        match editor.command() {
                            Ok(next) => {
                                command = Some(next);
                                close = true;
                            }
                            Err(error) => editor.error = Some(error),
                        }
                    }
                    if ui.button("Cancel").clicked() {
                        close = true;
                    }
                });
            });
        }
        if close {
            self.editor = None;
        }
        if let Some(command) = command {
            if let Command::WriteMemory { address, bytes } = &command {
                self.note_patch(*address, bytes.len());
            }
            self.send(command);
        }
    }

    fn launch(&mut self, project: &Project, intent: Intent) {
        let analysis = &project.analysis;
        self.log.clear();
        self.snapshot = None;
        self.previous.clear();
        self.memory = None;
        self.patched.clear();
        self.run_past_entry = intent == Intent::Run && !project.breakpoints.is_empty();
        self.running = true;
        self.write_log(format!("Starting {}", analysis.file_name));
        self.session = Some(Session::start(Launch {
            path: analysis.path.clone(),
            args: self.args.clone(),
            bits: if analysis.arch == Arch::X86 { 32 } else { 64 },
            image_base: analysis.image_base,
            entry: analysis.entry,
            breakpoints: project.breakpoints.iter().copied().collect(),
            hide_console: false,
        }));
    }

    // Asks for consent the first time a given file would run, then starts it.
    fn start(&mut self, project: &Project, intent: Intent) -> Option<String> {
        if let Some(problem) = launch_problem(&project.analysis) {
            return Some(problem);
        }
        if self.agreed_for.as_deref() == Some(project.analysis.sha256.as_str()) {
            self.launch(project, intent);
        } else {
            self.asking = Some(intent);
        }
        None
    }

    pub fn run(&mut self, project: &Project) -> Option<String> {
        if self.session.is_none() {
            return self.start(project, Intent::Run);
        }
        if self.is_stopped() {
            self.send(Command::Continue);
        }
        None
    }

    fn step(&mut self, project: &Project, command: Command) -> Option<String> {
        if self.session.is_none() {
            return self.start(project, Intent::Step);
        }
        if self.is_stopped() {
            self.send(command);
        }
        None
    }

    pub fn step_into(&mut self, project: &Project) -> Option<String> {
        self.step(project, Command::StepInto)
    }

    pub fn step_over(&mut self, project: &Project) -> Option<String> {
        self.step(project, Command::StepOver)
    }

    pub fn step_out(&mut self, project: &Project) -> Option<String> {
        self.step(project, Command::StepOut)
    }

    pub fn run_to(&mut self, project: &Project, va: u64) -> Option<String> {
        self.step(project, Command::RunTo(va))
    }

    pub fn pause(&mut self) {
        if self.running {
            self.send(Command::Pause);
        }
    }

    pub fn stop(&mut self) {
        self.send(Command::Stop);
    }

    // Quick patches come from the listing's right-click menu.
    pub fn write_bytes(&mut self, address: u64, bytes: &[u8]) -> Option<String> {
        if !self.is_stopped() {
            return Some("Pause the program before patching its memory.".to_owned());
        }
        if bytes.is_empty() {
            return Some("There are no bytes to write.".to_owned());
        }
        self.send(Command::WriteMemory {
            address,
            bytes: bytes.to_vec(),
        });
        self.note_patch(address, bytes.len());
        self.write_log(format!("Wrote {} byte(s) at {address:#x}", bytes.len()));
        None
    }

    fn note_patch(&mut self, address: u64, len: usize) {
        if len == 0 {
            return;
        }
        self.patched
            .push((address, address.saturating_add(len as u64)));
        self.patched.sort_unstable();
        let mut merged: Vec<(u64, u64)> = Vec::with_capacity(self.patched.len());
        for &(start, end) in &self.patched {
            match merged.last_mut() {
                Some(last) if start <= last.1 => last.1 = last.1.max(end),
                _ => merged.push((start, end)),
            }
        }
        self.patched = merged;
    }

    // True when any of the instruction's bytes were written by Euphoria.
    pub fn is_patched(&self, address: u64, len: usize) -> bool {
        let end = address.saturating_add(len as u64);
        self.patched
            .iter()
            .any(|&(start, stop)| start < end && address < stop)
    }

    pub fn open_jump(&mut self, address: u64, length: usize) {
        if !self.is_stopped() {
            return;
        }
        let target = self
            .snapshot
            .as_ref()
            .map_or(address, |snapshot| snapshot.ip);
        self.jump = Some(JumpEdit {
            address,
            length,
            target: format!("{target:#x}"),
            error: None,
        });
    }

    fn send(&self, command: Command) {
        if let Some(session) = &self.session {
            session.send(command);
        }
    }

    // Drops the session when a different file gets opened. Dropping it ends the program.
    pub fn close(&mut self) {
        self.session = None;
        self.running = false;
        self.snapshot = None;
        self.previous.clear();
        self.asking = None;
        self.patched.clear();
    }

    pub fn poll(&mut self, ctx: &egui::Context) -> Vec<Notice> {
        let mut notices = Vec::new();
        let Some(session) = &self.session else {
            return notices;
        };
        ctx.request_repaint_after(std::time::Duration::from_millis(60));

        let mut events = Vec::new();
        while let Some(event) = session.poll() {
            events.push(event);
        }
        for event in events {
            match event {
                Event::Started { pid, base } => {
                    self.write_log(format!("Running as process {pid}, loaded at {base:#x}"));
                }
                Event::Running => self.running = true,
                Event::Stopped(snapshot) => {
                    if snapshot.reason == StopReason::Entry && self.run_past_entry {
                        self.run_past_entry = false;
                        self.send(Command::Continue);
                        continue;
                    }
                    self.running = false;
                    if let Some(old) = self.snapshot.take() {
                        self.previous = old.registers;
                    }
                    let message = stop_message(&snapshot);
                    self.write_log(message.clone());
                    notices.push(Notice::Stopped {
                        image_ip: snapshot.to_image(snapshot.ip),
                        message,
                    });
                    self.snapshot = Some(snapshot);
                    if let Some((address, _)) = self.memory {
                        self.send(Command::ReadMemory {
                            address,
                            len: MEMORY_BYTES,
                        });
                    }
                }
                Event::Memory { address, bytes } => self.memory = Some((address, bytes)),
                Event::Refreshed(snapshot) => {
                    self.snapshot = Some(snapshot);
                    if let Some((address, _)) = self.memory {
                        self.send(Command::ReadMemory {
                            address,
                            len: MEMORY_BYTES,
                        });
                    }
                }
                Event::Log(line) => self.write_log(line),
                Event::Exited(code) => {
                    let message = format!("The program exited with code {code:#x}");
                    self.write_log(message.clone());
                    notices.push(Notice::Message(message));
                    self.session = None;
                    self.running = false;
                    self.snapshot = None;
                    self.previous.clear();
                    self.patched.clear();
                    return notices;
                }
                Event::Failed(message) => {
                    self.write_log(message.clone());
                    notices.push(Notice::Message(message));
                    self.session = None;
                    self.running = false;
                    self.patched.clear();
                    return notices;
                }
            }
        }
        notices
    }

    fn jump_dialog(&mut self, ctx: &egui::Context) {
        let stopped = self.is_stopped();
        let Some(jump) = &mut self.jump else {
            return;
        };
        let mut decision = None;
        egui::Modal::new(egui::Id::unique("debug_jump")).show(ctx, |ui| {
            ui.set_max_width(460.0);
            ui.label(RichText::new(format!("Jump from {:#x}", jump.address)).size(16.0));
            ui.add_space(6.0);
            ui.label(format!(
                "Euphoria writes a 5-byte relative jump over the first 5 of {} byte(s) and fills \
                 the rest with NOPs. The target must be within 2 GB of the instruction.",
                jump.length
            ));
            ui.add_space(8.0);
            ui.label(RichText::new("Target address").color(theme::MUTED));
            ui.add(
                egui::TextEdit::singleline(&mut jump.target)
                    .font(theme::mono())
                    .desired_width(f32::INFINITY),
            );
            if let Some(error) = &jump.error {
                ui.label(RichText::new(error).color(theme::ERROR));
            }
            ui.add_space(10.0);
            ui.horizontal(|ui| {
                if ui
                    .add_enabled(stopped, egui::Button::new("Write jump"))
                    .clicked()
                {
                    decision = Some(true);
                }
                if ui.button("Cancel").clicked() {
                    decision = Some(false);
                }
            });
        });

        match decision {
            Some(true) => {
                let Some(jump) = self.jump.take() else {
                    return;
                };
                let bytes = parse_hex(&jump.target)
                    .and_then(|target| jump_bytes(jump.address, jump.length, target));
                match bytes {
                    Ok(bytes) => {
                        self.note_patch(jump.address, bytes.len());
                        self.send(Command::WriteMemory {
                            address: jump.address,
                            bytes,
                        });
                        self.write_log(format!("Wrote a jump at {:#x}", jump.address));
                    }
                    Err(message) => {
                        self.jump = Some(JumpEdit {
                            error: Some(message),
                            ..jump
                        });
                    }
                }
            }
            Some(false) => self.jump = None,
            None => {}
        }
    }

    pub fn dialog(&mut self, ctx: &egui::Context, project: Option<&Project>) {
        self.jump_dialog(ctx);
        let Some(intent) = self.asking else {
            return;
        };
        let Some(project) = project else {
            self.asking = None;
            return;
        };

        let mut choice = None;
        egui::Modal::new(egui::Id::unique("debug_consent")).show(ctx, |ui| {
            ui.set_max_width(520.0);
            ui.label(RichText::new(format!("Run {}?", project.analysis.file_name)).size(16.0));
            ui.add_space(8.0);
            ui.label(
                "Debugging starts this program on your computer with your permissions, so \
                 anything it does, it really does. Only run programs you own or are allowed to \
                 inspect, and use a virtual machine for anything you don't trust.",
            );
            ui.add_space(10.0);
            ui.label(RichText::new("Command line arguments").color(theme::MUTED));
            ui.add(
                egui::TextEdit::singleline(&mut self.args)
                    .font(theme::mono())
                    .desired_width(f32::INFINITY),
            );
            ui.add_space(14.0);
            ui.horizontal(|ui| {
                if ui.button("Run it").clicked() {
                    choice = Some(true);
                }
                if ui.button("Cancel").clicked() {
                    choice = Some(false);
                }
            });
        });

        match choice {
            Some(true) => {
                self.asking = None;
                self.agreed_for = Some(project.analysis.sha256.clone());
                self.launch(project, intent);
            }
            Some(false) => self.asking = None,
            None => {}
        }
    }

    fn state_text(&self) -> (String, Color32) {
        if self.session.is_none() {
            ("Not running".to_owned(), theme::MUTED)
        } else if self.running {
            ("Running".to_owned(), theme::ACCENT)
        } else {
            match &self.snapshot {
                Some(snapshot) => (format!("Paused at {:#x}", snapshot.ip), theme::CURRENT_MARK),
                None => ("Starting".to_owned(), theme::MUTED),
            }
        }
    }
}

fn stop_message(snapshot: &Snapshot) -> String {
    let at = snapshot.ip;
    match snapshot.reason {
        StopReason::Entry => format!("Paused at the entry point, {at:#x}"),
        StopReason::Breakpoint => format!("Hit a breakpoint at {at:#x}"),
        StopReason::Step => format!("Stepped to {at:#x}"),
        StopReason::Paused => format!("Paused at {at:#x}"),
        StopReason::Exception { code, first_chance } => format!(
            "{} ({code:#x}) at {at:#x}{}",
            exception_name(code),
            if first_chance { "" } else { ", not handled" }
        ),
    }
}

// The row of buttons under the Listing header, also used on the other code views.
pub fn controls(ui: &mut Ui, project: &mut Project, debug: &mut DebugState) -> Option<Action> {
    // Live modules have no launchable process of their own; running, stepping, and breakpoints
    // belong to the live Debugger view and are read-only there.
    if project.live_base.is_some() {
        let mut action = None;
        egui::Frame::new()
            .fill(theme::SURFACE)
            .inner_margin(egui::Margin::symmetric(10, 6))
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.label(RichText::new("Live module").color(theme::ACCENT).strong())
                        .on_hover_text(
                            "These addresses and bytes come from the attached process. Use the \
                         Debugger tab to capture registers, read memory, or decompile at the \
                         instruction pointer.",
                        );
                    ui.separator();
                    if ui.button("Decompile").on_hover_text("F5").clicked() {
                        action = Some(Action::ShowDecompiler);
                    }
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        ui.label(RichText::new("read-only").color(theme::MUTED))
                            .on_hover_text(
                                "Launch, step, and breakpoint controls start a program from \
                                 disk, so they are off while a live module is loaded.",
                            );
                    });
                });
            });
        return action;
    }

    let mut action = None;
    let mut problem = None;
    let cursor_va = project.listing.rows.get(project.cursor).map(|row| row.va);
    let has_mark = cursor_va.is_some_and(|va| project.breakpoints.contains(&va));

    egui::Frame::new()
        .fill(theme::SURFACE)
        .inner_margin(egui::Margin::symmetric(10, 6))
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                let label = if has_mark {
                    "Remove breakpoint"
                } else {
                    "Breakpoint"
                };
                if ui
                    .button(RichText::new(label).color(theme::BREAKPOINT))
                    .on_hover_text("F2")
                    .clicked()
                    && let Some(va) = cursor_va
                {
                    debug.toggle_breakpoint(project, va);
                }
                ui.separator();

                let stopped = debug.is_stopped();
                let idle = !debug.is_active();
                let run_label = if debug.is_active() { "Continue" } else { "Run" };
                if ui
                    .add_enabled(stopped || idle, egui::Button::new(run_label))
                    .on_hover_text("F9, or Shift+F3 to resume")
                    .clicked()
                {
                    problem = debug.run(project);
                }
                if ui
                    .add_enabled(debug.running, egui::Button::new("Pause"))
                    .on_hover_text("F3 - suspend the program")
                    .clicked()
                {
                    debug.pause();
                }
                if ui
                    .add_enabled(stopped || idle, egui::Button::new("Step into"))
                    .on_hover_text("F7")
                    .clicked()
                {
                    problem = debug.step_into(project);
                }
                if ui
                    .add_enabled(stopped || idle, egui::Button::new("Step over"))
                    .on_hover_text("F8")
                    .clicked()
                {
                    problem = debug.step_over(project);
                }
                if ui
                    .add_enabled(stopped, egui::Button::new("Step out"))
                    .on_hover_text("Shift+F8")
                    .clicked()
                {
                    problem = debug.step_out(project);
                }
                if ui
                    .add_enabled(stopped, egui::Button::new("Run to cursor"))
                    .on_hover_text("F4")
                    .clicked()
                    && let Some(va) = cursor_va
                {
                    problem = debug.run_to(project, va);
                }
                if ui
                    .add_enabled(debug.is_active(), egui::Button::new("Stop"))
                    .on_hover_text("Ctrl+F9 - terminate the program")
                    .clicked()
                {
                    debug.stop();
                }
                ui.separator();
                if ui.button("Decompile").on_hover_text("F5").clicked() {
                    action = Some(Action::ShowDecompiler);
                }

                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    let (text, color) = debug.state_text();
                    ui.label(RichText::new(text).color(color));
                });
            });
        });

    problem.map(Action::Status).or(action)
}

fn mono_text(ui: &Ui, rect: Rect, x: f32, text: &str, color: Color32) -> Rect {
    ui.painter_at(rect).text(
        egui::pos2(rect.left() + x, rect.center().y),
        egui::Align2::LEFT_CENTER,
        text,
        theme::mono(),
        color,
    )
}

fn title(ui: &mut Ui, text: &str) {
    ui.add_space(6.0);
    ui.label(RichText::new(text).color(theme::MUTED));
    ui.add_space(2.0);
}

pub fn show(ui: &mut Ui, project: &mut Project, debug: &mut DebugState) -> Option<Action> {
    debug.editor_dialog(ui.ctx());
    let mut action = controls(ui, project, debug);

    egui::Panel::bottom("debug_bottom")
        .exact_size(BOTTOM_HEIGHT)
        .frame(egui::Frame::new().fill(theme::SURFACE).inner_margin(8))
        .show(ui, |ui| {
            if let Some(next) = bottom(ui, project, debug) {
                action = Some(next);
            }
        });

    let Some(snapshot) = debug.snapshot.clone().filter(|_| debug.is_stopped()) else {
        let message = if debug.is_active() {
            "The program is running. Pause it or wait for a breakpoint."
        } else {
            "Press Run to start the program, or Step into to pause on its first instruction."
        };
        ui.centered_and_justified(|ui| {
            ui.label(RichText::new(message).color(theme::MUTED).size(18.0));
        });
        return action;
    };

    egui::Panel::left("debug_registers")
        .exact_size(REGISTER_WIDTH)
        .frame(egui::Frame::new().fill(theme::SURFACE).inner_margin(8))
        .show(ui, |ui| registers(ui, &snapshot, debug));
    egui::Panel::right("debug_stack")
        .exact_size(STACK_WIDTH)
        .frame(egui::Frame::new().fill(theme::SURFACE).inner_margin(8))
        .show(ui, |ui| stack(ui, &snapshot, debug));

    if let Some(next) = code(ui, &snapshot, project, debug) {
        action = Some(next);
    }
    action
}

fn registers(ui: &mut Ui, snapshot: &Snapshot, debug: &mut DebugState) {
    title(ui, "Registers");
    egui::ScrollArea::vertical()
        .id_salt("registers")
        .auto_shrink(false)
        .show(ui, |ui| {
            ui.spacing_mut().item_spacing.y = 0.0;
            for &(name, value) in &snapshot.registers {
                let changed = debug
                    .previous
                    .iter()
                    .any(|&(old, old_value)| old == name && old_value != value);
                let size = egui::vec2(ui.available_width(), ROW);
                let (rect, response) = ui.allocate_exact_size(size, Sense::click());
                if response.hovered() {
                    ui.painter().rect_filled(rect, 0.0, theme::HOVER);
                }
                mono_text(ui, rect, 0.0, name, theme::REGISTER);
                let color = if changed { theme::NUMBER } else { theme::TEXT };
                mono_text(ui, rect, 56.0, &format!("{value:016x}"), color);
                if response.double_clicked() {
                    debug.edit_register(name, value);
                }
                let mut response = response;
                if let Some(place) = snapshot.describe(value) {
                    response = response.on_hover_text(place);
                }
                response.context_menu(|ui| {
                    if ui.button("Edit value").clicked() {
                        debug.edit_register(name, value);
                        ui.close();
                    }
                    if ui.button("Copy value").clicked() {
                        ui.ctx().copy_text(format!("{value:016x}"));
                        ui.close();
                    }
                });
            }
        });
}

fn stack(ui: &mut Ui, snapshot: &Snapshot, debug: &mut DebugState) {
    title(ui, "Stack");
    let width = pointer_width(snapshot);
    egui::ScrollArea::vertical()
        .id_salt("stack")
        .auto_shrink(false)
        .show(ui, |ui| {
            ui.spacing_mut().item_spacing.y = 0.0;
            for &(address, value) in &snapshot.stack {
                let size = egui::vec2(ui.available_width(), ROW);
                let (rect, response) = ui.allocate_exact_size(size, Sense::click());
                if response.hovered() {
                    ui.painter().rect_filled(rect, 0.0, theme::HOVER);
                }
                if response.clicked() {
                    open_memory(debug, value);
                }
                let color = if address == snapshot.sp {
                    theme::CURRENT_MARK
                } else {
                    theme::MUTED
                };
                mono_text(ui, rect, 0.0, &format!("{address:012x}"), color);
                mono_text(ui, rect, 108.0, &format!("{value:016x}"), theme::TEXT);
                if let Some(place) = snapshot.describe(value) {
                    mono_text(ui, rect, 248.0, &place, theme::CALL);
                }
                response.context_menu(|ui| {
                    if ui.button("Edit value").clicked() {
                        debug.edit_value(address, value, width);
                        ui.close();
                    }
                    if ui.button("Follow pointer").clicked() {
                        open_memory(debug, value);
                        ui.close();
                    }
                    if ui.button("Copy value").clicked() {
                        ui.ctx().copy_text(format!("{value:016x}"));
                        ui.close();
                    }
                });
            }
        });
}

fn open_memory(debug: &mut DebugState, address: u64) {
    debug.pane = Pane::Memory;
    debug.memory_address = format!("{address:#x}");
    debug.send(Command::ReadMemory {
        address,
        len: MEMORY_BYTES,
    });
}

fn code(
    ui: &mut Ui,
    snapshot: &Snapshot,
    project: &mut Project,
    debug: &mut DebugState,
) -> Option<Action> {
    let mut action = None;
    title(ui, &format!("Thread {}", snapshot.thread));
    egui::ScrollArea::vertical()
        .id_salt("debug_code")
        .auto_shrink(false)
        .show(ui, |ui| {
            ui.spacing_mut().item_spacing.y = 0.0;
            for line in &snapshot.code {
                let image = snapshot.to_image(line.address);
                let size = egui::vec2(ui.available_width(), ROW);
                let (rect, response) = ui.allocate_exact_size(size, Sense::click());
                if line.address == snapshot.ip {
                    ui.painter().rect_filled(rect, 0.0, theme::CURRENT);
                } else if response.hovered() {
                    ui.painter().rect_filled(rect, 0.0, theme::HOVER);
                }
                if project.breakpoints.contains(&image) {
                    table::marker(ui, rect, theme::BREAKPOINT);
                } else if project.bookmarks.contains(&image) {
                    table::marker(ui, rect, theme::CURRENT_MARK);
                }
                if response.double_clicked() {
                    debug.toggle_breakpoint(project, image);
                } else if response.clicked() {
                    action = Some(Action::Focus(image));
                }

                mono_text(
                    ui,
                    rect,
                    12.0,
                    &format!("{:#x}", line.address),
                    theme::MUTED,
                );
                mono_text(ui, rect, 170.0, &line.text, theme::TEXT);
            }
        });
    action
}

fn bottom(ui: &mut Ui, project: &mut Project, debug: &mut DebugState) -> Option<Action> {
    let mut action = None;
    ui.horizontal(|ui| {
        for (pane, name) in [
            (Pane::Log, "Log"),
            (Pane::Breakpoints, "Breakpoints"),
            (Pane::Bookmarks, "Bookmarks"),
            (Pane::Memory, "Memory"),
            (Pane::Modules, "Modules"),
            (Pane::Threads, "Threads"),
        ] {
            let selected = debug.pane == pane;
            let color = if selected { theme::TEXT } else { theme::MUTED };
            let fill = if selected {
                theme::PILL
            } else {
                Color32::TRANSPARENT
            };
            if ui
                .add(egui::Button::new(RichText::new(name).color(color)).fill(fill))
                .clicked()
            {
                debug.pane = pane;
            }
        }
    });
    ui.add_space(4.0);

    match debug.pane {
        Pane::Log => {
            egui::ScrollArea::vertical()
                .id_salt("debug_log")
                .auto_shrink(false)
                .stick_to_bottom(true)
                .show(ui, |ui| {
                    for line in &debug.log {
                        ui.label(RichText::new(line).font(theme::mono()));
                    }
                });
        }
        Pane::Breakpoints => action = breakpoint_list(ui, project, debug),
        Pane::Bookmarks => {
            egui::ScrollArea::vertical()
                .id_salt("debug_bookmarks")
                .auto_shrink(false)
                .show(ui, |ui| {
                    if project.bookmarks.is_empty() {
                        ui.label(
                            RichText::new("Press Ctrl+M or right-click a line to add one.")
                                .color(theme::MUTED),
                        );
                    }
                    let mut remove = None;
                    for &va in &project.bookmarks {
                        ui.horizontal(|ui| {
                            if ui
                                .selectable_label(
                                    false,
                                    RichText::new(format!("{va:#x}")).font(theme::mono()),
                                )
                                .clicked()
                            {
                                action = Some(Action::Focus(va));
                            }
                            if ui.small_button("×").clicked() {
                                remove = Some(va);
                            }
                        });
                    }
                    if let Some(va) = remove {
                        project.bookmarks.remove(&va);
                    }
                });
        }
        Pane::Memory => memory_pane(ui, debug),
        Pane::Modules => {
            let modules = debug
                .snapshot
                .as_ref()
                .map_or(&[][..], |snapshot| snapshot.modules.as_slice());
            egui::ScrollArea::vertical()
                .id_salt("debug_modules")
                .auto_shrink(false)
                .show(ui, |ui| {
                    if modules.is_empty() {
                        ui.label(RichText::new("Shown while paused").color(theme::MUTED));
                    }
                    for module in modules {
                        ui.label(
                            RichText::new(format!(
                                "{:016x}  {:>10}  {}",
                                module.base, module.size, module.name
                            ))
                            .font(theme::mono()),
                        );
                    }
                });
        }
        Pane::Threads => {
            let list = debug
                .snapshot
                .as_ref()
                .map(|snapshot| (snapshot.threads.clone(), snapshot.thread));
            egui::ScrollArea::vertical()
                .id_salt("debug_threads")
                .auto_shrink(false)
                .show(ui, |ui| match list {
                    Some((threads, current)) => {
                        for thread in threads {
                            if ui
                                .selectable_label(thread == current, format!("Thread {thread}"))
                                .clicked()
                            {
                                debug.send(Command::SelectThread(thread));
                            }
                        }
                    }
                    None => {
                        ui.label(RichText::new("Shown while paused").color(theme::MUTED));
                    }
                });
        }
    }
    action
}

fn breakpoint_list(ui: &mut Ui, project: &mut Project, debug: &mut DebugState) -> Option<Action> {
    let mut action = None;
    let mut removing = None;
    if project.breakpoints.is_empty() {
        ui.label(
            RichText::new("None yet. Pick a line in Listing and press F2.").color(theme::MUTED),
        );
        return None;
    }
    egui::ScrollArea::vertical()
        .id_salt("debug_breakpoints")
        .auto_shrink(false)
        .show(ui, |ui| {
            for &va in &project.breakpoints {
                ui.horizontal(|ui| {
                    if ui.small_button("×").clicked() {
                        removing = Some(va);
                    }
                    let routine = project
                        .analysis
                        .function_containing(va)
                        .map(|function| crate::tabs::function_label(project, function))
                        .unwrap_or_default();
                    let label = ui.selectable_label(
                        false,
                        RichText::new(format!("{va:#x}  {routine}")).font(theme::mono()),
                    );
                    if label.clicked() {
                        action = Some(Action::Go(va));
                    }
                });
            }
        });
    if let Some(va) = removing {
        debug.toggle_breakpoint(project, va);
    }
    action
}

fn memory_pane(ui: &mut Ui, debug: &mut DebugState) {
    ui.horizontal(|ui| {
        let field = ui.add(
            egui::TextEdit::singleline(&mut debug.memory_address)
                .hint_text("Address")
                .font(theme::mono())
                .desired_width(220.0),
        );
        let submitted = field.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
        if ui.button("Read").clicked() || submitted {
            let text = debug.memory_address.trim().trim_start_matches("0x");
            if let Ok(address) = u64::from_str_radix(text, 16) {
                debug.send(Command::ReadMemory {
                    address,
                    len: MEMORY_BYTES,
                });
            }
        }
    });

    let Some((address, bytes)) = debug.memory.clone() else {
        return;
    };
    let font = theme::mono();
    let glyph = ui.ctx().fonts_mut(|fonts| fonts.glyph_width(&font, '0'));
    let hex_x = 14.0 * glyph;
    let ascii_x = 63.0 * glyph;

    egui::ScrollArea::vertical()
        .id_salt("debug_memory")
        .auto_shrink(false)
        .show(ui, |ui| {
            if bytes.is_empty() {
                ui.label(RichText::new("Nothing readable at that address").color(theme::MUTED));
                return;
            }
            for (line, chunk) in bytes.chunks(HEX_PER_LINE).enumerate() {
                let line_address = address + (line * HEX_PER_LINE) as u64;
                let size = egui::vec2(ui.available_width(), ROW);
                let (rect, response) = ui.allocate_exact_size(size, Sense::click());
                let byte_at = |pos: egui::Pos2| -> Option<usize> {
                    let offset = pos.x - (rect.left() + hex_x);
                    if offset >= 0.0 {
                        let cell = (offset / (glyph * 3.0)) as usize;
                        if cell < chunk.len() {
                            return Some(cell);
                        }
                    }
                    let offset = pos.x - (rect.left() + ascii_x);
                    if offset >= 0.0 {
                        let cell = (offset / glyph) as usize;
                        if cell < chunk.len() {
                            return Some(cell);
                        }
                    }
                    None
                };
                let hovered = response.hover_pos().and_then(byte_at);

                mono_text(ui, rect, 0.0, &format!("{line_address:012x}"), theme::MUTED);
                for (index, byte) in chunk.iter().enumerate() {
                    let x = hex_x + index as f32 * glyph * 3.0;
                    if hovered == Some(index) {
                        let cell = Rect::from_min_size(
                            egui::pos2(rect.left() + x, rect.top()),
                            egui::vec2(glyph * 2.0, rect.height()),
                        );
                        ui.painter().rect_filled(cell, 0.0, theme::HOVER);
                    }
                    mono_text(ui, rect, x, &format!("{byte:02x}"), theme::TEXT);
                }
                let text: String = chunk
                    .iter()
                    .map(|&byte| {
                        if (0x20..0x7F).contains(&byte) {
                            byte as char
                        } else {
                            '.'
                        }
                    })
                    .collect();
                mono_text(ui, rect, ascii_x, &text, theme::MUTED);

                let index = hovered.unwrap_or(0).min(chunk.len() - 1);
                let key = egui::Id::unique(("debug_memory_menu", line_address));
                if response.secondary_clicked() {
                    ui.memory_mut(|memory| memory.data.insert_temp(key, index));
                }
                let index = ui
                    .memory(|memory| memory.data.get_temp::<usize>(key))
                    .unwrap_or(index);
                let byte_address = line_address + index as u64;
                response.context_menu(|ui| {
                    if ui
                        .button(format!("Edit byte at {byte_address:#x}"))
                        .clicked()
                    {
                        debug.edit_bytes(byte_address, &chunk[index..index + 1]);
                        ui.close();
                    }
                    let rest = &chunk[index..];
                    if !rest.is_empty()
                        && ui
                            .button(format!("Edit {} byte(s) at {byte_address:#x}", rest.len()))
                            .clicked()
                    {
                        debug.edit_bytes(byte_address, rest);
                        ui.close();
                    }
                    if ui.button("Copy line").clicked() {
                        let text: Vec<String> =
                            chunk.iter().map(|byte| format!("{byte:02x}")).collect();
                        ui.ctx().copy_text(text.join(" "));
                        ui.close();
                    }
                });
            }
        });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn patched_ranges_cover_written_bytes_and_merge() {
        let mut debug = DebugState::default();
        debug.note_patch(0x1000, 4);
        debug.note_patch(0x1004, 2);
        assert!(debug.is_patched(0x1000, 1));
        assert!(debug.is_patched(0x1003, 3));
        assert!(!debug.is_patched(0x1006, 1));
        assert!(!debug.is_patched(0x0fff, 1));
        assert_eq!(debug.patched, vec![(0x1000, 0x1006)]);
        debug.close();
        assert!(!debug.is_patched(0x1000, 1));
    }

    #[test]
    fn jump_bytes_encode_a_relative_jump_and_pad_with_nops() {
        let bytes = jump_bytes(0x1000, 7, 0x2000).unwrap();
        assert_eq!(bytes.len(), 7);
        assert_eq!(bytes[0], 0xE9);
        assert_eq!(
            i32::from_le_bytes([bytes[1], bytes[2], bytes[3], bytes[4]]),
            0x2000 - 0x1005
        );
        assert!(bytes[5..].iter().all(|&byte| byte == 0x90));

        assert!(jump_bytes(0x1000, 4, 0x2000).is_err());
        assert!(jump_bytes(0, 5, u64::MAX / 2).is_err());
    }

    #[test]
    fn hex_values_accept_prefix_and_underscores() {
        assert_eq!(parse_hex("0x10"), Ok(16));
        assert_eq!(parse_hex("ff_ff"), Ok(0xffff));
        assert!(parse_hex("xyz").is_err());
        assert!(parse_hex("  ").is_err());
    }

    #[test]
    fn byte_lists_accept_groups_and_contiguous_digits() {
        assert_eq!(parse_bytes("48 8b 05"), Ok(vec![0x48, 0x8b, 0x05]));
        assert_eq!(parse_bytes("488b05"), Ok(vec![0x48, 0x8b, 0x05]));
        assert_eq!(parse_bytes("0x90"), Ok(vec![0x90]));
        assert!(parse_bytes("abc").is_err());
        assert!(parse_bytes("").is_err());
    }

    #[test]
    fn writes_are_truncated_to_the_register_width() {
        assert_eq!(truncate(0x1_2345_6789, 4), 0x2345_6789);
        assert_eq!(truncate(u64::MAX, 8), u64::MAX);
        assert_eq!(register_width("eax"), 4);
        assert_eq!(register_width("r15"), 8);
        assert_eq!(register_width("eflags"), 4);
    }

    #[test]
    fn register_edits_keep_only_the_low_bits() {
        let editor = Editor::register("eax", 0x1122_3344_5566_7788);
        assert_eq!(
            editor.command(),
            Ok(Command::WriteRegister {
                name: "eax",
                value: 0x5566_7788
            })
        );
    }

    #[test]
    fn value_edits_write_little_endian_bytes() {
        let editor = Editor::value(0x1000, 0x1122_3344, 4);
        assert_eq!(
            editor.command(),
            Ok(Command::WriteMemory {
                address: 0x1000,
                bytes: vec![0x44, 0x33, 0x22, 0x11]
            })
        );
    }

    #[test]
    fn invalid_edits_report_an_error_instead_of_a_command() {
        let mut editor = Editor::bytes(0x1000, &[0x90]);
        editor.text = "zz".to_owned();
        assert!(editor.command().is_err());
    }
}
