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

    fn launch(&mut self, project: &Project, intent: Intent) {
        let analysis = &project.analysis;
        self.log.clear();
        self.snapshot = None;
        self.previous.clear();
        self.memory = None;
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
                Event::Log(line) => self.write_log(line),
                Event::Exited(code) => {
                    let message = format!("The program exited with code {code:#x}");
                    self.write_log(message.clone());
                    notices.push(Notice::Message(message));
                    self.session = None;
                    self.running = false;
                    self.snapshot = None;
                    self.previous.clear();
                    return notices;
                }
                Event::Failed(message) => {
                    self.write_log(message.clone());
                    notices.push(Notice::Message(message));
                    self.session = None;
                    self.running = false;
                    return notices;
                }
            }
        }
        notices
    }

    pub fn dialog(&mut self, ctx: &egui::Context, project: Option<&Project>) {
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
                    .on_hover_text("F9")
                    .clicked()
                {
                    problem = debug.run(project);
                }
                if ui
                    .add_enabled(debug.running, egui::Button::new("Pause"))
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
        .show(ui, |ui| registers(ui, &snapshot, &debug.previous));
    egui::Panel::right("debug_stack")
        .exact_size(STACK_WIDTH)
        .frame(egui::Frame::new().fill(theme::SURFACE).inner_margin(8))
        .show(ui, |ui| stack(ui, &snapshot, debug));

    if let Some(next) = code(ui, &snapshot, project, debug) {
        action = Some(next);
    }
    action
}

fn registers(ui: &mut Ui, snapshot: &Snapshot, previous: &[(&'static str, u64)]) {
    title(ui, "Registers");
    egui::ScrollArea::vertical()
        .id_salt("registers")
        .auto_shrink(false)
        .show(ui, |ui| {
            ui.spacing_mut().item_spacing.y = 0.0;
            for (name, value) in &snapshot.registers {
                let changed = previous
                    .iter()
                    .find(|(old, _)| old == name)
                    .is_some_and(|(_, old)| old != value);
                let size = egui::vec2(ui.available_width(), ROW);
                let (rect, response) = ui.allocate_exact_size(size, Sense::hover());
                mono_text(ui, rect, 0.0, name, theme::REGISTER);
                let color = if changed { theme::NUMBER } else { theme::TEXT };
                mono_text(ui, rect, 56.0, &format!("{value:016x}"), color);
                if let Some(place) = snapshot.describe(*value) {
                    response.on_hover_text(place);
                }
            }
        });
}

fn stack(ui: &mut Ui, snapshot: &Snapshot, debug: &mut DebugState) {
    title(ui, "Stack");
    egui::ScrollArea::vertical()
        .id_salt("stack")
        .auto_shrink(false)
        .show(ui, |ui| {
            ui.spacing_mut().item_spacing.y = 0.0;
            for (address, value) in &snapshot.stack {
                let size = egui::vec2(ui.available_width(), ROW);
                let (rect, response) = ui.allocate_exact_size(size, Sense::click());
                if response.hovered() {
                    ui.painter().rect_filled(rect, 0.0, theme::HOVER);
                }
                if response.clicked() {
                    open_memory(debug, *value);
                }
                let color = if *address == snapshot.sp {
                    theme::CURRENT_MARK
                } else {
                    theme::MUTED
                };
                mono_text(ui, rect, 0.0, &format!("{address:012x}"), color);
                mono_text(ui, rect, 108.0, &format!("{value:016x}"), theme::TEXT);
                if let Some(place) = snapshot.describe(*value) {
                    mono_text(ui, rect, 248.0, &place, theme::CALL);
                }
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
                        .map(crate::tabs::function_label)
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

    let Some((address, bytes)) = &debug.memory else {
        return;
    };
    egui::ScrollArea::vertical()
        .id_salt("debug_memory")
        .auto_shrink(false)
        .show(ui, |ui| {
            if bytes.is_empty() {
                ui.label(RichText::new("Nothing readable at that address").color(theme::MUTED));
            }
            for (line, chunk) in bytes.chunks(HEX_PER_LINE).enumerate() {
                let hex: Vec<String> = chunk.iter().map(|byte| format!("{byte:02x}")).collect();
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
                ui.label(
                    RichText::new(format!(
                        "{:012x}  {:<47}  {text}",
                        address + (line * HEX_PER_LINE) as u64,
                        hex.join(" ")
                    ))
                    .font(theme::mono()),
                );
            }
        });
}
