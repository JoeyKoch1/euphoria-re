mod advanced;
mod apk_view;
mod canvas;
mod debug_view;
mod decompile_view;
mod dump_view;
mod file_job;
mod graph_view;
mod network;
mod plugin_view;
mod public_view;
mod sql_view;
mod table;
mod tabs;
mod theme;
mod tools;

use std::collections::BTreeSet;
use std::env;
use std::path::Path;
use std::sync::Arc;

use eframe::egui::{self, Align, Layout, RichText, Ui};
use euphoria_engine::{Analysis, Arch, Inspection, Listing, dataset};
use euphoria_plugins::Request;

use advanced::Hypervisor;
use apk_view::ApkView;
use debug_view::{DebugState, Notice};
use decompile_view::DecompileState;
use dump_view::{DumpState, Source};
use file_job::{FileJob, LoadedFile, Outcome};
use graph_view::GraphState;
use network::NetworkState;
use plugin_view::PluginPage;
use public_view::PublicState;
use sql_view::SqlView;
use tabs::Filter;
use tools::XorState;

const MAX_JUMP_ROWS: usize = 256;

const HELP: &str = "jump <address or routine name>, help";

#[derive(Clone, Copy, Default, PartialEq)]
enum Tab {
    #[default]
    Listing,
    Graph,
    Decompiler,
    Debugger,
    Routines,
    Xrefs,
    Strings,
    Xor,
    File,
    Apk,
    Sql,
    Networking,
    Host(usize),
    Plugins,
    Added {
        plugin: usize,
        tab: usize,
    },
    Advanced,
}

impl Tab {
    const MAIN: [(Self, &'static str); 12] = [
        (Self::Listing, "Listing"),
        (Self::Graph, "Graph"),
        (Self::Decompiler, "Decompiler"),
        (Self::Debugger, "Debugger"),
        (Self::Routines, "Routines"),
        (Self::Xrefs, "Xrefs"),
        (Self::Strings, "Strings"),
        (Self::Xor, "XOR"),
        (Self::File, "File"),
        (Self::Apk, "APK"),
        (Self::Sql, "SQL"),
        (Self::Networking, "Networking"),
    ];
}

struct Project {
    analysis: Arc<Analysis>,
    listing: Arc<Listing>,
    jumps: Vec<(usize, usize)>,
    functions: Filter,
    references: Filter,
    strings: Filter,
    graph: GraphState,
    decompile: DecompileState,
    public: PublicState,
    breakpoints: BTreeSet<u64>,
    xor: XorState,
    inspection: Inspection,
    cursor: usize,
    scroll_to: Option<usize>,
}

impl Project {
    fn open(
        path: &Path,
        progress: impl Fn(&'static str) -> anyhow::Result<()>,
    ) -> anyhow::Result<Self> {
        progress("Analyzing file...")?;
        let analysis = Analysis::open(path)?;
        progress("Building disassembly...")?;
        let listing = analysis.listing();
        progress("Indexing routines...")?;
        let jumps = listing.jumps(MAX_JUMP_ROWS);
        let entry = listing.row_at(analysis.entry).unwrap_or(0);
        progress("Inspecting sections...")?;
        let inspection = analysis.inspect();

        Ok(Self {
            functions: Filter::all(analysis.functions.len()),
            references: Filter::all(listing.xrefs.len()),
            strings: Filter::all(listing.strings.len()),
            graph: GraphState::new(analysis.functions.len()),
            decompile: DecompileState::default(),
            public: PublicState::default(),
            breakpoints: BTreeSet::new(),
            xor: XorState::default(),
            inspection,
            cursor: entry,
            scroll_to: Some(entry),
            analysis: Arc::new(analysis),
            listing: Arc::new(listing),
            jumps,
        })
    }
}

fn arch_label(arch: Arch) -> &'static str {
    match arch {
        Arch::X86_64 => "64-bit x86",
        Arch::X86 => "32-bit x86",
        Arch::Aarch64 => "ARM64",
    }
}

#[derive(Default)]
struct App {
    logo: Option<egui::TextureHandle>,
    project: Option<Project>,
    sql: Option<SqlView>,
    apk: Option<ApkView>,
    dump: DumpState,
    debug: DebugState,
    network: NetworkState,
    hypervisor: Hypervisor,
    plugins: PluginPage,
    last_tab_title: String,
    tab: Tab,
    path: String,
    command: String,
    status: Option<String>,
    error: Option<String>,
    file_job: Option<FileJob>,
}

impl App {
    fn open(&mut self, path: &Path) {
        if self.file_job.is_some() {
            return;
        }
        self.path = path.display().to_string();
        self.status = None;
        self.clear_file();
        self.file_job = Some(FileJob::open(path.to_owned()));
    }

    fn clear_file(&mut self) {
        self.debug.close();
        self.project = None;
        self.apk = None;
        self.sql = None;
        self.network = NetworkState::default();
        self.plugins.host.set_binary(None);
        self.command.clear();
        self.error = None;
        self.tab = Tab::Listing;
    }

    fn poll_file_job(&mut self, ctx: &egui::Context) {
        let Some(job) = self.file_job.as_mut() else {
            return;
        };
        let outcome = job.poll();
        if let Some(outcome) = outcome {
            self.file_job = None;
            match outcome {
                Ok(Outcome::Opened(path, loaded, network)) => {
                    self.path = path.display().to_string();
                    self.network = network;
                    match *loaded {
                        LoadedFile::Binary(mut project, view) => {
                            project.public = PublicState::new(&project.analysis.sha256);
                            self.plugins.host.set_binary(Some(view));
                            self.project = Some(*project);
                            self.tab = Tab::Listing;
                        }
                        LoadedFile::Apk(apk, view) => {
                            self.plugins.host.set_binary(Some(view));
                            self.apk = Some(apk);
                            self.tab = Tab::Apk;
                        }
                        LoadedFile::Sql(sql) => {
                            self.sql = Some(sql);
                            self.tab = Tab::Sql;
                        }
                    }
                    self.status = None;
                }
                Ok(Outcome::Saved(bytes)) => self.status = Some(format!("Saved {bytes} bytes")),
                Err(error) => {
                    self.error = Some(error.clone());
                    self.status = Some(error);
                }
            }
        } else {
            ctx.request_repaint_after(std::time::Duration::from_millis(50));
        }
    }

    fn browse(&mut self) {
        if let Some(path) = rfd::FileDialog::new().pick_file() {
            self.open(&path);
        }
    }

    fn open_typed_path(&mut self) {
        let path = self.path.trim().trim_matches('"').to_owned();
        if !path.is_empty() {
            self.open(Path::new(&path));
        }
    }

    fn save_dataset(&mut self) {
        if self.file_job.is_some() {
            return;
        }
        let Some(project) = &self.project else {
            return;
        };
        let stem = Path::new(&project.analysis.file_name)
            .file_stem()
            .unwrap_or_default()
            .to_string_lossy()
            .into_owned();
        let Some(path) = rfd::FileDialog::new()
            .set_file_name(format!("{stem}.{}", dataset::EXTENSION))
            .add_filter("Euphoria dataset", &[dataset::EXTENSION])
            .save_file()
        else {
            return;
        };

        self.error = None;
        self.file_job = Some(FileJob::save(
            path,
            Arc::clone(&project.analysis),
            self.network.snapshot(),
        ));
    }

    fn dump_source(&self) -> Option<Source> {
        let apk = self
            .apk
            .as_ref()
            .map(|view| Source::Apk(Arc::clone(&view.apk)));
        let binary = self.project.as_ref().map(|project| {
            Source::Binary(Arc::clone(&project.analysis), Arc::clone(&project.listing))
        });
        if self.tab == Tab::Apk {
            apk.or(binary)
        } else {
            binary.or(apk)
        }
    }

    fn go(&mut self, va: u64) {
        let Some(project) = &mut self.project else {
            return;
        };
        match project.listing.row_at(va) {
            Some(row) => {
                project.cursor = row;
                project.scroll_to = Some(row);
                self.tab = Tab::Listing;
                self.status = None;
            }
            None => self.status = Some(format!("Nothing decoded at {va:#x}")),
        }
    }

    fn focus(&mut self, va: u64) {
        let Some(project) = &mut self.project else {
            return;
        };
        if let Some(row) = project.listing.row_at(va) {
            project.cursor = row;
            project.scroll_to = Some(row);
            project.graph.center_on_cursor();
            self.status = None;
        }
    }

    fn debug_keys(&mut self, ctx: &egui::Context) {
        let code_tab = matches!(
            self.tab,
            Tab::Listing | Tab::Graph | Tab::Decompiler | Tab::Debugger
        );
        if !code_tab || ctx.egui_wants_keyboard_input() {
            return;
        }
        let Some(project) = &mut self.project else {
            return;
        };

        let (shift, pressed) = ctx.input(|input| {
            let keys = [
                egui::Key::F2,
                egui::Key::F4,
                egui::Key::F5,
                egui::Key::F7,
                egui::Key::F8,
                egui::Key::F9,
            ]
            .map(|key| input.key_pressed(key));
            (input.modifiers.shift, keys)
        });
        let [breakpoint, run_to, decompile, into, over, run] = pressed;
        let cursor = project.listing.rows.get(project.cursor).map(|row| row.va);

        if breakpoint && let Some(va) = cursor {
            self.debug.toggle_breakpoint(project, va);
        }
        if decompile {
            self.tab = if self.tab == Tab::Decompiler {
                Tab::Listing
            } else {
                Tab::Decompiler
            };
            project.scroll_to = Some(project.cursor);
        }

        let mut problem = None;
        if run {
            problem = self.debug.run(project);
        }
        if into {
            problem = self.debug.step_into(project);
        }
        if over {
            problem = if shift {
                self.debug.step_out(project)
            } else {
                self.debug.step_over(project)
            };
        }
        if run_to
            && self.debug.is_stopped()
            && let Some(va) = cursor
        {
            problem = self.debug.run_to(project, va);
        }
        if problem.is_some() {
            self.status = problem;
        }
    }

    fn poll_debugger(&mut self, ctx: &egui::Context) {
        for notice in self.debug.poll(ctx) {
            match notice {
                Notice::Stopped { image_ip, message } => {
                    self.status = Some(message);
                    let inside = self
                        .project
                        .as_ref()
                        .and_then(|project| project.analysis.function_containing(image_ip))
                        .is_some();
                    if inside {
                        self.focus(image_ip);
                    }
                }
                Notice::Message(message) => self.status = Some(message),
            }
        }
    }

    fn toggle_graph(&mut self) {
        match self.tab {
            Tab::Listing => {
                self.tab = Tab::Graph;
                if let Some(project) = &mut self.project {
                    project.graph.center_on_cursor();
                }
            }
            Tab::Graph => {
                self.tab = Tab::Listing;
                if let Some(project) = &mut self.project {
                    project.scroll_to = Some(project.cursor);
                }
            }
            _ => {}
        }
    }

    fn run_command(&mut self) {
        let command = std::mem::take(&mut self.command);
        let mut parts = command.split_whitespace();
        match (parts.next(), parts.next()) {
            (Some("jump" | "j"), Some(target)) => {
                let resolved = self
                    .project
                    .as_ref()
                    .and_then(|p| p.analysis.resolve(target));
                match resolved {
                    Some(va) => self.go(va),
                    None => self.status = Some(format!("No address or routine called {target}")),
                }
            }
            (None, _) => {}
            _ => self.status = Some(format!("Try: {HELP}")),
        }
    }

    fn toolbar(&mut self, ui: &mut Ui) {
        ui.horizontal(|ui| {
            if let Some(logo) = &self.logo {
                ui.image((logo.id(), egui::vec2(24.0, 24.0)))
                    .on_hover_text("Euphoria");
            }
            let field = ui.add(
                egui::TextEdit::singleline(&mut self.path)
                    .hint_text("Binary, .euph, or SQL file")
                    .desired_width(440.0),
            );
            let submitted =
                field.lost_focus() && ui.input(|input| input.key_pressed(egui::Key::Enter));
            if ui
                .add_enabled(self.file_job.is_none(), egui::Button::new("Browse"))
                .clicked()
            {
                self.browse();
            }
            if ui
                .add_enabled(self.file_job.is_none(), egui::Button::new("Open"))
                .clicked()
                || submitted
            {
                self.open_typed_path();
            }
            if ui
                .add_enabled(
                    self.project.is_some() && self.file_job.is_none(),
                    egui::Button::new("Save .euph"),
                )
                .clicked()
            {
                self.save_dataset();
            }

            let source = self.dump_source();
            let can_dump = source.is_some() && !self.dump.is_running();
            if ui
                .add_enabled(can_dump, egui::Button::new("Dump"))
                .clicked()
                && let Some(source) = source
            {
                self.dump.ask(source);
            }

            ui.add_space(16.0);
            if let Some(job) = self.file_job.as_mut() {
                ui.spinner();
                ui.label(job.progress);
                if ui.button("Cancel").clicked() {
                    job.cancel();
                }
            }
            let jump = ui.add(
                egui::TextEdit::singleline(&mut self.command)
                    .hint_text(RichText::new("jump 0x140001000").font(theme::mono()))
                    .font(theme::mono())
                    .desired_width(240.0),
            );
            if jump.lost_focus() && ui.input(|input| input.key_pressed(egui::Key::Enter)) {
                self.run_command();
                jump.request_focus();
            }

            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                if let Some(row) = self
                    .project
                    .as_ref()
                    .and_then(|p| p.listing.rows.get(p.cursor))
                {
                    ui.label(RichText::new(format!("{:#x}", row.va)).font(theme::mono()));
                }
            });
        });
    }

    fn tab_button(&mut self, ui: &mut Ui, tab: Tab, title: &str) {
        let selected = self.tab == tab;
        let color = if selected { theme::TEXT } else { theme::MUTED };
        let fill = if selected {
            theme::PILL
        } else {
            egui::Color32::TRANSPARENT
        };
        let button = egui::Button::new(RichText::new(title).color(color)).fill(fill);
        if ui.add(button).clicked() {
            self.tab = tab;
        }
    }

    fn tab_bar(&mut self, ui: &mut Ui) {
        ui.horizontal_wrapped(|ui| {
            for (tab, title) in Tab::MAIN {
                self.tab_button(ui, tab, title);
            }

            let mut close = None;
            for index in 0..self.network.hosts.len() {
                let domain = self.network.hosts[index].domain.clone();
                self.tab_button(ui, Tab::Host(index), &domain);
                if ui.small_button("×").clicked() {
                    close = Some(index);
                }
            }
            if let Some(index) = close {
                self.network.close(index);
                self.tab = match self.tab {
                    Tab::Host(open) if open == index => Tab::Networking,
                    Tab::Host(open) if open > index => Tab::Host(open - 1),
                    other => other,
                };
            }

            self.tab_button(ui, Tab::Plugins, "Plugins");
            for info in self.plugins.host.tabs() {
                let tab = Tab::Added {
                    plugin: info.plugin,
                    tab: info.tab,
                };
                self.tab_button(ui, tab, &info.title);
            }

            self.tab_button(ui, Tab::Advanced, "Advanced");
        });
    }

    fn tab_title(&self) -> String {
        match self.tab {
            Tab::Host(index) => self
                .network
                .hosts
                .get(index)
                .map_or_else(String::new, |host| host.domain.clone()),
            Tab::Plugins => "Plugins".to_owned(),
            Tab::Added { plugin, tab } => self
                .plugins
                .host
                .tabs()
                .into_iter()
                .find(|info| info.plugin == plugin && info.tab == tab)
                .map_or_else(String::new, |info| info.title),
            Tab::Advanced => "Advanced".to_owned(),
            tab => Tab::MAIN
                .iter()
                .find(|(main, _)| *main == tab)
                .map_or_else(String::new, |(_, title)| (*title).to_owned()),
        }
    }

    fn run_plugin_requests(&mut self) {
        for request in self.plugins.host.take_requests() {
            match request {
                Request::Jump(va) => self.go(va),
                Request::Status(text) => self.status = Some(text),
            }
        }
    }

    fn status_bar(&self, ui: &mut Ui) {
        ui.horizontal(|ui| {
            if let Some(project) = &self.project {
                let analysis = &project.analysis;
                ui.label(
                    RichText::new(&analysis.file_name)
                        .color(theme::TEXT)
                        .strong(),
                );
                for detail in [
                    arch_label(analysis.arch).to_owned(),
                    format!("{} routines", analysis.functions.len()),
                    format!("{} ops", project.listing.rows.len()),
                    format!("{} xrefs", project.listing.xrefs.len()),
                    format!("{} strings", project.listing.strings.len()),
                ] {
                    ui.add_space(10.0);
                    ui.label(RichText::new(detail).color(theme::MUTED));
                }
            }
            if let Some(message) = &self.status {
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    ui.label(RichText::new(message).color(theme::MUTED));
                });
            }
        });
    }

    fn empty_state(&mut self, ui: &mut Ui) {
        ui.vertical_centered(|ui| {
            ui.add_space(ui.available_height() / 2.0 - 60.0);
            if let Some(error) = &self.error {
                ui.label(RichText::new(error).color(theme::ERROR));
                ui.add_space(12.0);
            }
            ui.label(
                RichText::new("Open a binary you own or are allowed to inspect")
                    .color(theme::MUTED),
            );
            ui.add_space(12.0);
            if ui.button("Browse").clicked() {
                self.browse();
            }
        });
    }

    fn content(&mut self, ui: &mut Ui) {
        let action = match self.tab {
            Tab::Apk => apk_view::show(ui, &mut self.apk),
            Tab::Sql => sql_view::show(ui, &mut self.sql),
            Tab::Networking => network::links(
                ui,
                &mut self.network,
                self.project.as_ref().map(|p| p.analysis.as_ref()),
            ),
            Tab::Host(index) => {
                network::host_tab(ui, &mut self.network, index);
                None
            }
            Tab::Plugins => {
                plugin_view::show(ui, &mut self.plugins);
                None
            }
            Tab::Added { plugin, tab } => {
                if !plugin_view::plugin_tab(ui, &mut self.plugins, plugin, tab) {
                    self.tab = Tab::Plugins;
                    self.status = Some("That plugin stopped. See Plugins, Local.".to_owned());
                }
                None
            }
            Tab::Advanced => {
                advanced::show(ui, &mut self.hypervisor);
                None
            }
            tab => {
                let Some(project) = &mut self.project else {
                    self.empty_state(ui);
                    return;
                };
                let live = self.debug.current_image_ip();
                match tab {
                    Tab::Graph => graph_view::show(ui, project, live),
                    Tab::Decompiler => decompile_view::show(ui, project, &mut self.debug),
                    Tab::Debugger => debug_view::show(ui, project, &mut self.debug),
                    Tab::Routines => tabs::functions(ui, project),
                    Tab::Xrefs => tabs::references(ui, project),
                    Tab::Strings => tabs::strings(ui, project),
                    Tab::Xor => tools::xor_tab(ui, project),
                    Tab::File => {
                        let shared = public_view::show(ui, project);
                        tools::overview(ui, project).or(shared)
                    }
                    _ => tabs::disassembly(ui, project, &mut self.debug),
                }
            }
        };

        match action {
            Some(tabs::Action::Go(va)) => self.go(va),
            Some(tabs::Action::Focus(va)) => self.focus(va),
            Some(tabs::Action::Select(row)) => {
                if let Some(project) = &mut self.project {
                    project.cursor = row;
                }
            }
            Some(tabs::Action::Status(message)) => self.status = Some(message),
            Some(tabs::Action::Open(path)) => self.open(&path),
            Some(tabs::Action::ShowHost(index)) => self.tab = Tab::Host(index),
            Some(tabs::Action::ShowDecompiler) => self.tab = Tab::Decompiler,
            None => {}
        }
    }
}

fn bar(fill: egui::Color32) -> egui::Frame {
    egui::Frame::new()
        .fill(fill)
        .inner_margin(egui::Margin::symmetric(12, 8))
}

impl eframe::App for App {
    fn ui(&mut self, ui: &mut Ui, _frame: &mut eframe::Frame) {
        let ctx = ui.ctx().clone();
        self.poll_file_job(&ctx);
        self.network.poll(&ctx);
        self.plugins.poll(&ctx);
        self.poll_debugger(&ctx);
        self.debug_keys(&ctx);
        if !ctx.egui_wants_keyboard_input() && ctx.input(|i| i.key_pressed(egui::Key::Space)) {
            self.toggle_graph();
        }

        egui::Panel::bottom("status")
            .frame(bar(theme::SURFACE))
            .show(ui, |ui| self.status_bar(ui));
        egui::Panel::bottom("tabs")
            .frame(bar(theme::BACKGROUND))
            .show(ui, |ui| self.tab_bar(ui));
        egui::Panel::top("toolbar")
            .frame(bar(theme::BACKGROUND))
            .show(ui, |ui| self.toolbar(ui));
        egui::CentralPanel::default()
            .frame(egui::Frame::new().fill(theme::BACKGROUND))
            .show(ui, |ui| self.content(ui));

        self.network.consent_dialog(&ctx);
        self.plugins.confirm_dialog(&ctx);
        self.dump.dialog(&ctx);
        self.debug.dialog(&ctx, self.project.as_ref());
        if let Some(line) = self.dump.poll(&ctx) {
            self.status = Some(line);
        }

        let title = self.tab_title();
        if title != self.last_tab_title {
            self.plugins.host.emit_tab_changed(&title);
            self.last_tab_title = title;
        }
        self.run_plugin_requests();
    }
}

fn main() -> eframe::Result {
    let mut app = App::default();
    if let Some(path) = env::args_os().nth(1) {
        app.open(Path::new(&path));
    }

    let icon = eframe::icon_data::from_png_bytes(include_bytes!("../assets/icon.png"))
        .expect("invalid bundled app icon");
    let logo = egui::ColorImage::from_rgba_unmultiplied(
        [icon.width as usize, icon.height as usize],
        &icon.rgba,
    );
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_icon(icon)
            .with_maximized(true),
        ..Default::default()
    };

    eframe::run_native(
        "Euphoria",
        options,
        Box::new(|cc| {
            theme::apply(&cc.egui_ctx);
            app.logo = Some(cc.egui_ctx.load_texture("logo", logo, Default::default()));
            Ok(Box::new(app))
        }),
    )
}

#[cfg(test)]
mod file_tests {
    use super::*;

    #[test]
    fn switching_files_clears_previous_views_and_commands() {
        let empty_zip = b"PK\x05\x06\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";
        let apk = euphoria_apk::Apk::parse("empty.apk".into(), empty_zip.to_vec()).unwrap();
        let mut app = App {
            apk: Some(ApkView::new(apk)),
            sql: Some(SqlView::new(euphoria_sql::Script::default())),
            command: "old command".into(),
            tab: Tab::Apk,
            ..App::default()
        };
        app.clear_file();
        assert!(app.apk.is_none());
        assert!(app.sql.is_none());
        assert!(app.project.is_none());
        assert!(app.dump_source().is_none());
        assert!(app.network.hosts.is_empty());
        assert!(app.command.is_empty());
        assert!(app.tab == Tab::Listing);
    }
}
