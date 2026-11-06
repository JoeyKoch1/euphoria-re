mod advanced;
mod apk_view;
mod assist;
mod attach;
mod canvas;
mod debug_view;
mod decompile_view;
mod dump_view;
mod file_job;
mod graph_view;
mod guide;
mod network;
mod plugin_view;
mod public_view;
mod recovery;
mod samples;
mod sql_view;
mod table;
mod tabs;
mod theme;
mod tools;
mod workspace;

use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::path::Path;
use std::sync::Arc;

use eframe::egui::{self, Align, Layout, RichText, Ui};
use euphoria_android::AndroidRuntime;
use euphoria_engine::{Analysis, Arch, Inspection, Listing, dataset};
use euphoria_plugins::Request;

use advanced::AdvancedState;
use apk_view::ApkView;
use attach::{AttachState, LogoAction};
use debug_view::{DebugState, Notice};
use decompile_view::DecompileState;
use dump_view::{DumpState, Source};
use file_job::{FileJob, LoadedFile, Outcome};
use graph_view::GraphState;
use guide::{Guide, GuideAction};
use network::NetworkState;
use plugin_view::PluginPage;
use public_view::PublicState;
use sql_view::SqlView;
use tabs::Filter;
use tools::XorState;
use workspace::Workspace;

const MAX_JUMP_ROWS: usize = 256;

const HELP: &str = "jump <address, routine, or string>, func: <name>, str: <text>, help";

#[derive(Clone, Copy, PartialEq, Eq)]
enum SearchScope {
    All,
    Functions,
    Strings,
}

struct Hit {
    va: u64,
    label: String,
    kind: &'static str,
}

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
    Patch,
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

    fn needs_advanced_analysis(self) -> bool {
        matches!(self, Self::Xor | Self::Apk | Self::Sql | Self::Networking)
    }
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
    bookmarks: BTreeSet<u64>,
    xor: XorState,
    inspection: Inspection,
    names: BTreeMap<u64, String>,
    comments: BTreeMap<u64, String>,
    cursor: usize,
    scroll_to: Option<usize>,
    live_base: Option<u64>,
}

impl Project {
    fn open(
        path: &Path,
        progress: impl Fn(&'static str) -> anyhow::Result<()>,
    ) -> anyhow::Result<Self> {
        progress("Analyzing file...")?;
        let analysis = Analysis::open(path)?;
        Self::from_analysis(analysis, None, progress)
    }

    // Loads the module the way the running process has it mapped, so listing addresses and
    // decompiled code match the live process instead of the file on disk.
    fn open_live(
        path: &Path,
        image_base: u64,
        read: impl Fn(u64, usize) -> Vec<u8>,
        progress: impl Fn(&'static str) -> anyhow::Result<()>,
    ) -> anyhow::Result<Self> {
        progress("Reading the live module...")?;
        let analysis = Analysis::open_live(path, image_base, read)?;
        Self::from_analysis(analysis, Some(image_base), progress)
    }

    fn from_analysis(
        analysis: Analysis,
        live_base: Option<u64>,
        progress: impl Fn(&'static str) -> anyhow::Result<()>,
    ) -> anyhow::Result<Self> {
        progress("Building disassembly...")?;
        let listing = analysis.listing();
        progress("Indexing routines...")?;
        let jumps = listing.jumps(MAX_JUMP_ROWS);
        let entry = listing.row_at(analysis.entry).unwrap_or(0);
        progress("Inspecting sections...")?;
        let inspection = analysis.inspect();
        let workspace = Workspace::from_extras(&analysis.extras);

        Ok(Self {
            functions: Filter::all(analysis.functions.len()),
            references: Filter::all(listing.xrefs.len()),
            strings: Filter::all(listing.strings.len()),
            graph: GraphState::new(analysis.functions.len()),
            decompile: DecompileState::default(),
            public: PublicState::default(),
            breakpoints: BTreeSet::new(),
            bookmarks: BTreeSet::new(),
            xor: XorState::default(),
            inspection,
            names: workspace.names,
            comments: workspace.comments,
            cursor: entry,
            scroll_to: Some(entry),
            analysis: Arc::new(analysis),
            listing: Arc::new(listing),
            jumps,
            live_base,
        })
    }

    // One search box for the addresses, routine names, and strings an analyst usually jumps to.
    fn find(&self, query: &str, limit: usize) -> Vec<Hit> {
        let (scope, needle) = match query.split_once(':') {
            Some((prefix, rest)) => match prefix.to_ascii_lowercase().as_str() {
                "s" | "str" | "string" => (SearchScope::Strings, rest.trim()),
                "f" | "fn" | "func" => (SearchScope::Functions, rest.trim()),
                _ => (SearchScope::All, query.trim()),
            },
            None => (SearchScope::All, query.trim()),
        };
        if needle.is_empty() || limit == 0 {
            return Vec::new();
        }
        let lower = needle.to_lowercase();
        let mut hits = Vec::new();

        if scope != SearchScope::Strings {
            if let Some(va) = parse_address(needle)
                && self
                    .analysis
                    .sections
                    .iter()
                    .any(|section| va >= section.va && va - section.va < section.size)
            {
                hits.push(Hit {
                    va,
                    label: format!("{va:#x}"),
                    kind: "address",
                });
            }

            let mut named = Vec::new();
            for function in &self.analysis.functions {
                let Some(name) = self.names.get(&function.va).or(function.name.as_ref()) else {
                    continue;
                };
                let folded = name.to_lowercase();
                let rank = if folded == lower {
                    0
                } else if folded.starts_with(&lower) {
                    1
                } else if folded.contains(&lower) {
                    2
                } else {
                    continue;
                };
                named.push((rank, function.va, name.clone()));
            }
            named.sort_by_key(|(rank, va, _)| (*rank, *va));
            hits.extend(named.into_iter().map(|(_, va, label)| Hit {
                va,
                label,
                kind: "routine",
            }));
        }

        if scope != SearchScope::Functions {
            for entry in &self.listing.strings {
                if !tabs::contains_folded(&entry.value, &lower) {
                    continue;
                }
                let mut label: String = entry.value.chars().take(70).collect();
                if label.len() < entry.value.len() {
                    label.push('…');
                }
                hits.push(Hit {
                    va: entry.va,
                    label: format!("\"{label}\""),
                    kind: "string",
                });
                if hits.len() >= limit {
                    break;
                }
            }
        }

        hits.truncate(limit);
        hits
    }
}

fn arch_label(arch: Arch) -> &'static str {
    match arch {
        Arch::X86_64 => "64-bit x86",
        Arch::X86 => "32-bit x86",
        Arch::Aarch64 => "ARM64",
    }
}

fn parse_address(text: &str) -> Option<u64> {
    let (digits, prefixed) = match text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
        Some(rest) => (rest, true),
        None => (text, false),
    };
    if digits.is_empty()
        || !digits.chars().all(|digit| digit.is_ascii_hexdigit())
        || (!prefixed && digits.len() < 4)
    {
        return None;
    }
    u64::from_str_radix(digits, 16).ok()
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum EditKind {
    Rename,
    Comment,
}

struct Edit {
    address: u64,
    kind: EditKind,
    text: String,
}

#[derive(Default)]
struct App {
    logo: Option<egui::TextureHandle>,
    project: Option<Project>,
    sql: Option<SqlView>,
    apk: Option<ApkView>,
    dump: DumpState,
    debug: DebugState,
    attach: AttachState,
    network: NetworkState,
    advanced: AdvancedState,
    android: AndroidRuntime,
    plugins: PluginPage,
    guide: Guide,
    last_tab_title: String,
    tab: Tab,
    path: String,
    command: String,
    status: Option<String>,
    error: Option<String>,
    file_job: Option<FileJob>,
    live_load: bool,
    was_attached: bool,
    edit: Option<Edit>,
    assist: assist::Config,
    assist_state: assist::State,
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
        self.android.stop();
        self.debug.close();
        self.project = None;
        self.apk = None;
        self.sql = None;
        self.network = NetworkState::default();
        self.advanced.reset_file();
        self.plugins.host.set_binary(None);
        self.assist_state = assist::State::default();
        self.command.clear();
        self.error = None;
        self.tab = Tab::Listing;
    }

    // Starting a live load replaces whatever file was open, including a previous live module.
    fn open_live(&mut self, load: attach::LiveLoad) {
        // Attaching replaces whatever is loading; that load can no longer be shown as live.
        self.file_job = None;
        self.path = load.path.display().to_string();
        self.clear_file();
        self.status = Some(format!("Reading {} from the process...", load.module));
        self.live_load = true;
        self.tab = Tab::Debugger;
        self.file_job = Some(FileJob::open_live(load.path, load.base, load.pid));
    }

    // When the attachment ends, the live module's addresses mean nothing anymore.
    fn release_live(&mut self) {
        if self.live_load {
            self.file_job = None;
            self.live_load = false;
        }
        if self
            .project
            .as_ref()
            .is_some_and(|project| project.live_base.is_some())
        {
            self.clear_file();
        }
    }

    fn poll_file_job(&mut self, ctx: &egui::Context) {
        let Some(job) = self.file_job.as_mut() else {
            return;
        };
        let outcome = job.poll();
        if let Some(outcome) = outcome {
            let live_job = self.live_load;
            self.file_job = None;
            self.live_load = false;
            match outcome {
                Ok(Outcome::Opened(path, loaded, network)) => {
                    self.path = path.display().to_string();
                    self.network = network;
                    let mut recovered = None;
                    match *loaded {
                        LoadedFile::Binary(mut project, view) => {
                            let live = project.live_base.is_some();
                            project.public = PublicState::new(&project.analysis.sha256);
                            if !live {
                                recovered = recovery::restore(&mut project);
                            }
                            self.plugins.host.set_binary(Some(view));
                            self.project = Some(*project);
                            self.tab = if live { Tab::Debugger } else { Tab::Listing };
                        }
                        LoadedFile::Apk(apk, view) => {
                            self.plugins.host.set_binary(Some(view));
                            self.apk = Some(apk);
                            self.advanced.enabled = true;
                            self.tab = Tab::Apk;
                        }
                        LoadedFile::Sql(sql) => {
                            self.sql = Some(sql);
                            self.advanced.enabled = true;
                            self.tab = Tab::Sql;
                        }
                    }
                    self.status = recovered;
                }
                Ok(Outcome::Saved(bytes)) => {
                    if let Some(project) = &self.project {
                        recovery::discard(&project.analysis.sha256);
                    }
                    self.status = Some(format!("Saved {bytes} bytes"));
                }
                Err(error) => {
                    self.error = Some(error.clone());
                    self.status = Some(error);
                }
            }
            // A fresh live module is much more useful with registers already filled in.
            if live_job
                && self
                    .project
                    .as_ref()
                    .is_some_and(|project| project.live_base.is_some())
                && let Some(message) = self.attach.capture_contexts()
            {
                self.status = Some(message);
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
        let workspace = Workspace {
            names: project.names.clone(),
            comments: project.comments.clone(),
        };
        let extras = workspace.merge(self.network.snapshot());
        self.file_job = Some(FileJob::save(path, Arc::clone(&project.analysis), extras));
    }

    fn edit_dialog(&mut self, ctx: &egui::Context) {
        let Some(mut edit) = self.edit.take() else {
            return;
        };
        let (title, hint) = match edit.kind {
            EditKind::Rename => ("Rename routine", "Leave empty to use the original name"),
            EditKind::Comment => ("Comment", "Leave empty to remove the comment"),
        };
        let mut save = false;
        let mut cancel = false;
        egui::Window::new(title)
            .collapsible(false)
            .resizable(false)
            .anchor(egui::Align2::CENTER_CENTER, egui::vec2(0.0, -40.0))
            .show(ctx, |ui| {
                ui.label(
                    RichText::new(format!("{:#x}", edit.address))
                        .monospace()
                        .color(theme::MUTED),
                );
                let field = ui.add(
                    egui::TextEdit::singleline(&mut edit.text)
                        .hint_text(hint)
                        .desired_width(360.0),
                );
                field.request_focus();
                ui.horizontal(|ui| {
                    if ui.button("Save").clicked() {
                        save = true;
                    }
                    if ui.button("Cancel").clicked() {
                        cancel = true;
                    }
                });
                if field.lost_focus() && ui.input(|input| input.key_pressed(egui::Key::Enter)) {
                    save = true;
                }
                if ui.input(|input| input.key_pressed(egui::Key::Escape)) {
                    cancel = true;
                }
            });

        if cancel {
            return;
        }
        if save {
            if let Some(project) = &mut self.project {
                let text = edit.text.trim();
                let (map, done) = match edit.kind {
                    EditKind::Rename => (&mut project.names, "Renamed"),
                    EditKind::Comment => (&mut project.comments, "Commented"),
                };
                if text.is_empty() {
                    map.remove(&edit.address);
                    self.status = Some(format!(
                        "Cleared the {} at {:#x}",
                        match edit.kind {
                            EditKind::Rename => "name",
                            EditKind::Comment => "comment",
                        },
                        edit.address
                    ));
                } else {
                    map.insert(edit.address, text.to_owned());
                    self.status = Some(format!("{done} {:#x}", edit.address));
                }
                recovery::save(project);
            }
            return;
        }
        self.edit = Some(edit);
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
            Tab::Listing | Tab::Graph | Tab::Decompiler | Tab::Debugger | Tab::File | Tab::Patch
        );
        if !code_tab || ctx.egui_wants_keyboard_input() || self.guide.is_open() {
            return;
        }

        let (shift, ctrl, pressed) = ctx.input(|input| {
            let keys = [
                egui::Key::F2,
                egui::Key::F3,
                egui::Key::F4,
                egui::Key::F5,
                egui::Key::F7,
                egui::Key::F8,
                egui::Key::F9,
            ]
            .map(|key| input.key_pressed(key));
            (input.modifiers.shift, input.modifiers.ctrl, keys)
        });
        let [breakpoint, control, run_to, decompile, into, over, run] = pressed;

        // With no launched program, the same keys drive an attached process instead.
        if !self.debug.is_active() && self.attach.is_attached() {
            if control {
                self.status = if shift {
                    self.attach.resume()
                } else {
                    self.attach.suspend()
                };
            }
            if ctrl && run {
                self.attach.request_kill();
            }
        }

        let Some(project) = &mut self.project else {
            return;
        };
        let live = project.live_base.is_some();
        let cursor = project.listing.rows.get(project.cursor).map(|row| row.va);

        if ctrl
            && ctx.input(|input| input.key_pressed(egui::Key::M))
            && let Some(va) = cursor
        {
            self.status = Some(if project.bookmarks.remove(&va) {
                format!("Removed bookmark at {va:#x}")
            } else {
                project.bookmarks.insert(va);
                format!("Bookmarked {va:#x}")
            });
        }

        if !live
            && breakpoint
            && let Some(va) = cursor
        {
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
        // Launch, step, and stop only apply to a program Euphoria started itself. The attached
        // process is driven from the live Debugger view.
        if live {
            return;
        }

        let mut problem = None;
        if control && self.debug.is_active() {
            if shift {
                problem = self.debug.run(project);
            } else {
                self.debug.pause();
            }
        }
        if run && !ctrl {
            problem = self.debug.run(project);
        }
        if run && ctrl && self.debug.is_active() {
            self.debug.stop();
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
        let command = command.trim();
        if command.is_empty() {
            return;
        }
        let folded = command.to_ascii_lowercase();
        let target = ["jump ", "goto ", "j "]
            .iter()
            .find_map(|prefix| folded.starts_with(prefix).then(|| &command[prefix.len()..]))
            .unwrap_or(command)
            .trim();
        if target.eq_ignore_ascii_case("help") {
            self.status = Some(format!("Try: {HELP}"));
            return;
        }
        let hit = self
            .project
            .as_ref()
            .and_then(|project| project.find(target, 1).into_iter().next());
        match hit {
            Some(hit) => self.go(hit.va),
            None => self.status = Some(format!("Nothing matches {target}")),
        }
    }

    fn toolbar(&mut self, ui: &mut Ui) {
        ui.horizontal(|ui| {
            let logo = self.logo.as_ref().map(|logo| logo.id());
            if let Some(texture) = logo {
                let (action, rect) = attach::logo_menu(ui, texture, &mut self.attach);
                self.guide.record("logo", rect);
                match action {
                    LogoAction::Browse => self.browse(),
                    LogoAction::Tour => self.guide.start(),
                    LogoAction::None => {}
                }
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
            let open = ui.add_enabled(self.file_job.is_none(), egui::Button::new("Open"));
            self.guide.record("open", open.rect);
            if open.clicked() || submitted {
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
                    .hint_text(
                        RichText::new("Jump to an address, routine, or string").font(theme::mono()),
                    )
                    .font(theme::mono())
                    .desired_width(300.0),
            );
            if jump.lost_focus() && ui.input(|input| input.key_pressed(egui::Key::Enter)) {
                self.run_command();
                jump.request_focus();
            }
            if jump.has_focus() && !self.command.trim().is_empty() {
                let hits = self
                    .project
                    .as_ref()
                    .map_or_else(Vec::new, |project| project.find(&self.command, 8));
                if !hits.is_empty() {
                    let mut chosen = None;
                    egui::Area::new(jump.id.with("omnibox"))
                        .order(egui::Order::Foreground)
                        .fixed_pos(jump.rect.left_bottom() + egui::vec2(0.0, 4.0))
                        .show(ui.ctx(), |ui| {
                            egui::Frame::popup(ui.style()).show(ui, |ui| {
                                ui.set_min_width(jump.rect.width().max(360.0));
                                for hit in &hits {
                                    let text = RichText::new(format!(
                                        "{:<7} {:#x}  {}",
                                        hit.kind, hit.va, hit.label
                                    ))
                                    .font(theme::mono());
                                    if ui.add(egui::Button::new(text).frame(false)).clicked() {
                                        chosen = Some(hit.va);
                                    }
                                }
                            });
                        });
                    if let Some(va) = chosen {
                        self.command.clear();
                        self.go(va);
                    }
                }
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
        let response = ui.add(button);
        if let Some(anchor) = tab_anchor(tab) {
            self.guide.record(anchor, response.rect);
        }
        if response.clicked() {
            self.tab = tab;
        }
    }

    fn tab_bar(&mut self, ui: &mut Ui) {
        if !self.advanced.enabled && self.tab.needs_advanced_analysis() {
            self.tab = Tab::Listing;
        }
        if !self.attach.is_attached() && self.tab == Tab::Patch {
            self.tab = Tab::Listing;
        }
        ui.horizontal_wrapped(|ui| {
            for (tab, title) in Tab::MAIN {
                if !self.advanced.enabled && tab.needs_advanced_analysis() {
                    continue;
                }
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
            if self.attach.is_attached() {
                self.tab_button(ui, Tab::Patch, "Patch File");
            }
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
            Tab::Patch => "Patch File".to_owned(),
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
                Request::Rename { va, name } => self.rename_from_plugin(va, name),
            }
        }
    }

    fn rename_from_plugin(&mut self, va: u64, name: Option<String>) {
        let Some(project) = self.project.as_mut() else {
            return;
        };
        let Some(address) = project
            .analysis
            .function_containing(va)
            .map(|function| function.va)
        else {
            return;
        };
        match name {
            Some(name) => {
                project.names.insert(address, name);
            }
            None => {
                project.names.remove(&address);
            }
        }
        recovery::save(project);
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
            if let Some(label) = self.attach.label() {
                ui.add_space(14.0);
                ui.label(RichText::new(format!("attached to {label}")).color(theme::ACCENT))
                    .on_hover_text(
                        "Euphoria holds a handle to this process. Detach from the Euphoria menu.",
                    );
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
            Tab::Apk => apk_view::show(ui, &mut self.apk, &mut self.android),
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
                let cursor = self
                    .project
                    .as_ref()
                    .and_then(|project| project.listing.rows.get(project.cursor))
                    .map(|row| row.va);
                advanced::show(ui, &mut self.advanced, self.project.as_ref(), cursor)
            }
            Tab::Patch => self.attach.patch_tab(ui),
            Tab::Debugger if self.attach.is_attached() => {
                self.attach.live_debugger(ui, self.project.as_mut())
            }
            Tab::File => {
                let mut action = None;
                if let Some(project) = &mut self.project {
                    let shared = public_view::show(ui, project);
                    action = tools::overview(ui, project).or(shared);
                } else if !self.attach.is_attached() {
                    self.empty_state(ui);
                }
                if let Some(next) = self.attach.resources(ui) {
                    action = Some(next);
                }
                action
            }
            tab => {
                let Some(project) = &mut self.project else {
                    self.empty_state(ui);
                    return;
                };
                let live = self.debug.current_image_ip();
                match tab {
                    Tab::Graph => graph_view::show(ui, project, live),
                    Tab::Decompiler => decompile_view::show(
                        ui,
                        project,
                        &mut self.debug,
                        &mut self.assist,
                        &mut self.assist_state,
                    ),
                    Tab::Debugger => debug_view::show(ui, project, &mut self.debug),
                    Tab::Routines => tabs::functions(ui, project, &self.debug),
                    Tab::Xrefs => tabs::references(ui, project),
                    Tab::Strings => tabs::strings(ui, project),
                    Tab::Xor => tools::xor_tab(ui, project),
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
            Some(tabs::Action::Patch {
                address,
                bytes,
                note,
            }) => {
                self.status = Some(match self.debug.write_bytes(address, &bytes) {
                    Some(problem) => problem,
                    None => note,
                });
            }
            Some(tabs::Action::JumpEditor { address, length }) => {
                self.debug.open_jump(address, length);
            }
            Some(tabs::Action::EditBytes { address, bytes }) => {
                self.debug.edit_bytes(address, &bytes);
            }
            Some(tabs::Action::Breakpoint(va)) => {
                if let Some(project) = &mut self.project {
                    self.debug.toggle_breakpoint(project, va);
                }
            }
            Some(tabs::Action::Bookmark(va)) => {
                if let Some(project) = &mut self.project {
                    self.status = Some(if project.bookmarks.remove(&va) {
                        format!("Removed bookmark at {va:#x}")
                    } else {
                        project.bookmarks.insert(va);
                        format!("Bookmarked {va:#x}")
                    });
                }
            }
            Some(tabs::Action::Rename(va)) => {
                if let Some(project) = &self.project {
                    let address = project
                        .analysis
                        .function_containing(va)
                        .map_or(va, |function| function.va);
                    let text = project.names.get(&address).cloned().unwrap_or_default();
                    self.edit = Some(Edit {
                        address,
                        kind: EditKind::Rename,
                        text,
                    });
                }
            }
            Some(tabs::Action::Comment(va)) => {
                if let Some(project) = &self.project {
                    let text = project.comments.get(&va).cloned().unwrap_or_default();
                    self.edit = Some(Edit {
                        address: va,
                        kind: EditKind::Comment,
                        text,
                    });
                }
            }
            Some(tabs::Action::Decompile(va)) => {
                let Some(project) = &mut self.project else {
                    self.status = Some(format!("Nothing is loaded for {va:#x}"));
                    return;
                };
                match project.listing.row_at(va) {
                    Some(row) => {
                        project.cursor = row;
                        project.scroll_to = Some(row);
                        self.tab = Tab::Decompiler;
                        self.status = None;
                    }
                    None => self.status = Some(format!("Nothing decoded at {va:#x}")),
                }
            }
            None => {}
        }
    }
}

fn bar(fill: egui::Color32) -> egui::Frame {
    egui::Frame::new()
        .fill(fill)
        .inner_margin(egui::Margin::symmetric(12, 8))
}

fn tab_anchor(tab: Tab) -> Option<&'static str> {
    match tab {
        Tab::Listing => Some("tab_listing"),
        Tab::Debugger => Some("tab_debugger"),
        Tab::Advanced => Some("tab_advanced"),
        _ => None,
    }
}

impl eframe::App for App {
    fn ui(&mut self, ui: &mut Ui, _frame: &mut eframe::Frame) {
        let ctx = ui.ctx().clone();
        self.poll_file_job(&ctx);
        self.attach.poll(&ctx);
        if let Some(load) = self.attach.take_load_request() {
            self.open_live(load);
        }
        self.network.poll(&ctx);
        self.plugins.poll(&ctx);
        self.poll_debugger(&ctx);
        let android_changed = self.android.poll();
        if android_changed
            || self.android.is_active()
            || self.android.is_scanning()
            || self.android.is_setting_up()
        {
            ctx.request_repaint_after(std::time::Duration::from_millis(100));
        }
        self.debug_keys(&ctx);
        if !ctx.egui_wants_keyboard_input()
            && !self.guide.is_open()
            && ctx.input(|i| i.key_pressed(egui::Key::Space))
        {
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
        self.edit_dialog(&ctx);
        if let Some(message) = self.attach.dialog(&ctx) {
            self.status = Some(message);
            if self.attach.is_attached() {
                self.tab = Tab::Patch;
            }
        }
        if self.attach.take_patch_request() {
            self.tab = Tab::Patch;
        }
        if let Some(message) = self.attach.take_notice() {
            self.status = Some(message);
        }
        if !self.attach.is_attached() && self.tab == Tab::Patch {
            self.tab = Tab::Listing;
        }
        let attached = self.attach.is_attached();
        if self.was_attached && !attached {
            self.release_live();
        }
        self.was_attached = attached;
        if let GuideAction::Open(path) = self.guide.show(&ctx) {
            self.open(&path);
        }
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
    let mut app = App {
        assist: assist::Config::load(),
        ..App::default()
    };
    let file = env::args_os().nth(1);
    app.guide = Guide::load(file.is_some());
    if let Some(path) = file.as_ref() {
        app.open(Path::new(path));
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
    fn analysis_tabs_are_gated_by_the_advanced_switch() {
        for tab in [Tab::Xor, Tab::Apk, Tab::Sql, Tab::Networking] {
            assert!(tab.needs_advanced_analysis());
        }
        for tab in [
            Tab::Listing,
            Tab::Graph,
            Tab::Decompiler,
            Tab::Debugger,
            Tab::Routines,
            Tab::Xrefs,
            Tab::Strings,
            Tab::File,
            Tab::Advanced,
        ] {
            assert!(!tab.needs_advanced_analysis());
        }
    }

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

#[cfg(test)]
mod render_tests {
    use std::collections::BTreeMap;

    use super::*;

    fn sample_project() -> Project {
        let data = vec![0x90; 32];
        let analysis = Analysis {
            path: "test.bin".into(),
            arch: Arch::X86_64,
            entry: 0x1000,
            image_base: 0,
            is_pe: true,
            sections: vec![euphoria_engine::Section {
                va: 0x1000,
                offset: 0,
                size: data.len() as u64,
                executable: true,
            }],
            functions: vec![euphoria_engine::Function {
                va: 0x1000,
                size: data.len() as u64,
                name: Some("target".into()),
            }],
            section_names: vec![".text".into()],
            import_count: 0,
            imports: Vec::new(),
            iat: BTreeMap::new(),
            file_name: "test.bin".into(),
            sha256: "00".into(),
            extras: serde_json::Value::Null,
            data: Arc::new(data),
        };
        let listing = analysis.listing();
        Project {
            jumps: listing.jumps(MAX_JUMP_ROWS),
            functions: Filter::all(1),
            references: Filter::all(listing.xrefs.len()),
            strings: Filter::all(listing.strings.len()),
            graph: GraphState::new(1),
            decompile: DecompileState::default(),
            public: PublicState::default(),
            breakpoints: BTreeSet::new(),
            bookmarks: BTreeSet::new(),
            xor: XorState::default(),
            inspection: analysis.inspect(),
            names: BTreeMap::new(),
            comments: BTreeMap::new(),
            cursor: 0,
            scroll_to: None,
            analysis: Arc::new(analysis),
            listing: Arc::new(listing),
            live_base: None,
        }
    }

    #[test]
    fn decompiler_renders_disassembly_beside_pseudocode() {
        use euphoria_decompiler::{Line, Output, Token, TokenKind};

        let mut project = sample_project();
        project.decompile.insert_for_test(
            0x1000,
            Output {
                va: 0x1000,
                name: "target".into(),
                lines: vec![Line {
                    indent: 0,
                    tokens: vec![Token {
                        text: "nop;".into(),
                        kind: TokenKind::Plain,
                        target: None,
                    }],
                    va: Some(0x1000),
                    guess: None,
                }],
            },
        );
        let mut debug = DebugState::default();
        let mut assist_config = assist::Config {
            enabled: true,
            model: "test-model".into(),
            ..assist::Config::default()
        };
        let mut assist_state = assist::State::default();
        let ctx = egui::Context::default();
        let input = egui::RawInput {
            screen_rect: Some(egui::Rect::from_min_size(
                egui::pos2(0.0, 0.0),
                egui::vec2(1280.0, 800.0),
            )),
            ..egui::RawInput::default()
        };
        let mut output = ctx.run_ui(input, |ctx| {
            egui::CentralPanel::default().show(ctx, |ui| {
                let action = decompile_view::show(
                    ui,
                    &mut project,
                    &mut debug,
                    &mut assist_config,
                    &mut assist_state,
                );
                assert!(action.is_none());
            });
        });
        output.textures_delta.clear();
    }

    #[test]
    fn omnibox_finds_addresses_names_and_strings() {
        let mut project = sample_project();
        project.names.insert(0x1000, "decrypt_packet".into());

        let hit = project.find("decrypt", 8).into_iter().next().unwrap();
        assert_eq!((hit.va, hit.kind), (0x1000, "routine"));

        let hit = project.find("0x1000", 8).into_iter().next().unwrap();
        assert_eq!((hit.va, hit.kind), (0x1000, "address"));

        let hit = project.find("func:decrypt", 8).into_iter().next().unwrap();
        assert_eq!(hit.va, 0x1000);

        assert!(project.find("str:anything", 8).is_empty());
        assert!(project.find("fade", 8).is_empty());
        assert_eq!(parse_address("add"), None);
        assert_eq!(parse_address("0x10"), Some(0x10));
    }

    #[test]
    fn graph_tab_renders_without_a_saved_view() {
        let mut project = sample_project();
        let ctx = egui::Context::default();
        let input = egui::RawInput {
            screen_rect: Some(egui::Rect::from_min_size(
                egui::pos2(0.0, 0.0),
                egui::vec2(1280.0, 800.0),
            )),
            ..egui::RawInput::default()
        };
        let mut output = ctx.run_ui(input, |ctx| {
            egui::CentralPanel::default().show(ctx, |ui| {
                let action = graph_view::show(ui, &mut project, None);
                assert!(action.is_none());
            });
        });
        output.textures_delta.clear();
    }

    #[test]
    fn advanced_tab_renders_with_and_without_a_file() {
        let project = sample_project();
        let mut state = AdvancedState::default();
        let ctx = egui::Context::default();

        for project in [None, Some(&project)] {
            let input = egui::RawInput {
                screen_rect: Some(egui::Rect::from_min_size(
                    egui::pos2(0.0, 0.0),
                    egui::vec2(1280.0, 800.0),
                )),
                ..egui::RawInput::default()
            };
            let mut output = ctx.run_ui(input, |ctx| {
                egui::CentralPanel::default().show(ctx, |ui| {
                    let action = advanced::show(ui, &mut state, project, Some(0x1000));
                    assert!(action.is_none());
                });
            });
            output.textures_delta.clear();
        }
    }

    #[test]
    fn guide_renders_the_tour_over_recorded_anchors() {
        let ctx = egui::Context::default();
        let mut guide = Guide::default();
        guide.start();
        for (key, x) in [("logo", 30.0), ("open", 300.0), ("tab_listing", 60.0)] {
            guide.record(
                key,
                egui::Rect::from_min_size(egui::pos2(x, 20.0), egui::vec2(80.0, 24.0)),
            );
        }
        let input = egui::RawInput {
            screen_rect: Some(egui::Rect::from_min_size(
                egui::pos2(0.0, 0.0),
                egui::vec2(1280.0, 800.0),
            )),
            ..egui::RawInput::default()
        };
        let mut output = ctx.run_ui(input, |ctx| {
            let _ = guide.show(ctx);
            egui::CentralPanel::default().show(ctx, |_ui| {});
        });
        output.textures_delta.clear();
        assert!(guide.is_open());
    }

    #[test]
    fn patch_tab_renders_without_an_attachment() {
        let mut state = AttachState::default();
        let ctx = egui::Context::default();
        let input = egui::RawInput {
            screen_rect: Some(egui::Rect::from_min_size(
                egui::pos2(0.0, 0.0),
                egui::vec2(1280.0, 800.0),
            )),
            ..egui::RawInput::default()
        };
        let mut output = ctx.run_ui(input, |ctx| {
            egui::CentralPanel::default().show(ctx, |ui| {
                let action = state.patch_tab(ui);
                assert!(action.is_none());
            });
        });
        output.textures_delta.clear();
    }
}
