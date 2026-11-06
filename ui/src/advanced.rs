use std::path::Path;
use std::sync::Arc;
use std::sync::mpsc::{self, Receiver};
use std::thread;
use std::time::Duration;

use eframe::egui::{self, RichText, Ui};
use euphoria_decompiler::{Decompiler, FieldAccess};
use euphoria_engine::search::{self, Pattern};
use euphoria_engine::{Analysis, ByteMatch, PACKED_ENTROPY, Patch, Section};

use crate::tabs::{self, Action};
use crate::{Project, theme, tools};

const CREDIT: &str = "This Hypervisor was provided by .zhk_ on Discord";
const AMD_VENDOR: &str = "AuthenticAMD";
const INTEL_VENDOR: &str = "GenuineIntel";

const SEARCH_LIMIT: usize = 500;
const SNIPPET_BYTES: usize = 16;
const RESULT_HEIGHT: f32 = 220.0;
const MAX_PATCH_BYTES: usize = 4096;
const MAX_TOP_ROUTINES: usize = 6;
const MAX_SIGNAL_NAMES: usize = 8;

const SIGNALS: &[(&str, &[&str])] = &[
    (
        "Debugger checks",
        &[
            "IsDebuggerPresent",
            "CheckRemoteDebuggerPresent",
            "NtQueryInformationProcess",
            "NtSetInformationThread",
            "OutputDebugStringA",
            "OutputDebugStringW",
            "DebugActiveProcess",
            "QueryPerformanceCounter",
            "GetTickCount",
            "GetTickCount64",
        ],
    ),
    (
        "Process injection",
        &[
            "VirtualAllocEx",
            "WriteProcessMemory",
            "ReadProcessMemory",
            "CreateRemoteThread",
            "NtCreateThreadEx",
            "QueueUserAPC",
            "SetWindowsHookExA",
            "SetWindowsHookExW",
            "VirtualProtectEx",
            "NtUnmapViewOfSection",
        ],
    ),
    (
        "Process control",
        &[
            "CreateProcessA",
            "CreateProcessW",
            "ShellExecuteA",
            "ShellExecuteW",
            "WinExec",
            "OpenProcess",
            "TerminateProcess",
            "CreateToolhelp32Snapshot",
            "Process32First",
            "Process32FirstW",
            "Process32Next",
            "Process32NextW",
            "EnumProcesses",
        ],
    ),
    (
        "Networking",
        &[
            "WSAStartup",
            "socket",
            "connect",
            "send",
            "recv",
            "getaddrinfo",
            "URLDownloadToFileA",
            "URLDownloadToFileW",
            "InternetOpenA",
            "InternetOpenW",
            "InternetOpenUrlA",
            "InternetOpenUrlW",
            "InternetReadFile",
            "HttpSendRequestA",
            "HttpSendRequestW",
            "WinHttpOpen",
            "WinHttpConnect",
            "WinHttpOpenRequest",
            "WinHttpSendRequest",
            "WinHttpReceiveResponse",
        ],
    ),
    (
        "Cryptography",
        &[
            "CryptEncrypt",
            "CryptDecrypt",
            "CryptAcquireContextA",
            "CryptAcquireContextW",
            "CryptGenKey",
            "BCryptEncrypt",
            "BCryptDecrypt",
            "BCryptGenerateSymmetricKey",
            "BCryptOpenAlgorithmProvider",
        ],
    ),
    (
        "Registry",
        &[
            "RegOpenKeyExA",
            "RegOpenKeyExW",
            "RegSetValueExA",
            "RegSetValueExW",
            "RegCreateKeyExA",
            "RegCreateKeyExW",
            "RegDeleteKeyA",
            "RegDeleteKeyW",
        ],
    ),
    (
        "Files and services",
        &[
            "CreateFileA",
            "CreateFileW",
            "WriteFile",
            "DeleteFileA",
            "DeleteFileW",
            "MoveFileExA",
            "MoveFileExW",
            "CopyFileA",
            "CopyFileW",
            "CreateServiceA",
            "CreateServiceW",
            "StartServiceA",
            "StartServiceW",
        ],
    ),
];

#[derive(Clone, Copy, Default, PartialEq, Eq)]
enum Scope {
    #[default]
    Whole,
    Code,
    Routine,
}

impl Scope {
    const ALL: [Self; 3] = [Self::Whole, Self::Code, Self::Routine];

    fn label(self) -> &'static str {
        match self {
            Self::Whole => "All sections",
            Self::Code => "Executable sections",
            Self::Routine => "Current routine",
        }
    }
}

#[derive(Default)]
struct SearchState {
    pattern: String,
    scope: Scope,
    job: Option<Receiver<Vec<ByteMatch>>>,
    results: Vec<ByteMatch>,
    summary: String,
    error: Option<String>,
    selected: Option<usize>,
}

impl SearchState {
    fn start(&mut self, analysis: &Analysis, routine: Option<(u64, u64)>, ctx: &egui::Context) {
        self.error = None;
        self.results.clear();
        self.selected = None;
        let pattern = match Pattern::parse(&self.pattern) {
            Ok(pattern) => pattern,
            Err(message) => {
                self.error = Some(message);
                return;
            }
        };
        let sections = match self.scope {
            Scope::Whole => analysis.sections.clone(),
            Scope::Code => analysis
                .sections
                .iter()
                .copied()
                .filter(|section| section.executable)
                .collect(),
            Scope::Routine => {
                let Some((va, size)) = routine else {
                    self.error = Some("Put the listing cursor inside a routine first".to_owned());
                    return;
                };
                let Some(offset) = analysis.file_offset(va) else {
                    self.error = Some(format!("No file data at {va:#x}"));
                    return;
                };
                if size == 0 {
                    self.error = Some("That routine is empty".to_owned());
                    return;
                }
                vec![Section {
                    va,
                    offset: offset as u64,
                    size,
                    executable: true,
                }]
            }
        };
        if sections.is_empty() {
            self.error = Some("There are no sections to search in".to_owned());
            return;
        }

        let data = Arc::clone(&analysis.data);
        let (sender, receiver) = mpsc::channel();
        let ctx = ctx.clone();
        self.summary = format!(
            "{} in {}",
            pattern.text(),
            self.scope.label().to_lowercase()
        );
        thread::spawn(move || {
            let hits = search::find(&data, &sections, &pattern, SEARCH_LIMIT);
            let _ = sender.send(hits);
            ctx.request_repaint();
        });
        self.job = Some(receiver);
    }

    fn poll(&mut self) -> bool {
        let Some(receiver) = &self.job else {
            return false;
        };
        match receiver.try_recv() {
            Ok(hits) => {
                self.results = hits;
                self.job = None;
                true
            }
            Err(mpsc::TryRecvError::Empty) => false,
            Err(mpsc::TryRecvError::Disconnected) => {
                self.error = Some("The search stopped unexpectedly".to_owned());
                self.job = None;
                true
            }
        }
    }
}

#[derive(Default)]
struct FieldState {
    job: Option<Receiver<Result<Vec<FieldAccess>, String>>>,
    for_va: Option<u64>,
    name: String,
    outcome: Option<Result<Vec<FieldAccess>, String>>,
}

impl FieldState {
    fn poll(&mut self, project: &Project, cursor: Option<u64>, ctx: &egui::Context) {
        if let Some(receiver) = &self.job
            && let Ok(outcome) = receiver.try_recv()
        {
            self.outcome = Some(outcome);
            self.job = None;
        }

        let target = cursor
            .and_then(|va| project.analysis.function_containing(va))
            .map(|function| function.va);
        if target == self.for_va {
            return;
        }
        self.for_va = target;
        self.outcome = None;
        self.job = None;
        self.name.clear();

        let Some(va) = target else {
            return;
        };
        self.name = project
            .analysis
            .function_at(va)
            .and_then(|function| function.name.clone())
            .unwrap_or_else(|| format!("sub_{va:x}"));

        let analysis = Arc::clone(&project.analysis);
        let listing = Arc::clone(&project.listing);
        let (sender, receiver) = mpsc::channel();
        let ctx = ctx.clone();
        thread::spawn(move || {
            let outcome = Decompiler::new(&analysis, &listing)
                .field_map(va)
                .map_err(|error| format!("{error:#}"));
            let _ = sender.send(outcome);
            ctx.request_repaint();
        });
        self.job = Some(receiver);
    }
}

#[derive(Default)]
struct PatchStudio {
    address: String,
    length: String,
    replacement: String,
    patches: Vec<Patch>,
    error: Option<String>,
}

impl PatchStudio {
    fn measure(&mut self, analysis: &Analysis) {
        self.error = None;
        let Some(va) = self.target(analysis) else {
            return;
        };
        match text_length(analysis, va) {
            Ok(length) => self.length = length.to_string(),
            Err(message) => self.error = Some(message),
        }
    }

    fn stage(&mut self, analysis: &Analysis) {
        self.error = None;
        match self.plan(analysis) {
            Ok(patch) => self.patches.push(patch),
            Err(message) => self.error = Some(message),
        }
    }

    fn plan(&self, analysis: &Analysis) -> Result<Patch, String> {
        let Some(va) = self.target(analysis) else {
            return Err("Enter an address such as 0x140001000".to_owned());
        };
        let original_len = match self.length.trim() {
            "" => text_length(analysis, va)?,
            text => text
                .parse::<usize>()
                .map_err(|_| "Enter a length in bytes, or leave it blank".to_owned())?,
        };
        if original_len == 0 {
            return Err("The edit needs at least one byte to replace".to_owned());
        }
        if original_len > MAX_PATCH_BYTES {
            return Err(format!("Edits are limited to {MAX_PATCH_BYTES} bytes"));
        }
        if self.replacement.is_empty() {
            return Err("Enter the replacement text".to_owned());
        }
        if self.replacement.contains('\0') {
            return Err("The replacement cannot contain a null byte".to_owned());
        }
        let patch = analysis
            .plan_patch(va, original_len, &self.replacement)
            .map_err(|error| format!("{error:#}"))?;
        if let Some(other) = self.patches.iter().find(|other| overlaps(other, &patch)) {
            return Err(format!(
                "That overlaps the edit already staged at {:#x}",
                other.va
            ));
        }
        Ok(patch)
    }

    fn save(&mut self, analysis: &Analysis) -> Option<Action> {
        if self.patches.is_empty() {
            return None;
        }
        let path = rfd::FileDialog::new()
            .set_title("Save patched copy")
            .set_file_name(suggested_name(&analysis.file_name))
            .save_file()?;
        self.error = None;
        match analysis.save_patched(&path, &self.patches) {
            Ok(()) => Some(Action::Status(format!(
                "Saved patched copy to {}",
                path.display()
            ))),
            Err(error) => {
                self.error = Some(format!("{error:#}"));
                None
            }
        }
    }

    fn target(&self, analysis: &Analysis) -> Option<u64> {
        let text = self.address.trim();
        if text.is_empty() {
            return None;
        }
        analysis.resolve(text)
    }
}

#[derive(Default)]
pub struct AdvancedState {
    pub enabled: bool,
    hypervisor: Hypervisor,
    search: SearchState,
    fields: FieldState,
    studio: PatchStudio,
    recon: Option<(String, Recon)>,
}

impl AdvancedState {
    pub fn reset_file(&mut self) {
        self.search = SearchState::default();
        self.fields = FieldState::default();
        self.studio = PatchStudio::default();
        self.recon = None;
    }
}

struct Recon {
    notes: Vec<String>,
    signals: Vec<(&'static str, Vec<String>)>,
    top: Vec<(u64, String, u64)>,
}

pub fn show(
    ui: &mut Ui,
    state: &mut AdvancedState,
    project: Option<&Project>,
    cursor: Option<u64>,
) -> Option<Action> {
    state.search.poll();
    if let Some(project) = project {
        state.fields.poll(project, cursor, ui.ctx());
    }

    let mut action = None;
    egui::ScrollArea::vertical()
        .id_salt("advanced_tools")
        .auto_shrink([false, false])
        .show(ui, |ui| {
            settings_card(ui, &mut state.enabled, project);
            ui.add_space(10.0);

            if let Some(project) = project {
                if state
                    .recon
                    .as_ref()
                    .is_none_or(|(sha, _)| sha != &project.analysis.sha256)
                {
                    state.recon = Some((project.analysis.sha256.clone(), build_recon(project)));
                }
                if let Some((_, recon)) = &state.recon {
                    keep(&mut action, recon_card(ui, project, recon));
                }
                ui.add_space(10.0);

                keep(
                    &mut action,
                    search_card(ui, &mut state.search, project, cursor),
                );
                ui.add_space(10.0);

                keep(
                    &mut action,
                    patch_card(ui, &mut state.studio, project, cursor),
                );
                ui.add_space(10.0);

                fields_card(ui, &state.fields);
                ui.add_space(10.0);
            } else {
                tools::card(ui, |ui| {
                    ui.label(
                        RichText::new(
                            "Open a binary to search bytes, stage edits, and inspect routines.",
                        )
                        .color(theme::MUTED),
                    );
                });
                ui.add_space(10.0);
            }

            hypervisor_card(ui, &mut state.hypervisor);
        });
    action
}

fn keep(slot: &mut Option<Action>, next: Option<Action>) {
    if next.is_some() {
        *slot = next;
    }
}

fn settings_card(ui: &mut Ui, enabled: &mut bool, project: Option<&Project>) {
    tools::card(ui, |ui| {
        ui.horizontal(|ui| {
            ui.checkbox(enabled, "Advanced Analysis").on_hover_text(
                "Show the APK, SQL, Networking, and XOR tabs. These work on files and data \
                 rather than the debugger or disassembly views.",
            );
            if let Some(project) = project {
                let analysis = &project.analysis;
                ui.add_space(12.0);
                ui.label(
                    RichText::new(format!(
                        "{} · {} · entry {:#x} · {} routines · {} imports",
                        analysis.file_name,
                        crate::arch_label(analysis.arch),
                        analysis.entry,
                        analysis.functions.len(),
                        analysis.imports.len(),
                    ))
                    .color(theme::MUTED)
                    .size(11.5),
                );
            }
        });
    });
}

fn recon_card(ui: &mut Ui, project: &Project, recon: &Recon) -> Option<Action> {
    let inspection = &project.inspection;
    let mut action = None;
    tools::card(ui, |ui| {
        ui.horizontal(|ui| {
            ui.label(RichText::new("Recon").strong());
            ui.label(
                RichText::new(format!(
                    "{} sections · entropy {:.2} · {} detections",
                    inspection.sections.len(),
                    inspection.entropy,
                    inspection.detections.len(),
                ))
                .color(theme::MUTED)
                .size(11.5),
            );
        });

        if !recon.notes.is_empty() {
            ui.add_space(4.0);
            for note in &recon.notes {
                ui.label(RichText::new(format!("• {note}")).color(theme::NUMBER));
            }
        }

        ui.add_space(6.0);
        if recon.signals.is_empty() {
            ui.label(RichText::new("No well-known risky imports were found.").color(theme::MUTED));
        } else {
            egui::Grid::new("advanced_signals")
                .num_columns(2)
                .spacing([18.0, 5.0])
                .show(ui, |ui| {
                    for (category, names) in &recon.signals {
                        ui.label(RichText::new(*category).color(theme::MUTED));
                        let shown = names
                            .iter()
                            .take(MAX_SIGNAL_NAMES)
                            .cloned()
                            .collect::<Vec<_>>()
                            .join(", ");
                        let extra = names.len().saturating_sub(MAX_SIGNAL_NAMES);
                        let text = if extra == 0 {
                            shown
                        } else {
                            format!("{shown}, +{extra} more")
                        };
                        ui.label(RichText::new(text).font(theme::mono()).size(11.5))
                            .on_hover_text(names.join("\n"));
                        ui.end_row();
                    }
                });
        }

        ui.add_space(8.0);
        ui.label(RichText::new("Largest routines").color(theme::MUTED));
        ui.horizontal_wrapped(|ui| {
            for (va, name, size) in &recon.top {
                let label = format!("{name} · {}", size_label(*size));
                if ui
                    .add(egui::Button::new(
                        RichText::new(label).font(theme::mono()).size(11.5),
                    ))
                    .on_hover_text(format!("{va:#x} · {size} bytes"))
                    .clicked()
                {
                    action = Some(Action::Go(*va));
                }
            }
        });
    });
    action
}

fn build_recon(project: &Project) -> Recon {
    let analysis = &project.analysis;
    let inspection = &project.inspection;

    let mut notes = Vec::new();
    if analysis.function_containing(analysis.entry).is_none() {
        notes.push("The entry point is outside every known routine".to_owned());
    }
    let dense: Vec<&str> = inspection
        .sections
        .iter()
        .filter(|section| section.executable && section.entropy >= PACKED_ENTROPY)
        .map(|section| section.name.as_str())
        .collect();
    if !dense.is_empty() {
        notes.push(format!(
            "Executable sections look packed or encrypted: {}",
            dense.join(", ")
        ));
    }
    if analysis.imports.is_empty() {
        notes.push("No imports, which can mean static linking or packing".to_owned());
    }

    let mut signals = Vec::new();
    for (category, names) in SIGNALS {
        let mut found: Vec<String> = Vec::new();
        for import in &analysis.imports {
            let short = import.rsplit('!').next().unwrap_or(import);
            if names.iter().any(|name| short.eq_ignore_ascii_case(name))
                && !found.iter().any(|seen| seen.eq_ignore_ascii_case(short))
            {
                found.push(short.to_owned());
            }
        }
        if !found.is_empty() {
            found.sort_by_key(|name| name.to_lowercase());
            signals.push((*category, found));
        }
    }

    let mut functions: Vec<_> = analysis.functions.iter().collect();
    functions.sort_by_key(|function| std::cmp::Reverse(function.size));
    let top = functions
        .into_iter()
        .take(MAX_TOP_ROUTINES)
        .map(|function| {
            let name = function
                .name
                .clone()
                .unwrap_or_else(|| format!("sub_{:x}", function.va));
            (function.va, name, function.size)
        })
        .collect();

    Recon {
        notes,
        signals,
        top,
    }
}

fn search_card(
    ui: &mut Ui,
    state: &mut SearchState,
    project: &Project,
    cursor: Option<u64>,
) -> Option<Action> {
    let analysis = &project.analysis;
    let routine = cursor
        .and_then(|va| analysis.function_containing(va))
        .map(|function| (function.va, function.size));
    let mut action = None;

    tools::card(ui, |ui| {
        ui.horizontal(|ui| {
            ui.label(RichText::new("Byte search").strong());
            ui.label(
                RichText::new("?? or ? matches any byte")
                    .color(theme::MUTED)
                    .size(11.5),
            );
        });
        ui.add_space(4.0);
        ui.horizontal(|ui| {
            ui.add(
                egui::TextEdit::singleline(&mut state.pattern)
                    .hint_text("48 8B ?? 89 or 488B??89")
                    .font(theme::mono())
                    .desired_width(340.0),
            );
            egui::ComboBox::from_id_salt("advanced_search_scope")
                .selected_text(state.scope.label())
                .show_ui(ui, |ui| {
                    for scope in Scope::ALL {
                        ui.selectable_value(&mut state.scope, scope, scope.label());
                    }
                });

            let find = ui.add_enabled(
                state.job.is_none() && !state.pattern.trim().is_empty(),
                egui::Button::new("Find"),
            );
            if find.clicked() {
                state.start(analysis, routine, ui.ctx());
            }

            let from_cursor =
                ui.add_enabled(cursor.is_some(), egui::Button::new("Bytes at cursor"));
            if from_cursor.clicked()
                && let Some(va) = cursor
                && let Some(bytes) = analysis.read(va, 8)
            {
                state.pattern = tabs::hex_bytes(bytes);
                state.scope = Scope::Whole;
            }
        });

        if let Some(error) = &state.error {
            ui.add_space(4.0);
            ui.label(RichText::new(error).color(theme::ERROR));
        }

        if state.job.is_some() {
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                ui.spinner();
                ui.label(RichText::new("Scanning sections...").color(theme::MUTED));
            });
            ui.ctx().request_repaint_after(Duration::from_millis(100));
        } else if state.results.is_empty() {
            if !state.summary.is_empty() && state.error.is_none() {
                ui.add_space(4.0);
                ui.label(RichText::new("No matches").color(theme::MUTED));
            }
        } else {
            let limited = if state.results.len() >= SEARCH_LIMIT {
                " · limit reached"
            } else {
                ""
            };
            ui.add_space(4.0);
            ui.label(
                RichText::new(format!(
                    "{} matches for {}{limited}",
                    state.results.len(),
                    state.summary
                ))
                .color(theme::MUTED),
            );
            ui.add_space(2.0);
            egui::ScrollArea::vertical()
                .id_salt("advanced_search_results")
                .max_height(RESULT_HEIGHT)
                .auto_shrink([false, true])
                .show(ui, |ui| {
                    for (index, hit) in state.results.iter().enumerate() {
                        let section = analysis
                            .section_names
                            .get(hit.section)
                            .map_or("", String::as_str);
                        let snippet = analysis
                            .read(hit.va, SNIPPET_BYTES)
                            .map(tabs::hex_bytes)
                            .unwrap_or_default();
                        let label = format!("{:#x}  {section:<10}  {snippet}", hit.va);
                        let selected = state.selected == Some(index);
                        if ui
                            .selectable_label(
                                selected,
                                RichText::new(label).font(theme::mono()).size(12.0),
                            )
                            .clicked()
                        {
                            state.selected = Some(index);
                            action = Some(Action::Go(hit.va));
                        }
                    }
                });
        }
    });
    action
}

fn patch_card(
    ui: &mut Ui,
    studio: &mut PatchStudio,
    project: &Project,
    cursor: Option<u64>,
) -> Option<Action> {
    let analysis = &project.analysis;
    let mut action = None;
    tools::card(ui, |ui| {
        ui.horizontal(|ui| {
            ui.label(RichText::new("Patch studio").strong());
            ui.label(
                RichText::new("Edits are written to a new copy; the original is never changed.")
                    .color(theme::MUTED)
                    .size(11.5),
            );
        });
        ui.add_space(4.0);

        ui.horizontal(|ui| {
            ui.label(RichText::new("Address").color(theme::MUTED));
            ui.add(
                egui::TextEdit::singleline(&mut studio.address)
                    .hint_text("0x140001000 or routine name")
                    .font(theme::mono())
                    .desired_width(220.0),
            );
            if ui
                .add_enabled(cursor.is_some(), egui::Button::new("At cursor"))
                .clicked()
                && let Some(va) = cursor
            {
                studio.address = format!("{va:#x}");
                studio.error = None;
            }
            ui.add_space(10.0);
            ui.label(RichText::new("Length").color(theme::MUTED));
            ui.add(
                egui::TextEdit::singleline(&mut studio.length)
                    .hint_text("blank = text")
                    .font(theme::mono())
                    .desired_width(100.0),
            )
            .on_hover_text("Bytes to replace. Leave it blank to measure a null-terminated string.");
            if ui.button("Measure").clicked() {
                studio.measure(analysis);
            }
        });

        ui.horizontal(|ui| {
            ui.label(RichText::new("Replace").color(theme::MUTED));
            ui.add(
                egui::TextEdit::singleline(&mut studio.replacement)
                    .hint_text("New text")
                    .font(theme::mono())
                    .desired_width(460.0),
            );
            if ui.button("Stage edit").clicked() {
                studio.stage(analysis);
            }
        });

        if let Some(error) = &studio.error {
            ui.add_space(4.0);
            ui.label(RichText::new(error).color(theme::ERROR));
        }

        if studio.patches.is_empty() {
            return;
        }
        ui.add_space(6.0);
        let mut remove = None;
        for (index, patch) in studio.patches.iter().enumerate() {
            ui.horizontal(|ui| {
                if ui
                    .small_button("×")
                    .on_hover_text("Remove this edit")
                    .clicked()
                {
                    remove = Some(index);
                }
                ui.label(
                    RichText::new(format!("{:#x}", patch.va))
                        .font(theme::mono())
                        .color(theme::TEXT),
                );
                ui.label(
                    RichText::new(format!("{} bytes", patch.after.len()))
                        .color(theme::MUTED)
                        .size(11.5),
                );
                ui.label(
                    RichText::new(preview(&patch.before))
                        .font(theme::mono())
                        .size(11.5)
                        .color(theme::MUTED),
                );
                ui.label(RichText::new("→").color(theme::MUTED));
                ui.label(
                    RichText::new(preview(&patch.after))
                        .font(theme::mono())
                        .size(11.5)
                        .color(theme::ACCENT),
                );
            });
        }
        if let Some(index) = remove {
            studio.patches.remove(index);
        }

        ui.add_space(4.0);
        ui.horizontal(|ui| {
            if ui.button("Save patched copy...").clicked() {
                action = studio.save(analysis);
            }
            if ui.button("Clear staged edits").clicked() {
                studio.patches.clear();
            }
            ui.label(RichText::new(format!("{} staged", studio.patches.len())).color(theme::MUTED));
        });
    });
    action
}

fn fields_card(ui: &mut Ui, state: &FieldState) {
    tools::card(ui, |ui| {
        ui.horizontal(|ui| {
            ui.label(RichText::new("Structure hints").strong());
            if let Some(va) = state.for_va {
                ui.label(
                    RichText::new(format!("{} @ {va:#x}", state.name))
                        .font(theme::mono())
                        .color(theme::MUTED)
                        .size(11.5),
                );
            }
        });

        match &state.outcome {
            Some(Ok(fields)) if fields.is_empty() => {
                ui.label(
                    RichText::new("This routine only touches locals and globals.")
                        .color(theme::MUTED),
                );
            }
            Some(Ok(fields)) => {
                egui::Grid::new("advanced_fields")
                    .num_columns(4)
                    .spacing([18.0, 4.0])
                    .show(ui, |ui| {
                        for title in ["Field", "Type", "Reads", "Writes"] {
                            ui.label(RichText::new(title).color(theme::MUTED).size(11.5));
                        }
                        ui.end_row();
                        for field in fields {
                            let color = if field.float {
                                theme::NUMBER
                            } else {
                                theme::TEXT
                            };
                            ui.label(
                                RichText::new(field_label(field))
                                    .font(theme::mono())
                                    .color(color),
                            );
                            ui.label(
                                RichText::new(field.type_name())
                                    .font(theme::mono())
                                    .color(theme::MUTED),
                            );
                            ui.label(RichText::new(field.reads.to_string()).color(theme::MUTED));
                            ui.label(RichText::new(field.writes.to_string()).color(
                                if field.writes > 0 {
                                    theme::NUMBER
                                } else {
                                    theme::MUTED
                                },
                            ));
                            ui.end_row();
                        }
                    });
            }
            Some(Err(error)) => {
                ui.label(RichText::new(error).color(theme::ERROR));
            }
            None => {
                let message = if state.job.is_some() {
                    "Decompiling the routine..."
                } else {
                    "Move the listing cursor inside a routine to see its fields."
                };
                ui.horizontal(|ui| {
                    if state.job.is_some() {
                        ui.spinner();
                    }
                    ui.label(RichText::new(message).color(theme::MUTED));
                });
            }
        }

        if state.job.is_some() {
            ui.ctx().request_repaint_after(Duration::from_millis(100));
        }
    });
}

fn field_label(field: &FieldAccess) -> String {
    if field.offset < 0 {
        format!("{} - {:#x}", field.base, -field.offset)
    } else {
        format!("{} + {:#x}", field.base, field.offset)
    }
}

fn preview(bytes: &[u8]) -> String {
    let mut text: String = bytes
        .iter()
        .take(24)
        .map(|&byte| {
            if (0x20..0x7F).contains(&byte) {
                char::from(byte)
            } else {
                '.'
            }
        })
        .collect();
    if bytes.len() > 24 {
        text.push('…');
    }
    text
}

fn text_length(analysis: &Analysis, va: u64) -> Result<usize, String> {
    let bytes = analysis
        .read(va, MAX_PATCH_BYTES)
        .ok_or_else(|| format!("No file data at {va:#x}"))?;
    let length = bytes
        .iter()
        .position(|&byte| byte == 0)
        .ok_or("No null terminator nearby; enter the original length in bytes")?;
    if length == 0 {
        return Err("That address starts with a null byte".to_owned());
    }
    Ok(length)
}

fn overlaps(left: &Patch, right: &Patch) -> bool {
    left.offset < right.offset + right.before.len()
        && right.offset < left.offset + left.before.len()
}

fn suggested_name(file_name: &str) -> String {
    let path = Path::new(file_name);
    let stem = path.file_stem().unwrap_or_default().to_string_lossy();
    match path.extension().and_then(|extension| extension.to_str()) {
        Some(extension) => format!("{stem}.patched.{extension}"),
        None => format!("{stem}.patched"),
    }
}

fn size_label(size: u64) -> String {
    if size >= 1024 {
        format!("{:.1} KB", size as f64 / 1024.0)
    } else {
        format!("{size} B")
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum Hypervisor {
    #[default]
    Idle,
    Unsupported(String),
    Confirming,
    NotBuilt,
}

#[cfg(target_arch = "x86_64")]
fn cpu_vendor() -> String {
    let info = std::arch::x86_64::__cpuid(0);
    let bytes: Vec<u8> = [info.ebx, info.edx, info.ecx]
        .iter()
        .flat_map(|part| part.to_le_bytes())
        .collect();
    String::from_utf8_lossy(&bytes).into_owned()
}

#[cfg(not(target_arch = "x86_64"))]
fn cpu_vendor() -> String {
    String::new()
}

fn first_check(vendor: &str) -> Hypervisor {
    if vendor == AMD_VENDOR {
        return Hypervisor::Confirming;
    }

    let cpu = if vendor == INTEL_VENDOR {
        "This machine has an Intel CPU."
    } else {
        "This machine does not have an AMD CPU."
    };
    Hypervisor::Unsupported(format!(
        "The Euphoria Hypervisor only runs on AMD CPUs right now. {cpu}"
    ))
}

fn hypervisor_card(ui: &mut Ui, state: &mut Hypervisor) {
    tools::card(ui, |ui| {
        ui.label(RichText::new("Euphoria Hypervisor").size(18.0));
        ui.add_space(8.0);
        if ui.button("Start").clicked() {
            *state = first_check(&cpu_vendor());
        }
        ui.add_space(6.0);
        ui.label(RichText::new(CREDIT).size(11.5).color(theme::MUTED));

        if *state == Hypervisor::NotBuilt {
            ui.add_space(14.0);
            ui.label(
                RichText::new(
                    "The hypervisor is not built yet, so nothing was started. \
                     Its code will go in the hypervisor folder.",
                )
                .color(theme::NUMBER),
            );
        }
    });

    let next = match state {
        Hypervisor::Unsupported(message) => {
            let message = message.clone();
            dialog(ui, "Not available on this CPU", &message, |ui| {
                ui.button("OK").clicked().then_some(Hypervisor::Idle)
            })
        }
        Hypervisor::Confirming => dialog(
            ui,
            "Are you sure you know what you are doing?",
            "A hypervisor runs underneath the operating system. A mistake at this level can \
             crash or freeze the whole machine.",
            |ui| {
                if ui.button("Yes, continue").clicked() {
                    Some(Hypervisor::NotBuilt)
                } else if ui.button("Cancel").clicked() {
                    Some(Hypervisor::Idle)
                } else {
                    None
                }
            },
        ),
        Hypervisor::Idle | Hypervisor::NotBuilt => None,
    };
    if let Some(next) = next {
        *state = next;
    }
}

fn dialog(
    ui: &Ui,
    title: &str,
    message: &str,
    buttons: impl FnOnce(&mut Ui) -> Option<Hypervisor>,
) -> Option<Hypervisor> {
    egui::Modal::new(egui::Id::unique("hypervisor_dialog"))
        .show(ui.ctx(), |ui| {
            ui.set_max_width(440.0);
            ui.label(RichText::new(title).size(16.0));
            ui.add_space(8.0);
            ui.label(message);
            ui.add_space(14.0);
            ui.horizontal(buttons).inner
        })
        .inner
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;

    fn analysis(data: &[u8]) -> Analysis {
        Analysis {
            path: "test.bin".into(),
            arch: euphoria_engine::Arch::X86_64,
            entry: 0x1000,
            sections: vec![Section {
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
            image_base: 0,
            is_pe: true,
            file_name: "test.bin".into(),
            sha256: "00".into(),
            extras: serde_json::Value::Null,
            data: Arc::new(data.to_vec()),
        }
    }

    #[test]
    fn wildcard_search_finishes_with_the_expected_match() {
        let analysis = analysis(&[0x8B, 0x41, 0x10, 0x89, 0x51, 0x14, 0xC3]);
        let ctx = egui::Context::default();
        let mut state = SearchState {
            pattern: "8B 41 ??".into(),
            ..SearchState::default()
        };
        state.start(&analysis, None, &ctx);
        let mut finished = false;
        for _ in 0..500 {
            if state.poll() {
                finished = true;
                break;
            }
            thread::sleep(Duration::from_millis(2));
        }
        assert!(finished, "the search did not finish");
        assert!(state.error.is_none());
        assert_eq!(
            state.results,
            vec![ByteMatch {
                va: 0x1000,
                offset: 0,
                section: 0
            }]
        );
    }

    #[test]
    fn staged_edits_reject_overlap_and_save_a_verified_copy() {
        let data = b"http://old.example\0".to_vec();
        let analysis = analysis(&data);
        let mut studio = PatchStudio {
            address: "0x1000".into(),
            replacement: "http://new".into(),
            ..PatchStudio::default()
        };

        studio.measure(&analysis);
        assert_eq!(studio.length, "18");
        studio.stage(&analysis);
        assert!(studio.error.is_none(), "{:?}", studio.error);
        assert_eq!(studio.patches.len(), 1);

        studio.replacement = "http://another".into();
        studio.stage(&analysis);
        assert!(
            studio
                .error
                .as_deref()
                .is_some_and(|text| text.contains("overlaps"))
        );
        assert_eq!(studio.patches.len(), 1);

        let path = std::env::temp_dir().join(format!("euphoria-patch-{}.bin", std::process::id()));
        let _ = std::fs::remove_file(&path);
        analysis.save_patched(&path, &studio.patches).unwrap();
        let saved = std::fs::read(&path).unwrap();
        let _ = std::fs::remove_file(&path);

        assert_eq!(saved.len(), data.len());
        assert_eq!(&saved[..10], b"http://new");
        assert!(saved[10..18].iter().all(|&byte| byte == 0));
        assert_eq!(saved[18], 0);
    }

    #[test]
    fn amd_goes_to_the_confirmation() {
        assert_eq!(first_check("AuthenticAMD"), Hypervisor::Confirming);
    }

    #[test]
    fn intel_and_others_are_stopped_first() {
        let intel = first_check("GenuineIntel");
        assert!(matches!(&intel, Hypervisor::Unsupported(text) if text.contains("Intel CPU")));

        let other = first_check("");
        assert!(matches!(&other, Hypervisor::Unsupported(text) if text.contains("AMD")));
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn reads_a_cpu_vendor() {
        assert_eq!(cpu_vendor().len(), 12);
    }

    #[test]
    fn preview_keeps_printable_text_and_shortens_the_rest() {
        assert_eq!(preview(b"https://local"), "https://local");
        assert_eq!(preview(b"a\0b\xff"), "a.b.");
        assert!(preview(&[b'x'; 40]).ends_with('…'));
    }

    #[test]
    fn names_a_patched_copy_beside_the_original() {
        assert_eq!(suggested_name("game.exe"), "game.patched.exe");
        assert_eq!(suggested_name("sample"), "sample.patched");
    }

    #[test]
    fn detects_overlapping_edits() {
        let patch = |offset: usize, len: usize| Patch {
            va: 0x1000 + offset as u64,
            offset,
            before: vec![0; len],
            after: vec![0; len],
        };
        assert!(overlaps(&patch(8, 4), &patch(10, 4)));
        assert!(!overlaps(&patch(8, 4), &patch(12, 4)));
        assert!(!overlaps(&patch(8, 4), &patch(0, 4)));
    }
}
