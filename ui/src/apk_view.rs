use std::sync::Arc;

use eframe::egui::{self, Color32, FontId, RichText, Sense, Ui};
use euphoria_android::{
    AndroidConfig, AndroidRuntime, AppInfo, CaptureEvent, Phase, SETUP_HELP, SOURCES,
};
use euphoria_apk::{Apk, ClassLine, is_dangerous_permission};

use crate::table::{self, Column, fill, fixed};
use crate::tabs::{Action, Filter};
use crate::{tabs, theme, tools};

const STRINGS: [Column; 4] = [
    fixed("DEX", 70.0),
    fixed("Index", 100.0),
    fixed("Encoding", 100.0),
    fill("Text"),
];
const FILES: [Column; 3] = [fill("File"), fixed("Bytes", 130.0), fixed("Packed", 130.0)];
const SIDEBAR_WIDTH: f32 = 420.0;
const SIDEBAR_ROW: f32 = 26.0;
const CODE_ROW: f32 = 20.0;
const CODE_WIDTH: f32 = 3000.0;
const MAX_TIP_CHARS: usize = 600;

#[derive(Clone, Copy, PartialEq)]
enum Section {
    Summary,
    Manifest,
    Classes,
    Strings,
    Files,
    Runtime,
}

struct ClassRow {
    dex: usize,
    class: usize,
    name: String,
}

pub struct ApkView {
    pub apk: Arc<Apk>,
    section: Section,
    classes: Vec<ClassRow>,
    class_filter: Filter,
    selected: Option<usize>,
    lines: Vec<ClassLine>,
    strings: Filter,
    escape_unicode: bool,
    files: Filter,
    settings_open: bool,
    setup_open: bool,
    settings: AndroidConfig,
    network_selected: Option<u64>,
}

impl ApkView {
    pub fn new(apk: Apk) -> Self {
        let mut classes = Vec::with_capacity(apk.class_count());
        for (dex_index, dex) in apk.dexes.iter().enumerate() {
            for (class_index, class) in dex.classes.iter().enumerate() {
                classes.push(ClassRow {
                    dex: dex_index,
                    class: class_index,
                    name: dex.class_name(class),
                });
            }
        }

        Self {
            section: Section::Summary,
            class_filter: Filter::all(classes.len()),
            selected: None,
            lines: Vec::new(),
            strings: Filter::all(apk.strings.len()),
            escape_unicode: false,
            files: Filter::all(apk.files.len()),
            classes,
            settings_open: false,
            setup_open: false,
            settings: AndroidConfig::default(),
            network_selected: None,
            apk: Arc::new(apk),
        }
    }

    fn select_class(&mut self, row: usize) {
        self.selected = Some(row);
        let info = &self.classes[row];
        let dex = &self.apk.dexes[info.dex];
        self.lines = dex.class_lines(&dex.classes[info.class]);
    }

    fn open_settings(&mut self, runtime: &AndroidRuntime) {
        self.settings = runtime.config().clone();
        self.settings_open = true;
    }
}

pub fn show(
    ui: &mut Ui,
    view: &mut Option<ApkView>,
    runtime: &mut AndroidRuntime,
) -> Option<Action> {
    if view.is_some() {
        runtime.ensure_scanned();
    }

    let mut action = None;
    let mut start_runtime = false;
    egui::Frame::new()
        .inner_margin(egui::Margin::symmetric(12, 10))
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                if ui.button("Load APK").clicked()
                    && let Some(path) = rfd::FileDialog::new()
                        .add_filter("Android package", &["apk"])
                        .pick_file()
                {
                    action = Some(Action::Open(path));
                }

                let Some(view) = view.as_mut() else {
                    return;
                };
                if ui
                    .add_enabled(runtime.can_run(), egui::Button::new("Run APK"))
                    .on_hover_text(
                        "Boot a disposable Android Virtual Device, install this APK, and launch it",
                    )
                    .clicked()
                {
                    start_runtime = true;
                }
                ui.separator();
                for (section, title) in [
                    (Section::Summary, "Summary"),
                    (Section::Manifest, "Manifest"),
                    (Section::Classes, "Classes"),
                    (Section::Strings, "Strings"),
                    (Section::Files, "Files"),
                    (Section::Runtime, "Runtime"),
                ] {
                    let fill = if view.section == section {
                        theme::PILL
                    } else {
                        Color32::TRANSPARENT
                    };
                    if ui.add(egui::Button::new(title).fill(fill)).clicked() {
                        view.section = section;
                    }
                }
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.label(RichText::new(&view.apk.file_name).color(theme::TEXT));
                    ui.label(
                        RichText::new(runtime.phase().label()).color(phase_color(runtime.phase())),
                    );
                });
            });
        });

    let Some(view) = view else {
        tabs::no_results(
            ui,
            "Load an APK to read its manifest, classes, and bytecode",
        );
        return action;
    };

    if start_runtime {
        request_run(view, runtime);
        view.section = Section::Runtime;
    }

    match view.section {
        Section::Summary => summary(ui, &view.apk),
        Section::Manifest => manifest(ui, &view.apk),
        Section::Classes => classes(ui, view),
        Section::Strings => strings(ui, view),
        Section::Files => files(ui, view),
        Section::Runtime => runtime_panel(ui, view, runtime),
    }
    if view.settings_open {
        settings_dialog(ui.ctx(), view, runtime);
    }
    if view.setup_open {
        setup_dialog(ui.ctx(), view, runtime);
    }
    action
}

// Run asks for consent first when the tools are missing, instead of downloading anything quietly.
fn request_run(view: &mut ApkView, runtime: &mut AndroidRuntime) {
    if runtime.blocker().is_some() {
        view.setup_open = true;
    } else {
        start_apk(&view.apk, runtime);
    }
}

fn phase_color(phase: Phase) -> Color32 {
    match phase {
        Phase::Running => theme::ACCENT,
        Phase::Error => theme::ERROR,
        Phase::NotConfigured => theme::NUMBER,
        _ => theme::MUTED,
    }
}

fn start_apk(apk: &Apk, runtime: &mut AndroidRuntime) {
    let info = match AppInfo::new(
        apk.manifest.package.clone(),
        apk.manifest.launcher_activity.clone(),
        &apk.manifest.min_sdk,
        &apk.manifest.target_sdk,
        apk.native_abis(),
        apk.file_name.clone(),
        apk.sha256.clone(),
        Arc::clone(&apk.data),
    ) {
        Ok(info) => info,
        Err(error) => {
            runtime.set_notice(format!("This APK cannot be run: {error:#}"));
            return;
        }
    };
    if let Err(error) = runtime.run(info) {
        runtime.set_notice(format!("{error:#}"));
    }
}

fn fact(ui: &mut Ui, name: &str, value: &str) {
    if value.is_empty() {
        return;
    }
    ui.label(RichText::new(name).color(theme::MUTED));
    ui.label(RichText::new(value).font(theme::mono()));
    ui.end_row();
}

fn yes_no(value: Option<bool>) -> &'static str {
    match value {
        Some(true) => "yes",
        Some(false) => "no",
        None => "not set",
    }
}

fn summary(ui: &mut Ui, apk: &Apk) {
    egui::ScrollArea::vertical()
        .id_salt("apk_summary")
        .auto_shrink(false)
        .show(ui, |ui| {
            egui::Frame::new()
                .inner_margin(egui::Margin::symmetric(16, 6))
                .show(ui, |ui| {
                    let manifest = &apk.manifest;
                    egui::Grid::new("apk_facts")
                        .spacing(egui::vec2(24.0, 6.0))
                        .show(ui, |ui| {
                            fact(ui, "Package", &manifest.package);
                            fact(ui, "Version", &manifest.version_name);
                            fact(ui, "Version code", &manifest.version_code);
                            fact(ui, "Min SDK", &manifest.min_sdk);
                            fact(ui, "Target SDK", &manifest.target_sdk);
                            fact(ui, "SHA-256", &apk.sha256);
                            fact(ui, "Size", &format!("{} bytes", apk.data.len()));
                            fact(ui, "DEX files", &apk.dexes.len().to_string());
                            fact(ui, "Classes", &apk.class_count().to_string());
                            fact(ui, "Methods", &apk.method_count().to_string());
                            fact(ui, "Strings", &apk.strings.len().to_string());
                            fact(
                                ui,
                                "Debuggable",
                                if manifest.debuggable { "yes" } else { "no" },
                            );
                            fact(ui, "Allows backup", yes_no(manifest.allow_backup));
                            fact(ui, "Plain HTTP allowed", yes_no(manifest.cleartext_traffic));
                            fact(
                                ui,
                                "Signed with",
                                &signing_text(&apk.signing.v1_files, apk.signing.v2_or_later),
                            );
                            fact(ui, "Protectors", &apk.protectors.join(", "));
                        });

                    for warning in &apk.warnings {
                        ui.label(RichText::new(warning).color(theme::NUMBER));
                    }

                    ui.add_space(14.0);
                    ui.label(
                        RichText::new(format!("Permissions ({})", manifest.permissions.len()))
                            .size(16.0),
                    );
                    for permission in &manifest.permissions {
                        let color = if is_dangerous_permission(permission) {
                            theme::ERROR
                        } else {
                            theme::TEXT
                        };
                        ui.label(RichText::new(permission).font(theme::mono()).color(color));
                    }

                    ui.add_space(14.0);
                    ui.label(
                        RichText::new(format!("Components ({})", manifest.components.len()))
                            .size(16.0),
                    );
                    for component in &manifest.components {
                        let exported = if component.exported == Some(true) {
                            "  exported"
                        } else {
                            ""
                        };
                        ui.label(
                            RichText::new(format!(
                                "{}  {}{exported}",
                                component.kind, component.name
                            ))
                            .font(theme::mono()),
                        );
                    }

                    ui.add_space(14.0);
                    ui.label(
                        RichText::new(format!("Native libraries ({})", apk.natives.len()))
                            .size(16.0),
                    );
                    for library in &apk.natives {
                        ui.label(
                            RichText::new(format!(
                                "{}  {} bytes, entropy {:.2}",
                                library.path, library.size, library.entropy
                            ))
                            .font(theme::mono()),
                        );
                    }
                });
        });
}

fn signing_text(v1_files: &[String], v2: bool) -> String {
    let mut schemes = Vec::new();
    if !v1_files.is_empty() {
        schemes.push("v1 (JAR)");
    }
    if v2 {
        schemes.push("v2 or later");
    }
    if schemes.is_empty() {
        "nothing found".to_owned()
    } else {
        schemes.join(", ")
    }
}

fn manifest(ui: &mut Ui, apk: &Apk) {
    egui::Frame::new()
        .fill(theme::SURFACE)
        .inner_margin(egui::Margin::symmetric(12, 8))
        .show(ui, |ui| {
            egui::ScrollArea::both()
                .id_salt("apk_manifest")
                .auto_shrink(false)
                .show(ui, |ui| {
                    ui.add(
                        egui::Label::new(RichText::new(&apk.manifest_xml).font(theme::mono()))
                            .extend(),
                    );
                });
        });
}

fn classes(ui: &mut Ui, view: &mut ApkView) {
    let mut clicked = None;
    {
        let rows = &view.classes;
        let filter = &mut view.class_filter;
        let selected = view.selected;
        egui::Panel::left("apk_classes")
            .exact_size(SIDEBAR_WIDTH)
            .frame(egui::Frame::new().fill(theme::SURFACE).inner_margin(8))
            .show(ui, |ui| {
                let field = ui.add(
                    egui::TextEdit::singleline(&mut filter.query)
                        .hint_text(format!("Find one of {} classes", rows.len()))
                        .desired_width(f32::INFINITY),
                );
                if field.changed() {
                    filter.update(rows.len(), |i| rows[i].name.clone());
                }
                ui.add_space(4.0);

                ui.spacing_mut().item_spacing.y = 0.0;
                egui::ScrollArea::vertical()
                    .id_salt("apk_class_list")
                    .auto_shrink(false)
                    .show_rows(ui, SIDEBAR_ROW, filter.matches.len(), |ui, range| {
                        for position in range {
                            let index = filter.matches[position];
                            let size = egui::vec2(ui.available_width(), SIDEBAR_ROW);
                            let (rect, response) = ui.allocate_exact_size(size, Sense::click());
                            let is_selected = selected == Some(index);
                            if is_selected {
                                ui.painter().rect_filled(rect, 6.0, theme::PILL);
                            } else if response.hovered() {
                                ui.painter().rect_filled(rect, 6.0, theme::HOVER);
                            }
                            let color = if is_selected {
                                theme::TEXT
                            } else {
                                theme::MUTED
                            };
                            table::text(
                                ui,
                                rect,
                                &rows[index].name,
                                color,
                                FontId::monospace(12.5),
                            );
                            if response.clicked() {
                                clicked = Some(index);
                            }
                        }
                    });
            });
    }
    if let Some(index) = clicked {
        view.select_class(index);
    }

    if view.lines.is_empty() {
        tabs::no_results(ui, "Pick a class to read its bytecode");
        return;
    }

    let lines = &view.lines;
    ui.spacing_mut().item_spacing.y = 0.0;
    egui::ScrollArea::both()
        .id_salt("apk_code")
        .auto_shrink(false)
        .show_rows(ui, CODE_ROW, lines.len(), |ui, range| {
            for index in range {
                let (rect, _) =
                    ui.allocate_exact_size(egui::vec2(CODE_WIDTH, CODE_ROW), Sense::hover());
                draw_code_line(ui, rect, &lines[index]);
            }
        });
}

fn draw_code_line(ui: &Ui, rect: egui::Rect, line: &ClassLine) {
    let font = theme::mono();
    match line {
        ClassLine::Blank => {}
        ClassLine::Text(text) => {
            table::text(ui, rect, text, theme::MUTED, font);
        }
        ClassLine::Member(text) => {
            table::text(ui, rect, text, theme::CALL, font);
        }
        ClassLine::Insn(insn) => {
            let mut cell = rect;
            let offset = format!("    {:04x}  ", insn.offset);
            let drawn = table::text(ui, cell, &offset, theme::MUTED, font.clone());
            cell.min.x = drawn.right() - 12.0;

            let color = if insn.mnemonic.starts_with("invoke") {
                theme::CALL
            } else {
                theme::MNEMONIC
            };
            let name = format!("{} ", insn.mnemonic);
            let drawn = table::text(ui, cell, &name, color, font.clone());
            cell.min.x = drawn.right() - 12.0;
            table::text(ui, cell, &insn.operands, theme::TEXT, font);
        }
    }
}

fn strings(ui: &mut Ui, view: &mut ApkView) {
    ui.checkbox(&mut view.escape_unicode, "Escape Unicode")
        .on_hover_text("Show Unicode code points when characters appear as boxes. This does not decrypt strings.");
    let apk = &view.apk;
    let filter = &mut view.strings;
    filter.bar_matching(
        ui,
        "Filter by text, or type base64",
        apk.strings.len(),
        |i, query| {
            let found = &apk.strings[i];
            tabs::contains_folded(&found.value, query)
                || found.base64.as_ref().is_some_and(|decoded| {
                    tabs::contains_folded("base64", query) || tabs::contains_folded(decoded, query)
                })
        },
    );
    if filter.matches.is_empty() {
        tabs::no_results(ui, "Nothing matches");
        return;
    }

    table::show(
        ui,
        "apk_strings",
        &STRINGS,
        filter.matches.len(),
        None,
        |ui, range, widths| {
            for position in range {
                let found = &apk.strings[filter.matches[position]];
                let row = table::row(ui, widths, false);
                table::text(
                    ui,
                    row.cells[0],
                    &found.dex.to_string(),
                    theme::MUTED,
                    theme::mono(),
                );
                table::text(
                    ui,
                    row.cells[1],
                    &found.index.to_string(),
                    theme::MUTED,
                    theme::mono(),
                );

                let (kind, color) = if found.base64.is_some() {
                    ("Base64", theme::ACCENT)
                } else {
                    ("Text", theme::TEXT)
                };
                table::text(ui, row.cells[2], kind, theme::MUTED, theme::body());
                let shown = string_preview(&found.value, view.escape_unicode);
                let drawn = table::text(ui, row.cells[3], &shown, color, theme::mono());
                if let Some(decoded) = &found.base64 {
                    let shown: String = decoded.chars().take(MAX_TIP_CHARS).collect();
                    tools::underline(ui, drawn, color);
                    tools::tip(
                        ui,
                        row.cells[3],
                        ("apk_string_tip", position),
                        &format!("Decoded from Base64:\n{shown}"),
                    );
                }
            }
        },
    );
}

fn string_preview(value: &str, escape_unicode: bool) -> String {
    let mut shown = String::new();
    for ch in value.chars().take(MAX_TIP_CHARS) {
        if escape_unicode {
            shown.extend(ch.escape_default());
        } else {
            shown.extend(ch.escape_debug());
        }
    }
    if value.chars().nth(MAX_TIP_CHARS).is_some() {
        shown.push_str("...");
    }
    shown
}

#[cfg(test)]
mod string_tests {
    use super::*;

    #[test]
    fn previews_stay_on_one_line_and_can_show_missing_glyphs() {
        assert_eq!(string_preview("a\n\r\t\0", false), "a\\n\\r\\t\\0");
        assert_eq!(string_preview("水", false), "水");
        assert_eq!(string_preview("水", true), "\\u{6c34}");
        assert!(string_preview(&"a".repeat(MAX_TIP_CHARS + 1), false).ends_with("..."));
    }
}

fn files(ui: &mut Ui, view: &mut ApkView) {
    let apk = &view.apk;
    let filter = &mut view.files;
    filter.bar(ui, "Filter files", apk.files.len(), |i| {
        apk.files[i].name.clone()
    });
    if filter.matches.is_empty() {
        tabs::no_results(ui, "Nothing matches");
        return;
    }

    table::show(
        ui,
        "apk_files",
        &FILES,
        filter.matches.len(),
        None,
        |ui, range, widths| {
            for position in range {
                let file = &apk.files[filter.matches[position]];
                let row = table::row(ui, widths, false);
                table::text(ui, row.cells[0], &file.name, theme::TEXT, theme::mono());
                table::text(
                    ui,
                    row.cells[1],
                    &file.size.to_string(),
                    theme::MUTED,
                    theme::mono(),
                );
                table::text(
                    ui,
                    row.cells[2],
                    &file.compressed.to_string(),
                    theme::MUTED,
                    theme::mono(),
                );
            }
        },
    );
}

fn runtime_panel(ui: &mut Ui, view: &mut ApkView, runtime: &mut AndroidRuntime) {
    let mut logs = runtime.logcat_visible();
    let mut network = runtime.capture_visible();
    ui.horizontal_wrapped(|ui| {
        if ui
            .add_enabled(runtime.can_run(), egui::Button::new("Run APK"))
            .clicked()
        {
            request_run(view, runtime);
        }
        if ui
            .add_enabled(runtime.is_active(), egui::Button::new("Stop"))
            .clicked()
        {
            runtime.stop();
        }
        if ui
            .add_enabled(runtime.is_active(), egui::Button::new("Restart"))
            .on_hover_text("Cold-boot the same AVD again")
            .clicked()
        {
            runtime.restart();
        }
        if ui
            .add_enabled(runtime.is_active(), egui::Button::new("Reset"))
            .on_hover_text("Boot again after wiping the AVD's user data")
            .clicked()
        {
            runtime.reset();
        }
        ui.separator();
        if ui
            .add_enabled(runtime.phase().is_running(), egui::Button::new("Stop app"))
            .clicked()
        {
            runtime.stop_app();
        }
        if ui
            .add_enabled(
                runtime.phase().is_running(),
                egui::Button::new("Relaunch app"),
            )
            .clicked()
        {
            runtime.relaunch_app();
        }
        if ui
            .add_enabled(
                runtime.device().is_some(),
                egui::Button::new("Show display"),
            )
            .on_hover_text("Open or reopen the scrcpy window for the running device")
            .clicked()
        {
            runtime.show_display();
        }
        ui.separator();
        if ui.button("Settings").clicked() {
            view.open_settings(runtime);
        }
        if ui.button("Refresh tools").clicked() {
            runtime.refresh();
        }
        if ui.checkbox(&mut logs, "Logcat").changed() {
            runtime.set_logcat_visible(logs);
        }
        if ui
            .checkbox(&mut network, "Network")
            .on_hover_text("Show HTTP requests and HTTPS tunnel metadata captured by the proxy")
            .changed()
        {
            runtime.set_capture_visible(network);
        }
    });

    ui.add_space(4.0);
    ui.horizontal(|ui| {
        let phase = runtime.phase();
        ui.label(
            RichText::new(phase.label())
                .color(phase_color(phase))
                .strong(),
        );
        if runtime.is_busy() || runtime.is_scanning() {
            ui.spinner();
        }
        if !runtime.detail().is_empty() {
            ui.label(RichText::new(runtime.detail()).color(theme::TEXT));
        }
    });

    let mut dismiss_notice = false;
    if let Some(notice) = runtime.notice() {
        ui.add_space(4.0);
        ui.horizontal_wrapped(|ui| {
            ui.label(RichText::new(notice).color(theme::CALL));
            if ui.small_button("Dismiss").clicked() {
                dismiss_notice = true;
            }
        });
    }
    let mut dismiss_error = false;
    if let Some(error) = runtime.error() {
        egui::Frame::new()
            .fill(theme::SURFACE)
            .inner_margin(egui::Margin::symmetric(10, 8))
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.label(RichText::new("Runtime error").color(theme::ERROR).strong());
                    if ui.small_button("Dismiss").clicked() {
                        dismiss_error = true;
                    }
                });
                ui.add(egui::Label::new(RichText::new(error).color(theme::ERROR)).wrap());
            });
    }
    if dismiss_error {
        runtime.clear_error();
    }
    if dismiss_notice {
        runtime.clear_notice();
    }

    let log_height = if runtime.logcat_visible() { 250.0 } else { 0.0 };
    let network_height = if runtime.capture_visible() {
        210.0
    } else {
        0.0
    };
    let info_height = (ui.available_height() - log_height - network_height - 24.0).max(80.0);
    egui::ScrollArea::vertical()
        .id_salt("apk_runtime_info")
        .max_height(info_height)
        .auto_shrink(false)
        .show(ui, |ui| runtime_info(ui, view, runtime));

    if runtime.capture_visible() {
        capture_panel(ui, view, runtime, 150.0);
    }
    if runtime.logcat_visible() {
        logcat_panel(ui, runtime, 210.0);
    }
}

fn capture_panel(ui: &mut Ui, view: &mut ApkView, runtime: &mut AndroidRuntime, height: f32) {
    let mut clear = false;
    let mut copy = false;
    ui.horizontal(|ui| {
        ui.label(
            RichText::new(format!(
                "Network capture ({} exchanges)",
                runtime.capture().len()
            ))
            .color(theme::TEXT),
        );
        if ui.small_button("Clear").clicked() {
            clear = true;
        }
        if ui.small_button("Copy").clicked() {
            copy = true;
        }
        ui.label(
            RichText::new("HTTP is decoded; HTTPS is an encrypted tunnel").color(theme::MUTED),
        );
    });
    if clear {
        runtime.clear_capture();
        view.network_selected = None;
    }
    if copy {
        let text = runtime
            .capture()
            .iter()
            .map(capture_line)
            .collect::<Vec<_>>()
            .join("\n");
        ui.ctx().copy_text(text);
    }

    egui::Frame::new()
        .fill(theme::SURFACE)
        .inner_margin(egui::Margin::symmetric(8, 6))
        .show(ui, |ui| {
            egui::ScrollArea::vertical()
                .id_salt("apk_capture")
                .max_height(height)
                .auto_shrink(false)
                .stick_to_bottom(true)
                .show(ui, |ui| {
                    if runtime.capture().is_empty() {
                        ui.label(
                            RichText::new(
                                "No traffic yet. Apps that ignore Android's system HTTP proxy \
                                 will not appear here.",
                            )
                            .color(theme::MUTED),
                        );
                    }
                    for event in runtime.capture() {
                        let selected = view.network_selected == Some(event.id);
                        let color = if event.status.is_some_and(|status| status >= 400) {
                            theme::ERROR
                        } else {
                            theme::TEXT
                        };
                        let line = RichText::new(capture_line(event))
                            .font(FontId::monospace(11.5))
                            .color(color);
                        if ui.selectable_label(selected, line).clicked() {
                            view.network_selected = Some(event.id);
                        }
                    }
                });

            let selected = view
                .network_selected
                .and_then(|id| runtime.capture().iter().find(|event| event.id == id));
            if let Some(event) = selected {
                ui.add_space(4.0);
                let detail = if !event.note.is_empty() {
                    event.note.clone()
                } else if event.preview.is_empty() {
                    "(no body preview)".to_owned()
                } else {
                    event.preview.clone()
                };
                let content_type = if event.content_type.is_empty() {
                    String::new()
                } else {
                    format!(" ({})", event.content_type)
                };
                ui.label(
                    RichText::new(format!(
                        "{} {} {}{}  ·  {} up / {} down  ·  {} ms{}",
                        event.method,
                        event.scheme.to_ascii_uppercase(),
                        event.host,
                        event.path,
                        bytes_text(event.request_bytes),
                        bytes_text(event.response_bytes),
                        event.millis,
                        content_type
                    ))
                    .font(FontId::monospace(11.5))
                    .color(theme::MUTED),
                );
                ui.add(
                    egui::Label::new(
                        RichText::new(detail.chars().take(MAX_TIP_CHARS).collect::<String>())
                            .font(FontId::monospace(11.5))
                            .color(theme::TEXT),
                    )
                    .wrap(),
                );
            }
        });
}

fn capture_line(event: &CaptureEvent) -> String {
    let status = event
        .status
        .map_or_else(|| "tunnel".to_owned(), |status| status.to_string());
    format!(
        "#{:<4} {:<5} {:<6} {}{}  {:<6}  {} up / {} down  {} ms",
        event.id,
        event.scheme.to_ascii_uppercase(),
        event.method,
        event.host,
        event.path,
        status,
        bytes_text(event.request_bytes),
        bytes_text(event.response_bytes),
        event.millis
    )
}

fn bytes_text(bytes: u64) -> String {
    const KIB: f64 = 1024.0;
    const MIB: f64 = KIB * 1024.0;
    let bytes = bytes as f64;
    if bytes >= MIB {
        format!("{:.1} MB", bytes / MIB)
    } else if bytes >= KIB {
        format!("{:.1} kB", bytes / KIB)
    } else {
        format!("{bytes:.0} B")
    }
}

fn runtime_info(ui: &mut Ui, view: &mut ApkView, runtime: &AndroidRuntime) {
    if let Some(device) = runtime.device() {
        ui.add_space(6.0);
        egui::Grid::new("android_device")
            .num_columns(2)
            .spacing(egui::vec2(20.0, 5.0))
            .show(ui, |ui| {
                fact(ui, "Serial", &device.serial);
                fact(ui, "AVD", &device.avd);
                fact(ui, "Model", &device.model);
                fact(ui, "Android", &device.android_text());
                fact(ui, "CPU ABIs", &device.abi_list.join(", "));
                fact(
                    ui,
                    "Resolution",
                    device.resolution.as_deref().unwrap_or_default(),
                );
                fact(ui, "Density", device.density.as_deref().unwrap_or_default());
                fact(ui, "Package", &device.package);
                fact(
                    ui,
                    "Launcher",
                    device.component.as_deref().unwrap_or_default(),
                );
            });
    }

    if let Some(blocker) = runtime.blocker() {
        ui.add_space(8.0);
        ui.label(RichText::new(blocker).color(theme::NUMBER));
        if runtime.setup_available()
            && ui
                .button("Set up automatically")
                .on_hover_text(
                    "Downloads the official Android command-line tools, emulator, adb, a system \
                     image, an AVD, and scrcpy after you confirm.",
                )
                .clicked()
        {
            view.setup_open = true;
        }
        egui::CollapsingHeader::new("How to install the Android tools")
            .default_open(true)
            .show(ui, |ui| {
                ui.add(egui::Label::new(RichText::new(SETUP_HELP).color(theme::MUTED)).wrap());
            });
    }

    if let Some(environment) = runtime.environment() {
        ui.add_space(8.0);
        egui::CollapsingHeader::new("Android tools").show(ui, |ui| {
            for line in environment.summary() {
                ui.label(RichText::new(line).font(theme::mono()).color(theme::MUTED));
            }
            for note in &environment.notes {
                ui.label(RichText::new(note).color(theme::NUMBER));
            }
            if !environment.avds.is_empty() {
                ui.add_space(6.0);
                ui.label(RichText::new("Virtual devices").color(theme::TEXT));
                for avd in &environment.avds {
                    let mut text = avd.label();
                    if let Some(error) = &avd.error {
                        text.push_str(&format!(" — {error}"));
                    }
                    ui.label(RichText::new(text).font(theme::mono()).color(theme::MUTED));
                }
            }
        });
    } else if runtime.is_scanning() {
        ui.add_space(8.0);
        ui.label(
            RichText::new("Looking for the Android SDK, emulator, adb, scrcpy, and AVDs...")
                .color(theme::MUTED),
        );
    } else {
        ui.add_space(8.0);
        ui.label(
            RichText::new("Run the APK to boot a disposable Android Virtual Device.")
                .color(theme::MUTED),
        );
    }

    ui.add_space(8.0);
    ui.label(
        RichText::new(
            "Euphoria installs into a disposable AVD. Do not sign in to personal accounts there, \
             and use Reset to return the device to a clean state.",
        )
        .color(theme::MUTED),
    );
}

fn logcat_panel(ui: &mut Ui, runtime: &mut AndroidRuntime, height: f32) {
    let mut clear = false;
    let mut copy = false;
    ui.horizontal(|ui| {
        ui.label(
            RichText::new(format!("Logcat ({} lines)", runtime.logcat().len())).color(theme::TEXT),
        );
        if ui.small_button("Clear").clicked() {
            clear = true;
        }
        if ui.small_button("Copy").clicked() {
            copy = true;
        }
    });
    if clear {
        runtime.clear_logcat();
    }
    if copy {
        let text = runtime
            .logcat()
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>()
            .join("\n");
        ui.ctx().copy_text(text);
    }

    egui::Frame::new()
        .fill(theme::SURFACE)
        .inner_margin(egui::Margin::symmetric(8, 6))
        .show(ui, |ui| {
            egui::ScrollArea::vertical()
                .id_salt("apk_logcat")
                .max_height(height)
                .auto_shrink(false)
                .stick_to_bottom(true)
                .show(ui, |ui| {
                    for line in runtime.logcat() {
                        ui.add(
                            egui::Label::new(
                                RichText::new(line)
                                    .font(FontId::monospace(11.5))
                                    .color(log_color(line)),
                            )
                            .wrap(),
                        );
                    }
                });
        });
}

fn log_color(line: &str) -> Color32 {
    let upper = line.to_ascii_uppercase();
    if upper.contains("FATAL") || upper.contains(" E ") || upper.contains("ERROR") {
        theme::ERROR
    } else if upper.contains(" W ") || upper.contains("WARN") {
        theme::NUMBER
    } else {
        theme::MUTED
    }
}

fn setup_dialog(ctx: &egui::Context, view: &mut ApkView, runtime: &mut AndroidRuntime) {
    let mut open = view.setup_open;
    let mut install = false;
    let mut run = false;
    let mut settings = false;

    egui::Modal::new(egui::Id::unique("android_setup")).show(ctx, |ui| {
        ui.set_max_width(640.0);
        ui.label(RichText::new("Android tools are needed").size(17.0));
        ui.add_space(6.0);

        if runtime.is_setting_up() {
            ui.add(
                egui::Label::new(RichText::new(runtime.setup_detail()).color(theme::TEXT)).wrap(),
            );
            ui.add_space(8.0);
            match runtime.setup_percent() {
                Some(percent) => {
                    ui.add(egui::ProgressBar::new(percent as f32 / 100.0).show_percentage());
                }
                None => {
                    ui.spinner();
                }
            }
            ui.add_space(8.0);
            ui.add(
                egui::Label::new(
                    RichText::new(
                        "Keep Euphoria open while the tools download and install. Nothing is \
                         downloaded until you press Install.",
                    )
                    .color(theme::MUTED),
                )
                .wrap(),
            );
            ui.add_space(10.0);
            if ui.button("Cancel setup").clicked() {
                runtime.cancel_setup();
            }
        } else if let Some(error) = runtime.setup_error() {
            ui.label(
                RichText::new("Setup did not finish")
                    .color(theme::ERROR)
                    .strong(),
            );
            ui.add_space(4.0);
            ui.add(egui::Label::new(RichText::new(error).color(theme::ERROR)).wrap());
            ui.add_space(10.0);
            ui.horizontal(|ui| {
                if runtime.setup_available() && ui.button("Try again").clicked() {
                    install = true;
                }
                if ui.button("Settings").clicked() {
                    settings = true;
                }
                if ui.button("Close").clicked() {
                    open = false;
                }
            });
        } else if let Some(message) = runtime.setup_message() {
            ui.add(egui::Label::new(RichText::new(message).color(theme::TEXT)).wrap());
            ui.add_space(8.0);
            if runtime.is_scanning() {
                ui.horizontal(|ui| {
                    ui.spinner();
                    ui.label(RichText::new("Checking the installed tools...").color(theme::MUTED));
                });
            } else if !runtime.setup_available() {
                ui.label(RichText::new("The APK can run now.").color(theme::ACCENT));
            }
            ui.add_space(10.0);
            ui.horizontal(|ui| {
                if !runtime.is_scanning()
                    && !runtime.setup_available()
                    && ui.button("Run APK").clicked()
                {
                    run = true;
                }
                if ui.button("Close").clicked() {
                    open = false;
                }
            });
        } else if runtime.setup_available() {
            if let Some(blocker) = runtime.blocker() {
                ui.add(egui::Label::new(RichText::new(blocker).color(theme::NUMBER)).wrap());
                ui.add_space(6.0);
            }
            ui.add(
                egui::Label::new(
                    RichText::new(
                        "Euphoria can download the official tools and set them up for you. Only \
                         what is missing gets installed.",
                    )
                    .color(theme::TEXT),
                )
                .wrap(),
            );
            ui.add_space(6.0);
            for line in [
                "Android command-line tools, platform-tools (adb), and the emulator from \
                 dl.google.com",
                "A Google APIs system image and a disposable AVD named Euphoria_API_34",
                "scrcpy from its official GitHub release on Windows; the emulator's own window \
                 is used on other platforms",
            ] {
                ui.label(
                    RichText::new(format!("- {line}"))
                        .font(theme::body())
                        .color(theme::TEXT),
                );
            }
            ui.add_space(8.0);
            ui.label(RichText::new("Install location").color(theme::MUTED));
            ui.label(RichText::new(runtime.setup_root().display().to_string()).font(theme::mono()));
            ui.add_space(6.0);
            ui.add(
                egui::Label::new(
                    RichText::new(
                        "Expect roughly 1.5-2 GB of downloads. Java 17 or newer is required; setup \
                         stops with instructions if it is missing.",
                    )
                    .color(theme::MUTED),
                )
                .wrap(),
            );
            ui.add_space(6.0);
            ui.add(egui::Label::new(RichText::new(SOURCES).color(theme::MUTED)).wrap());
            ui.add_space(10.0);
            ui.horizontal(|ui| {
                if ui.button("Install").clicked() {
                    install = true;
                }
                if ui.button("Cancel").clicked() {
                    open = false;
                }
                if ui.button("Settings").clicked() {
                    settings = true;
                }
            });
        } else if runtime.is_scanning() || runtime.environment().is_none() {
            ui.horizontal(|ui| {
                ui.spinner();
                ui.label(RichText::new("Checking the Android tools...").color(theme::MUTED));
            });
            ui.add_space(10.0);
            if ui.button("Close").clicked() {
                open = false;
            }
        } else {
            if let Some(blocker) = runtime.blocker() {
                ui.add(egui::Label::new(RichText::new(blocker).color(theme::NUMBER)).wrap());
            }
            ui.add_space(6.0);
            ui.add(egui::Label::new(RichText::new(SETUP_HELP).color(theme::MUTED)).wrap());
            ui.add_space(10.0);
            ui.horizontal(|ui| {
                if ui.button("Settings").clicked() {
                    settings = true;
                }
                if ui.button("Close").clicked() {
                    open = false;
                }
            });
        }
    });

    if install {
        runtime.start_setup();
    }
    if run {
        start_apk(&view.apk, runtime);
        open = false;
    }
    if settings {
        view.open_settings(runtime);
        open = false;
    }
    view.setup_open = open;
}

fn settings_dialog(ctx: &egui::Context, view: &mut ApkView, runtime: &mut AndroidRuntime) {
    let mut open = view.settings_open;
    let mut save = false;

    egui::Modal::new(egui::Id::unique("android_settings")).show(ctx, |ui| {
        ui.set_max_width(620.0);
        ui.label(RichText::new("Android emulator settings").size(17.0));
        ui.add_space(4.0);
        ui.label(
            RichText::new(format!(
                "Saved to {}",
                euphoria_android::config_path().display()
            ))
            .font(theme::mono())
            .color(theme::MUTED),
        );
        ui.add_space(8.0);

        egui::ScrollArea::vertical()
            .max_height(430.0)
            .show(ui, |ui| {
                let config = &mut view.settings;
                egui::Grid::new("android_paths")
                    .num_columns(2)
                    .spacing(egui::vec2(14.0, 6.0))
                    .show(ui, |ui| {
                        path_row(ui, "Android SDK", &mut config.sdk_root);
                        path_row(ui, "Emulator", &mut config.emulator_path);
                        path_row(ui, "adb", &mut config.adb_path);
                        path_row(ui, "scrcpy", &mut config.scrcpy_path);
                    });
                ui.label(
                RichText::new(
                    "An empty path lets Euphoria search the SDK, environment variables, and PATH.",
                )
                .color(theme::MUTED),
            );
                ui.add_space(10.0);

                let avd_label = if config.avd.is_empty() {
                    "(choose automatically)".to_owned()
                } else {
                    config.avd.clone()
                };
                ui.horizontal(|ui| {
                    ui.label("Virtual device");
                    egui::ComboBox::from_id_salt("android_avd")
                        .selected_text(avd_label)
                        .width(360.0)
                        .show_ui(ui, |ui| {
                            ui.selectable_value(
                                &mut config.avd,
                                String::new(),
                                "(choose automatically)",
                            );
                            for avd in runtime.avds() {
                                ui.selectable_value(&mut config.avd, avd.name.clone(), avd.label());
                            }
                        });
                });
                if runtime.avds().is_empty() {
                    ui.label(
                        RichText::new(
                            "No AVDs were found yet. Install one, then use Refresh tools.",
                        )
                        .color(theme::NUMBER),
                    );
                }
                ui.add_space(10.0);

                egui::Grid::new("android_tuning")
                    .num_columns(2)
                    .spacing(egui::vec2(14.0, 8.0))
                    .show(ui, |ui| {
                        ui.label("Resolution");
                        ui.horizontal(|ui| {
                            ui.add(egui::DragValue::new(&mut config.width).range(0..=4096));
                            ui.label("×");
                            ui.add(egui::DragValue::new(&mut config.height).range(0..=4096));
                            ui.label(RichText::new("0 disables the skin").color(theme::MUTED));
                        });
                        ui.end_row();

                        ui.label("Target FPS");
                        ui.horizontal(|ui| {
                            ui.add(egui::DragValue::new(&mut config.max_fps).range(1..=240));
                            ui.label(
                                RichText::new("requested, not guaranteed").color(theme::MUTED),
                            );
                        });
                        ui.end_row();

                        ui.label("Boot timeout");
                        ui.horizontal(|ui| {
                            ui.add(
                                egui::DragValue::new(&mut config.boot_timeout_secs)
                                    .range(30..=1800),
                            );
                            ui.label("seconds");
                        });
                        ui.end_row();

                        ui.label("GPU");
                        egui::ComboBox::from_id_salt("android_gpu")
                            .selected_text(config.gpu.clone())
                            .show_ui(ui, |ui| {
                                for (value, label) in [
                                    ("auto", "Auto"),
                                    ("host", "Host GPU"),
                                    ("angle", "ANGLE"),
                                    ("swiftshader_indirect", "SwiftShader"),
                                    ("guest", "Guest"),
                                ] {
                                    ui.selectable_value(&mut config.gpu, value.to_owned(), label);
                                }
                            });
                        ui.end_row();
                    });

                ui.add_space(8.0);
                ui.checkbox(
                    &mut config.show_emulator_window,
                    "Show the emulator's own window",
                )
                .on_hover_text(
                    "scrcpy is used for the display when it is available; this shows the official \
                 emulator window instead.",
                );
                ui.checkbox(
                    &mut config.grant_permissions,
                    "Grant runtime permissions during install (adb install -g)",
                );
                ui.checkbox(
                    &mut config.reduce_animations,
                    "Reduce animations for debugging",
                );
                ui.checkbox(
                    &mut config.apply_wallpaper,
                    "Use the Euphoria logo as the AVD wallpaper",
                )
                .on_hover_text(
                    "Sets the home-screen wallpaper once Android has booted. This is cosmetic and \
                 never blocks the app if Android refuses.",
                );
                ui.checkbox(
                &mut config.capture_network,
                "Capture emulator HTTP traffic",
            )
            .on_hover_text(
                "Points the AVD's system HTTP proxy at a local proxy and lists requests in the \
                 Network console. HTTPS bodies stay encrypted; only the destination and byte \
                 counts are shown.",
            );
                ui.checkbox(
                    &mut config.allow_software_accel,
                    "Allow software emulation when virtualization is unavailable (very slow)",
                );
                ui.add_space(6.0);
                ui.label(
                    RichText::new(
                        "Changes apply the next time the emulator starts. FPS is a target; actual \
                     performance depends on the host and the app.",
                    )
                    .color(theme::MUTED),
                );
            });

        ui.add_space(10.0);
        ui.horizontal(|ui| {
            if ui.button("Save").clicked() {
                save = true;
            }
            if ui.button("Cancel").clicked() {
                open = false;
            }
        });
    });

    if save {
        *runtime.config_mut() = view.settings.clone();
        match runtime.save_config() {
            Ok(()) => {
                runtime.set_notice("Android settings saved.");
                open = false;
            }
            Err(error) => {
                runtime.set_notice(format!("Could not save Android settings: {error:#}"));
            }
        }
    }
    view.settings_open = open;
}

fn path_row(ui: &mut Ui, label: &str, value: &mut String) {
    ui.label(label);
    ui.add(
        egui::TextEdit::singleline(value)
            .hint_text("auto")
            .desired_width(f32::INFINITY),
    );
    ui.end_row();
}
