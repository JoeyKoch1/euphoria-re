use std::sync::Arc;

use eframe::egui::{self, Color32, FontId, RichText, Sense, Ui};
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
            apk: Arc::new(apk),
        }
    }

    fn select_class(&mut self, row: usize) {
        self.selected = Some(row);
        let info = &self.classes[row];
        let dex = &self.apk.dexes[info.dex];
        self.lines = dex.class_lines(&dex.classes[info.class]);
    }
}

pub fn show(ui: &mut Ui, view: &mut Option<ApkView>) -> Option<Action> {
    let mut action = None;
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
                for (section, title) in [
                    (Section::Summary, "Summary"),
                    (Section::Manifest, "Manifest"),
                    (Section::Classes, "Classes"),
                    (Section::Strings, "Strings"),
                    (Section::Files, "Files"),
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

    match view.section {
        Section::Summary => summary(ui, &view.apk),
        Section::Manifest => manifest(ui, &view.apk),
        Section::Classes => classes(ui, view),
        Section::Strings => strings(ui, view),
        Section::Files => files(ui, view),
    }
    action
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
