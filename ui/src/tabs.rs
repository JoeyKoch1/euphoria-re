use std::ops::Range;
use std::time::{Duration, Instant};

use eframe::egui::{self, Color32, Rect, RichText, Sense, Stroke, Ui};
use euphoria_engine::{Function, Line, StringEntry, TokenKind, XrefKind};

use crate::debug_view::{self, DebugState};
use crate::table::{self, Column, fill, fixed};
use crate::{Project, theme, tools};

const MAX_FLOW_LANES: usize = 3;
const FLOW_LANE_WIDTH: f32 = 10.0;

const DISASSEMBLY: [Column; 5] = [
    fixed("Jumps", 56.0),
    fixed("VA", 160.0),
    fixed("Raw", 340.0),
    fill("Code"),
    fill("Notes"),
];
const FUNCTIONS: [Column; 4] = [
    fixed("Starts", 170.0),
    fixed("Ends", 170.0),
    fixed("Bytes", 110.0),
    fill("Routine"),
];
const REFERENCES: [Column; 4] = [
    fixed("Used at", 170.0),
    fixed("Points to", 170.0),
    fixed("How", 110.0),
    fill("Which is"),
];
const STRINGS: [Column; 5] = [
    fixed("VA", 170.0),
    fixed("Chars", 90.0),
    fixed("Used by", 110.0),
    fixed("Encoding", 90.0),
    fill("Text"),
];
const MAX_TIP_CHARS: usize = 600;

pub enum Action {
    Go(u64),
    Focus(u64),
    Select(usize),
    Status(String),
    Open(std::path::PathBuf),
    ShowHost(usize),
    ShowDecompiler,
}

pub struct Filter {
    pub query: String,
    pub matches: Vec<usize>,
    selected: Option<usize>,
    pending: Option<Instant>,
}

impl Filter {
    pub fn all(count: usize) -> Self {
        Self {
            query: String::new(),
            matches: (0..count).collect(),
            selected: None,
            pending: None,
        }
    }

    pub fn update(&mut self, count: usize, haystack: impl Fn(usize) -> String) {
        self.update_matching(count, |i, query| contains_folded(&haystack(i), query));
    }

    fn update_matching(&mut self, count: usize, matches: impl Fn(usize, &str) -> bool) {
        let query = self.query.to_lowercase();
        self.matches = (0..count)
            .filter(|&i| query.is_empty() || matches(i, &query))
            .collect();
        self.selected = None;
        self.pending = None;
    }

    pub fn bar(
        &mut self,
        ui: &mut Ui,
        hint: &str,
        count: usize,
        haystack: impl Fn(usize) -> String,
    ) {
        self.bar_matching(ui, hint, count, |i, query| {
            contains_folded(&haystack(i), query)
        });
    }

    pub fn bar_matching(
        &mut self,
        ui: &mut Ui,
        hint: &str,
        count: usize,
        matches: impl Fn(usize, &str) -> bool,
    ) {
        egui::Frame::new()
            .inner_margin(egui::Margin::symmetric(12, 10))
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    let field = ui.add(
                        egui::TextEdit::singleline(&mut self.query)
                            .hint_text(hint)
                            .desired_width(460.0),
                    );
                    if field.changed() {
                        self.pending = Some(Instant::now());
                    }
                    if let Some(changed) = self.pending {
                        let delay = Duration::from_millis(150);
                        if count < 10_000 || self.query.is_empty() || changed.elapsed() >= delay {
                            self.update_matching(count, &matches);
                        } else {
                            ui.ctx()
                                .request_repaint_after(delay.saturating_sub(changed.elapsed()));
                        }
                    }
                    ui.label(
                        RichText::new(format!("{} of {count}", self.matches.len()))
                            .color(theme::MUTED),
                    );
                });
            });
    }
}

pub fn contains_folded(text: &str, query: &str) -> bool {
    if query.is_empty() {
        return true;
    }
    if text.is_ascii() {
        text.as_bytes()
            .windows(query.len())
            .any(|part| part.eq_ignore_ascii_case(query.as_bytes()))
    } else {
        text.to_lowercase().contains(query)
    }
}

pub fn disassembly(ui: &mut Ui, project: &mut Project, debug: &mut DebugState) -> Option<Action> {
    if project.listing.rows.is_empty() {
        no_results(
            ui,
            "Euphoria can't decode this file's code yet. x86 and x86-64 work today.",
        );
        return None;
    }

    table::header(ui, &DISASSEMBLY);
    let mut action = debug_view::controls(ui, project, debug);
    let scroll_to = project.scroll_to.take();
    let count = project.listing.rows.len();
    let live = debug.current_image_ip();

    table::body_rows(
        ui,
        "disassembly",
        &DISASSEMBLY,
        count,
        scroll_to,
        |ui, range, widths| {
            let lines = project
                .listing
                .render(&project.analysis.data, range.clone());
            let mut flow_cell = None;
            let mut centers = Vec::with_capacity(lines.len());

            for (index, line) in range.clone().zip(&lines) {
                let flagged = project.breakpoints.contains(&line.va);
                let row = table::code_row(
                    ui,
                    widths,
                    index == project.cursor,
                    flagged,
                    live == Some(line.va),
                );
                if row.response.clicked() {
                    project.cursor = index;
                }
                if row.response.double_clicked() {
                    debug.toggle_breakpoint(project, line.va);
                }

                flow_cell = Some(row.cells[0]);
                centers.push(row.cells[0].center().y);

                table::text(
                    ui,
                    row.cells[1],
                    &format!("{:#x}", line.va),
                    theme::MUTED,
                    theme::mono(),
                );
                table::text(
                    ui,
                    row.cells[2],
                    &hex_bytes(&line.bytes),
                    theme::TEXT,
                    theme::mono(),
                );
                if let Some(target) = instruction(ui, row.cells[3], line, index) {
                    action = Some(Action::Go(target));
                }
                if let Some(comment) = comment(project, line) {
                    let tip = line_tip(project, line);
                    let color = if tip.is_some() {
                        theme::ACCENT
                    } else {
                        theme::MUTED
                    };
                    table::text(ui, row.cells[4], &comment, color, theme::mono());
                    if let Some(tip) = tip {
                        tools::tip(ui, row.cells[4], ("line_tip", index), &tip);
                    }
                }
            }

            if let Some(cell) = flow_cell {
                flow(ui, cell, &project.jumps, project.cursor, range, &centers);
            }
        },
    );

    action
}

fn instruction(ui: &Ui, cell: Rect, line: &Line, index: usize) -> Option<u64> {
    let mut clicked = None;
    let mut cell = cell;
    for (position, token) in line.tokens.iter().enumerate() {
        let color = token_color(token.kind);
        let drawn = table::text(ui, cell, &token.text, color, theme::mono());
        if token.kind == TokenKind::Target {
            let id = ui.scope_id().with(("target", index, position));
            let response = ui
                .interact(drawn, id, Sense::click())
                .on_hover_cursor(egui::CursorIcon::PointingHand);
            ui.painter()
                .hline(drawn.x_range(), drawn.bottom(), Stroke::new(1.0, color));
            if response.clicked() {
                clicked = line.branch;
            }
        }
        cell.min.x = drawn.right() - 12.0;
    }
    clicked
}

pub fn token_color(kind: TokenKind) -> Color32 {
    match kind {
        TokenKind::Mnemonic => theme::MNEMONIC,
        TokenKind::Call => theme::CALL,
        TokenKind::Register => theme::REGISTER,
        TokenKind::Number | TokenKind::Target => theme::NUMBER,
        TokenKind::Text => theme::TEXT,
    }
}

pub fn function_label(function: &Function) -> String {
    match &function.name {
        Some(name) => name.clone(),
        None => format!("sub_{:x}", function.va),
    }
}

fn base64_tip(entry: &StringEntry) -> Option<String> {
    let decoded = entry.base64.as_ref()?;
    let shown: String = decoded.chars().take(MAX_TIP_CHARS).collect();
    Some(format!("Decoded from Base64:\n{shown}"))
}

pub fn line_tip(project: &Project, line: &Line) -> Option<String> {
    base64_tip(project.listing.string_at(line.data?)?)
}

pub fn comment(project: &Project, line: &Line) -> Option<String> {
    let name_at = |va| {
        project
            .analysis
            .function_at(va)
            .and_then(|function| function.name.clone())
    };

    if let Some(name) = line.branch.and_then(name_at) {
        return Some(name);
    }
    if let Some(entry) = line.data.and_then(|va| project.listing.string_at(va)) {
        return Some(format!("\"{}\"", entry.value));
    }
    if let Some(import) = line.data.and_then(|va| project.analysis.iat.get(&va)) {
        return Some(import.clone());
    }
    name_at(line.va)
}

fn flow(
    ui: &Ui,
    cell: Rect,
    jumps: &[(usize, usize)],
    cursor: usize,
    range: Range<usize>,
    centers: &[f32],
) {
    let Some((&top, &bottom)) = centers.first().zip(centers.last()) else {
        return;
    };

    let mut visible: Vec<_> = jumps
        .iter()
        .filter(|(from, to)| (*from).min(*to) < range.end && (*from).max(*to) >= range.start)
        .collect();
    visible.sort_by_key(|(from, to)| from.abs_diff(*to));
    visible.truncate(MAX_FLOW_LANES);

    let clip = Rect::from_min_max(
        egui::pos2(cell.left(), top),
        egui::pos2(cell.right(), bottom),
    );
    let painter = ui.painter_at(clip.expand2(egui::vec2(0.0, table::ROW_HEIGHT)));
    let right = cell.right() - 4.0;
    let y_of = |row: usize| range.contains(&row).then(|| centers[row - range.start]);

    for (lane, &&(from, to)) in visible.iter().enumerate() {
        let color = if from == cursor || to == cursor {
            theme::ACCENT
        } else {
            theme::MUTED
        };
        let stroke = Stroke::new(1.0, color);
        let x = right - 8.0 - lane as f32 * FLOW_LANE_WIDTH;

        let edge = |row: usize| y_of(row).unwrap_or(if row < range.start { top } else { bottom });
        painter.vline(
            x,
            edge(from).min(edge(to))..=edge(from).max(edge(to)),
            stroke,
        );

        if let Some(y) = y_of(from) {
            painter.hline(x..=right, y, stroke);
        }
        if let Some(y) = y_of(to) {
            painter.hline(x..=right, y, stroke);
            arrow(&painter, right, y, color);
        }
    }
}

fn arrow(painter: &egui::Painter, x: f32, y: f32, color: Color32) {
    painter.add(egui::Shape::convex_polygon(
        vec![
            egui::pos2(x, y),
            egui::pos2(x - 5.0, y - 3.0),
            egui::pos2(x - 5.0, y + 3.0),
        ],
        color,
        Stroke::NONE,
    ));
}

pub fn functions(ui: &mut Ui, project: &mut Project) -> Option<Action> {
    let functions = &project.analysis.functions;
    let filter = &mut project.functions;
    filter.bar(
        ui,
        "Filter by address or routine name",
        functions.len(),
        |i| {
            let function = &functions[i];
            format!(
                "{:#x} {}",
                function.va,
                function.name.as_deref().unwrap_or("")
            )
        },
    );
    if filter.matches.is_empty() {
        no_results(ui, "Nothing matches");
        return None;
    }

    let mut action = None;
    table::show(
        ui,
        "functions",
        &FUNCTIONS,
        filter.matches.len(),
        None,
        |ui, range, widths| {
            for position in range {
                let function = &functions[filter.matches[position]];
                let row = table::row(ui, widths, filter.selected == Some(position));
                if row.response.clicked() {
                    filter.selected = Some(position);
                    action = Some(Action::Go(function.va));
                }

                let end = function.va + function.size;
                table::text(
                    ui,
                    row.cells[0],
                    &format!("{:#x}", function.va),
                    theme::TEXT,
                    theme::mono(),
                );
                table::text(
                    ui,
                    row.cells[1],
                    &format!("{end:#x}"),
                    theme::MUTED,
                    theme::mono(),
                );
                table::text(
                    ui,
                    row.cells[2],
                    &function.size.to_string(),
                    theme::MUTED,
                    theme::mono(),
                );
                let name = function.name.as_deref().unwrap_or("unnamed");
                table::text(ui, row.cells[3], name, theme::TEXT, theme::mono());
            }
        },
    );
    action
}

pub fn references(ui: &mut Ui, project: &mut Project) -> Option<Action> {
    let xrefs = &project.listing.xrefs;
    let analysis = &project.analysis;
    let listing = &project.listing;
    let target_name = |va: u64| -> String {
        if let Some(name) = analysis.function_at(va).and_then(|f| f.name.as_deref()) {
            return name.to_owned();
        }
        listing
            .string_at(va)
            .map(|entry| format!("\"{}\"", entry.value))
            .unwrap_or_default()
    };

    let filter = &mut project.references;
    filter.bar(
        ui,
        "Filter by address, call, jump, data, or name",
        xrefs.len(),
        |i| {
            let xref = &xrefs[i];
            format!(
                "{:#x} {:#x} {} {}",
                xref.from,
                xref.to,
                kind_name(xref.kind),
                target_name(xref.to)
            )
        },
    );
    if filter.matches.is_empty() {
        no_results(ui, "Nothing matches");
        return None;
    }

    let mut action = None;
    table::show(
        ui,
        "references",
        &REFERENCES,
        filter.matches.len(),
        None,
        |ui, range, widths| {
            for position in range {
                let xref = &xrefs[filter.matches[position]];
                let row = table::row(ui, widths, filter.selected == Some(position));
                if row.response.clicked() {
                    filter.selected = Some(position);
                    action = Some(Action::Go(xref.from));
                }

                table::text(
                    ui,
                    row.cells[0],
                    &format!("{:#x}", xref.from),
                    theme::TEXT,
                    theme::mono(),
                );
                table::text(
                    ui,
                    row.cells[1],
                    &format!("{:#x}", xref.to),
                    theme::TEXT,
                    theme::mono(),
                );
                table::text(
                    ui,
                    row.cells[2],
                    kind_name(xref.kind),
                    theme::MUTED,
                    theme::body(),
                );
                table::text(
                    ui,
                    row.cells[3],
                    &target_name(xref.to),
                    theme::TEXT,
                    theme::mono(),
                );
            }
        },
    );
    action
}

fn kind_name(kind: XrefKind) -> &'static str {
    match kind {
        XrefKind::Call => "call",
        XrefKind::Jump => "jump",
        XrefKind::Data => "data",
    }
}

pub fn strings(ui: &mut Ui, project: &mut Project) -> Option<Action> {
    let listing = &project.listing;
    let strings = &listing.strings;
    let filter = &mut project.strings;
    filter.bar_matching(
        ui,
        "Filter by address or text, or type base64",
        strings.len(),
        |i, query| {
            let entry = &strings[i];
            contains_folded(&entry.value, query)
                || entry.base64.as_ref().is_some_and(|decoded| {
                    contains_folded("base64", query) || contains_folded(decoded, query)
                })
                || contains_folded(&format!("{:#x}", entry.va), query)
        },
    );
    if filter.matches.is_empty() {
        no_results(ui, "Nothing matches");
        return None;
    }

    let mut action = None;
    table::show(
        ui,
        "strings",
        &STRINGS,
        filter.matches.len(),
        None,
        |ui, range, widths| {
            for position in range {
                let entry = &strings[filter.matches[position]];
                let xrefs = listing.xrefs_to(entry.va);
                let row = table::row(ui, widths, filter.selected == Some(position));
                if row.response.clicked() {
                    filter.selected = Some(position);
                    action = Some(match xrefs.first() {
                        Some(xref) => Action::Go(xref.from),
                        None => Action::Status(format!("No code uses {:#x}", entry.va)),
                    });
                }

                table::text(
                    ui,
                    row.cells[0],
                    &format!("{:#x}", entry.va),
                    theme::TEXT,
                    theme::mono(),
                );
                table::text(
                    ui,
                    row.cells[1],
                    &entry.value.len().to_string(),
                    theme::MUTED,
                    theme::mono(),
                );
                table::text(
                    ui,
                    row.cells[2],
                    &xrefs.len().to_string(),
                    theme::MUTED,
                    theme::mono(),
                );
                let tip = base64_tip(entry);
                let (kind, color) = if tip.is_some() {
                    ("Base64", theme::ACCENT)
                } else {
                    ("ASCII", theme::TEXT)
                };
                table::text(ui, row.cells[3], kind, theme::MUTED, theme::body());
                let drawn = table::text(ui, row.cells[4], &entry.value, color, theme::mono());
                if let Some(tip) = tip {
                    tools::underline(ui, drawn, color);
                    tools::tip(ui, row.cells[4], ("string_tip", position), &tip);
                }
            }
        },
    );
    action
}

pub fn no_results(ui: &mut Ui, message: &str) {
    ui.centered_and_justified(|ui| {
        ui.label(RichText::new(message).color(theme::MUTED).size(20.0));
    });
}

pub fn hex_bytes(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|byte| format!("{byte:02X}"))
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod filter_tests {
    use super::*;

    #[test]
    fn filters_borrowed_text_and_restores_all_rows() {
        let rows = ["HELLO", "Ångström", "world"];
        let mut filter = Filter::all(rows.len());
        filter.query = "ång".into();
        filter.update_matching(rows.len(), |i, query| contains_folded(rows[i], query));
        assert_eq!(filter.matches, [1]);
        filter.query = "hello".into();
        filter.update_matching(rows.len(), |i, query| contains_folded(rows[i], query));
        assert_eq!(filter.matches, [0]);
        filter.query.clear();
        filter.update_matching(rows.len(), |_, _| panic!("empty search must not scan text"));
        assert_eq!(filter.matches, [0, 1, 2]);
        assert!(contains_folded("", ""));
        assert!(!contains_folded("a", "long query"));
    }
}
