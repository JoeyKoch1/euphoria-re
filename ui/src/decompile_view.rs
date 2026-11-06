use std::collections::HashMap;
use std::sync::Arc;
use std::sync::mpsc::{self, Receiver};
use std::thread;

use eframe::egui::{self, Color32, RichText, Sense, Stroke, Ui};
use euphoria_decompiler::{Decompiler, Output, TokenKind};
use euphoria_engine::Function;

use crate::debug_view::{self, DebugState};
use crate::tabs::{self, Action};
use crate::{Project, table, theme};

const ROW: f32 = 22.0;
const CHAR_WIDTH: f32 = 8.2;
const GUTTER: f32 = 14.0;
const INDENT_WIDTH: f32 = 28.0;

type Outcome = Result<Arc<Output>, String>;

pub struct DecompileState {
    results: HashMap<u64, Outcome>,
    job: Option<(u64, Receiver<Outcome>)>,
    scrolled_for: Option<u64>,
    split: bool,
    asm_scrolled_for: Option<u64>,
}

impl Default for DecompileState {
    fn default() -> Self {
        Self {
            results: HashMap::new(),
            job: None,
            scrolled_for: None,
            split: true,
            asm_scrolled_for: None,
        }
    }
}

impl DecompileState {
    #[cfg(test)]
    pub(crate) fn insert_for_test(&mut self, va: u64, output: Output) {
        self.results.insert(va, Ok(Arc::new(output)));
    }

    fn start(&mut self, project: &Project, va: u64, ctx: &egui::Context) {
        let analysis = Arc::clone(&project.analysis);
        let listing = Arc::clone(&project.listing);
        let (sender, receiver) = mpsc::channel();
        let ctx = ctx.clone();
        thread::spawn(move || {
            let outcome = Decompiler::new(&analysis, &listing)
                .decompile_at(va)
                .map(Arc::new)
                .map_err(|error| format!("{error:#}"));
            let _ = sender.send(outcome);
            ctx.request_repaint();
        });
        self.job = Some((va, receiver));
    }

    fn poll(&mut self) {
        let Some((va, receiver)) = &self.job else {
            return;
        };
        if let Ok(outcome) = receiver.try_recv() {
            self.results.insert(*va, outcome);
            self.job = None;
        }
    }
}

fn token_color(kind: TokenKind) -> Color32 {
    match kind {
        TokenKind::Plain => theme::MUTED,
        TokenKind::Keyword => theme::MNEMONIC,
        TokenKind::Type => theme::CALL,
        TokenKind::Variable => theme::TEXT,
        TokenKind::Number => theme::NUMBER,
        TokenKind::Text => theme::ACCENT,
        TokenKind::Call => theme::CODE_CALL,
        TokenKind::Comment | TokenKind::Label => theme::MUTED,
    }
}

pub fn show(
    ui: &mut Ui,
    project: &mut Project,
    debug: &mut DebugState,
    assist_config: &mut crate::assist::Config,
    assist_state: &mut crate::assist::State,
) -> Option<Action> {
    let mut action = debug_view::controls(ui, project, debug);

    let cursor_va = project.listing.rows.get(project.cursor).map(|row| row.va);
    let function = cursor_va
        .and_then(|va| project.analysis.function_containing(va))
        .cloned();
    let (Some(cursor_va), Some(function)) = (cursor_va, function) else {
        tabs::no_results(ui, "Pick a line inside a routine to decompile it");
        return action;
    };

    project.decompile.poll();
    if !project.decompile.results.contains_key(&function.va) {
        if project.decompile.job.is_none() {
            let mut state = std::mem::take(&mut project.decompile);
            state.start(project, function.va, ui.ctx());
            project.decompile = state;
        }
        tabs::no_results(ui, "Decompiling...");
        return action;
    }

    let output = match &project.decompile.results[&function.va] {
        Ok(output) => Arc::clone(output),
        Err(message) => {
            let message = format!("Could not decompile this routine: {message}");
            tabs::no_results(ui, &message);
            return action;
        }
    };

    let current = output.line_of(cursor_va);
    let live_line = debug.current_image_ip().and_then(|ip| output.line_of(ip));

    ui.spacing_mut().item_spacing.y = 4.0;
    let label = tabs::function_label(project, &function);
    ui.horizontal(|ui| {
        ui.label(
            RichText::new(format!("{label}  {:#x}", function.va))
                .monospace()
                .color(theme::TEXT),
        );
        if ui
            .small_button("Rename")
            .on_hover_text("Give this routine a name of your own")
            .clicked()
        {
            action = Some(Action::Rename(function.va));
        }
        if ui
            .small_button("Comment")
            .on_hover_text("Comment the instruction under the cursor")
            .clicked()
        {
            action = Some(Action::Comment(cursor_va));
        }
        ui.separator();
        if ui
            .selectable_label(project.decompile.split, "Split")
            .on_hover_text("Show the routine's disassembly beside the pseudo-C")
            .clicked()
        {
            project.decompile.split = !project.decompile.split;
        }
    });
    ui.spacing_mut().item_spacing.y = 0.0;

    let code = if assist_config.enabled {
        output.text()
    } else {
        String::new()
    };
    crate::assist::panel(ui, assist_config, assist_state, function.va, &code);

    if project.decompile.split {
        egui::Panel::left("decompiler_asm")
            .resizable(true)
            .default_size(440.0)
            .min_size(200.0)
            .show(ui, |ui| {
                if let Some(selected) = show_asm(ui, project, debug, &function, cursor_va) {
                    action = Some(selected);
                }
            });
    }

    let pseudo = show_pseudocode(ui, project, debug, &output, cursor_va, current, live_line);
    pseudo.or(action)
}

fn show_asm(
    ui: &mut Ui,
    project: &mut Project,
    debug: &mut DebugState,
    function: &Function,
    cursor_va: u64,
) -> Option<Action> {
    let rows = project.listing.rows_of(function);
    let count = rows.len();
    if count == 0 {
        tabs::no_results(ui, "No instructions were decoded for this routine");
        return None;
    }

    let mut action = None;
    let cursor_row = project.cursor;
    let live = debug.current_image_ip();

    let mut area = egui::ScrollArea::vertical()
        .id_salt(("decompiled_asm", function.va))
        .auto_shrink(false);
    if project.decompile.asm_scrolled_for != Some(cursor_va) {
        project.decompile.asm_scrolled_for = Some(cursor_va);
        let index = project
            .listing
            .row_at(cursor_va)
            .map_or(0, |row| row.saturating_sub(rows.start));
        let offset = index as f32 * ROW - ui.available_height() / 2.0;
        area = area.vertical_scroll_offset(offset.max(0.0));
    }

    area.show_rows(ui, ROW, count, |ui, range| {
        let lines = project.listing.render(
            &project.analysis.data,
            rows.start + range.start..rows.start + range.end,
        );
        for (offset, line) in range.clone().zip(&lines) {
            let index = rows.start + offset;
            let patched = debug.is_patched(line.va, line.bytes.len());
            let (rect, response) = ui.allocate_exact_size(
                egui::vec2(ui.available_width().max(1.0), ROW),
                Sense::click(),
            );

            if live == Some(line.va) {
                ui.painter().rect_filled(rect, 0.0, theme::CURRENT);
            } else if index == cursor_row {
                ui.painter().rect_filled(rect, 0.0, theme::SELECTED);
            } else if response.hovered() {
                ui.painter().rect_filled(rect, 0.0, theme::HOVER);
            }
            if project.breakpoints.contains(&line.va) {
                table::marker(ui, rect, theme::BREAKPOINT);
            } else if index == cursor_row {
                table::marker(ui, rect, theme::ACCENT);
            }

            if response.clicked() {
                action = Some(Action::Select(index));
            }
            if response.double_clicked() {
                debug.toggle_breakpoint(project, line.va);
            }

            let base = if patched {
                theme::PATCHED
            } else {
                theme::MUTED
            };
            let mut x = rect.left() + 8.0;
            let drawn = ui.painter().text(
                egui::pos2(x, rect.center().y),
                egui::Align2::LEFT_CENTER,
                format!("{:#x}", line.va),
                theme::mono(),
                base,
            );
            x = drawn.right() + 12.0;
            for (position, token) in line.tokens.iter().enumerate() {
                let color = if patched {
                    theme::PATCHED
                } else {
                    tabs::token_color(token.kind)
                };
                let drawn = ui.painter().text(
                    egui::pos2(x, rect.center().y),
                    egui::Align2::LEFT_CENTER,
                    &token.text,
                    theme::mono(),
                    color,
                );
                if token.kind == euphoria_engine::TokenKind::Target {
                    let id = ui
                        .scope_id()
                        .with(("decompiler_asm_target", index, position));
                    let hit = ui
                        .interact(drawn, id, Sense::click())
                        .on_hover_cursor(egui::CursorIcon::PointingHand);
                    ui.painter()
                        .hline(drawn.x_range(), drawn.bottom(), Stroke::new(1.0, color));
                    if hit.clicked()
                        && let Some(target) = line.branch
                    {
                        action = Some(Action::Go(target));
                    }
                }
                x = drawn.right() + 6.0;
            }

            let response = match tabs::comment(project, line) {
                Some(tip) => response.on_hover_text(tip),
                None => response,
            }
            .on_hover_text(tabs::hex_bytes(&line.bytes));
            if patched {
                response.on_hover_text("Euphoria wrote over these bytes in the running process.");
            }
        }
    });

    action
}

fn show_pseudocode(
    ui: &mut Ui,
    project: &mut Project,
    debug: &mut DebugState,
    output: &Output,
    cursor_va: u64,
    current: Option<usize>,
    live_line: Option<usize>,
) -> Option<Action> {
    let mut action = None;
    let width = output
        .lines
        .iter()
        .map(|line| {
            let chars: usize = line
                .tokens
                .iter()
                .map(|token| token.text.chars().count())
                .sum();
            line.indent as f32 * INDENT_WIDTH + chars as f32 * CHAR_WIDTH
        })
        .fold(0.0, f32::max)
        + 80.0;

    let mut area = egui::ScrollArea::both()
        .id_salt(("decompiled", output.va))
        .auto_shrink(false);
    if project.decompile.scrolled_for != Some(cursor_va) {
        project.decompile.scrolled_for = Some(cursor_va);
        if let Some(line) = current {
            let offset = line as f32 * ROW - ui.available_height() / 2.0;
            area = area.vertical_scroll_offset(offset.max(0.0));
        }
    }

    ui.spacing_mut().item_spacing.y = 0.0;
    area.show_rows(ui, ROW, output.lines.len(), |ui, range| {
        for index in range {
            let line = &output.lines[index];
            let size = egui::vec2(ui.available_width().max(width), ROW);
            let (rect, response) = ui.allocate_exact_size(size, Sense::click());
            let response = match line.guess {
                Some(guess) => response.on_hover_text(guess.reason()),
                None => response,
            };

            if live_line == Some(index) {
                ui.painter().rect_filled(rect, 0.0, theme::CURRENT);
            } else if current == Some(index) {
                ui.painter().rect_filled(rect, 0.0, theme::SELECTED);
            } else if response.hovered() && line.va.is_some() {
                ui.painter().rect_filled(rect, 0.0, theme::HOVER);
            }

            let has_mark = line.va.is_some_and(|va| project.breakpoints.contains(&va));
            if has_mark {
                table::marker(ui, rect, theme::BREAKPOINT);
            } else if current == Some(index) {
                table::marker(ui, rect, theme::ACCENT);
            } else if line.guess.is_some() {
                table::marker(ui, rect, theme::GUESSED);
            }

            if response.clicked()
                && let Some(va) = line.va
                && let Some(row) = project.listing.row_at(va)
            {
                project.decompile.scrolled_for = Some(project.listing.rows[row].va);
                action = Some(Action::Select(row));
            }
            if response.double_clicked()
                && let Some(va) = line.va
            {
                debug.toggle_breakpoint(project, va);
            }

            let mut x = rect.left() + GUTTER + line.indent as f32 * INDENT_WIDTH;
            for (position, token) in line.tokens.iter().enumerate() {
                let color = token_color(token.kind);
                let text = token
                    .target
                    .and_then(|va| project.names.get(&va))
                    .map_or(token.text.as_str(), String::as_str);
                let drawn = ui.painter().text(
                    egui::pos2(x, rect.center().y),
                    egui::Align2::LEFT_CENTER,
                    text,
                    theme::mono(),
                    color,
                );
                if let Some(target) = token.target {
                    let id = ui.scope_id().with(("decompiled_call", index, position));
                    let hit = ui
                        .interact(drawn, id, Sense::click())
                        .on_hover_cursor(egui::CursorIcon::PointingHand);
                    ui.painter()
                        .hline(drawn.x_range(), drawn.bottom(), Stroke::new(1.0, color));
                    if hit.clicked() {
                        action = Some(Action::Focus(target));
                    }
                }
                x = drawn.right();
            }
        }
    });

    action
}
