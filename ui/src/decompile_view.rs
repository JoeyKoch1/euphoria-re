use std::collections::HashMap;
use std::sync::Arc;
use std::sync::mpsc::{self, Receiver};
use std::thread;

use eframe::egui::{self, Color32, Sense, Stroke, Ui};
use euphoria_decompiler::{Decompiler, Output, TokenKind};

use crate::debug_view::{self, DebugState};
use crate::tabs::{self, Action};
use crate::{Project, table, theme};

const ROW: f32 = 22.0;
const CHAR_WIDTH: f32 = 8.2;
const GUTTER: f32 = 14.0;
const INDENT_WIDTH: f32 = 28.0;

type Outcome = Result<Arc<Output>, String>;

#[derive(Default)]
pub struct DecompileState {
    results: HashMap<u64, Outcome>,
    job: Option<(u64, Receiver<Outcome>)>,
    scrolled_for: Option<u64>,
}

impl DecompileState {
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

pub fn show(ui: &mut Ui, project: &mut Project, debug: &mut DebugState) -> Option<Action> {
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
        .id_salt(("decompiled", function.va))
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
                let drawn = ui.painter().text(
                    egui::pos2(x, rect.center().y),
                    egui::Align2::LEFT_CENTER,
                    &token.text,
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
