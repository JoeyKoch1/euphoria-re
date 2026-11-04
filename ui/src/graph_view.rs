use eframe::egui::{self, FontId, Rect, RichText, Sense, Stroke, Ui};
use euphoria_engine::{Cfg, EdgeKind, Function, GraphLayout, Line, TokenKind, layout};

use crate::canvas::{self, Viewport};
use crate::tabs::{self, Action, Filter};
use crate::{Project, table, theme};

const FONT_SIZE: f32 = 12.5;
const LINE_HEIGHT: f32 = 18.0;
const HEADER_HEIGHT: f32 = 26.0;
const PADDING: f32 = 12.0;
const ADDRESS_CHARS: usize = 14;
const MAX_COMMENT_CHARS: usize = 44;
const MIN_BLOCK_CHARS: usize = 28;
const MAX_BLOCKS: usize = 3000;
const TEXT_ZOOM: f32 = 0.35;
const SIDEBAR_WIDTH: f32 = 300.0;
const SIDEBAR_ROW: f32 = 26.0;

struct LineText {
    comment: Option<String>,
    tip: Option<String>,
}

struct View {
    va: u64,
    name: String,
    first_row: usize,
    cfg: Cfg,
    layout: GraphLayout,
    text: Vec<LineText>,
    kinds: Vec<EdgeKind>,
    viewport: Viewport,
}

pub struct GraphState {
    filter: Filter,
    view: Option<View>,
    center: bool,
}

impl GraphState {
    pub fn new(functions: usize) -> Self {
        Self {
            filter: Filter::all(functions),
            view: None,
            center: false,
        }
    }

    pub fn center_on_cursor(&mut self) {
        self.center = true;
    }
}

fn line_chars(line: &Line, comment: Option<&String>) -> usize {
    let tokens: usize = line
        .tokens
        .iter()
        .map(|token| token.text.chars().count())
        .sum();
    let comment = comment.map_or(0, |text| text.chars().count() + 3);
    ADDRESS_CHARS + 2 + tokens + comment
}

fn build_view(ui: &Ui, project: &Project, function: &Function) -> View {
    let data = &project.analysis.data;
    let cfg = Cfg::build(&project.listing, data, function);

    let text: Vec<LineText> = cfg
        .lines
        .iter()
        .map(|line| LineText {
            comment: tabs::comment(project, line).map(|comment| clip(&comment)),
            tip: tabs::line_tip(project, line),
        })
        .collect();

    let font = FontId::monospace(FONT_SIZE);
    let char_width = ui.ctx().fonts_mut(|fonts| fonts.glyph_width(&font, '0'));
    let sizes: Vec<(f32, f32)> = cfg
        .blocks
        .iter()
        .map(|block| {
            let chars = block
                .lines
                .clone()
                .map(|at| line_chars(&cfg.lines[at], text[at].comment.as_ref()))
                .max()
                .unwrap_or(0)
                .max(MIN_BLOCK_CHARS);
            (
                chars as f32 * char_width + PADDING * 2.0,
                HEADER_HEIGHT + block.lines.len() as f32 * LINE_HEIGHT + PADDING,
            )
        })
        .collect();

    let mut edges = Vec::new();
    let mut kinds = Vec::new();
    for (from, block) in cfg.blocks.iter().enumerate() {
        for edge in &block.edges {
            edges.push((from, edge.to));
            kinds.push(edge.kind);
        }
    }

    View {
        va: function.va,
        name: tabs::function_label(function),
        first_row: project.listing.rows_of(function).start,
        layout: layout(&sizes, &edges),
        cfg,
        text,
        kinds,
        viewport: Viewport::default(),
    }
}

fn clip(text: &str) -> String {
    if text.chars().count() <= MAX_COMMENT_CHARS {
        return text.to_owned();
    }
    let clipped: String = text.chars().take(MAX_COMMENT_CHARS - 1).collect();
    format!("{clipped}…")
}

pub fn show(ui: &mut Ui, project: &mut Project) -> Option<Action> {
    let mut action = sidebar(ui, project);

    let cursor_va = project.listing.rows.get(project.cursor).map(|row| row.va);
    let function = cursor_va
        .and_then(|va| project.analysis.function_containing(va))
        .cloned();
    let Some(function) = function else {
        tabs::no_results(ui, "No routine here to draw");
        return action;
    };

    let stale = project
        .graph
        .view
        .as_ref()
        .is_none_or(|view| view.va != function.va);
    if stale {
        let view = build_view(ui, project, &function);
        project.graph.view = Some(view);
    }

    let cursor = project.cursor;
    let center = std::mem::take(&mut project.graph.center);
    let Some(view) = project.graph.view.as_mut() else {
        return action;
    };

    if view.cfg.blocks.is_empty() {
        tabs::no_results(ui, "Nothing in this routine can be reached");
        return action;
    }
    if view.cfg.blocks.len() > MAX_BLOCKS {
        tabs::no_results(ui, "This routine is too large to draw. Read it in Listing.");
        return action;
    }

    header(ui, view);
    if let Some(next) = draw_canvas(ui, view, cursor, center) {
        action = Some(next);
    }
    action
}

fn sidebar(ui: &mut Ui, project: &mut Project) -> Option<Action> {
    let mut action = None;
    let functions = &project.analysis.functions;
    let filter = &mut project.graph.filter;
    let current = project.graph.view.as_ref().map(|view| view.va);

    egui::Panel::left("graph_functions")
        .exact_size(SIDEBAR_WIDTH)
        .frame(egui::Frame::new().fill(theme::SURFACE).inner_margin(8))
        .show(ui, |ui| {
            let field = ui.add(
                egui::TextEdit::singleline(&mut filter.query)
                    .hint_text("Find a routine")
                    .desired_width(f32::INFINITY),
            );
            if field.changed() {
                filter.update(functions.len(), |i| tabs::function_label(&functions[i]));
            }
            ui.add_space(4.0);

            ui.spacing_mut().item_spacing.y = 0.0;
            ui.style_mut().wrap_mode = Some(egui::TextWrapMode::Truncate);
            egui::ScrollArea::vertical()
                .id_salt("graph_function_list")
                .auto_shrink(false)
                .show_rows(ui, SIDEBAR_ROW, filter.matches.len(), |ui, range| {
                    for position in range {
                        let function = &functions[filter.matches[position]];
                        let selected = current == Some(function.va);
                        let size = egui::vec2(ui.available_width(), SIDEBAR_ROW);
                        let (rect, response) = ui.allocate_exact_size(size, Sense::click());
                        if selected {
                            ui.painter().rect_filled(rect, 6.0, theme::PILL);
                        } else if response.hovered() {
                            ui.painter().rect_filled(rect, 6.0, theme::HOVER);
                        }
                        let color = if selected { theme::TEXT } else { theme::MUTED };
                        table::text(
                            ui,
                            rect,
                            &tabs::function_label(function),
                            color,
                            FontId::monospace(12.5),
                        );
                        if response.clicked() {
                            action = Some(Action::Focus(function.va));
                        }
                    }
                });
        });
    action
}

fn header(ui: &mut Ui, view: &mut View) {
    egui::Frame::new()
        .inner_margin(egui::Margin::symmetric(12, 8))
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.label(RichText::new(&view.name).font(theme::mono()));
                ui.label(
                    RichText::new(format!(
                        "{} nodes, {} ops",
                        view.cfg.blocks.len(),
                        view.cfg.lines.len()
                    ))
                    .color(theme::MUTED),
                );
                if ui.button("Show all").clicked() {
                    view.viewport.request_fit();
                }
                ui.label(
                    RichText::new(
                        "Hold and drag to move. Ctrl + wheel zooms. Space flips to Listing.",
                    )
                    .color(theme::MUTED),
                );
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    for (label, color) in [
                        ("direct", theme::MUTED),
                        ("falls through", theme::NUMBER),
                        ("jumps", theme::ACCENT),
                    ] {
                        ui.label(RichText::new(label).color(color));
                    }
                });
            });
        });
}

fn draw_canvas(ui: &mut Ui, view: &mut View, cursor: usize, center: bool) -> Option<Action> {
    let rect = ui.available_rect_before_wrap();
    let response = ui.allocate_rect(rect, Sense::click_and_drag());

    let first = view.layout.nodes[0];
    view.viewport.place(
        rect,
        (view.layout.width, view.layout.height),
        (first.x + first.width / 2.0, first.y),
    );

    let selected_line = cursor
        .checked_sub(view.first_row)
        .filter(|&line| line < view.cfg.lines.len());
    let selected_block = selected_line.and_then(|line| view.cfg.block_of_line(line));

    if center && let Some(block) = selected_block {
        let node = view.layout.nodes[block];
        view.viewport.center_on(
            rect,
            (node.x + node.width / 2.0, node.y + node.height / 2.0),
        );
    }
    view.viewport.handle_input(ui, &response, rect);

    let painter = ui.painter_at(rect);
    painter.rect_filled(rect, 0.0, theme::SURFACE);

    let zoom = view.viewport.zoom;
    for (route, kind) in view.layout.routes.iter().zip(&view.kinds) {
        let color = match kind {
            EdgeKind::Taken => theme::ACCENT,
            EdgeKind::NotTaken => theme::NUMBER,
            EdgeKind::Always => theme::MUTED,
        };
        let highlighted =
            selected_block.is_some_and(|block| route.from == block || route.to == block);
        canvas::draw_route(&painter, route, color, highlighted, &view.viewport, rect);
    }

    let mut action = None;
    for (index, node) in view.layout.nodes.iter().enumerate() {
        let min = view.viewport.to_screen(rect, (node.x, node.y));
        let block_rect = Rect::from_min_size(min, egui::vec2(node.width, node.height) * zoom);
        if !block_rect.intersects(rect) {
            continue;
        }

        let border = if selected_block == Some(index) {
            theme::ACCENT
        } else {
            theme::GRAPH_BORDER
        };
        let radius = 6.0 * zoom;
        painter.rect_filled(block_rect, radius, theme::GRAPH_BLOCK);
        painter.rect_stroke(
            block_rect,
            radius,
            Stroke::new(1.0, border),
            egui::StrokeKind::Inside,
        );

        if zoom < TEXT_ZOOM {
            continue;
        }

        let block = &view.cfg.blocks[index];
        let font = FontId::monospace(FONT_SIZE * zoom);
        let title = if index == 0 {
            clip(&view.name)
        } else {
            format!("loc_{:x}", block.va)
        };
        painter.text(
            egui::pos2(min.x + PADDING * zoom, min.y + HEADER_HEIGHT * zoom / 2.0),
            egui::Align2::LEFT_CENTER,
            title,
            font.clone(),
            theme::MUTED,
        );
        painter.hline(
            block_rect.x_range(),
            min.y + HEADER_HEIGHT * zoom,
            Stroke::new(1.0, theme::GRAPH_BORDER),
        );

        for (slot, at) in block.lines.clone().enumerate() {
            let top = min.y + (HEADER_HEIGHT + PADDING / 2.0 + slot as f32 * LINE_HEIGHT) * zoom;
            let line_rect = Rect::from_min_size(
                egui::pos2(block_rect.left(), top),
                egui::vec2(block_rect.width(), LINE_HEIGHT * zoom),
            );
            if !line_rect.intersects(rect) {
                continue;
            }

            let id = ui.scope_id().with(("graph_line", view.va, at));
            let hit = ui.interact(line_rect.intersect(rect), id, Sense::click());
            if hit.clicked() {
                action = Some(Action::Select(view.first_row + at));
            }
            if hit.double_clicked() {
                action = Some(Action::Go(view.cfg.lines[at].va));
            }
            if selected_line == Some(at) {
                painter.rect_filled(line_rect, 0.0, theme::SELECTED);
            } else if hit.hovered() {
                painter.rect_filled(line_rect, 0.0, theme::HOVER);
            }

            if let Some(target) = draw_line(ui, &painter, view, at, line_rect, &font) {
                action = Some(Action::Focus(target));
            }
        }
    }
    action
}

fn draw_line(
    ui: &Ui,
    painter: &egui::Painter,
    view: &View,
    at: usize,
    rect: Rect,
    font: &FontId,
) -> Option<u64> {
    let line = &view.cfg.lines[at];
    let char_width = ui.ctx().fonts_mut(|fonts| fonts.glyph_width(font, '0'));
    let y = rect.center().y;
    let mut x = rect.left() + PADDING * view.viewport.zoom;
    let mut clicked = None;

    painter.text(
        egui::pos2(x, y),
        egui::Align2::LEFT_CENTER,
        format!("{:#x}", line.va),
        font.clone(),
        theme::MUTED,
    );
    x += char_width * (ADDRESS_CHARS + 2) as f32;

    for (position, token) in line.tokens.iter().enumerate() {
        let width = char_width * token.text.chars().count() as f32;
        let color = tabs::token_color(token.kind);
        painter.text(
            egui::pos2(x, y),
            egui::Align2::LEFT_CENTER,
            &token.text,
            font.clone(),
            color,
        );

        if token.kind == TokenKind::Target {
            let area =
                Rect::from_min_size(egui::pos2(x, rect.top()), egui::vec2(width, rect.height()));
            let id = ui.scope_id().with(("graph_target", view.va, at, position));
            let hit = ui
                .interact(area, id, Sense::click())
                .on_hover_cursor(egui::CursorIcon::PointingHand);
            painter.hline(area.x_range(), y + font.size * 0.6, Stroke::new(1.0, color));
            if hit.clicked() {
                clicked = line.branch;
            }
        }
        x += width;
    }

    if let Some(comment) = &view.text[at].comment {
        let color = if view.text[at].tip.is_some() {
            theme::ACCENT
        } else {
            theme::MUTED
        };
        let text = format!(" ; {comment}");
        let width = char_width * text.chars().count() as f32;
        painter.text(
            egui::pos2(x, y),
            egui::Align2::LEFT_CENTER,
            text,
            font.clone(),
            color,
        );

        if let Some(tip) = &view.text[at].tip {
            let area =
                Rect::from_min_size(egui::pos2(x, rect.top()), egui::vec2(width, rect.height()));
            let id = ui.scope_id().with(("graph_tip", view.va, at));
            ui.interact(area, id, Sense::hover()).on_hover_text(tip);
        }
    }
    clicked
}
