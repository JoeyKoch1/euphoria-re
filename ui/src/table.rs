use std::ops::Range;

use eframe::egui::{self, Align2, Color32, FontId, Rect, Response, Sense, Stroke, Ui};

use crate::theme;

pub const ROW_HEIGHT: f32 = 30.0;
const HEADER_HEIGHT: f32 = 30.0;
const CELL_PADDING: f32 = 12.0;
const MARKER_WIDTH: f32 = 3.0;

pub enum Width {
    Fixed(f32),
    Fill,
}

pub struct Column {
    pub title: &'static str,
    pub width: Width,
}

pub const fn fixed(title: &'static str, width: f32) -> Column {
    Column {
        title,
        width: Width::Fixed(width),
    }
}

pub const fn fill(title: &'static str) -> Column {
    Column {
        title,
        width: Width::Fill,
    }
}

pub struct Row {
    pub cells: Vec<Rect>,
    pub response: Response,
}

pub struct Widths(Vec<f32>);

pub fn show(
    ui: &mut Ui,
    id: &str,
    columns: &[Column],
    count: usize,
    scroll_to: Option<usize>,
    body: impl FnOnce(&mut Ui, Range<usize>, &Widths),
) {
    header(ui, columns);
    body_rows(ui, id, columns, count, scroll_to, body);
}

pub fn body_rows(
    ui: &mut Ui,
    id: &str,
    columns: &[Column],
    count: usize,
    scroll_to: Option<usize>,
    body: impl FnOnce(&mut Ui, Range<usize>, &Widths),
) {
    let widths = resolve(columns, ui.available_width());

    let mut area = egui::ScrollArea::vertical().id_salt(id).auto_shrink(false);
    if let Some(index) = scroll_to {
        let centered = index as f32 * ROW_HEIGHT - ui.available_height() / 2.0;
        area = area.vertical_scroll_offset(centered.max(0.0));
    }

    ui.spacing_mut().item_spacing.y = 0.0;
    area.show_rows(ui, ROW_HEIGHT, count, |ui, range| body(ui, range, &widths));
}

fn resolve(columns: &[Column], total: f32) -> Widths {
    let used: f32 = columns
        .iter()
        .map(|column| match column.width {
            Width::Fixed(width) => width,
            Width::Fill => 0.0,
        })
        .sum();
    let fills = columns
        .iter()
        .filter(|column| matches!(column.width, Width::Fill))
        .count();
    let share = (total - used).max(120.0) / fills.max(1) as f32;

    Widths(
        columns
            .iter()
            .map(|column| match column.width {
                Width::Fixed(width) => width,
                Width::Fill => share,
            })
            .collect(),
    )
}

fn cells(rect: Rect, widths: &Widths) -> Vec<Rect> {
    let mut x = rect.left();
    widths
        .0
        .iter()
        .map(|width| {
            let cell = Rect::from_min_max(
                egui::pos2(x, rect.top()),
                egui::pos2(x + width, rect.bottom()),
            );
            x += width;
            cell
        })
        .collect()
}

pub fn header(ui: &mut Ui, columns: &[Column]) {
    let widths = &resolve(columns, ui.available_width());
    let size = egui::vec2(ui.available_width(), HEADER_HEIGHT);
    let (rect, _) = ui.allocate_exact_size(size, Sense::hover());
    ui.painter().rect_filled(rect, 0.0, theme::HEADER);
    for (column, cell) in columns.iter().zip(cells(rect, widths)) {
        text(ui, cell, column.title, theme::MUTED, theme::body());
    }
}

pub fn row(ui: &mut Ui, widths: &Widths, selected: bool) -> Row {
    code_row(ui, widths, selected, false, false, false)
}

pub fn marker(ui: &Ui, rect: Rect, color: Color32) {
    let bar = Rect::from_min_size(rect.min, egui::vec2(MARKER_WIDTH, rect.height()));
    ui.painter().rect_filled(bar, 0.0, color);
}

// `flagged` is a breakpoint, whose red bar stays put after the selection moves on. `live` is the
// instruction a paused program would run next.
pub fn code_row(
    ui: &mut Ui,
    widths: &Widths,
    selected: bool,
    flagged: bool,
    bookmarked: bool,
    live: bool,
) -> Row {
    let size = egui::vec2(ui.available_width(), ROW_HEIGHT);
    let (rect, response) = ui.allocate_exact_size(size, Sense::click());

    let painter = ui.painter();
    if live {
        painter.rect_filled(rect, 0.0, theme::CURRENT);
    } else if selected {
        painter.rect_filled(rect, 0.0, theme::SELECTED);
    } else if response.hovered() {
        painter.rect_filled(rect, 0.0, theme::HOVER);
    }
    painter.hline(
        rect.x_range(),
        rect.bottom(),
        Stroke::new(1.0, theme::BORDER),
    );
    if flagged {
        marker(ui, rect, theme::BREAKPOINT);
    } else if bookmarked {
        marker(ui, rect, theme::CURRENT_MARK);
    } else if selected {
        marker(ui, rect, theme::ACCENT);
    }

    Row {
        cells: cells(rect, widths),
        response,
    }
}

pub fn text(ui: &Ui, cell: Rect, value: &str, color: Color32, font: FontId) -> Rect {
    ui.painter_at(cell).text(
        egui::pos2(cell.left() + CELL_PADDING, cell.center().y),
        Align2::LEFT_CENTER,
        value,
        font,
        color,
    )
}
