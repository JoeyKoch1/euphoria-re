use std::path::PathBuf;

use eframe::egui::{self, Color32, FontId, Rect, RichText, Sense, Stroke, Ui};
use euphoria_engine::{GraphLayout, layout};
use euphoria_sql::{Level, ObjectKind, RelationKind, Script, Statement};

use crate::canvas::{self, Viewport};
use crate::table::{self, Column, fill, fixed};
use crate::tabs::{self, Action, Filter};
use crate::theme;

const STATEMENTS: [Column; 5] = [
    fixed("Line", 70.0),
    fixed("Type", 170.0),
    fill("What it does"),
    fill("Touches"),
    fill("Watch out"),
];
const MAX_COLUMNS_SHOWN: usize = 10;
const NODE_LINE: f32 = 18.0;
const NODE_HEADER: f32 = 28.0;
const NODE_PADDING: f32 = 12.0;
const NODE_FONT: f32 = 12.5;
const NODE_MIN_CHARS: usize = 22;
const TEXT_ZOOM: f32 = 0.35;

#[derive(Clone, Copy, PartialEq)]
enum Mode {
    Statements,
    Map,
}

pub struct SqlView {
    script: Script,
    filter: Filter,
    mode: Mode,
    layout: GraphLayout,
    viewport: Viewport,
    selected: Option<usize>,
    selected_object: Option<usize>,
}

impl SqlView {
    pub fn new(script: Script) -> Self {
        Self {
            filter: Filter::all(script.statements.len()),
            mode: Mode::Statements,
            layout: GraphLayout::default(),
            viewport: Viewport::default(),
            selected: None,
            selected_object: None,
            script,
        }
    }
}

fn object_lines(script: &Script, index: usize) -> usize {
    let object = &script.objects[index];
    let extra = usize::from(object.columns.len() > MAX_COLUMNS_SHOWN);
    object.columns.len().min(MAX_COLUMNS_SHOWN) + extra + 1
}

fn kind_label(kind: ObjectKind) -> &'static str {
    match kind {
        ObjectKind::Table => "table",
        ObjectKind::View => "view",
        ObjectKind::Trigger => "trigger",
        ObjectKind::Procedure => "routine",
        ObjectKind::Unknown => "referenced",
    }
}

fn relation_color(kind: RelationKind) -> Color32 {
    match kind {
        RelationKind::Feeds => theme::ACCENT,
        RelationKind::References => theme::CALL,
        RelationKind::Fires => theme::NUMBER,
    }
}

fn level_color(level: Level) -> Color32 {
    match level {
        Level::Danger => theme::ERROR,
        Level::Warning => theme::NUMBER,
        Level::Note => theme::MUTED,
    }
}

fn build_layout(ui: &Ui, script: &Script) -> GraphLayout {
    let font = FontId::monospace(NODE_FONT);
    let char_width = ui.ctx().fonts_mut(|fonts| fonts.glyph_width(&font, '0'));

    let sizes: Vec<(f32, f32)> = (0..script.objects.len())
        .map(|index| {
            let object = &script.objects[index];
            let chars = object
                .columns
                .iter()
                .take(MAX_COLUMNS_SHOWN)
                .map(|column| column.chars().count())
                .chain([object.name.chars().count() + 2, NODE_MIN_CHARS])
                .max()
                .unwrap_or(NODE_MIN_CHARS);
            (
                chars as f32 * char_width + NODE_PADDING * 2.0,
                NODE_HEADER + object_lines(script, index) as f32 * NODE_LINE + NODE_PADDING,
            )
        })
        .collect();

    let edges: Vec<(usize, usize)> = script
        .relations
        .iter()
        .map(|relation| (relation.from, relation.to))
        .collect();
    layout(&sizes, &edges)
}

fn pick_file() -> Option<PathBuf> {
    rfd::FileDialog::new().pick_file()
}

fn toolbar(ui: &mut Ui, view: Option<&mut SqlView>) -> Option<Action> {
    let mut action = None;
    egui::Frame::new()
        .inner_margin(egui::Margin::symmetric(12, 10))
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                if ui.button("Load SQL file").clicked()
                    && let Some(path) = pick_file()
                {
                    action = Some(Action::Open(path));
                }

                let Some(view) = view else {
                    return;
                };
                for (mode, title) in [(Mode::Statements, "Statements"), (Mode::Map, "Map")] {
                    let selected = view.mode == mode;
                    let fill = if selected {
                        theme::PILL
                    } else {
                        Color32::TRANSPARENT
                    };
                    if ui.add(egui::Button::new(title).fill(fill)).clicked() {
                        view.mode = mode;
                    }
                }
                if view.mode == Mode::Map && ui.button("Show all").clicked() {
                    view.viewport.request_fit();
                }

                let script = &view.script;
                ui.label(
                    RichText::new(format!(
                        "{} statements, {} objects, {} worth checking",
                        script.statements.len(),
                        script.objects.len(),
                        script.flagged()
                    ))
                    .color(theme::MUTED),
                );
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    let name = std::path::Path::new(&script.source)
                        .file_name()
                        .unwrap_or_default()
                        .to_string_lossy();
                    ui.label(RichText::new(name).color(theme::TEXT));
                });
            });
        });
    action
}

pub fn show(ui: &mut Ui, view: &mut Option<SqlView>) -> Option<Action> {
    let action = toolbar(ui, view.as_mut());
    let Some(view) = view else {
        tabs::no_results(
            ui,
            "Load a SQL script or SQLite file to see what it does. Nothing in it gets run.",
        );
        return action;
    };

    match view.mode {
        Mode::Statements => statements(ui, view),
        Mode::Map => map(ui, view),
    }
    action
}

fn touches(statement: &Statement) -> String {
    let mut parts = Vec::new();
    if !statement.writes.is_empty() {
        parts.push(format!("writes {}", statement.writes.join(", ")));
    }
    if !statement.reads.is_empty() {
        parts.push(format!("reads {}", statement.reads.join(", ")));
    }
    parts.join("; ")
}

fn statements(ui: &mut Ui, view: &mut SqlView) {
    let script = &view.script;
    let filter = &mut view.filter;
    filter.bar(
        ui,
        "Filter by table, type, or text",
        script.statements.len(),
        |i| {
            let statement = &script.statements[i];
            let flags: Vec<&str> = statement.flags.iter().map(|flag| flag.message).collect();
            format!(
                "{} {} {} {} {}",
                statement.kind,
                statement.summary,
                touches(statement),
                flags.join(" "),
                statement.text
            )
        },
    );
    if filter.matches.is_empty() {
        tabs::no_results(ui, "Nothing matches");
        return;
    }

    if let Some(selected) = view.selected.and_then(|index| script.statements.get(index)) {
        egui::Panel::bottom("sql_statement_text")
            .default_size(150.0)
            .frame(
                egui::Frame::new()
                    .fill(theme::SURFACE)
                    .inner_margin(egui::Margin::symmetric(12, 8)),
            )
            .show(ui, |ui| {
                egui::ScrollArea::vertical()
                    .id_salt("sql_text")
                    .auto_shrink(false)
                    .show(ui, |ui| {
                        ui.add(
                            egui::Label::new(RichText::new(&selected.text).font(theme::mono()))
                                .wrap(),
                        );
                    });
            });
    }

    let selected = &mut view.selected;
    table::show(
        ui,
        "sql_statements",
        &STATEMENTS,
        filter.matches.len(),
        None,
        |ui, range, widths| {
            for position in range {
                let index = filter.matches[position];
                let statement = &script.statements[index];
                let row = table::row(ui, widths, *selected == Some(index));
                if row.response.clicked() {
                    *selected = Some(index);
                }

                table::text(
                    ui,
                    row.cells[0],
                    &statement.line.to_string(),
                    theme::MUTED,
                    theme::mono(),
                );
                table::text(
                    ui,
                    row.cells[1],
                    &statement.kind,
                    theme::MNEMONIC,
                    theme::mono(),
                );
                table::text(
                    ui,
                    row.cells[2],
                    &statement.summary,
                    theme::TEXT,
                    theme::body(),
                );
                table::text(
                    ui,
                    row.cells[3],
                    &touches(statement),
                    theme::MUTED,
                    theme::body(),
                );
                if let Some(flag) = statement.flags.iter().max_by_key(|flag| flag.level as u8) {
                    table::text(
                        ui,
                        row.cells[4],
                        flag.message,
                        level_color(flag.level),
                        theme::body(),
                    );
                }
            }
        },
    );
}

fn map(ui: &mut Ui, view: &mut SqlView) {
    if view.script.objects.is_empty() {
        tabs::no_results(ui, "No tables or views found in this file");
        return;
    }
    if view.layout.nodes.is_empty() {
        view.layout = build_layout(ui, &view.script);
    }

    egui::Frame::new()
        .inner_margin(egui::Margin::symmetric(12, 4))
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                for (label, color) in [
                    ("data flows", theme::ACCENT),
                    ("foreign key", theme::CALL),
                    ("trigger fires", theme::NUMBER),
                ] {
                    ui.label(RichText::new(label).color(color));
                }
            });
        });

    let rect = ui.available_rect_before_wrap();
    let response = ui.allocate_rect(rect, Sense::click_and_drag());
    let first = view.layout.nodes[0];
    view.viewport.place(
        rect,
        (view.layout.width, view.layout.height),
        (first.x + first.width / 2.0, first.y),
    );
    view.viewport.handle_input(ui, &response, rect);

    let painter = ui.painter_at(rect);
    painter.rect_filled(rect, 0.0, theme::SURFACE);

    for (route, relation) in view.layout.routes.iter().zip(&view.script.relations) {
        let highlighted = view
            .selected_object
            .is_some_and(|object| route.from == object || route.to == object);
        canvas::draw_route(
            &painter,
            route,
            relation_color(relation.kind),
            highlighted,
            &view.viewport,
            rect,
        );
    }

    let zoom = view.viewport.zoom;
    for (index, node) in view.layout.nodes.iter().enumerate() {
        let min = view.viewport.to_screen(rect, (node.x, node.y));
        let box_rect = Rect::from_min_size(min, egui::vec2(node.width, node.height) * zoom);
        if !box_rect.intersects(rect) {
            continue;
        }

        let id = ui.scope_id().with(("sql_node", index));
        if ui
            .interact(box_rect.intersect(rect), id, Sense::click())
            .clicked()
        {
            view.selected_object = Some(index);
        }

        let border = if view.selected_object == Some(index) {
            theme::ACCENT
        } else {
            theme::GRAPH_BORDER
        };
        let radius = 6.0 * zoom;
        painter.rect_filled(box_rect, radius, theme::GRAPH_BLOCK);
        painter.rect_stroke(
            box_rect,
            radius,
            Stroke::new(1.0, border),
            egui::StrokeKind::Inside,
        );
        if zoom < TEXT_ZOOM {
            continue;
        }

        let object = &view.script.objects[index];
        let font = FontId::monospace(NODE_FONT * zoom);
        let x = min.x + NODE_PADDING * zoom;
        painter.text(
            egui::pos2(x, min.y + NODE_HEADER * zoom / 2.0),
            egui::Align2::LEFT_CENTER,
            &object.name,
            font.clone(),
            theme::TEXT,
        );
        painter.hline(
            box_rect.x_range(),
            min.y + NODE_HEADER * zoom,
            Stroke::new(1.0, theme::GRAPH_BORDER),
        );

        let mut y = min.y + (NODE_HEADER + NODE_PADDING / 2.0 + NODE_LINE / 2.0) * zoom;
        let mut line = |text: &str, color| {
            painter.text(
                egui::pos2(x, y),
                egui::Align2::LEFT_CENTER,
                text,
                font.clone(),
                color,
            );
            y += NODE_LINE * zoom;
        };

        let kind = match object.rows {
            Some(rows) => format!("{}, {rows} rows", kind_label(object.kind)),
            None => kind_label(object.kind).to_owned(),
        };
        line(&kind, theme::MNEMONIC);
        for column in object.columns.iter().take(MAX_COLUMNS_SHOWN) {
            line(column, theme::MUTED);
        }
        if object.columns.len() > MAX_COLUMNS_SHOWN {
            line(
                &format!("+{} more", object.columns.len() - MAX_COLUMNS_SHOWN),
                theme::MUTED,
            );
        }
    }
}
