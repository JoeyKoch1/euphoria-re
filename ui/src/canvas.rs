use eframe::egui::epaint::CubicBezierShape;
use eframe::egui::{self, Color32, Painter, Pos2, Rect, Response, Stroke, Ui, Vec2};
use euphoria_engine::Route;

pub const MIN_ZOOM: f32 = 0.12;
const MAX_ZOOM: f32 = 2.0;
const READABLE_ZOOM: f32 = 0.8;
const MARGIN: f32 = 48.0;

pub struct Viewport {
    pub pan: Vec2,
    pub zoom: f32,
    placed: bool,
}

impl Default for Viewport {
    fn default() -> Self {
        Self {
            pan: Vec2::ZERO,
            zoom: 1.0,
            placed: false,
        }
    }
}

impl Viewport {
    pub fn to_screen(&self, rect: Rect, point: (f32, f32)) -> Pos2 {
        rect.min + self.pan + egui::vec2(point.0, point.1) * self.zoom
    }

    pub fn request_fit(&mut self) {
        self.placed = false;
        self.zoom = 0.0;
    }

    // First use keeps text readable, so a large graph opens zoomed in on its top node.
    pub fn place(&mut self, rect: Rect, size: (f32, f32), top: (f32, f32)) {
        if self.placed {
            return;
        }

        let wide = (rect.width() - MARGIN) / size.0.max(1.0);
        let tall = (rect.height() - MARGIN) / size.1.max(1.0);
        let fit = wide.min(tall).clamp(MIN_ZOOM, 1.0);

        if self.zoom == 0.0 || fit >= READABLE_ZOOM {
            self.zoom = fit;
            self.pan = (rect.size() - egui::vec2(size.0, size.1) * fit) / 2.0;
        } else {
            self.zoom = READABLE_ZOOM;
            self.pan = egui::vec2(
                rect.width() / 2.0 - top.0 * self.zoom,
                MARGIN / 2.0 - top.1 * self.zoom,
            );
        }
        self.placed = true;
    }

    pub fn center_on(&mut self, rect: Rect, point: (f32, f32)) {
        self.pan = rect.size() / 2.0 - egui::vec2(point.0, point.1) * self.zoom;
    }

    pub fn handle_input(&mut self, ui: &Ui, response: &Response, rect: Rect) {
        self.pan += response.drag_delta();
        if !response.hovered() {
            return;
        }

        let (scroll, zoom_delta, pointer) = ui.input(|input| {
            (
                input.smooth_scroll_delta,
                input.zoom_delta(),
                input.pointer.hover_pos(),
            )
        });
        self.pan += scroll;
        if zoom_delta != 1.0
            && let Some(pointer) = pointer
        {
            let zoom = (self.zoom * zoom_delta).clamp(MIN_ZOOM, MAX_ZOOM);
            let anchor = pointer - rect.min - self.pan;
            self.pan += anchor - anchor * (zoom / self.zoom);
            self.zoom = zoom;
        }
    }
}

pub fn draw_route(
    painter: &Painter,
    route: &Route,
    color: Color32,
    highlighted: bool,
    viewport: &Viewport,
    rect: Rect,
) {
    let points: Vec<Pos2> = route
        .points
        .iter()
        .map(|&point| viewport.to_screen(rect, point))
        .collect();
    if points.len() < 2 || !Rect::from_points(&points).expand(24.0).intersects(rect) {
        return;
    }

    let stroke = Stroke::new(if highlighted { 2.2 } else { 1.2 }, color);
    for pair in points.windows(2) {
        let (a, b) = (pair[0], pair[1]);
        let bend = (b.y - a.y) / 2.0;
        painter.add(CubicBezierShape::from_points_stroke(
            [a, a + egui::vec2(0.0, bend), b - egui::vec2(0.0, bend), b],
            false,
            Color32::TRANSPARENT,
            stroke,
        ));
    }

    let tip = points[points.len() - 1];
    let direction = egui::vec2(0.0, 1.0);
    let scale = viewport.zoom.max(0.6);
    let side = direction.rot90() * 4.0 * scale;
    let base = tip - direction * 8.0 * scale;
    painter.add(egui::Shape::convex_polygon(
        vec![tip, base + side, base - side],
        color,
        Stroke::NONE,
    ));
}
