use eframe::egui::{self, Color32, CornerRadius, FontId, Stroke};

pub const BACKGROUND: Color32 = Color32::from_rgb(0x1A, 0x1A, 0x1A);
pub const SURFACE: Color32 = Color32::from_rgb(0x14, 0x14, 0x14);
pub const HEADER: Color32 = Color32::from_rgb(0x24, 0x24, 0x24);
pub const INPUT: Color32 = Color32::from_rgb(0x22, 0x22, 0x22);
pub const BORDER: Color32 = Color32::from_rgb(0x2C, 0x2C, 0x2C);
pub const HOVER: Color32 = Color32::from_rgb(0x20, 0x20, 0x20);
pub const SELECTED: Color32 = Color32::from_rgb(0x2A, 0x2A, 0x2A);
pub const PILL: Color32 = Color32::from_rgb(0x2E, 0x2E, 0x2E);
pub const GRAPH_BLOCK: Color32 = Color32::from_rgb(0x1F, 0x1F, 0x1F);
pub const GRAPH_BORDER: Color32 = Color32::from_rgb(0x38, 0x38, 0x38);

pub const TEXT: Color32 = Color32::from_rgb(0xD8, 0xD8, 0xD8);
pub const MUTED: Color32 = Color32::from_rgb(0x8C, 0x8C, 0x8C);
pub const PATCHED: Color32 = Color32::from_rgb(0x78, 0x78, 0x78);
pub const GUESSED: Color32 = Color32::from_rgb(0xC9, 0x9A, 0x52);
pub const ACCENT: Color32 = Color32::from_rgb(0x8F, 0xD0, 0x8F);
pub const ERROR: Color32 = Color32::from_rgb(0xE0, 0x6C, 0x75);

pub const BREAKPOINT: Color32 = Color32::from_rgb(0xE5, 0x4B, 0x4B);
pub const CURRENT: Color32 = Color32::from_rgb(0x3B, 0x34, 0x1F);
pub const CURRENT_MARK: Color32 = Color32::from_rgb(0xE5, 0xC0, 0x6B);
pub const CODE_CALL: Color32 = Color32::from_rgb(0x82, 0xAA, 0xE8);

pub const MNEMONIC: Color32 = Color32::from_rgb(0xB7, 0xA6, 0xDB);
pub const CALL: Color32 = Color32::from_rgb(0x6C, 0xC4, 0xC4);
pub const REGISTER: Color32 = Color32::from_rgb(0xE0, 0x7A, 0x80);
pub const NUMBER: Color32 = Color32::from_rgb(0xE5, 0xA3, 0x6B);

pub fn mono() -> FontId {
    FontId::monospace(13.5)
}

pub fn body() -> FontId {
    FontId::proportional(14.0)
}

pub fn apply(ctx: &egui::Context) {
    let radius = CornerRadius::same(8);
    let mut visuals = egui::Visuals::dark();

    visuals.panel_fill = BACKGROUND;
    visuals.window_fill = BACKGROUND;
    visuals.extreme_bg_color = INPUT;
    visuals.override_text_color = Some(TEXT);
    visuals.selection.bg_fill = SELECTED;
    visuals.selection.stroke = Stroke::new(1.0, TEXT);

    for widget in [
        &mut visuals.widgets.noninteractive,
        &mut visuals.widgets.inactive,
        &mut visuals.widgets.hovered,
        &mut visuals.widgets.active,
        &mut visuals.widgets.open,
    ] {
        widget.corner_radius = radius;
    }
    visuals.widgets.noninteractive.bg_stroke = Stroke::new(1.0, BORDER);
    visuals.widgets.inactive.weak_bg_fill = INPUT;
    visuals.widgets.inactive.bg_fill = INPUT;
    visuals.widgets.hovered.weak_bg_fill = PILL;
    visuals.widgets.active.weak_bg_fill = PILL;

    ctx.set_visuals(visuals);
    ctx.all_styles_mut(|style| {
        style.spacing.button_padding = egui::vec2(14.0, 7.0);
        style.spacing.item_spacing = egui::vec2(8.0, 6.0);
        style.spacing.interact_size.y = 32.0;
    });
}
