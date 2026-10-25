//! Shared GUI widgets and display formatting.
use eframe::egui::{self, Color32, RichText, Stroke, Vec2};

pub(super) fn caption(ui: &mut egui::Ui, text: impl Into<String>) -> egui::Response {
    ui.label(
        RichText::new(text)
            .small()
            .color(ui.visuals().weak_text_color()),
    )
}

pub(super) fn path_picker(ui: &mut egui::Ui, value: &mut String, hint: &str, button: &str) -> bool {
    ui.horizontal(|ui| {
        ui.add(
            egui::TextEdit::singleline(value)
                .hint_text(hint)
                .desired_width(315.0),
        );
        ui.button(button).clicked()
    })
    .inner
}

pub(super) fn card(ctx: &egui::Context) -> egui::Frame {
    let style = ctx.style();
    egui::Frame::new()
        .fill(style.visuals.window_fill)
        .stroke(style.visuals.widgets.noninteractive.bg_stroke)
        .corner_radius(14)
        .inner_margin(16)
}
pub(super) fn section(ui: &mut egui::Ui, number: &str, title: &str) {
    ui.allocate_ui_with_layout(
        Vec2::new(ui.available_width(), 18.0),
        egui::Layout::left_to_right(egui::Align::Center),
        |ui| {
            caption(ui, number);
            ui.label(RichText::new(title).strong());
        },
    );
    ui.add_space(6.0);
}
pub(super) fn pill(ui: &mut egui::Ui, text: &str, color: Color32) {
    let galley = ui
        .painter()
        .layout_no_wrap(text.into(), egui::FontId::proportional(12.0), color);
    let (rect, _) =
        ui.allocate_exact_size(galley.size() + Vec2::new(20.0, 10.0), egui::Sense::hover());
    ui.painter()
        .rect_filled(rect, 12, tint(color, ui.visuals().window_fill));
    ui.painter()
        .galley(rect.center() - galley.size() * 0.5, galley, color);
}
pub(super) fn tint(color: Color32, background: Color32) -> Color32 {
    let channel = |c: u8, base: u8| ((u16::from(c) * 8 + u16::from(base) * 92) / 100) as u8;
    Color32::from_rgb(
        channel(color.r(), background.r()),
        channel(color.g(), background.g()),
        channel(color.b(), background.b()),
    )
}
pub(super) fn metric(ui: &mut egui::Ui, label: &str, value: &str) {
    caption(ui, label);
    ui.label(RichText::new(value).size(20.0).strong());
}
pub(super) fn laptop(ui: &mut egui::Ui, connected: bool) {
    let (rect, _) = ui.allocate_exact_size(Vec2::new(62.0, 54.0), egui::Sense::hover());
    let color = if connected {
        ui.visuals().hyperlink_color
    } else {
        ui.visuals().weak_text_color()
    };
    let screen = egui::Rect::from_min_size(rect.min + Vec2::new(9.0, 6.0), Vec2::new(43.0, 30.0));
    ui.painter()
        .rect_filled(screen, 4, tint(color, ui.visuals().window_fill));
    ui.painter().rect_stroke(
        screen,
        4,
        Stroke::new(1.8_f32, color),
        egui::StrokeKind::Inside,
    );
    ui.painter().line_segment(
        [
            rect.min + Vec2::new(4.0, 40.0),
            rect.min + Vec2::new(58.0, 40.0),
        ],
        Stroke::new(2.0_f32, color),
    );
}
pub(super) use zalivka::progress::human_bytes;
pub(super) fn elapsed_text(seconds: u64) -> String {
    format!(
        "{:02}:{:02}:{:02}",
        seconds / 3600,
        seconds / 60 % 60,
        seconds % 60
    )
}
pub(super) fn friendly_phase(name: &str) -> &'static str {
    if name.starts_with("cleanup") || name.contains("bootable") || name.contains("autoboot") {
        "Завершение"
    } else if name.contains("recovery") {
        "Обновление recoveryOS"
    } else if name.contains("firmware") || name.starts_with("update_") || name.contains("ticket") {
        "Обновление прошивки"
    } else if name.contains("restore") || name.contains("filesystem") || name.contains("mount") {
        "Подготовка системы"
    } else {
        "Подготовка Mac"
    }
}
