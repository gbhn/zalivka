use anyhow::{Context, Result};
use eframe::egui::{self, Color32, Stroke, Vec2};
use std::path::{Path, PathBuf};

const BG: Color32 = Color32::from_rgb(245, 247, 250);
const INK: Color32 = Color32::from_rgb(24, 32, 48);
const MUTED: Color32 = Color32::from_rgb(101, 112, 130);
const LINE: Color32 = Color32::from_rgb(225, 230, 238);
pub(super) const BLUE: Color32 = Color32::from_rgb(43, 103, 224);
const GREEN: Color32 = Color32::from_rgb(24, 117, 88);
pub(super) const RED: Color32 = Color32::from_rgb(193, 58, 68);

pub(super) fn configure(ctx: &egui::Context) {
    apply_preference(
        ctx,
        preference_file()
            .as_deref()
            .map(read_preference)
            .unwrap_or_default(),
    );
    ctx.style_mut_of(egui::Theme::Light, |style| {
        style.visuals = egui::Visuals::light();
        style.visuals.panel_fill = BG;
        style.visuals.window_fill = Color32::WHITE;
        style.visuals.override_text_color = Some(INK);
        style.visuals.weak_text_color = Some(MUTED);
        style.visuals.error_fg_color = RED;
        style.visuals.widgets.inactive.bg_fill = Color32::WHITE;
        style.visuals.widgets.inactive.weak_bg_fill = Color32::WHITE;
        style.visuals.widgets.inactive.bg_stroke = Stroke::new(1.0_f32, LINE);
        style.visuals.widgets.hovered.bg_fill = Color32::from_rgb(237, 242, 253);
        style.visuals.widgets.hovered.weak_bg_fill = Color32::from_rgb(237, 242, 253);
        style.visuals.widgets.hovered.bg_stroke = Stroke::new(1.0_f32, BLUE);
        style.visuals.widgets.active.bg_fill = Color32::from_rgb(225, 234, 253);
        style.visuals.widgets.active.weak_bg_fill = Color32::from_rgb(225, 234, 253);
        style.visuals.widgets.noninteractive.bg_stroke = Stroke::new(1.0_f32, LINE);
    });
    ctx.style_mut_of(egui::Theme::Dark, |style| {
        style.visuals = egui::Visuals::dark();
        style.visuals.panel_fill = Color32::from_rgb(16, 22, 31);
        style.visuals.window_fill = Color32::from_rgb(24, 32, 44);
        style.visuals.extreme_bg_color = Color32::from_rgb(12, 17, 25);
        style.visuals.override_text_color = Some(Color32::from_rgb(230, 236, 246));
        style.visuals.weak_text_color = Some(Color32::from_rgb(166, 179, 199));
        style.visuals.error_fg_color = Color32::from_rgb(255, 136, 150);
        style.visuals.hyperlink_color = Color32::from_rgb(132, 179, 255);
        style.visuals.widgets.noninteractive.bg_fill = style.visuals.window_fill;
        style.visuals.widgets.noninteractive.bg_stroke =
            Stroke::new(1.0_f32, Color32::from_rgb(52, 65, 84));
        for (widget, fill) in [
            (
                &mut style.visuals.widgets.inactive,
                Color32::from_rgb(33, 44, 60),
            ),
            (
                &mut style.visuals.widgets.hovered,
                Color32::from_rgb(44, 62, 86),
            ),
            (
                &mut style.visuals.widgets.active,
                Color32::from_rgb(53, 78, 113),
            ),
            (
                &mut style.visuals.widgets.open,
                Color32::from_rgb(33, 44, 60),
            ),
        ] {
            widget.bg_fill = fill;
            widget.weak_bg_fill = fill;
        }
    });
    ctx.all_styles_mut(|style| {
        style.visuals.selection.bg_fill = BLUE;
        style.visuals.selection.stroke = Stroke::new(1.0_f32, Color32::WHITE);
        for widget in [
            &mut style.visuals.widgets.inactive,
            &mut style.visuals.widgets.hovered,
            &mut style.visuals.widgets.active,
            &mut style.visuals.widgets.noninteractive,
            &mut style.visuals.widgets.open,
        ] {
            widget.corner_radius = 8.into();
        }
        style.spacing.item_spacing = Vec2::new(10.0, 8.0);
        style.spacing.button_padding = Vec2::new(15.0, 9.0);
        style.spacing.interact_size.y = 34.0;
        style.spacing.scroll = egui::style::ScrollStyle::solid();
        for (text, size) in [
            (egui::TextStyle::Body, 14.0),
            (egui::TextStyle::Button, 14.0),
            (egui::TextStyle::Heading, 25.0),
            (egui::TextStyle::Small, 12.0),
        ] {
            style
                .text_styles
                .insert(text, egui::FontId::proportional(size));
        }
    });
    #[cfg(windows)]
    if let Some(windows) = std::env::var_os("WINDIR")
        && let Ok(bytes) = std::fs::read(PathBuf::from(windows).join("Fonts/segoeui.ttf"))
    {
        let mut fonts = egui::FontDefinitions::default();
        fonts
            .font_data
            .insert("system".into(), egui::FontData::from_owned(bytes).into());
        fonts
            .families
            .entry(egui::FontFamily::Proportional)
            .or_default()
            .insert(0, "system".into());
        ctx.set_fonts(fonts);
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Tone {
    Neutral,
    Success,
    Error,
}
impl Tone {
    pub(super) fn color(self, visuals: &egui::Visuals) -> Color32 {
        match self {
            Self::Neutral => visuals.weak_text_color(),
            Self::Error => visuals.error_fg_color,
            Self::Success if visuals.dark_mode => Color32::from_rgb(98, 213, 165),
            Self::Success => GREEN,
        }
    }
}

fn preference_file() -> Option<PathBuf> {
    let root = if cfg!(windows) {
        std::env::var_os("LOCALAPPDATA").map(PathBuf::from)
    } else {
        std::env::var_os("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".config")))
    }?;
    root.is_absolute()
        .then(|| root.join("zalivka").join("theme"))
}

fn read_preference(path: &Path) -> egui::ThemePreference {
    match std::fs::read_to_string(path).unwrap_or_default().trim() {
        "dark" => egui::ThemePreference::Dark,
        "light" => egui::ThemePreference::Light,
        _ => egui::ThemePreference::System,
    }
}

pub(super) fn apply_preference(ctx: &egui::Context, preference: egui::ThemePreference) {
    ctx.set_theme(preference);
    ctx.send_viewport_cmd(egui::ViewportCommand::SetTheme(match preference {
        egui::ThemePreference::Dark => egui::SystemTheme::Dark,
        egui::ThemePreference::Light => egui::SystemTheme::Light,
        egui::ThemePreference::System => egui::SystemTheme::SystemDefault,
    }));
}

pub(super) fn save_preference(preference: egui::ThemePreference) -> Result<()> {
    let path = preference_file().context("Не удалось определить папку настроек")?;
    write_preference(&path, preference)
}

fn write_preference(path: &Path, preference: egui::ThemePreference) -> Result<()> {
    std::fs::create_dir_all(path.parent().context("Некорректный путь настроек")?)?;
    std::fs::write(
        path,
        match preference {
            egui::ThemePreference::Dark => "dark",
            egui::ThemePreference::Light => "light",
            egui::ThemePreference::System => "system",
        },
    )
    .context("Не удалось сохранить тему оформления")
}

#[cfg(test)]
#[path = "../../tests/unit/gui/theme.rs"]
mod tests;
