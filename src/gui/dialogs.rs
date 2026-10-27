//! Settings and the confirmation bound to the selected DFU device.
use super::theme::{BLUE, RED};
use super::widgets::{caption, card, path_picker};
use super::{App, Confirmation, Picker, setup::Action, theme};
use eframe::egui::{self, Color32, RichText};
use zalivka::device::{DeviceInfo, Mode};

impl Confirmation {
    pub(super) fn ready(&self, target: Option<&DeviceInfo>) -> bool {
        self.accepted && target.is_some_and(|d| d.ecid == self.ecid && d.mode == Mode::Dfu)
    }
}

impl App {
    pub(super) fn confirmation(&mut self, ctx: &egui::Context) {
        let Some(mut pending) = self.confirmation.take() else {
            return;
        };
        let target = self.target();
        let mut cancel = false;
        let mut launch = None;
        let response = egui::Modal::new(egui::Id::new("confirm"))
            .frame(card(ctx).inner_margin(26))
            .show(ctx, |ui| {
                ui.set_width(400.0_f32.min((ctx.content_rect().width() - 84.0).max(0.0)));
                egui::ScrollArea::vertical()
                    .max_height((ctx.content_rect().height() - 84.0).max(0.0))
                    .show(ui, |ui| {
                        let erase = pending.action == Action::Restore;
                        ui.label(
                            RichText::new(if erase {
                                "Стереть и восстановить Mac?"
                            } else {
                                "Запустить Revive?"
                            })
                            .size(23.0)
                            .strong(),
                        );
                        ui.add_space(9.0);
                        ui.label(
                            RichText::new(format!("Mac, ECID {:016x}", pending.ecid))
                                .monospace()
                                .color(ui.visuals().weak_text_color()),
                        );
                        ui.add_space(12.0);
                        ui.label(if erase {
                            "Все данные на этом Mac будут удалены."
                        } else {
                            "Будут обновлены прошивка и recoveryOS. Без стирания диска."
                        });
                        ui.add_space(12.0);
                        ui.checkbox(
                            &mut pending.accepted,
                            if erase {
                                "Я согласен на удаление всех данных с этого Mac"
                            } else {
                                "Я согласен на обновление прошивки и recoveryOS"
                            },
                        );
                        if target.is_none_or(|d| d.ecid != pending.ecid || d.mode != Mode::Dfu) {
                            ui.label(
                                RichText::new("Выбранный Mac недоступен в DFU")
                                    .color(ui.visuals().error_fg_color),
                            );
                        }
                        ui.add_space(18.0);
                        ui.horizontal(|ui| {
                            if ui.button("Отмена").clicked() {
                                cancel = true;
                            }
                            let label = if erase {
                                "Стереть Mac"
                            } else {
                                "Начать Revive"
                            };
                            if ui
                                .add_enabled(
                                    pending.ready(target),
                                    egui::Button::new(RichText::new(label).color(Color32::WHITE))
                                        .fill(if erase { RED } else { BLUE }),
                                )
                                .clicked()
                            {
                                launch = Some(pending.action);
                            }
                        });
                    });
            });
        if !cancel && !response.should_close() && launch.is_none() {
            self.confirmation = Some(pending);
        }
        if let Some(action) = launch {
            self.start(action, ctx);
        }
    }
    pub(super) fn settings(&mut self, ctx: &egui::Context) {
        if !self.settings_open {
            return;
        }
        let mut close = false;
        let response = egui::Modal::new(egui::Id::new("settings"))
            .frame(card(ctx).inner_margin(24))
            .show(ctx, |ui| {
                ui.set_width(540.0_f32.min((ctx.content_rect().width() - 82.0).max(0.0)));
                ui.horizontal(|ui| {
                    ui.heading("Настройки");
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if ui.button("Готово").clicked() {
                            close = true;
                        }
                    });
                });
                ui.separator();
                ui.add_space(4.0);
                egui::ScrollArea::vertical()
                    .id_salt("settings-content")
                    .auto_shrink([false, true])
                    .max_height((ctx.content_rect().height() - 160.0).clamp(64.0, 520.0))
                    .show(ui, |ui| {
                        ui.label(RichText::new("Тема оформления").strong());
                        let mut preference = ctx.options(|options| options.theme_preference);
                        let previous = preference;
                        ui.horizontal_wrapped(|ui| {
                            for (value, label) in [
                                (egui::ThemePreference::System, "Как в системе"),
                                (egui::ThemePreference::Light, "Светлая"),
                                (egui::ThemePreference::Dark, "Тёмная"),
                            ] {
                                ui.radio_value(&mut preference, value, label);
                            }
                        });
                        if preference != previous {
                            theme::apply_preference(ctx, preference);
                            if let Err(error) = theme::save_preference(preference) {
                                self.error("Тема применена, но не сохранена", error);
                            }
                            ctx.request_repaint();
                        }
                        ui.add_space(12.0);
                        ui.separator();
                        ui.add_space(10.0);
                        ui.add_enabled_ui(self.job.is_none() && !self.picking, |ui| {
                            ui.label(RichText::new("Папка прошивок").strong());
                            if path_picker(ui, &mut self.setup.cache, "По умолчанию", "Выбрать")
                            {
                                self.pick(Picker::Cache, ctx);
                            }
                            caption(ui, "Здесь сохраняются скачанные прошивки.");
                            ui.add_space(10.0);
                            ui.collapsing("Дополнительные параметры", |ui| {
                                ui.label("ECID вручную");
                                ui.add_sized(
                                    egui::vec2(ui.available_width(), 34.0),
                                    egui::TextEdit::singleline(&mut self.setup.ecid),
                                );
                                ui.label("Токены WKMS");
                                if path_picker(ui, &mut self.setup.tokens, "Файл .plist", "Файл")
                                {
                                    self.pick(Picker::Tokens, ctx);
                                }
                                ui.label("AppleConnect DAWTKN");
                                if path_picker(
                                    ui,
                                    &mut self.setup.connect_data,
                                    "Файл DAWTKN",
                                    "Файл",
                                ) {
                                    self.pick(Picker::Connect, ctx);
                                }
                            });
                            ui.add_space(12.0);
                            ui.separator();
                            ui.add_space(6.0);
                            ui.label(
                                RichText::new(if cfg!(windows) {
                                    "USB и драйверы"
                                } else {
                                    "Диагностика"
                                })
                                .strong(),
                            );
                            if cfg!(windows) {
                                if ui
                                    .add_sized(
                                        egui::vec2(ui.available_width(), 34.0),
                                        egui::Button::new("Подготовить Windows"),
                                    )
                                    .clicked()
                                {
                                    close = true;
                                    self.start(Action::PrepareWindows, ctx);
                                }
                                caption(
                                    ui,
                                    "Установка недостающих драйверов и остановка службы Apple.",
                                );
                                ui.add_space(8.0);
                            }
                            if ui
                                .add_sized(
                                    egui::vec2(ui.available_width(), 34.0),
                                    egui::Button::new("Диагностика USB"),
                                )
                                .clicked()
                            {
                                close = true;
                                self.start(Action::Doctor, ctx);
                            }
                        });
                    });
            });
        if close || response.should_close() {
            self.settings_open = false;
        }
    }
}
