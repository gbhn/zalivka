//! Settings and the confirmation bound to the selected DFU device.
use super::theme::{BLUE, RED};
use super::widgets::{caption, card, path_picker};
use super::{App, Confirmation, Picker, setup::Action, theme};
use eframe::egui::{self, Color32, RichText};
use zalivka::device::{DeviceInfo, Mode};
use zalivka::localization::{format as trf, text as tr};

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
        let response = egui::Modal::new(egui::Id::unique("confirm"))
            .frame(card(ctx).inner_margin(26))
            .show(ctx, |ui| {
                ui.set_width(400.0_f32.min((ctx.content_rect().width() - 84.0).max(0.0)));
                egui::ScrollArea::vertical()
                    .max_height((ctx.content_rect().height() - 84.0).max(0.0))
                    .show(ui, |ui| {
                        let erase = pending.action == Action::Restore;
                        ui.label(
                            RichText::new(tr(if erase {
                                "Erase and restore this Mac?"
                            } else {
                                "Start Revive?"
                            }))
                            .size(23.0)
                            .strong(),
                        );
                        ui.add_space(9.0);
                        ui.label(
                            RichText::new(trf(
                                "Mac, ECID {:016x}",
                                &[&format!("{:016x}", pending.ecid)],
                            ))
                            .monospace()
                            .color(ui.visuals().weak_text_color()),
                        );
                        ui.add_space(12.0);
                        ui.label(tr(if erase {
                            "All data on this Mac will be erased."
                        } else {
                            "Firmware and recoveryOS will be updated. The disk will not be erased."
                        }));
                        ui.add_space(12.0);
                        ui.checkbox(
                            &mut pending.accepted,
                            tr(if erase {
                                "I agree to erase all data on this Mac"
                            } else {
                                "I agree to update firmware and recoveryOS"
                            }),
                        );
                        if target.is_none_or(|d| d.ecid != pending.ecid || d.mode != Mode::Dfu) {
                            ui.label(
                                RichText::new(tr("The selected Mac is unavailable in DFU mode"))
                                    .color(ui.visuals().error_fg_color),
                            );
                        }
                        ui.add_space(18.0);
                        ui.horizontal(|ui| {
                            if ui.button(tr("Cancel")).clicked() {
                                cancel = true;
                            }
                            let label = if erase { "Erase Mac" } else { "Start Revive" };
                            if ui
                                .add_enabled(
                                    pending.ready(target),
                                    egui::Button::new(
                                        RichText::new(tr(label)).color(Color32::WHITE),
                                    )
                                    .fill(if erase {
                                        RED
                                    } else {
                                        BLUE
                                    }),
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
        let response = egui::Modal::new(egui::Id::unique("settings"))
            .frame(card(ctx).inner_margin(24))
            .show(ctx, |ui| {
                ui.set_width(540.0_f32.min((ctx.content_rect().width() - 82.0).max(0.0)));
                ui.horizontal(|ui| {
                    ui.heading(tr("Settings"));
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if ui.button(tr("Done")).clicked() {
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
                        ui.label(RichText::new(tr("Language")).strong());
                        let mut language = self.localization.preference().to_owned();
                        egui::ComboBox::from_id_salt("language")
                            .selected_text(if language == "system" { tr("System default") } else { self.localization.name().to_owned() })
                            .show_ui(ui, |ui| {
                                ui.selectable_value(&mut language, "system".into(), tr("System default"));
                                for (id, name) in self.localization.languages() {
                                    ui.selectable_value(&mut language, id, name);
                                }
                            });
                        if language != self.localization.preference() {
                            self.localization.select(&language);
                            if let Err(error) = self.localization.save_preference() {
                                self.error("Language applied but not saved", error);
                            }
                            ctx.request_repaint();
                        }
                        ui.add_space(12.0);
                        ui.label(RichText::new(tr("Appearance")).strong());
                        let mut preference = ctx.options(|options| options.theme_preference);
                        let previous = preference;
                        ui.horizontal_wrapped(|ui| {
                            for (value, label) in [
                                (egui::ThemePreference::System, "System default"),
                                (egui::ThemePreference::Light, "Light"),
                                (egui::ThemePreference::Dark, "Dark"),
                            ] {
                                ui.radio_value(&mut preference, value,tr( label));
                            }
                        });
                        if preference != previous {
                            theme::apply_preference(ctx, preference);
                            if let Err(error) = theme::save_preference(preference) {
                                self.error("Theme applied but not saved", error);
                            }
                            ctx.request_repaint();
                        }
                        ui.add_space(12.0);
                        ui.separator();
                        ui.add_space(10.0);
                        ui.add_enabled_ui(self.job.is_none() && !self.picking, |ui| {
                            ui.label(RichText::new(tr("Firmware folder")).strong());
                            if path_picker(ui, &mut self.setup.cache, "Default", "Browse")
                            {
                                self.pick(Picker::Cache, ctx);
                            }
                            caption(ui, "Downloaded firmware is saved here.");
                            ui.add_space(10.0);
                            ui.collapsing(tr("Advanced options"), |ui| {
                                ui.label(tr("Manual ECID"));
                                ui.add_sized(
                                    egui::vec2(ui.available_width(), 34.0),
                                    egui::TextEdit::singleline(&mut self.setup.ecid),
                                );
                                ui.label(tr("WKMS tokens"));
                                if path_picker(ui, &mut self.setup.tokens, ".plist file", "File")
                                {
                                    self.pick(Picker::Tokens, ctx);
                                }
                                ui.label(tr("AppleConnect DAWTKN"));
                                if path_picker(
                                    ui,
                                    &mut self.setup.connect_data,
                                    "DAWTKN file",
                                    "File",
                                ) {
                                    self.pick(Picker::Connect, ctx);
                                }
                            });
                            ui.add_space(12.0);
                            ui.separator();
                            ui.add_space(6.0);
                            ui.label(
                                RichText::new(tr(if cfg!(windows) {
                                    "USB and drivers"
                                } else if cfg!(target_os = "linux") {
                                    "USB access"
                                } else {
                                    "Diagnostics"
                                }))
                                .strong(),
                            );
                            if cfg!(windows) {
                                if ui
                                    .add_sized(
                                        egui::vec2(ui.available_width(), 34.0),
                                        egui::Button::new(tr("Set up Windows")),
                                    )
                                    .clicked()
                                {
                                    close = true;
                                    self.start(Action::PrepareWindows, ctx);
                                }
                                caption(
                                    ui,
                                    "Install missing drivers and stop the Apple service.",
                                );
                                ui.add_space(8.0);
                                if ui
                                    .add_sized(
                                        egui::vec2(ui.available_width(), 34.0),
                                        egui::Button::new(tr("Reset Apple USB drivers")),
                                    )
                                    .clicked()
                                {
                                    close = true;
                                    self.start(Action::ResetDrivers, ctx);
                                }
                                caption(ui, "Remove DFU / Recovery / Restore device records, including disconnected devices, reinstall the Apple driver, and rescan devices. Reconnect the Mac and enter DFU mode after the reset.");
                                ui.add_space(8.0);
                            }
                            if cfg!(target_os = "linux") {
                                if ui.add_sized(
                                    egui::vec2(ui.available_width(), 34.0),
                                    egui::Button::new(tr("Install USB access rules")),
                                ).clicked() {
                                    close = true;
                                    self.start(Action::InstallUdev, ctx);
                                }
                                caption(ui, "Allow your Linux user to access Apple USB devices. The system will request administrator access.");
                                ui.add_space(8.0);
                            }
                            if ui
                                .add_sized(
                                    egui::vec2(ui.available_width(), 34.0),
                                    egui::Button::new(tr("USB diagnostics")),
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
