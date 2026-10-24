//! Main window layout, journal and frame updates.
use super::theme::BLUE;
use super::widgets::{caption, card, tint};
use super::{App, Picker, SCAN_INTERVAL};
use eframe::egui::{self, Color32, RichText, Vec2};
use std::time::Duration;

impl App {
    pub(super) fn header(&mut self, ctx: &egui::Context) {
        egui::TopBottomPanel::top("header")
            .frame(
                egui::Frame::new()
                    .fill(ctx.style().visuals.window_fill)
                    .inner_margin(egui::Margin::symmetric(26, 15)),
            )
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    let (rect, _) = ui.allocate_exact_size(Vec2::splat(30.0), egui::Sense::hover());
                    ui.painter().rect_filled(rect, 9, BLUE);
                    ui.painter().text(
                        rect.center(),
                        egui::Align2::CENTER_CENTER,
                        "Z",
                        egui::FontId::proportional(21.0),
                        Color32::WHITE,
                    );
                    ui.label(RichText::new("Zalivka").size(20.0).strong());
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if ui.button("Настройки").clicked() {
                            self.settings_open = true;
                        }
                        if ui
                            .selectable_label(
                                self.journal_open,
                                RichText::new("Журнал").color(if self.journal_open {
                                    Color32::WHITE
                                } else {
                                    ui.visuals().text_color()
                                }),
                            )
                            .clicked()
                        {
                            self.journal_open = !self.journal_open;
                        }
                    });
                });
            });
    }
    pub(super) fn journal(&mut self, ctx: &egui::Context) {
        if !self.journal_open {
            return;
        }
        egui::TopBottomPanel::bottom("journal")
            .resizable(true)
            .default_height(220.0)
            .min_height(110.0)
            .max_height(350.0)
            .frame(
                egui::Frame::new()
                    .fill(ctx.style().visuals.window_fill)
                    .inner_margin(16),
            )
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    ui.strong("Журнал");
                    caption(ui, format!("{} строк", self.logs.len()));
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if ui.small_button("Скрыть").clicked() {
                            self.journal_open = false;
                        }
                        if ui
                            .add_enabled(
                                !self.logs.is_empty() && !self.picking,
                                egui::Button::new("Сохранить").small(),
                            )
                            .clicked()
                        {
                            self.pick(Picker::Log, ctx);
                        }
                        if ui
                            .add_enabled(
                                !self.logs.is_empty(),
                                egui::Button::new("Копировать").small(),
                            )
                            .clicked()
                        {
                            ctx.copy_text(self.journal_text());
                        }
                    });
                });
                ui.separator();
                if self.logs.is_empty() {
                    ui.label(
                        RichText::new("Здесь появится ход операции.")
                            .color(ui.visuals().weak_text_color()),
                    );
                }
                let row_height = ui.text_style_height(&egui::TextStyle::Monospace);
                egui::ScrollArea::both()
                    .auto_shrink([false, false])
                    .stick_to_bottom(true)
                    .show_rows(ui, row_height, self.logs.len(), |ui, rows| {
                        for row in rows {
                            let text = &self.logs[row];
                            let color =
                                if text.contains("Error:") || text.contains("CHECKPOINT_ERROR") {
                                    ui.visuals().error_fg_color
                                } else {
                                    ui.visuals().weak_text_color()
                                };
                            ui.add(
                                egui::Label::new(
                                    RichText::new(text).monospace().size(12.0).color(color),
                                )
                                .wrap_mode(egui::TextWrapMode::Extend),
                            );
                        }
                    });
            });
    }
}

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.poll(ctx);
        if self.job.is_none() && !self.picking && self.last_scan.elapsed() >= SCAN_INTERVAL {
            self.detect(ctx);
        }
        ctx.request_repaint_after(if self.job.is_some() || self.scanning {
            Duration::from_millis(100)
        } else {
            Duration::from_secs(1)
        });
        if ctx.input(|i| i.viewport().close_requested())
            && let Some(job) = &mut self.job
        {
            if !job.can_stop() {
                ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
                self.error(
                    "Операция ещё выполняется",
                    "Дождитесь завершения перед закрытием окна.",
                );
            } else {
                let _ = job.stop();
            }
        }
        if self.job.is_none() && !self.picking && self.confirmation.is_none() {
            let dropped = ctx.input(|i| {
                i.raw
                    .dropped_files
                    .iter()
                    .filter_map(|f| f.path.clone())
                    .find(|p| {
                        p.extension()
                            .is_some_and(|s| s.eq_ignore_ascii_case("ipsw"))
                    })
            });
            if let Some(path) = dropped {
                self.setup.ipsw = path.display().to_string();
                self.setup.automatic = false;
            }
        }
        self.header(ctx);
        egui::TopBottomPanel::bottom("footer")
            .frame(
                egui::Frame::new()
                    .fill(ctx.style().visuals.panel_fill)
                    .inner_margin(egui::Margin::symmetric(26, 9)),
            )
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    caption(
                        ui,
                        if self.job.is_some() {
                            "Выполняется операция"
                        } else if self.target().is_some() {
                            "Mac подключён"
                        } else {
                            "Ожидание устройства"
                        },
                    );
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        caption(ui, format!("Zalivka {}", env!("CARGO_PKG_VERSION")));
                    });
                });
            });
        self.journal(ctx);
        if self.job.is_none() {
            egui::TopBottomPanel::bottom("actions")
                .show_separator_line(false)
                .frame(
                    egui::Frame::new()
                        .fill(ctx.style().visuals.panel_fill)
                        .inner_margin(egui::Margin::symmetric(22, 12)),
                )
                .show(ctx, |ui| {
                    ui.add_enabled_ui(!self.picking, |ui| self.actions(ui));
                });
        }
        egui::CentralPanel::default()
            .frame(
                egui::Frame::new()
                    .fill(ctx.style().visuals.panel_fill)
                    .inner_margin(22),
            )
            .show(ctx, |ui| {
                egui::ScrollArea::vertical()
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        ui.heading("Восстановление Mac");
                        ui.add_space(9.0);
                        if let Some(notice) = &self.notice {
                            let mut dismiss = false;
                            let color = notice.tone.color(ui.visuals());
                            card(ui.ctx())
                                .fill(tint(color, ui.visuals().window_fill))
                                .show(ui, |ui| {
                                    ui.horizontal(|ui| {
                                        ui.label(
                                            RichText::new(&notice.title).strong().color(color),
                                        );
                                        ui.with_layout(
                                            egui::Layout::right_to_left(egui::Align::Center),
                                            |ui| {
                                                if ui.small_button("Скрыть").clicked() {
                                                    dismiss = true;
                                                }
                                            },
                                        );
                                    });
                                    caption(ui, &notice.detail);
                                });
                            if dismiss {
                                self.notice = None;
                            }
                            ui.add_space(12.0);
                        }
                        if self.job.is_some() {
                            self.active_job(ui);
                        } else {
                            ui.add_enabled_ui(!self.picking, |ui| {
                                self.windows_card(ui, ctx);
                                self.device_card(ui, ctx);
                                ui.add_space(12.0);
                                self.firmware_card(ui, ctx);
                            });
                        }
                    });
            });
        self.settings(ctx);
        self.confirmation(ctx);
    }
}
