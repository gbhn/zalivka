//! Main window layout, journal and frame updates.
use super::widgets::{caption, pill, tint};
use super::{App, Level, Notice, Picker, SCAN_INTERVAL, Tone, UI_REFRESH_INTERVAL};
use eframe::egui::{self, Color32, RichText, Vec2};
use std::time::Instant;

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
                    let logo = self.logo.get_or_insert_with(|| {
                        let icon = super::logo_icon();
                        ctx.load_texture(
                            "zalivka-logo",
                            egui::ColorImage::from_rgba_unmultiplied(
                                [icon.width as usize, icon.height as usize],
                                &icon.rgba,
                            ),
                            egui::TextureOptions::LINEAR,
                        )
                    });
                    ui.add(
                        egui::Image::new(&*logo)
                            .fit_to_exact_size(Vec2::new(56.0, 44.0))
                            .alt_text("Логотип Zalivka"),
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
        let max_height = (ctx.content_rect().height() * 0.35).min(350.0);
        egui::TopBottomPanel::bottom("journal")
            .resizable(true)
            .default_height(max_height.min(220.0))
            .min_height(110.0)
            .max_height(max_height)
            .frame(
                egui::Frame::new()
                    .fill(ctx.style().visuals.window_fill)
                    .inner_margin(16),
            )
            .show(ctx, |ui| {
                ui.spacing_mut().interact_size.y = 24.0;
                ui.spacing_mut().item_spacing.y = 4.0;
                ui.horizontal_wrapped(|ui| {
                    ui.strong("Журнал");
                    ui.with_layout(
                        egui::Layout::right_to_left(egui::Align::Center).with_main_wrap(true),
                        |ui| {
                            if ui.small_button("Скрыть").clicked() {
                                self.journal_open = false;
                            }
                            if ui
                                .add_enabled(
                                    !self.logs.is_empty() && !self.picking,
                                    egui::Button::new("Сохранить журнал").small(),
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
                                ctx.copy_text(self.journal_text(self.log_details));
                            }
                            ui.checkbox(&mut self.log_details, "Технические подробности");
                        },
                    );
                });
                ui.separator();
                let records: Vec<_> = self
                    .logs
                    .iter()
                    .filter(|record| self.log_details || record.level != Level::Debug)
                    .collect();
                if records.is_empty() {
                    ui.label(
                        RichText::new("Здесь появится ход операции.")
                            .color(ui.visuals().weak_text_color()),
                    );
                }
                let row_height = ui.text_style_height(&egui::TextStyle::Monospace);
                egui::ScrollArea::both()
                    .auto_shrink([false, false])
                    .min_scrolled_height(0.0)
                    .stick_to_bottom(true)
                    .show_rows(ui, row_height, records.len(), |ui, rows| {
                        for row in rows {
                            let record = records[row];
                            let color = match record.level {
                                Level::Error => ui.visuals().error_fg_color,
                                Level::Warning => ui.visuals().warn_fg_color,
                                Level::Info => ui.visuals().text_color(),
                                Level::Debug => ui.visuals().weak_text_color(),
                            };
                            ui.add(
                                egui::Label::new(
                                    RichText::new(record.to_string())
                                        .monospace()
                                        .size(12.0)
                                        .color(color),
                                )
                                .wrap_mode(egui::TextWrapMode::Extend),
                            );
                        }
                    });
            });
    }

    fn notification(&mut self, ctx: &egui::Context, bounds: egui::Rect) {
        let Some(notice) = &self.notice else { return };
        if let Some(deadline) = notice.expires_at {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                self.notice = None;
                return;
            }
            ctx.request_repaint_after(remaining);
        }
        let mut dismiss = false;
        egui::Area::new(egui::Id::new("notification"))
            .order(egui::Order::Foreground)
            .movable(false)
            .anchor(egui::Align2::RIGHT_TOP, Vec2::ZERO)
            .constrain_to(bounds)
            .show(ctx, |ui| {
                let color = match notice.tone {
                    Tone::Neutral => ui.visuals().hyperlink_color,
                    tone => tone.color(ui.visuals()),
                };
                let frame = egui::Frame::popup(ui.style())
                    .corner_radius(12)
                    .inner_margin(14)
                    .stroke(egui::Stroke::new(
                        1.0_f32,
                        tint(color, ui.visuals().window_fill),
                    ));
                let width = bounds.width().min(420.0) - frame.total_margin().sum().x;
                frame.show(ui, |ui| {
                    ui.set_width(width);
                    ui.horizontal_top(|ui| {
                        pill(
                            ui,
                            match notice.tone {
                                Tone::Neutral => "i",
                                Tone::Success => "✓",
                                Tone::Error => "!",
                            },
                            color,
                        );
                        let text_width = ui.available_width() - 24.0 - ui.spacing().item_spacing.x;
                        ui.vertical(|ui| {
                            ui.set_width(text_width);
                            ui.add(egui::Label::new(RichText::new(&notice.title).strong()).wrap());
                            if !notice.detail.is_empty() {
                                egui::ScrollArea::vertical()
                                    .id_salt("notification_detail")
                                    .max_height((bounds.height() - 110.0).clamp(24.0, 140.0))
                                    .show(ui, |ui| {
                                        ui.add(
                                            egui::Label::new(
                                                RichText::new(&notice.detail)
                                                    .size(13.0)
                                                    .color(ui.visuals().weak_text_color()),
                                            )
                                            .wrap(),
                                        );
                                    });
                            }
                            if notice.tone == Tone::Error
                                && !self.logs.is_empty()
                                && ui.small_button("Открыть журнал").clicked()
                            {
                                self.journal_open = true;
                            }
                        });
                        dismiss = ui
                            .add_sized(
                                [24.0, 24.0],
                                egui::Button::new(RichText::new("×").size(20.0)).frame(false),
                            )
                            .on_hover_text("Закрыть уведомление")
                            .clicked();
                    });
                });
            });
        if dismiss {
            self.notice = None;
        }
    }
}

impl App {
    pub(super) fn view(&mut self, ctx: &egui::Context) {
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
                        ui.add(
                            egui::Label::new(
                                RichText::new(format!("Zalivka {}", zalivka::VERSION))
                                    .small()
                                    .color(ui.visuals().weak_text_color()),
                            )
                            .truncate(),
                        )
                        .on_hover_text(zalivka::VERSION);
                    });
                });
            });
        self.journal(ctx);
        let mut notification_bounds = ctx.content_rect().shrink(14.0);
        notification_bounds.min.y = ctx.available_rect().top() + 14.0;
        egui::CentralPanel::default()
            .frame(
                egui::Frame::new()
                    .fill(ctx.style().visuals.panel_fill)
                    .inner_margin(22),
            )
            .show(ctx, |ui| {
                egui::ScrollArea::vertical()
                    .id_salt("main_content")
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        ui.heading("Восстановление Mac");
                        ui.add_space(9.0);
                        if self.job.is_some() {
                            self.active_job(ui);
                        } else {
                            ui.add_enabled_ui(!self.picking, |ui| {
                                self.windows_card(ui, ctx);
                                if ui.available_width() >= 780.0 {
                                    ui.columns(2, |columns| {
                                        let mut device =
                                            self.prepare_device_card(&mut columns[0], ctx);
                                        let mut firmware =
                                            self.prepare_firmware_card(&mut columns[1], ctx);
                                        let height = device
                                            .content_ui
                                            .min_size()
                                            .y
                                            .max(firmware.content_ui.min_size().y);
                                        for frame in [&mut device, &mut firmware] {
                                            let mut bounds = frame.content_ui.min_rect();
                                            bounds.set_height(height);
                                            frame.content_ui.expand_to_include_rect(bounds);
                                        }
                                        device.end(&mut columns[0]);
                                        firmware.end(&mut columns[1]);
                                    });
                                } else {
                                    self.prepare_device_card(ui, ctx).end(ui);
                                    ui.add_space(12.0);
                                    self.prepare_firmware_card(ui, ctx).end(ui);
                                }
                                ui.add_space(12.0);
                                self.actions(ui);
                            });
                        }
                    });
            });
        self.notification(ctx, notification_bounds);
        self.settings(ctx);
        self.confirmation(ctx);
    }
}

impl eframe::App for App {
    fn clear_color(&self, visuals: &egui::Visuals) -> [f32; 4] {
        visuals.panel_fill.to_normalized_gamma_f32()
    }

    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.poll(ctx);
        if self.job.is_none() && !self.picking && self.last_scan.elapsed() >= SCAN_INTERVAL {
            self.detect(ctx);
        }
        ctx.request_repaint_after(if self.job.is_some() {
            UI_REFRESH_INTERVAL
        } else {
            SCAN_INTERVAL
        });
        if ctx.input(|i| i.viewport().close_requested())
            && let Some(job) = &mut self.job
        {
            if !job.can_stop() {
                ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
                self.notice = Some(Notice {
                    title: "Операция ещё выполняется".into(),
                    detail: "Дождитесь завершения перед закрытием окна.".into(),
                    tone: Tone::Neutral,
                    expires_at: Some(Instant::now() + super::NOTICE_LIFETIME),
                });
            } else if let Err(error) = job.stop() {
                ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
                self.error("Не удалось остановить операцию", error);
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
        self.view(ctx);
    }
}
