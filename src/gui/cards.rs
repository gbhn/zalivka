//! Device, firmware, operation and Windows preparation cards.
use super::theme::{BLUE, Tone};
use super::widgets::{
    caption, card, elapsed_text, human_bytes, laptop, metric, operation_title, pill, progress_bar,
    section,
};
use super::{App, Confirmation, Picker, setup::Action, worker::ActivityId};
use eframe::egui::{self, Color32, RichText, Vec2};
use std::{
    path::Path,
    time::{Duration, Instant},
};
use zalivka::{device::Mode, drivers};

impl App {
    pub(super) fn device_card(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        card(ui.ctx()).show(ui, |ui| {
            section(ui, "01", "Устройство");
            ui.horizontal(|ui| {
                laptop(ui, self.target().is_some());
                ui.vertical(|ui| {
                    let title = self
                        .target()
                        .map(|d| {
                            if d.chip_id == 0x8012 {
                                "Mac с чипом T2"
                            } else {
                                "Mac с Apple Silicon"
                            }
                        })
                        .unwrap_or(if self.devices.is_empty() {
                            "Mac не подключён"
                        } else {
                            "Выберите Mac"
                        });
                    ui.label(RichText::new(title).size(19.0).strong());
                    if let Some(device) = self.target() {
                        ui.label(
                            RichText::new(format!("ECID {:016x}", device.ecid))
                                .monospace()
                                .size(12.0)
                                .color(ui.visuals().weak_text_color()),
                        );
                    } else {
                        ui.label(
                            RichText::new("Подключите Mac кабелем USB-C")
                                .color(ui.visuals().weak_text_color()),
                        );
                    }
                });
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui
                        .add_enabled(!self.scanning, egui::Button::new("Обновить"))
                        .clicked()
                    {
                        self.detect(ctx);
                    }
                    if self.scanning {
                        ui.add(egui::Spinner::new().size(18.0).color(BLUE));
                    }
                    if let Some(d) = self.target() {
                        pill(
                            ui,
                            if d.mode == Mode::Dfu {
                                "DFU"
                            } else {
                                "Recovery"
                            },
                            if d.mode == Mode::Dfu {
                                Tone::Success.color(ui.visuals())
                            } else {
                                ui.visuals().weak_text_color()
                            },
                        );
                    }
                });
            });
            if self.devices.len() > 1 || (!self.devices.is_empty() && self.target().is_none()) {
                ui.add_space(4.0);
                egui::ComboBox::from_id_salt("devices")
                    .selected_text("Выбрать устройство")
                    .width(ui.available_width())
                    .show_ui(ui, |ui| {
                        for d in &self.devices {
                            let ecid = format!("{:016x}", d.ecid);
                            ui.selectable_value(
                                &mut self.setup.ecid,
                                ecid.clone(),
                                format!("Mac, {ecid}, {:?}", d.mode),
                            );
                        }
                    });
            }
            if self.scan_error.is_some() {
                ui.horizontal(|ui| {
                    ui.label(
                        RichText::new("Не удалось проверить USB")
                            .color(ui.visuals().error_fg_color),
                    );
                    if ui.link("Диагностика").clicked() {
                        self.start(Action::Doctor, ctx);
                    }
                });
            }
        });
    }
    pub(super) fn firmware_card(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        card(ui.ctx()).show(ui, |ui| {
            section(ui, "02", "Прошивка");
            ui.horizontal(|ui| {
                for (automatic, title) in [(true, "Автоматически"), (false, "Локальный IPSW")]
                {
                    let color = if self.setup.automatic == automatic {
                        Color32::WHITE
                    } else {
                        ui.visuals().text_color()
                    };
                    ui.selectable_value(
                        &mut self.setup.automatic,
                        automatic,
                        RichText::new(title).color(color),
                    );
                }
            });
            ui.add_space(5.0);
            if self.setup.automatic {
                ui.horizontal(|ui| {
                    ui.vertical(|ui| {
                        ui.strong("Совместимая версия от Apple");
                        caption(ui, "Загрузка начнётся вместе с операцией");
                    });
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if ui
                            .add_enabled(
                                self.target().is_some(),
                                egui::Button::new("Скачать отдельно"),
                            )
                            .clicked()
                        {
                            self.start(Action::Download, ctx);
                        }
                    });
                });
            } else {
                ui.horizontal(|ui| {
                    ui.allocate_ui_with_layout(
                        Vec2::new((ui.available_width() - 245.0).max(120.0), 34.0),
                        egui::Layout::top_down(egui::Align::Min),
                        |ui| {
                            let path = Path::new(self.setup.ipsw.trim());
                            let name = path
                                .file_name()
                                .map(|n| n.to_string_lossy().into_owned())
                                .unwrap_or_else(|| "Перетащите IPSW в окно".into());
                            ui.add(egui::Label::new(RichText::new(name).strong()).truncate())
                                .on_hover_text(&self.setup.ipsw);
                            let detail = path
                                .metadata()
                                .ok()
                                .map(|m| human_bytes(m.len()))
                                .unwrap_or_else(|| "Файл прошивки Apple".into());
                            caption(ui, detail);
                        },
                    );
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if ui
                            .add_enabled(!self.picking, egui::Button::new("Выбрать файл"))
                            .clicked()
                        {
                            self.pick(Picker::Firmware, ctx);
                        }
                        if self.setup.local_file().is_ok() && ui.small_button("Проверить").clicked()
                        {
                            self.start(Action::Verify, ctx);
                        }
                    });
                });
            }
        });
    }
    pub(super) fn actions(&mut self, ui: &mut egui::Ui) {
        card(ui.ctx()).show(ui, |ui| {
            section(ui, "03", "Действие");
            let ready = self.blocked_reason().is_none() && !self.picking;
            ui.columns(2, |columns| {
                for (ui, (action, title, detail, button)) in columns.iter_mut().zip([
                    (
                        Action::Revive,
                        "Revive",
                        "Обновить прошивку и recoveryOS",
                        "Запустить Revive",
                    ),
                    (
                        Action::Restore,
                        "Полное восстановление",
                        "Стереть Mac и установить систему",
                        "Стереть и восстановить",
                    ),
                ]) {
                    ui.label(RichText::new(title).size(18.0).strong());
                    caption(ui, detail);
                    ui.add_space(7.0);
                    let button = if action == Action::Revive {
                        egui::Button::new(RichText::new(button).color(Color32::WHITE)).fill(BLUE)
                    } else {
                        egui::Button::new(RichText::new(button).color(ui.visuals().error_fg_color))
                    };
                    if ui
                        .add_enabled(
                            ready,
                            button.min_size(Vec2::new(ui.available_width(), 42.0)),
                        )
                        .clicked()
                        && let Some(target) = self.target()
                    {
                        self.confirmation = Some(Confirmation {
                            action,
                            ecid: target.ecid,
                            accepted: false,
                        });
                    }
                }
            });
            if let Some(reason) = self.blocked_reason() {
                ui.add_space(5.0);
                caption(ui, reason);
            }
            if cfg!(windows) {
                ui.add_space(10.0);
                ui.separator();
                ui.checkbox(
                    &mut self.setup.share_internet,
                    "Давать Mac интернет по USB после восстановления",
                );
                if ui
                    .add_enabled(
                        !self.picking,
                        egui::Button::new("Дать подключённому Mac интернет по USB"),
                    )
                    .clicked()
                {
                    self.start(Action::UsbInternet, ui.ctx());
                }
            }
        });
    }
    pub(super) fn active_job(&mut self, ui: &mut egui::Ui) {
        card(ui.ctx()).show(ui, |ui| {
            let Some(job) = self.job.as_ref() else { return };
            ui.horizontal(|ui| {
                ui.add(egui::Spinner::new().size(24.0).color(BLUE));
                ui.label(RichText::new(job.action.title()).size(21.0).strong());
            });
            let now = Instant::now();
            let internet_speed = job.internet_speed(now);
            ui.add_space(12.0);
            ui.label(RichText::new(&job.phase).size(16.0));
            if job.action.writes_device() {
                caption(ui, "Общий прогресс восстановления (оценка)");
                progress_bar(ui, job.overall_fraction);
            } else if internet_speed.is_none() && job.activities.is_empty() {
                progress_bar(ui, None);
            }
            ui.add_space(14.0);
            ui.columns(3, |columns| {
                metric(
                    &mut columns[0],
                    "Прошло",
                    &elapsed_text(job.started.elapsed().as_secs()),
                );
                if let Some((upload, download)) = internet_speed {
                    metric(
                        &mut columns[1],
                        "↑ Up",
                        &format!("{}/с", human_bytes(upload as u64)),
                    );
                    metric(
                        &mut columns[2],
                        "↓ Down",
                        &format!("{}/с", human_bytes(download as u64)),
                    );
                }
            });
            ui.add_space(14.0);
            let idle = job.last_activity.elapsed();
            if !job.can_stop() && !job.action.writes_device() {
                ui.label("Дождитесь завершения установки и проверки службы Windows.");
            } else if job.can_stop()
                && ui
                    .add_enabled(!job.cancelled, egui::Button::new("Остановить"))
                    .clicked()
                && let Some(job) = &mut self.job
                && let Err(e) = job.stop()
            {
                self.error("Не удалось остановить операцию", e);
            }
            if idle > Duration::from_secs(5) {
                caption(
                    ui,
                    format!("Ожидание ответа, {}", elapsed_text(idle.as_secs())),
                );
            }
        });
        let Some(job) = &self.job else { return };
        let now = Instant::now();
        for (id, activity) in &job.activities {
            ui.add_space(12.0);
            ui.push_id(id, |ui| {
                card(ui.ctx()).show(ui, |ui| {
                    ui.set_width(ui.available_width());
                    let title = match id {
                        ActivityId::Operation(operation) => operation_title(*operation),
                        ActivityId::Transfer(_) => activity
                            .transfers
                            .values()
                            .next()
                            .map(|transfer| transfer.update.stage.clone())
                            .unwrap_or_default(),
                    };
                    ui.label(RichText::new(&title).size(16.0).strong());
                    progress_bar(ui, activity.fraction());
                    for transfer in activity.transfers.values() {
                        if transfer.update.stage != title {
                            caption(ui, &transfer.update.stage);
                        }
                        caption(
                            ui,
                            format!(
                                "Передано: {}{}",
                                human_bytes(transfer.update.completed),
                                transfer
                                    .update
                                    .total
                                    .map(|total| format!(" из {}", human_bytes(total)))
                                    .unwrap_or_default()
                            ),
                        );
                        ui.add_space(8.0);
                        ui.columns(2, |columns| {
                            metric(
                                &mut columns[0],
                                "Скорость",
                                &format!("{:.1} МиБ/с", transfer.speed(now) / 1048576.0),
                            );
                            let remaining = transfer
                                .remaining(now)
                                .map(elapsed_text)
                                .unwrap_or_else(|| "—".into());
                            metric(&mut columns[1], "До конца передачи", &remaining);
                        });
                    }
                });
            });
        }
    }
    pub(super) fn windows_card(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        let host = match &self.host {
            Ok(Some(host)) => host,
            Ok(None) => return,
            Err(error) => {
                let retry = card(ui.ctx())
                    .show(ui, |ui| {
                        ui.label(
                            RichText::new("Не удалось проверить Windows")
                                .strong()
                                .color(ui.visuals().error_fg_color),
                        );
                        ui.label(error);
                        ui.button("Повторить проверку").clicked()
                    })
                    .inner;
                if retry {
                    self.detect(ctx);
                }
                ui.add_space(12.0);
                return;
            }
        };
        if !host.needs_preparation() && !host.apple_service_installed {
            return;
        }
        let mut prepare = false;
        let mut open_apps = false;
        card(ui.ctx()).show(ui, |ui| {
            ui.strong("Подготовка Windows");
            if host.apple_service_running {
                ui.label(
                    RichText::new("Apple Mobile Device Service работает и может мешать подключению к Mac.")
                        .color(ui.visuals().error_fg_color),
                );
                ui.label("Кнопка ниже остановит службу. Если она запускается снова, удалите Apple Mobile Device Support в приложениях Windows.");
            } else if host.apple_service_installed {
                ui.label(
                    RichText::new("Apple Mobile Device Service остановлена.")
                        .color(Tone::Success.color(ui.visuals())),
                );
            }
            if !host.apple_driver_installed {
                ui.label("USB-драйвер Apple не найден. Установим подписанный драйвер из Zalivka — интернет и iTunes не нужны.");
            }
            if !host.usb_network_driver_available {
                ui.label(
                    RichText::new("Штатный WinUSB отсутствует. Требуется восстановить системные файлы Windows.")
                        .color(ui.visuals().error_fg_color),
                );
            } else if host.usb_network_interfaces.is_empty() {
                caption(ui, "Драйвер USB-сети есть в Windows. Привязки проверятся после подключения загруженного Mac; в DFU они недоступны.");
            } else {
                for interface in &host.usb_network_interfaces {
                    let status = if interface.ready {
                        "драйвер готов"
                    } else {
                        "требуется подготовка"
                    };
                    ui.label(format!(
                        "USB-сеть, {}, интерфейс {}: {status}",
                        interface.serial, interface.interface,
                    ))
                    .on_hover_text(interface.error.as_deref().unwrap_or("WinUSB готов"));
                }
            }
            if host.needs_preparation() {
                ui.add_space(6.0);
                let label = if !host.apple_driver_installed
                    || host.usb_network_interfaces.iter().any(|i| !i.ready)
                {
                    "Установить недостающие драйверы"
                } else if host.apple_service_running {
                    "Остановить службу Apple"
                } else {
                    "Повторить проверку драйверов"
                };
                prepare = ui.button(label).clicked();
                caption(ui, "Windows запросит права администратора.");
            }
            if host.apple_service_installed {
                open_apps = ui.link("Открыть приложения Windows для удаления").clicked();
            }
        });
        if prepare {
            self.start(Action::PrepareWindows, ctx);
        }
        if open_apps && let Err(error) = drivers::open_installed_apps() {
            self.error(
                "Не удалось открыть приложения Windows",
                format!("{error:#}"),
            );
        }
        ui.add_space(12.0);
    }
}
