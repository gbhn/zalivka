use super::*;

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
                                format!("Mac · {ecid} · {:?}", d.mode),
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
                            erase: String::new(),
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
                caption(
                    ui,
                    "После восстановления — до 15 минут. При запуске кнопкой — без ограничения времени. Оставьте кабель подключённым и Zalivka открытой.",
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
            ui.add_space(12.0);
            let stage = self
                .transfer
                .as_ref()
                .map(|t| t.update.stage.as_str())
                .unwrap_or(&self.phase);
            ui.label(RichText::new(stage).size(16.0));
            let fraction = self
                .transfer
                .as_ref()
                .and_then(|t| t.update.fraction())
                .or(self.fraction);
            if let Some(value) = fraction {
                ui.add(
                    egui::ProgressBar::new(value)
                        .fill(BLUE)
                        .desired_height(10.0),
                );
            } else {
                ui.add(
                    egui::ProgressBar::new(0.0)
                        .animate(true)
                        .desired_height(10.0),
                );
            }
            ui.horizontal(|ui| {
                caption(ui, "Текущий этап");
                if let Some(value) = fraction {
                    ui.label(
                        RichText::new(format!("{:.0}%", value * 100.0))
                            .small()
                            .strong(),
                    );
                }
            });
            ui.add_space(14.0);
            let now = Instant::now();
            ui.columns(3, |columns| {
                metric(
                    &mut columns[0],
                    "Прошло",
                    &elapsed_text(job.started.elapsed().as_secs()),
                );
                if let Some(t) = &self.transfer {
                    metric(
                        &mut columns[1],
                        "Скорость",
                        &format!("{:.1} МиБ/с", t.speed(now) / 1048576.0),
                    );
                    let value = t
                        .remaining(now)
                        .map(elapsed_text)
                        .unwrap_or_else(|| "—".into());
                    metric(&mut columns[2], "Осталось на этапе", &value);
                }
            });
            if let Some(t) = &self.transfer {
                ui.add_space(8.0);
                caption(
                    ui,
                    format!(
                        "{}{}",
                        human_bytes(t.update.completed),
                        t.update
                            .total
                            .map(|n| format!(" из {}", human_bytes(n)))
                            .unwrap_or_default()
                    ),
                );
            }
            ui.add_space(14.0);
            if job.action.writes_device() && !job.restore_completed {
                caption(ui, "Оставьте питание и USB подключёнными");
            } else if !job.can_stop() {
                ui.label("Дождитесь завершения установки и проверки службы Windows.");
            } else if ui
                .add_enabled(!job.cancelled, egui::Button::new("Остановить"))
                .clicked()
                && let Some(job) = &mut self.job
            {
                match job.child.kill() {
                    Ok(()) => job.cancelled = true,
                    Err(e) => self.error("Не удалось остановить операцию", e),
                }
            }
            if self.last_activity.elapsed() > Duration::from_secs(5) {
                caption(
                    ui,
                    format!(
                        "Ожидание ответа · {}",
                        elapsed_text(self.last_activity.elapsed().as_secs())
                    ),
                );
            }
        });
    }
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
                ui.set_width(400.0);
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
                    RichText::new(format!("Mac · ECID {:016x}", pending.ecid))
                        .monospace()
                        .color(ui.visuals().weak_text_color()),
                );
                ui.add_space(12.0);
                ui.label(if erase {
                    "Все данные на этом Mac будут удалены."
                } else {
                    "Будут обновлены прошивка и recoveryOS. Без стирания диска."
                });
                if erase {
                    ui.add_space(8.0);
                    ui.label("Введите ERASE для подтверждения");
                    ui.add(
                        egui::TextEdit::singleline(&mut pending.erase)
                            .hint_text("ERASE")
                            .desired_width(f32::INFINITY),
                    );
                }
                ui.add_space(12.0);
                ui.checkbox(
                    &mut pending.accepted,
                    "Я понимаю экспериментальный статус инструмента",
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
            .frame(card(ctx).inner_margin(26))
            .show(ctx, |ui| {
                ui.set_width(420.0);
                ui.horizontal(|ui| {
                    ui.heading("Настройки");
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if ui.button("Готово").clicked() {
                            close = true;
                        }
                    });
                });
                ui.add_space(12.0);
                ui.label(RichText::new("Тема оформления").strong());
                let mut preference = ctx.options(|options| options.theme_preference);
                let previous = preference;
                ui.horizontal(|ui| {
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
                    ui.add_space(10.0);
                    ui.collapsing("Дополнительные параметры", |ui| {
                        ui.label("ECID вручную");
                        ui.add(
                            egui::TextEdit::singleline(&mut self.setup.ecid)
                                .desired_width(f32::INFINITY),
                        );
                        ui.label("Токены WKMS");
                        if path_picker(ui, &mut self.setup.tokens, "Файл .plist", "Файл") {
                            self.pick(Picker::Tokens, ctx);
                        }
                        ui.label("AppleConnect DAWTKN");
                        if path_picker(ui, &mut self.setup.connect_data, "Файл DAWTKN", "Файл")
                        {
                            self.pick(Picker::Connect, ctx);
                        }
                    });
                    ui.add_space(12.0);
                    ui.separator();
                    if cfg!(windows)
                        && ui
                            .button("Подготовить Windows: драйверы и служба Apple")
                            .clicked()
                    {
                        close = true;
                        self.start(Action::PrepareWindows, ctx);
                    }
                    if ui.button("Диагностика USB").clicked() {
                        close = true;
                        self.start(Action::Doctor, ctx);
                    }
                });
            });
        if close || response.should_close() {
            self.settings_open = false;
        }
    }

    pub(super) fn windows_card(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        let host = match self.host.clone() {
            Ok(Some(host)) => host,
            Ok(None) => return,
            Err(error) => {
                card(ui.ctx()).show(ui, |ui| {
                    ui.label(
                        RichText::new("Не удалось проверить Windows")
                            .strong()
                            .color(ui.visuals().error_fg_color),
                    );
                    ui.label(error);
                    if ui.button("Повторить проверку").clicked() {
                        self.detect(ctx);
                    }
                });
                ui.add_space(12.0);
                return;
            }
        };
        if !host.needs_preparation() && !host.apple_service_installed {
            return;
        }
        card(ui.ctx()).show(ui, |ui| {
            ui.strong("Подготовка Windows");
            if host.apple_service_running {
                ui.label(RichText::new("Apple Mobile Device Service работает и может мешать подключению к Mac.").color(ui.visuals().error_fg_color));
                ui.label("Кнопка ниже остановит службу. Если она запускается снова, удалите Apple Mobile Device Support в приложениях Windows.");
            } else if host.apple_service_installed {
                ui.label(RichText::new("Apple Mobile Device Service остановлена.").color(Tone::Success.color(ui.visuals())));
            }
            if !host.apple_driver_installed {
                ui.label("USB-драйвер Apple не найден. Установим подписанный драйвер из Zalivka — интернет и iTunes не нужны.");
            }
            if !host.usb_network_driver_available {
                ui.label(RichText::new("Штатный WinUSB отсутствует. Требуется восстановить системные файлы Windows.").color(ui.visuals().error_fg_color));
            } else if host.usb_network_interfaces.is_empty() {
                caption(ui, "Драйвер USB-сети есть в Windows. Привязки проверятся после подключения загруженного Mac; в DFU они недоступны.");
            } else {
                for interface in &host.usb_network_interfaces {
                    let label = format!("USB-сеть · {} · интерфейс {}: {}", interface.serial, interface.interface,
                        if interface.ready { "драйвер готов" } else { "требуется подготовка" });
                    ui.label(label).on_hover_text(interface.error.as_deref().unwrap_or("WinUSB готов"));
                }
            }
            if host.needs_preparation() {
                ui.add_space(6.0);
                let label = if !host.apple_driver_installed || host.usb_network_interfaces.iter().any(|i| !i.ready) {
                    "Установить недостающие драйверы"
                } else if host.apple_service_running { "Остановить службу Apple" }
                else { "Повторить проверку драйверов" };
                if ui.button(label).clicked() {
                    self.start(Action::PrepareWindows, ctx);
                }
                caption(ui, "Windows запросит права администратора.");
            }
            if host.apple_service_installed && ui.link("Открыть приложения Windows для удаления").clicked()
                && let Err(error) = drivers::open_installed_apps()
            { self.error("Не удалось открыть приложения Windows", format!("{error:#}")); }
        });
        ui.add_space(12.0);
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
                let _ = job.child.kill();
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
