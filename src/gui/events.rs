//! Apply background events and finish jobs only after their logs are drained.
use super::*;

impl App {
    pub(super) fn worker_event(&mut self, event: progress::Event) {
        let Some(job) = &mut self.job else { return };
        if matches!(
            &event,
            progress::Event::Checkpoint { .. } | progress::Event::OperationProgress { .. }
        ) && self
            .transfer
            .as_ref()
            .is_some_and(|transfer| transfer.update.finished)
        {
            self.transfer = None;
        }
        match event {
            progress::Event::Transfer(update) => {
                let keep = update.completed == 0
                    || update.finished
                    || self
                        .transfer
                        .as_ref()
                        .is_none_or(|t| t.update.stage != update.stage)
                    || self.last_stats.elapsed() >= Duration::from_secs(10);
                if keep {
                    self.journal_line(format!(
                        "{}: {}{} · {:.1} МиБ/с",
                        update.stage,
                        human_bytes(update.completed),
                        update
                            .total
                            .map(|n| format!(" / {}", human_bytes(n)))
                            .unwrap_or_default(),
                        update.bytes_per_second / 1048576.0,
                    ));
                    self.last_stats = Instant::now();
                }
                self.transfer = Some(Transfer {
                    update,
                    received: Instant::now(),
                });
                self.fraction = None;
            }
            progress::Event::RestoreCompleted => {
                job.restore_completed = true;
                self.phase = "Восстановление завершено".into();
                self.transfer = None;
                self.fraction = None;
            }
            progress::Event::RebootRequired => self.windows_reboot_required = true,
            progress::Event::InternetWaiting => {
                job.preparing_internet = false;
                self.phase = "Ожидание USB-сети Mac".into();
                self.transfer = None;
                self.fraction = None;
            }
            progress::Event::InternetPreparing => {
                job.preparing_internet = true;
                self.phase = "Подтвердите запрос прав администратора Windows".into();
            }
            progress::Event::InternetReady => {
                job.preparing_internet = false;
                self.phase = "Интернет по USB · оставьте Zalivka открытой".into();
            }
            progress::Event::InternetUnavailable { error } => job.internet_error = Some(error),
            progress::Event::Checkpoint { name } => {
                self.phase = friendly_phase(&name).into();
                self.fraction = None;
            }
            progress::Event::OperationProgress { progress, .. } => {
                self.fraction = (progress >= 0).then(|| (progress as f32 / 100.0).clamp(0.0, 1.0));
            }
        }
    }

    pub(super) fn poll(&mut self, ctx: &egui::Context) {
        while let Ok(event) = self.rx.try_recv() {
            match event {
                Event::Scan { devices, host } => {
                    self.scanning = false;
                    self.host = host;
                    match devices {
                        Ok(devices) => {
                            if self.setup.ecid.is_empty() && devices.len() == 1 {
                                self.setup.ecid = format!("{:016x}", devices[0].ecid);
                            }
                            self.devices = devices;
                            self.scan_error = None;
                        }
                        Err(e) => {
                            self.devices.clear();
                            self.scan_error = Some(e);
                        }
                    }
                }
                Event::Line(id, line) if self.job.as_ref().is_some_and(|j| j.id == id) => {
                    self.log(line)
                }
                Event::Worker(id, event) if self.job.as_ref().is_some_and(|job| job.id == id) => {
                    if let Some(job) = &mut self.job {
                        let _ = event.write_to(&mut job.log);
                    }
                    self.last_activity = Instant::now();
                    self.worker_event(event);
                }
                Event::ReaderDone(id) => {
                    if let Some(j) = &mut self.job
                        && j.id == id
                    {
                        j.readers = j.readers.saturating_sub(1);
                    }
                }
                Event::Picked(picker, path) => {
                    self.picking = false;
                    if let Some(path) = path {
                        match picker {
                            Picker::Firmware => {
                                self.setup.ipsw = path.display().to_string();
                                self.setup.automatic = false;
                            }
                            Picker::Cache => self.setup.cache = path.display().to_string(),
                            Picker::Tokens => self.setup.tokens = path.display().to_string(),
                            Picker::Connect => self.setup.connect_data = path.display().to_string(),
                            Picker::Log => {
                                let source = self.log_path.clone();
                                let text = self.journal_text();
                                let spawn = self.background(ctx, "save", move || {
                                    let result = worker::save_log(path, source.as_deref(), &text)
                                        .map_err(|e| format!("{e:#}"));
                                    Event::Saved(result)
                                });
                                if let Err(e) = spawn {
                                    self.error("Журнал не сохранён", e);
                                }
                            }
                        }
                    }
                }
                Event::Saved(Ok(path)) => {
                    self.notice = Some(Notice {
                        title: "Журнал сохранён".into(),
                        detail: path.display().to_string(),
                        tone: Tone::Success,
                    });
                }
                Event::Saved(Err(e)) => self.error("Журнал не сохранён", e),
                _ => {}
            }
        }
        let success = match self.job.as_mut().map(Job::finished) {
            Some(Ok(Some(success))) => success,
            Some(Err(e)) => {
                self.error("Не удалось получить статус операции", e);
                return;
            }
            _ => return,
        };
        let mut job = self.job.take().unwrap();
        let notice = job.completion_notice(success, self.windows_reboot_required);
        let _ = job.log.flush();
        if notice.tone == Tone::Error {
            self.journal_open = true;
        }
        self.notice = Some(notice);
        self.transfer = None;
        self.fraction = None;
        self.phase.clear();
        self.last_scan = Instant::now() - SCAN_INTERVAL;
    }
}

impl Job {
    pub(super) fn completion_notice(&self, success: bool, reboot_required: bool) -> Notice {
        let elapsed = elapsed_text(self.started.elapsed().as_secs());
        let (title, detail, tone) = if self.cancelled {
            (
                if self.action == Action::Restore && self.restore_completed {
                    "Восстановление завершено · раздача остановлена".into()
                } else {
                    "Операция остановлена".into()
                },
                elapsed,
                Tone::Neutral,
            )
        } else if !success {
            (
                format!("{}: ошибка", self.action.title()),
                "Подробности в журнале.".into(),
                Tone::Error,
            )
        } else if self.action == Action::PrepareWindows && reboot_required {
            (
                "Перезагрузите Windows".into(),
                "Драйвер установлен. Перезагрузите компьютер перед восстановлением Mac.".into(),
                Tone::Neutral,
            )
        } else if let Some(error) = &self.internet_error {
            (
                "Восстановление завершено · интернет по USB недоступен".into(),
                error.clone(),
                Tone::Neutral,
            )
        } else {
            (
                self.action.completed_title().into(),
                if self.action.writes_device() {
                    format!("{elapsed} · Проверьте запуск Mac.")
                } else {
                    elapsed
                },
                Tone::Success,
            )
        };
        Notice {
            title,
            detail,
            tone,
        }
    }
}
