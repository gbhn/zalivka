//! Apply background events and finish jobs only after their logs are drained.
use super::*;

impl App {
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
        let notice = self.completion_notice(
            job.action,
            job.cancelled,
            success,
            job.started.elapsed().as_secs(),
        );
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

    pub(super) fn completion_notice(
        &self,
        action: Action,
        cancelled: bool,
        success: bool,
        elapsed: u64,
    ) -> Notice {
        let elapsed = elapsed_text(elapsed);
        let (title, detail, tone) = if cancelled {
            let restored = action == Action::Restore
                && self
                    .logs
                    .iter()
                    .any(|s| s.starts_with("Restore completed; waiting for the Mac's USB network"));
            (
                if restored {
                    "Восстановление завершено · раздача остановлена".into()
                } else {
                    "Операция остановлена".into()
                },
                elapsed,
                Tone::Neutral,
            )
        } else if !success {
            (
                format!("{}: ошибка", action.title()),
                "Подробности в журнале.".into(),
                Tone::Error,
            )
        } else if action == Action::PrepareWindows && self.windows_reboot_required {
            (
                "Перезагрузите Windows".into(),
                "Драйвер установлен. Перезагрузите компьютер перед восстановлением Mac.".into(),
                Tone::Neutral,
            )
        } else if let Some(error) = self
            .logs
            .iter()
            .find_map(|line| line.strip_prefix("USB internet unavailable: "))
        {
            (
                "Восстановление завершено · интернет по USB недоступен".into(),
                error.into(),
                Tone::Neutral,
            )
        } else {
            (
                action.completed_title().into(),
                if action.writes_device() {
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
