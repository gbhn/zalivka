//! Apply background events and finish jobs only after their logs are drained.
use super::theme::Tone;
use super::widgets::elapsed_text;
use super::worker::{Job, Output};
use super::{
    App, Event, Level, Notice, Picker, Record, SCAN_INTERVAL, UI_REFRESH_INTERVAL, worker,
};
use eframe::egui;
use std::time::Instant;
use zalivka::progress;

impl App {
    pub(super) fn poll(&mut self, ctx: &egui::Context) {
        // Leave time for rendering and input even during a burst of log records.
        for index in 0..256 {
            let Ok(event) = self.rx.try_recv() else { break };
            // This frame already displays the events it consumes. Schedule
            // another only when a full batch may have left queued events.
            if index == 255 {
                ctx.request_repaint_after(UI_REFRESH_INTERVAL);
            }
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
                    if self.firmware.as_ref().is_some_and(|firmware| {
                        self.target().is_none_or(|device| !firmware.matches(device))
                    }) {
                        self.firmware = None;
                    }
                }
                Event::Firmware(request, release) => {
                    if let Some(firmware) = &self.firmware
                        && firmware.request == request
                    {
                        if self.target().is_some_and(|device| firmware.matches(device)) {
                            self.firmware.as_mut().unwrap().release = Some(release);
                        } else {
                            self.firmware = None;
                        }
                    }
                }
                Event::Worker(id, output) => {
                    let Some(job) = &mut self.job else { continue };
                    if job.id != id {
                        continue;
                    }
                    if matches!(&output, Output::State(progress::Event::RebootRequired)) {
                        self.windows_reboot_required = true;
                    }
                    let line = job.output(output);
                    let log_error = job.log_error.clone();
                    if let Some(line) = line {
                        self.journal_line(line);
                    }
                    self.journal_error(log_error.as_deref());
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
                                let mut text = self.journal_text(true);
                                if source.is_none() {
                                    text = format!(
                                        "Неполный журнал: сохранены последние {} записей из памяти.\n{text}\n",
                                        self.logs.len()
                                    );
                                }
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
                        expires_at: Some(Instant::now() + super::NOTICE_LIFETIME),
                    });
                }
                Event::Saved(Err(e)) => self.error("Журнал не сохранён", e),
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
        let level = match notice.tone {
            Tone::Error => Level::Error,
            Tone::Neutral if !job.cancelled => Level::Warning,
            _ => Level::Info,
        };
        let mut message = format!(
            "{}. Длительность: {}.",
            notice.title,
            elapsed_text(job.started.elapsed().as_secs())
        );
        if !notice.detail.is_empty() {
            message.push(' ');
            message.push_str(&notice.detail);
        }
        self.journal_line(job.record(Record::new(level, "session", message)));
        // The final record can be the first failed write. Build the displayed
        // result after that attempt so journal completeness is reported honestly.
        self.journal_error(job.log_error.as_deref());
        let notice = job.completion_notice(success, self.windows_reboot_required);
        if notice.tone == Tone::Error {
            self.journal_open = true;
        }
        self.notice = Some(notice);
        self.last_scan = Instant::now() - SCAN_INTERVAL;
    }
}
