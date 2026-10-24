//! Apply background events and finish jobs only after their logs are drained.
use super::theme::Tone;
use super::worker::{Job, Output};
use super::{App, Event, Notice, Picker, SCAN_INTERVAL, worker};
use eframe::egui;
use std::time::Instant;
use zalivka::progress;

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
                Event::Worker(id, output) => {
                    let Some(job) = &mut self.job else { continue };
                    if job.id != id {
                        continue;
                    }
                    if matches!(&output, Output::State(progress::Event::RebootRequired)) {
                        self.windows_reboot_required = true;
                    }
                    if let Some(line) = job.output(output) {
                        self.journal_line(line);
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
        let job = self.job.take().unwrap();
        let notice = job.completion_notice(success, self.windows_reboot_required);
        if notice.tone == Tone::Error {
            self.journal_open = true;
        }
        self.notice = Some(notice);
        self.last_scan = Instant::now() - SCAN_INTERVAL;
    }
}
