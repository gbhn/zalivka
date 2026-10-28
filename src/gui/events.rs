//! Apply background events and finish jobs only after their logs are drained.
use super::theme::Tone;
use super::worker::{Job, Output};
use super::{App, Event, Notice, Picker, SCAN_INTERVAL, UI_REFRESH_INTERVAL, worker};
use eframe::egui;
use std::time::Instant;
use zalivka::progress;

impl App {
    fn collect_job_logs(&mut self) -> bool {
        if let Some(job) = &mut self.job {
            let Some(lines) = job.pending_logs() else {
                return false;
            };
            let error = job.log_error.clone();
            if !lines.is_empty() {
                job.last_activity = Instant::now();
            }
            for line in lines {
                self.journal_line(line);
            }
            self.journal_error(error.as_deref());
        }
        true
    }
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
                    job.output(output);
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
                                self.collect_job_logs();
                                let source = self.log_path.clone();
                                let journal = self.job.as_ref().map(|job| job.journal.clone());
                                let logs = self.job.as_ref().map(|job| job.context.clone());
                                let mut text = self.journal_text(true);
                                if source.is_none() {
                                    text = format!(
                                        "Incomplete journal: saved the last {} records from memory.\n{text}\n",
                                        self.logs.len()
                                    );
                                }
                                let spawn = self.background(ctx, "save", move || {
                                    if let Some(logs) = logs
                                        && let Err(error) = logs.flush_logs()
                                    {
                                        return Event::Saved(Err(error.to_string()));
                                    }
                                    let result = worker::save_log(
                                        path,
                                        source.as_deref(),
                                        &text,
                                        journal.as_deref(),
                                    )
                                    .map_err(|e| format!("{e:#}"));
                                    Event::Saved(result)
                                });
                                if let Err(e) = spawn {
                                    self.error("Journal not saved", e);
                                }
                            }
                        }
                    }
                }
                Event::Saved(Ok(path)) => {
                    self.notice = Some(Notice {
                        title: "Journal saved".into(),
                        detail: path.display().to_string(),
                        journal_error: None,
                        tone: Tone::Success,
                        expires_at: Some(Instant::now() + super::NOTICE_LIFETIME),
                    });
                }
                Event::Saved(Err(e)) => self.error("Journal not saved", e),
            }
        }
        if !self.collect_job_logs() {
            return;
        }
        let success = match self.job.as_ref().and_then(Job::finished) {
            Some(success) => success,
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
