//! Native background operations, typed progress and a complete disk journal.
use super::journal::Journal;
use super::{Action, Event, Level, Notice, Record, Setup, Tone, UI_REFRESH_INTERVAL, progress};
use anyhow::{Context, Result};
use eframe::egui;
use std::{
    collections::BTreeMap,
    fs::File,
    path::PathBuf,
    sync::{Arc, Mutex, mpsc::Sender},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

pub(super) struct Job {
    pub(super) id: u64,
    pub(super) action: Action,
    pub(super) started: Instant,
    pub(super) context: progress::Context,
    pub(super) journal: Arc<Mutex<Journal>>,
    pub(super) completion: Option<Completion>,
    pub(super) restore_completed: bool,
    pub(super) transfers: BTreeMap<u64, Transfer>,
    overall_operations: BTreeMap<u64, Operation>,
    pub(super) overall_fraction: Option<f32>,
    pub(super) phase: String,
    pub(super) last_activity: Instant,
}

#[derive(Default)]
struct Operation {
    weight: u64,
    percent: u64,
    completed: u64,
}

impl Operation {
    fn advance(&mut self, percent: u64) {
        self.percent = self.percent.max(percent);
        // PRProgressComputeOverallProgress truncates each weighted contribution
        // to whole units before summing. Keep the multiply wide enough for u64.
        let completed = (u128::from(self.weight) * u128::from(self.percent) / 100) as u64;
        self.completed = self.completed.max(completed);
    }
}

pub(super) struct Transfer {
    pub(super) update: progress::Update,
    pub(super) received: Instant,
}
impl Transfer {
    pub(super) fn speed(&self, now: Instant) -> f64 {
        if now.duration_since(self.received) > Duration::from_secs(2) {
            0.0
        } else {
            self.update.bytes_per_second
        }
    }
    pub(super) fn remaining(&self, now: Instant) -> Option<u64> {
        let bytes = self.update.total?.saturating_sub(self.update.completed);
        let speed = self.speed(now);
        (bytes > 0 && speed > 0.0 && !self.update.finished)
            .then(|| (bytes as f64 / speed).ceil() as u64)
    }
}

pub(super) enum Output {
    State(progress::Event),
    Finished(Completion),
}

/// The worker owns the outcome. The journal and GUI derive their presentation
/// from this same result, including errors discovered while writing its tail.
#[derive(Default)]
pub(super) struct Completion {
    pub(super) success: bool,
    pub(super) cancelled: bool,
    pub(super) reboot_required: bool,
    pub(super) warning: Option<String>,
    pub(super) journal_error: Option<String>,
}

impl Job {
    pub(super) fn new(id: u64, action: Action, context: progress::Context, log: File) -> Self {
        let now = Instant::now();
        Self {
            id,
            action,
            started: now,
            context,
            journal: Arc::new(Mutex::new(Journal::new(log))),
            completion: None,
            restore_completed: false,
            transfers: BTreeMap::new(),
            overall_operations: BTreeMap::new(),
            overall_fraction: None,
            phase: if action == Action::InstallUdev {
                "Approve the Linux administrator prompt".into()
            } else if action.requires_admin() {
                "Approve the Windows administrator prompt".into()
            } else {
                "Preparing".into()
            },
            last_activity: now,
        }
    }

    pub(super) fn can_stop(&self) -> bool {
        !self.action.writes_device() && !self.action.requires_admin()
    }

    pub(super) fn stop(&mut self) -> std::io::Result<()> {
        if !self.can_stop() || self.completion.is_some() {
            return Err(std::io::Error::other(
                "This operation cannot be stopped right now",
            ));
        }
        self.context.cancel();
        Ok(())
    }

    pub(super) fn pending_logs(&mut self) -> Option<(Vec<Record>, Option<String>)> {
        // Rendering never waits for disk I/O in the journal thread.
        let mut journal = match self.journal.try_lock() {
            Ok(journal) => journal,
            Err(std::sync::TryLockError::Poisoned(error)) => error.into_inner(),
            Err(std::sync::TryLockError::WouldBlock) => return None,
        };
        Some(journal.drain())
    }

    pub(super) fn output(&mut self, output: Output) {
        match output {
            Output::State(event) => self.worker_event(event),
            Output::Finished(completion) => {
                if self.completion.is_none() {
                    self.completion = Some(completion);
                }
            }
        }
    }

    fn worker_event(&mut self, event: progress::Event) {
        self.last_activity = Instant::now();
        match event {
            progress::Event::Log(_) => {}
            progress::Event::Transfer(update) => {
                if update.finished {
                    self.transfers.remove(&update.id);
                } else {
                    self.transfers.insert(
                        update.id,
                        Transfer {
                            update,
                            received: Instant::now(),
                        },
                    );
                }
            }
            progress::Event::RestoreCompleted => {
                self.restore_completed = true;
                self.overall_fraction = Some(1.0);
                self.phase = "Restore complete".into();
                self.transfers.clear();
            }
            progress::Event::ProvisioningWarning { .. } | progress::Event::RebootRequired => {}
            progress::Event::Checkpoint { name, complete } => {
                if !complete {
                    self.phase = format!("Stage: {}", name.replace('_', " "));
                }
            }
            progress::Event::OperationWeights {
                weights,
                progresses,
            } => {
                // Weights can arrive after progress, or temporarily omit an
                // operation. Retain its measured progress across both cases.
                for operation in self.overall_operations.values_mut() {
                    operation.weight = 0;
                }
                for (id, weight) in weights {
                    let operation = self.overall_operations.entry(id).or_default();
                    operation.weight = weight;
                    operation.completed = operation.completed.min(weight);
                    operation.advance(operation.percent);
                }
                for (id, completed) in progresses {
                    if let Some(operation) = self.overall_operations.get_mut(&id) {
                        operation.completed =
                            operation.completed.max(completed.min(operation.weight));
                    }
                }
                self.update_overall();
            }
            progress::Event::OperationProgress {
                operation,
                progress,
                ..
            } => {
                // Apple's progress accumulator counts -1 as the full weight
                // of this operation. This is not a successful restore status.
                let percent = match progress {
                    -1 => 100,
                    0..=100 => progress as u64,
                    _ => return,
                };
                self.overall_operations
                    .entry(operation)
                    .or_default()
                    .advance(percent);
                self.update_overall();
            }
        }
    }

    fn update_overall(&mut self) {
        let total: f64 = self
            .overall_operations
            .values()
            .map(|operation| operation.weight as f64)
            .sum();
        if total > 0.0 && !self.restore_completed {
            let completed: f64 = self
                .overall_operations
                .values()
                .map(|operation| operation.completed.min(operation.weight) as f64)
                .sum();
            // The device advertises weights for selected operations only. Keep
            // this estimate monotonic and reserve 100% for RestoreCompleted.
            let percent = ((completed / total) as f32 * 100.0).trunc().min(99.0);
            let fraction = percent / 100.0;
            self.overall_fraction = Some(self.overall_fraction.unwrap_or_default().max(fraction));
        }
    }

    pub(super) fn worker_context(
        &self,
        tx: &Sender<Event>,
        ctx: &egui::Context,
        reboot_required: bool,
    ) -> Result<(progress::Context, Arc<Mutex<Completion>>)> {
        let id = self.id;
        let journal = self.journal.clone();
        let completion = Arc::new(Mutex::new(Completion {
            reboot_required,
            ..Completion::default()
        }));
        let completion_events = completion.clone();
        let events = tx.clone();
        let repaint = ctx.clone();
        let context = progress::Context::new(move |event| match event {
            progress::Event::Log(record) => {
                let mut journal = journal.lock().unwrap_or_else(|e| e.into_inner());
                let wake = journal.record(record);
                drop(journal);
                if wake {
                    repaint.request_repaint_after(UI_REFRESH_INTERVAL);
                }
            }
            event => {
                completion_events
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .observe(&event);
                let _ = events.send(Event::Worker(id, Output::State(event)));
                repaint.request_repaint_after(UI_REFRESH_INTERVAL);
            }
        });
        let journal = self.journal.clone();
        let repaint = ctx.clone();
        let context = context
            .with_async_logs(move || {
                let mut journal = journal.lock().unwrap_or_else(|e| e.into_inner());
                if journal.flush() {
                    repaint.request_repaint_after(UI_REFRESH_INTERVAL);
                }
            })
            .context("starting journal thread")?;
        Ok((context, completion))
    }

    pub(super) fn spawn(
        id: u64,
        action: Action,
        setup: &Setup,
        tx: &Sender<Event>,
        ctx: &egui::Context,
        reboot_required: bool,
    ) -> Result<(Self, PathBuf)> {
        let directory = zalivka::storage::log_directory()?;
        let stamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let name = format!("{}-{stamp}", action.log_name());
        let path = directory.join(format!("{name}.log"));
        let transcript = directory.join(format!("{name}.jsonl"));
        setup.validate(action)?;
        let log = File::options().write(true).create_new(true).open(&path)?;
        let mut job = Self::new(id, action, progress::Context::new(|_| {}), log);
        let record = Record::new(
            Level::Info,
            "session",
            format!(
                "Starting: {}; Zalivka {}{}",
                action.title(),
                zalivka::VERSION,
                if setup.ecid.is_empty() {
                    String::new()
                } else {
                    format!("; ECID: {}", setup.ecid)
                }
            ),
        );
        job.journal
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .record(record);
        job.journal
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .flush();
        let (context, completion) = job.worker_context(tx, ctx, reboot_required)?;
        job.context = context.clone();
        let setup = setup.clone();
        let started = job.started;
        let final_journal = job.journal.clone();
        let tx = tx.clone();
        let ctx = ctx.clone();
        std::thread::Builder::new()
            .name(format!("zalivka-{}", action.log_name()))
            .spawn(move || {
                let result = context.run(|| {
                    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        setup.run(action, &transcript)
                    }))
                    .unwrap_or_else(|panic| {
                        let message = panic
                            .downcast_ref::<String>()
                            .map(String::as_str)
                            .or_else(|| panic.downcast_ref::<&str>().copied())
                            .unwrap_or("unknown panic");
                        Err(anyhow::anyhow!("Operation thread: {message}"))
                    });
                    if let Err(error) = &result
                        && !context.cancelled()
                    {
                        zalivka::log!(Error, "app", "{error:#}");
                    }
                    result
                });
                let mut completion =
                    std::mem::take(&mut *completion.lock().unwrap_or_else(|e| e.into_inner()));
                completion.success = result.is_ok();
                let completion = completion.finish(action, started, &context, &final_journal);
                let _ = tx.send(Event::Worker(id, Output::Finished(completion)));
                ctx.request_repaint();
            })
            .context("starting native operation")?;
        Ok((job, path))
    }
}

impl Drop for Job {
    fn drop(&mut self) {
        if self.can_stop() && self.completion.is_none() {
            self.context.cancel();
        }
    }
}

impl Completion {
    fn observe(&mut self, event: &progress::Event) {
        match event {
            progress::Event::ProvisioningWarning { message } => {
                self.warning = Some(message.clone())
            }
            progress::Event::RebootRequired => self.reboot_required = true,
            _ => {}
        }
    }

    pub(super) fn finish(
        mut self,
        action: Action,
        started: Instant,
        context: &progress::Context,
        journal: &Mutex<Journal>,
    ) -> Self {
        // Child services have stopped. Drain their messages, write the result,
        // then include failures from that final write before publishing it.
        self.flush_logs(context, journal);
        context.run(|| zalivka::logging::publish(self.record(action, started)));
        self.flush_logs(context, journal);
        self
    }

    fn flush_logs(&mut self, context: &progress::Context, journal: &Mutex<Journal>) {
        if let Err(error) = context.flush_logs() {
            self.success = false;
            self.journal_error.get_or_insert_with(|| error.to_string());
        }
        self.cancelled = context.cancelled();
        if let Some(error) = journal.lock().unwrap_or_else(|e| e.into_inner()).error() {
            self.journal_error.get_or_insert_with(|| error.clone());
        }
    }

    pub(super) fn notice(&self, action: Action) -> Notice {
        let (title, detail, mut tone) = if self.cancelled {
            ("Operation stopped".into(), String::new(), Tone::Neutral)
        } else if !self.success {
            (
                format!("{}: error", action.title()),
                "See the journal for details.".into(),
                Tone::Error,
            )
        } else if matches!(action, Action::PrepareWindows | Action::ResetDrivers)
            && self.reboot_required
        {
            (
                "Restart Windows".into(),
                "Driver installed. Restart Windows before restoring the Mac.".into(),
                Tone::Neutral,
            )
        } else if action.writes_device()
            && let Some(warning) = &self.warning
        {
            (
                format!("{}: check activation", action.completed_title()),
                warning.into(),
                Tone::Neutral,
            )
        } else {
            (
                action.completed_title().into(),
                if action.writes_device() {
                    progress::MAC_STARTUP_HINT.into()
                } else if action == Action::ResetDrivers {
                    "Reconnect the Mac and enter DFU mode.".into()
                } else if action == Action::InstallUdev {
                    "Reconnect the USB cable to apply the new access rules.".into()
                } else {
                    String::new()
                },
                Tone::Success,
            )
        };
        if self.journal_error.is_some() && tone == Tone::Success {
            tone = Tone::Neutral;
        }
        Notice {
            title,
            detail,
            journal_error: self.journal_error.clone(),
            tone,
            expires_at: if self.journal_error.is_none() && (tone == Tone::Success || self.cancelled)
            {
                Some(Instant::now() + super::NOTICE_LIFETIME)
            } else {
                None
            },
        }
    }

    fn record(&self, action: Action, started: Instant) -> Record {
        let notice = self.notice(action);
        let mut message = format!(
            "{}. Duration: {}.",
            notice.title,
            super::widgets::elapsed_text(started.elapsed().as_secs())
        );
        if !notice.detail.is_empty() {
            message.push(' ');
            message.push_str(&notice.detail);
        }
        if let Some(error) = &notice.journal_error {
            message.push_str(&format!(
                " Disk journal incomplete: {error}. Recent history is available in this window."
            ));
        }
        Record::new(
            match notice.tone {
                Tone::Error => Level::Error,
                Tone::Neutral if !self.cancelled => Level::Warning,
                _ => Level::Info,
            },
            "session",
            message,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn polling_gui_logs_does_not_wait_for_the_journal_mutex() {
        let log = tempfile::tempfile().unwrap();
        let mut job = Job::new(1, Action::Verify, progress::Context::new(|_| {}), log);
        let journal = job.journal.clone();
        let locked = journal.lock().unwrap();
        let (done, result) = std::sync::mpsc::channel();
        let reader = std::thread::spawn(move || {
            done.send(job.pending_logs()).unwrap();
        });
        let pending = result.recv_timeout(Duration::from_secs(5));
        drop(locked);
        reader.join().unwrap();
        assert!(pending.expect("GUI waited for the disk journal").is_none());
    }
}
