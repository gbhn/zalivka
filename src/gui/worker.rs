//! Native background operations, typed progress and a complete disk journal.
use super::{Action, Event, Level, Notice, Record, Setup, Tone, UI_REFRESH_INTERVAL, progress};
use anyhow::{Context, Result};
use eframe::egui;
use std::{
    collections::{BTreeMap, VecDeque},
    fs::File,
    io::{BufWriter, Read, Write},
    path::{Path, PathBuf},
    sync::{Arc, Mutex, mpsc::Sender},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

pub(super) struct Job {
    pub(super) id: u64,
    pub(super) action: Action,
    pub(super) started: Instant,
    pub(super) context: progress::Context,
    pub(super) journal: Arc<Mutex<Journal>>,
    pub(super) log_error: Option<String>,
    pub(super) success: Option<bool>,
    pub(super) cancelled: bool,
    pub(super) restore_completed: bool,
    provisioning_warning: Option<String>,
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
    Finished(bool),
}

pub(super) struct Journal {
    pub(super) log: BufWriter<File>,
    error: Option<String>,
    pending: VecDeque<Record>,
}

impl Journal {
    fn new(log: File) -> Self {
        Self {
            log: BufWriter::with_capacity(256 * 1024, log),
            error: None,
            pending: VecDeque::new(),
        }
    }
    fn write(&mut self, mut record: Record) -> Record {
        record.normalize();
        if self.error.is_none()
            && let Err(error) = record.write_to(&mut self.log)
        {
            self.error = Some(error.to_string());
            record
                .message
                .push_str(&format!(" / Disk journal incomplete: {error}"));
            if record.level != Level::Error {
                record.level = Level::Warning;
            }
        }
        record
    }
    fn push(&mut self, record: Record) {
        self.pending.push_back(record);
        super::trim_logs(&mut self.pending);
    }
    fn flush(&mut self) -> Option<String> {
        if self.error.is_none()
            && let Err(error) = self.log.flush()
        {
            let error = error.to_string();
            self.error = Some(error.clone());
            return Some(error);
        }
        None
    }
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
            log_error: None,
            success: None,
            cancelled: false,
            restore_completed: false,
            provisioning_warning: None,
            transfers: BTreeMap::new(),
            overall_operations: BTreeMap::new(),
            overall_fraction: None,
            phase: if matches!(action, Action::PrepareWindows | Action::ResetDrivers) {
                "Approve the Windows administrator prompt".into()
            } else {
                "Preparing".into()
            },
            last_activity: now,
        }
    }

    pub(super) fn can_stop(&self) -> bool {
        !self.action.writes_device()
            && !matches!(self.action, Action::PrepareWindows | Action::ResetDrivers)
    }

    pub(super) fn stop(&mut self) -> std::io::Result<()> {
        if !self.can_stop() {
            return Err(std::io::Error::other(
                "This operation cannot be stopped right now",
            ));
        }
        if !self.cancelled {
            self.context.cancel();
            self.cancelled = true;
        }
        Ok(())
    }

    pub(super) fn record(&mut self, mut record: Record) -> Record {
        record.elapsed_ms = self.started.elapsed().as_millis() as u64;
        let mut journal = self.journal.lock().unwrap_or_else(|e| e.into_inner());
        let mut record = journal.write(record);
        if let Some(error) = journal.flush() {
            record
                .message
                .push_str(&format!(" / Disk journal incomplete: {error}"));
            if record.level != Level::Error {
                record.level = Level::Warning;
            }
        }
        self.log_error = journal.error.clone();
        record
    }

    pub(super) fn pending_logs(&mut self) -> Vec<Record> {
        // Rendering never waits for disk I/O in the journal thread.
        let mut journal = match self.journal.try_lock() {
            Ok(journal) => journal,
            Err(std::sync::TryLockError::Poisoned(error)) => error.into_inner(),
            Err(std::sync::TryLockError::WouldBlock) => return Vec::new(),
        };
        self.log_error = journal.error.clone();
        journal.pending.drain(..).collect()
    }

    pub(super) fn output(&mut self, output: Output) -> Option<Record> {
        match output {
            Output::State(event) => self.worker_event(event),
            Output::Finished(success) => {
                self.success = Some(success);
                None
            }
        }
    }

    fn worker_event(&mut self, event: progress::Event) -> Option<Record> {
        self.last_activity = Instant::now();
        if let progress::Event::Log(record) = event {
            return Some(self.record(record));
        }
        match event {
            progress::Event::Log(_) => unreachable!(),
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
                self.set_phase("Restore complete");
            }
            progress::Event::ProvisioningWarning { message } => {
                self.provisioning_warning = Some(message);
            }
            progress::Event::RebootRequired => {}
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
                    _ => return None,
                };
                self.overall_operations
                    .entry(operation)
                    .or_default()
                    .advance(percent);
                self.update_overall();
            }
        }
        None
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

    fn set_phase(&mut self, phase: &str) {
        self.phase = phase.into();
        self.transfers.clear();
    }

    pub(super) fn finished(&self) -> Option<bool> {
        self.success
    }

    pub(super) fn completion_notice(&self, success: bool, reboot_required: bool) -> Notice {
        let (title, mut detail, mut tone) = if self.cancelled {
            ("Operation stopped".into(), String::new(), Tone::Neutral)
        } else if !success {
            (
                format!("{}: error", self.action.title()),
                "See the journal for details.".into(),
                Tone::Error,
            )
        } else if matches!(self.action, Action::PrepareWindows | Action::ResetDrivers)
            && reboot_required
        {
            (
                "Restart Windows".into(),
                "Driver installed. Restart Windows before restoring the Mac.".into(),
                Tone::Neutral,
            )
        } else if self.action.writes_device()
            && let Some(warning) = &self.provisioning_warning
        {
            (
                format!("{}: check activation", self.action.completed_title()),
                warning.clone(),
                Tone::Neutral,
            )
        } else {
            (
                self.action.completed_title().into(),
                if self.action.writes_device() {
                    progress::MAC_STARTUP_HINT.into()
                } else if self.action == Action::ResetDrivers {
                    "Reconnect the Mac and enter DFU mode.".into()
                } else {
                    String::new()
                },
                Tone::Success,
            )
        };
        if let Some(error) = &self.log_error {
            if !detail.is_empty() {
                detail.push(' ');
            }
            detail.push_str(&format!(
                "Disk journal incomplete: {error}. Recent history is available in this window."
            ));
            if tone == Tone::Success {
                tone = Tone::Neutral;
            }
        }
        Notice {
            title,
            detail,
            tone,
            expires_at: if self.log_error.is_none() && (tone == Tone::Success || self.cancelled) {
                Some(Instant::now() + super::NOTICE_LIFETIME)
            } else {
                None
            },
        }
    }

    pub(super) fn spawn(
        id: u64,
        action: Action,
        setup: &Setup,
        tx: &Sender<Event>,
        ctx: &egui::Context,
    ) -> Result<(Self, PathBuf)> {
        let directory = zalivka::storage::log_directory()?;
        let stamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let name = format!("{}-{stamp}", action.log_name());
        let path = directory.join(format!("{name}.log"));
        let transcript = directory.join(format!("{name}.jsonl"));
        setup.validate(action)?;
        let log = File::options().write(true).create_new(true).open(&path)?;
        let mut job = Self::new(id, action, progress::Context::new(|_| {}), log);
        let record = job.record(Record::new(
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
        ));
        job.journal
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(record);
        let journal = job.journal.clone();
        let log_started = zalivka::logging::elapsed_ms();
        let events = tx.clone();
        let repaint = ctx.clone();
        let context = progress::Context::new(move |event| match event {
            progress::Event::Log(mut record) => {
                record.elapsed_ms = record.elapsed_ms.saturating_sub(log_started);
                let mut journal = journal.lock().unwrap_or_else(|e| e.into_inner());
                let wake = journal.pending.is_empty();
                let record = journal.write(record);
                journal.push(record);
                drop(journal);
                if wake {
                    repaint.request_repaint_after(UI_REFRESH_INTERVAL);
                }
            }
            event => {
                let _ = events.send(Event::Worker(id, Output::State(event)));
                repaint.request_repaint_after(UI_REFRESH_INTERVAL);
            }
        });
        let journal = job.journal.clone();
        let repaint = ctx.clone();
        let context = context
            .with_async_logs(move || {
                let mut journal = journal.lock().unwrap_or_else(|e| e.into_inner());
                if let Some(error) = journal.flush() {
                    journal.push(Record::new(
                        Level::Warning,
                        "journal",
                        format!("Disk journal incomplete: {error}"),
                    ));
                    repaint.request_repaint_after(UI_REFRESH_INTERVAL);
                }
            })
            .context("starting journal thread")?;
        job.context = context.clone();
        let setup = setup.clone();
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
                // All child services have stopped: drain their final dumps before
                // reporting completion or allowing the journal to be replaced.
                let logs = context.flush_logs();
                let _ = tx.send(Event::Worker(
                    id,
                    Output::Finished(result.is_ok() && logs.is_ok()),
                ));
                ctx.request_repaint();
            })
            .context("starting native operation")?;
        Ok((job, path))
    }
}

impl Drop for Job {
    fn drop(&mut self) {
        if self.can_stop() && self.success.is_none() {
            self.context.cancel();
        }
        let _ = self
            .journal
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .flush();
    }
}

pub(super) fn save_log(
    path: PathBuf,
    source: Option<&Path>,
    text: &str,
    journal: Option<&Mutex<Journal>>,
) -> Result<PathBuf> {
    let same = source
        .and_then(|source| source.canonicalize().ok())
        .zip(path.canonicalize().ok())
        .is_some_and(|(source, destination)| source == destination);
    let source = source
        .map(File::open)
        .transpose()?
        .map(|file| -> Result<_> {
            // Capture a complete record boundary, then release writers while the
            // potentially large snapshot is copied in the background.
            let mut journal =
                journal.map(|journal| journal.lock().unwrap_or_else(|e| e.into_inner()));
            if let Some(journal) = &mut journal {
                let _ = journal.flush();
                if let Some(error) = &journal.error {
                    anyhow::bail!("Disk journal incomplete: {error}");
                }
            }
            let length = file.metadata()?.len();
            Ok((file, length))
        })
        .transpose()?;
    if same {
        return Ok(path);
    }
    // Write beside the destination, then replace it only after a complete copy.
    // Distinct paths can be hard links to the active log; copying directly to
    // such a destination would truncate the source before it can be read.
    let directory = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let mut saved = tempfile::NamedTempFile::new_in(directory)?;
    if let Some((file, length)) = source {
        std::io::copy(&mut file.take(length), &mut saved)?;
    } else {
        saved.write_all(text.as_bytes())?;
    }
    saved.persist(&path).context("saving operation log")?;
    Ok(path)
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
        assert!(pending.expect("GUI waited for the disk journal").is_empty());
    }

    #[test]
    fn trace_history_is_bounded_while_the_disk_journal_remains_complete() {
        let file = tempfile::NamedTempFile::new().unwrap();
        let mut journal = Journal::new(file.reopen().unwrap());
        let record = journal.write(Record::new(Level::Info, "restore", "Starting stage"));
        journal.push(record);
        for index in 0..8000 {
            let record = journal.write(Record::new(Level::Trace, "fdr:conn", index));
            journal.push(record);
        }
        assert!(journal.flush().is_none());
        assert_eq!(journal.pending.len(), 4000);
        assert_eq!(journal.pending.front().unwrap().level, Level::Info);
        let directory = tempfile::tempdir().unwrap();
        let destination = directory.path().join("saved.log");
        let journal = Mutex::new(journal);
        save_log(
            destination.clone(),
            Some(file.path()),
            "visible tail",
            Some(&journal),
        )
        .unwrap();
        assert_eq!(
            std::fs::read(&destination).unwrap(),
            std::fs::read(file.path()).unwrap()
        );
        assert_eq!(
            std::fs::read_to_string(file.path())
                .unwrap()
                .lines()
                .count(),
            8001
        );
    }
}
