//! Child-process lifetime, progress and completion for one GUI operation.
use super::{Action, Event, Level, Notice, Record, Setup, Tone, UI_REFRESH_INTERVAL, progress};
use anyhow::{Context, Result};
use eframe::egui;
use std::{
    collections::BTreeMap,
    fs::File,
    io::{BufRead, BufReader, Write},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::mpsc::Sender,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

pub(super) struct Job {
    pub(super) id: u64,
    pub(super) action: Action,
    pub(super) started: Instant,
    child: Child,
    pub(super) log: File,
    pub(super) log_error: Option<String>,
    pub(super) success: Option<bool>,
    pub(super) readers: u8,
    pub(super) cancelled: bool,
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

/// Both output pipes belong to one job; only stdout carries state events.
pub(super) enum Output {
    Line(String),
    State(progress::Event),
    Closed,
}

impl Output {
    pub(super) fn parse(line: String, state_events: bool) -> Self {
        if state_events && let Some(event) = progress::Event::parse(&line) {
            Self::State(event)
        } else {
            Self::Line(line)
        }
    }
}

impl Job {
    pub(super) fn new(id: u64, action: Action, child: Child, log: File) -> Self {
        let now = Instant::now();
        Self {
            id,
            action,
            started: now,
            child,
            log,
            log_error: None,
            success: None,
            readers: 2,
            cancelled: false,
            restore_completed: false,
            transfers: BTreeMap::new(),
            overall_operations: BTreeMap::new(),
            overall_fraction: None,
            phase: if matches!(action, Action::PrepareWindows | Action::ResetDrivers) {
                "Подтвердите запрос прав администратора Windows".into()
            } else {
                "Подготовка".into()
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
            return Err(std::io::Error::other("Операцию сейчас нельзя остановить"));
        }
        if !self.cancelled {
            self.child.kill()?;
            self.cancelled = true;
        }
        Ok(())
    }

    pub(super) fn record(&mut self, mut record: Record) -> Record {
        record.elapsed_ms = self.started.elapsed().as_millis() as u64;
        record.normalize();
        if self.log_error.is_none()
            && let Err(error) = record.write_to(&mut self.log)
        {
            let error = error.to_string();
            record
                .message
                .push_str(&format!(" / Журнал на диске неполный: {error}"));
            if record.level != Level::Error {
                record.level = Level::Warning;
            }
            record.normalize();
            self.log_error = Some(error);
        }
        record
    }

    pub(super) fn output(&mut self, output: Output) -> Option<Record> {
        match output {
            Output::Line(line) => {
                self.last_activity = Instant::now();
                // stderr is reserved for unexpected runtime/OS diagnostics.
                Some(self.record(Record::new(Level::Warning, "worker", line)))
            }
            Output::State(event) => self.worker_event(event),
            Output::Closed => {
                self.readers = self.readers.saturating_sub(1);
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
                self.set_phase("Восстановление завершено");
            }
            progress::Event::RebootRequired => {}
            progress::Event::Checkpoint { name, complete } => {
                if !complete {
                    self.phase = format!("Этап: {}", name.replace('_', " "));
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

    // The exit code can arrive before the final stdout/stderr lines.
    pub(super) fn finished(&mut self) -> std::io::Result<Option<bool>> {
        if self.success.is_none() {
            self.success = self.child.try_wait()?.map(|status| status.success());
        }
        Ok(self.success.filter(|_| self.readers == 0))
    }

    pub(super) fn completion_notice(&self, success: bool, reboot_required: bool) -> Notice {
        let (title, mut detail, mut tone) = if self.cancelled {
            ("Операция остановлена".into(), String::new(), Tone::Neutral)
        } else if !success {
            (
                format!("{}: ошибка", self.action.title()),
                "Подробности в журнале.".into(),
                Tone::Error,
            )
        } else if matches!(self.action, Action::PrepareWindows | Action::ResetDrivers)
            && reboot_required
        {
            (
                "Перезагрузите Windows".into(),
                "Драйвер установлен. Перезагрузите компьютер перед восстановлением Mac.".into(),
                Tone::Neutral,
            )
        } else {
            (
                self.action.completed_title().into(),
                if self.action.writes_device() {
                    "Проверьте запуск Mac.".into()
                } else if self.action == Action::ResetDrivers {
                    "Подключите Mac заново и введите его в DFU.".into()
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
                "Журнал на диске неполный: {error}. В окне доступна последняя часть журнала."
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
        let name = format!("{}-{stamp}", action.command());
        let path = directory.join(format!("{name}.log"));
        let transcript = directory.join(format!("{name}.jsonl"));
        let args = setup.arguments(action, Some(&transcript))?;
        let log = File::options().write(true).create_new(true).open(&path)?;
        let mut command = Command::new(std::env::current_exe()?);
        command
            .args(args)
            .env(progress::WORKER_EVENTS_ENV, "1")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            command.creation_flags(0x08000000);
        }
        let mut child = command.spawn().context("starting worker")?;
        let stdout = child.stdout.take().context("worker has no stdout")?;
        let stderr = child.stderr.take().context("worker has no stderr")?;
        for (pipe, state_events) in [
            (Box::new(stdout) as Box<dyn std::io::Read + Send>, true),
            (Box::new(stderr), false),
        ] {
            let tx = tx.clone();
            let ctx = ctx.clone();
            if let Err(e) = std::thread::Builder::new()
                .name("zalivka-log".into())
                .spawn(move || {
                    for line in BufReader::new(pipe).lines() {
                        let line = match line {
                            Ok(line) => line,
                            Err(e) => {
                                let _ = tx.send(Event::Worker(
                                    id,
                                    Output::Line(format!("Log read error: {e}")),
                                ));
                                break;
                            }
                        };
                        if tx
                            .send(Event::Worker(id, Output::parse(line, state_events)))
                            .is_err()
                        {
                            break;
                        }
                        ctx.request_repaint_after(UI_REFRESH_INTERVAL);
                    }
                    let _ = tx.send(Event::Worker(id, Output::Closed));
                    ctx.request_repaint();
                })
            {
                let _ = child.kill();
                let _ = child.wait();
                return Err(e.into());
            }
        }
        Ok((Self::new(id, action, child, log), path))
    }
}

impl Drop for Job {
    fn drop(&mut self) {
        // A window can close immediately after stop(). Reap the killed child
        // here as well as in finished(), which may never run for that window.
        if self.cancelled {
            let _ = self.child.wait();
        }
    }
}

pub(super) fn save_log(path: PathBuf, source: Option<&Path>, text: &str) -> Result<PathBuf> {
    if let Some(source) = source {
        let same = source
            .canonicalize()
            .ok()
            .zip(path.canonicalize().ok())
            .is_some_and(|(a, b)| a == b);
        if same {
            return Ok(path);
        }
    }
    // Write beside the destination, then replace it only after a complete copy.
    // Distinct paths can be hard links to the active log; copying directly to
    // such a destination would truncate the source before it can be read.
    let directory = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let mut saved = tempfile::NamedTempFile::new_in(directory)?;
    if let Some(source) = source {
        std::io::copy(&mut File::open(source)?, &mut saved)?;
    } else {
        saved.write_all(text.as_bytes())?;
    }
    saved.persist(&path).context("saving operation log")?;
    Ok(path)
}
