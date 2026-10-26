//! Child-process lifetime, progress and completion for one GUI operation.
use super::widgets::elapsed_text;
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
    internet: Internet,
    pub(super) transfers: BTreeMap<u64, Transfer>,
    // Weights advertised by restored and each operation's highest known fraction.
    overall_operations: BTreeMap<u64, (u64, f32)>,
    pub(super) overall_fraction: Option<f32>,
    pub(super) phase: String,
    pub(super) last_activity: Instant,
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

enum Internet {
    Idle,
    Preparing,
    Ready {
        upload: f64,
        download: f64,
        received: Instant,
    },
    Unavailable(String),
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
            internet: Internet::Idle,
            transfers: BTreeMap::new(),
            overall_operations: BTreeMap::new(),
            overall_fraction: None,
            phase: if action == Action::PrepareWindows {
                "Подтвердите запрос прав администратора Windows".into()
            } else {
                "Подготовка".into()
            },
            last_activity: now,
        }
    }

    pub(super) fn can_stop(&self) -> bool {
        (!self.action.writes_device() || self.restore_completed)
            && self.action != Action::PrepareWindows
            && !matches!(self.internet, Internet::Preparing)
    }

    pub(super) fn internet_speed(&self, now: Instant) -> Option<(f64, f64)> {
        match self.internet {
            Internet::Ready {
                upload,
                download,
                received,
            } => Some(if now.duration_since(received) > Duration::from_secs(2) {
                (0.0, 0.0)
            } else {
                (upload, download)
            }),
            _ => None,
        }
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
            progress::Event::InternetWaiting => {
                self.internet = Internet::Idle;
                self.set_phase("Ожидание USB-сети Mac");
            }
            progress::Event::InternetPreparing => {
                self.internet = Internet::Preparing;
                self.set_phase("Подтвердите запрос прав администратора Windows");
            }
            progress::Event::InternetReady => {
                self.internet = Internet::Ready {
                    upload: 0.0,
                    download: 0.0,
                    received: Instant::now(),
                };
                self.set_phase("Интернет по USB, оставьте Zalivka открытой");
            }
            progress::Event::InternetSpeed {
                upload_bytes_per_second,
                download_bytes_per_second,
            } => {
                if matches!(self.internet, Internet::Ready { .. }) {
                    self.internet = Internet::Ready {
                        upload: upload_bytes_per_second,
                        download: download_bytes_per_second,
                        received: Instant::now(),
                    };
                }
            }
            progress::Event::InternetUnavailable { error } => {
                self.internet = Internet::Unavailable(error);
                self.set_phase("Интернет по USB недоступен");
            }
            progress::Event::Checkpoint { name, complete } => {
                if !complete {
                    self.phase = format!("Этап: {}", name.replace('_', " "));
                }
            }
            progress::Event::OperationWeights { weights } => {
                // Weights can arrive after progress, or temporarily omit an
                // operation. Retain its measured fraction across both cases.
                for (weight, _) in self.overall_operations.values_mut() {
                    *weight = 0;
                }
                for (operation, weight) in weights {
                    self.overall_operations.entry(operation).or_default().0 = weight;
                }
                self.update_overall();
            }
            progress::Event::OperationProgress {
                operation,
                progress,
                ..
            } => {
                if progress >= 0 {
                    self.advance_overall(operation, (progress as f32 / 100.0).min(1.0));
                }
            }
        }
        None
    }

    fn advance_overall(&mut self, operation: u64, fraction: f32) {
        let (_, previous) = self.overall_operations.entry(operation).or_default();
        *previous = previous.max(fraction);
        self.update_overall();
    }

    fn update_overall(&mut self) {
        let total: f64 = self
            .overall_operations
            .values()
            .map(|(weight, _)| *weight as f64)
            .sum();
        if total > 0.0 && !self.restore_completed {
            let completed: f64 = self
                .overall_operations
                .values()
                .map(|(weight, fraction)| *weight as f64 * f64::from(*fraction))
                .sum();
            // The device advertises weights for selected operations only. Keep
            // this estimate monotonic and reserve 100% for RestoreCompleted.
            let fraction = ((completed / total) as f32).min(0.99);
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
        let elapsed = elapsed_text(self.started.elapsed().as_secs());
        let (title, mut detail, mut tone) = if self.cancelled {
            (
                if self.action == Action::Restore && self.restore_completed {
                    "Восстановление завершено, раздача остановлена".into()
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
        } else if let Internet::Unavailable(error) = &self.internet {
            (
                "Восстановление завершено, интернет по USB недоступен".into(),
                error.clone(),
                Tone::Neutral,
            )
        } else {
            (
                self.action.completed_title().into(),
                if self.action.writes_device() {
                    format!("{elapsed}, Проверьте запуск Mac.")
                } else {
                    elapsed
                },
                Tone::Success,
            )
        };
        if let Some(error) = &self.log_error {
            detail.push_str(&format!(
                " Журнал на диске неполный: {error}. В окне доступна последняя часть журнала."
            ));
            if tone == Tone::Success {
                tone = Tone::Neutral;
            }
        }
        Notice {
            title,
            detail,
            tone,
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
