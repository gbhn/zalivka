//! Transfer identities, byte counters and operation progress shared with the GUI.
use serde::{Deserialize, Serialize};
use std::{
    cell::RefCell,
    io::{self, Write},
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, Instant},
};

pub const EVENT_PREFIX: &str = "ZALIVKA_EVENT ";
pub const WORKER_EVENTS_ENV: &str = "ZALIVKA_WORKER_EVENTS";
const INTERVAL: Duration = Duration::from_millis(500);
static NEXT_TRANSFER: AtomicU64 = AtomicU64::new(1);
thread_local! {
    static OPERATION: RefCell<(Option<u64>, Option<String>)> = const { RefCell::new((None, None)) };
}

pub(crate) fn current_operation() -> Option<u64> {
    OPERATION.with_borrow(|scope| scope.0)
}

pub(crate) fn current_async_context() -> Option<String> {
    OPERATION.with_borrow(|scope| scope.1.clone())
}

/// Keep the device's operation metadata with a request across worker threads.
pub(crate) fn with_operation<T>(
    operation: Option<u64>,
    context: Option<String>,
    run: impl FnOnce() -> T,
) -> T {
    struct Reset((Option<u64>, Option<String>));
    impl Drop for Reset {
        fn drop(&mut self) {
            OPERATION.with(|scope| scope.replace(std::mem::take(&mut self.0)));
        }
    }
    let _reset = Reset(OPERATION.with(|scope| scope.replace((operation, context))));
    run()
}

/// Worker state is independent of human-readable logs and their retained history.
#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum Event {
    Log(crate::logging::Record),
    Transfer(Update),
    RestoreCompleted,
    RebootRequired,
    InternetWaiting,
    InternetPreparing,
    InternetReady,
    InternetSpeed {
        upload_bytes_per_second: f64,
        download_bytes_per_second: f64,
    },
    InternetUnavailable {
        error: String,
    },
    Checkpoint {
        name: String,
        complete: bool,
    },
    OperationWeights {
        weights: Vec<(u64, u64)>,
    },
    OperationName {
        operation: u64,
        name: String,
    },
    OperationProgress {
        #[serde(default)]
        async_context: Option<String>,
        operation: u64,
        progress: i64,
    },
}

impl Event {
    pub fn parse(line: &str) -> Option<Self> {
        let mut event: Self = serde_json::from_str(line.strip_prefix(EVENT_PREFIX)?).ok()?;
        if let Self::Log(record) = &mut event {
            record.normalize();
        }
        match &event {
            Self::Transfer(update) if !update.valid() => None,
            Self::OperationWeights { weights }
                if weights.iter().all(|(_, weight)| *weight == 0) =>
            {
                None
            }
            Self::InternetSpeed {
                upload_bytes_per_second,
                download_bytes_per_second,
            } if [upload_bytes_per_second, download_bytes_per_second]
                .iter()
                .any(|speed| !speed.is_finite() || **speed < 0.0) =>
            {
                None
            }
            _ => Some(event),
        }
    }

    pub fn write_to(&self, mut output: impl Write) -> io::Result<()> {
        let json = serde_json::to_string(self).map_err(io::Error::other)?;
        writeln!(output, "{EVENT_PREFIX}{json}")
    }

    pub fn emit(&self) {
        // State and logs share one ordered worker pipe. State is private to the
        // GUI protocol; a terminal only receives formatted log records.
        if crate::logging::worker() {
            let _ = self.write_to(std::io::stdout().lock());
        }
    }
}

/// One aggregate record per image, including early failures. The write duration
/// contains the mux profile's USB/window/lock timings; those are nested costs.
pub(crate) struct TransferProfile {
    stage: String,
    started: Instant,
    pub bytes: u64,
    pub read: Option<Duration>,
    pub prepare: Duration,
    pub write: Duration,
    pub key_exchange: Duration,
    pub finished: bool,
}

impl TransferProfile {
    pub fn new(stage: impl Into<String>) -> Self {
        Self {
            stage: stage.into(),
            started: Instant::now(),
            bytes: 0,
            read: None,
            prepare: Duration::ZERO,
            write: Duration::ZERO,
            key_exchange: Duration::ZERO,
            finished: false,
        }
    }
}

impl Drop for TransferProfile {
    fn drop(&mut self) {
        let elapsed = self.started.elapsed();
        let measured =
            self.read.unwrap_or_default() + self.prepare + self.write + self.key_exchange;
        crate::log!(
            Debug,
            "transfer",
            "Профиль {}: bytes={}, finished={}, elapsed={:.3}s, read={:?}, prepare={:.3}s, write={:.3}s, key_exchange={:.3}s, other={:.3}s",
            self.stage,
            self.bytes,
            self.finished,
            elapsed.as_secs_f64(),
            self.read.map(|time| time.as_secs_f64()),
            self.prepare.as_secs_f64(),
            self.write.as_secs_f64(),
            self.key_exchange.as_secs_f64(),
            elapsed.saturating_sub(measured).as_secs_f64()
        );
    }
}

#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
pub struct Update {
    pub id: u64,
    pub operation: Option<u64>,
    #[serde(default)]
    pub async_context: Option<String>,
    pub stage: String,
    pub completed: u64,
    pub total: Option<u64>,
    pub bytes_per_second: f64,
    pub elapsed_seconds: f64,
    /// This stream ended; its job result determines success, including retries.
    pub finished: bool,
}

impl Update {
    fn valid(&self) -> bool {
        self.bytes_per_second.is_finite()
            && self.bytes_per_second >= 0.0
            && self.elapsed_seconds.is_finite()
            && self.elapsed_seconds >= 0.0
            && self.total.is_none_or(|total| self.completed <= total)
    }

    pub fn fraction(&self) -> Option<f32> {
        self.total.map(|total| {
            if total == 0 {
                1.0
            } else {
                self.completed as f32 / total as f32
            }
        })
    }
}

pub struct Progress {
    id: u64,
    operation: Option<u64>,
    async_context: Option<String>,
    stage: String,
    total: Option<u64>,
    completed: u64,
    initial_bytes: u64,
    started: Instant,
    sampled_at: Instant,
    sampled_bytes: u64,
    logged_at: Instant,
    finished: bool,
}

impl Progress {
    pub fn new(stage: impl Into<String>, total: Option<u64>, completed: u64) -> Self {
        let now = Instant::now();
        let progress = Self {
            id: NEXT_TRANSFER.fetch_add(1, Ordering::Relaxed),
            operation: current_operation(),
            async_context: current_async_context(),
            stage: stage.into(),
            total,
            completed,
            initial_bytes: completed,
            started: now,
            sampled_at: now,
            sampled_bytes: completed,
            logged_at: now,
            finished: false,
        };
        Event::Transfer(progress.update(now, false)).emit();
        crate::logging::emit(
            progress.level(),
            "transfer",
            format_args!(
                "{}: начало, {}{}",
                progress.stage,
                human_bytes(completed),
                total
                    .map(|n| format!(" из {}", human_bytes(n)))
                    .unwrap_or_default()
            ),
        );
        progress
    }

    pub fn advance(&mut self, bytes: u64) {
        self.completed = self.completed.saturating_add(bytes);
        let now = Instant::now();
        if now.duration_since(self.sampled_at) >= INTERVAL {
            let update = self.update(now, false);
            if now.duration_since(self.logged_at) >= Duration::from_secs(30) {
                crate::logging::emit(
                    self.level(),
                    "transfer",
                    format_args!("{}", update.summary()),
                );
                self.logged_at = now;
            }
            Event::Transfer(update).emit();
            self.sampled_at = now;
            self.sampled_bytes = self.completed;
        }
    }

    pub fn finish(&mut self) {
        self.finished = true;
        let update = self.update(Instant::now(), true);
        crate::logging::emit(
            self.level(),
            "transfer",
            format_args!("{}", update.summary()),
        );
        Event::Transfer(update).emit();
    }

    pub fn report(&self) {
        Event::Transfer(self.update(Instant::now(), false)).emit();
    }

    fn level(&self) -> crate::logging::Level {
        if self.total.unwrap_or(self.completed) >= 64 * 1024 * 1024 {
            crate::logging::Level::Info
        } else {
            crate::logging::Level::Debug
        }
    }

    fn update(&self, now: Instant, finished: bool) -> Update {
        let (elapsed, bytes) = if finished {
            (
                now.duration_since(self.started).as_secs_f64(),
                self.completed - self.initial_bytes,
            )
        } else {
            (
                now.duration_since(self.sampled_at).as_secs_f64(),
                self.completed - self.sampled_bytes,
            )
        };
        Update {
            id: self.id,
            operation: self.operation,
            async_context: self.async_context.clone(),
            stage: self.stage.clone(),
            completed: self.completed,
            total: self.total,
            bytes_per_second: if elapsed > 0.0 {
                bytes as f64 / elapsed
            } else {
                0.0
            },
            elapsed_seconds: now.duration_since(self.started).as_secs_f64(),
            finished,
        }
    }
}

impl Drop for Progress {
    fn drop(&mut self) {
        // Interrupted requests and partial HTTP ranges also end their stream.
        // A retry gets a new identity; do not leave the previous card behind.
        if !self.finished {
            Event::Transfer(self.update(Instant::now(), true)).emit();
        }
    }
}

impl Update {
    pub fn summary(&self) -> String {
        let size = human_bytes(self.completed);
        if self.finished {
            let speed = self.bytes_per_second / 1048576.0;
            format!(
                "{}: завершено, {size}, {:.1} с, {speed:.1} МиБ/с",
                self.stage, self.elapsed_seconds
            )
        } else {
            format!(
                "{}: {size}{}, {:.1} МиБ/с",
                self.stage,
                self.total
                    .map(|n| format!(" из {}", human_bytes(n)))
                    .unwrap_or_default(),
                self.bytes_per_second / 1048576.0
            )
        }
    }
}

pub fn human_bytes(bytes: u64) -> String {
    if bytes >= 1073741824 {
        format!("{:.2} ГиБ", bytes as f64 / 1073741824.0)
    } else if bytes >= 1048576 {
        format!("{:.1} МиБ", bytes as f64 / 1048576.0)
    } else if bytes >= 1024 {
        format!("{:.1} КиБ", bytes as f64 / 1024.0)
    } else {
        format!("{bytes} Б")
    }
}

#[cfg(test)]
#[path = "../tests/unit/progress.rs"]
mod tests;
