//! Byte counters shared by CLI workers and the desktop interface.
use serde::{Deserialize, Serialize};
use std::time::{Duration, Instant};

pub const PREFIX: &str = "ZALIVKA_PROGRESS ";
const INTERVAL: Duration = Duration::from_millis(500);

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
        eprintln!(
            "ZALIVKA_TRANSFER_PROFILE {}",
            serde_json::json!({
                "stage": self.stage, "payload_bytes": self.bytes, "finished": self.finished,
                "elapsed_seconds": elapsed.as_secs_f64(),
                "read_seconds": self.read.map(|time| time.as_secs_f64()),
                "prepare_seconds": self.prepare.as_secs_f64(),
                "write_seconds": self.write.as_secs_f64(),
                "key_exchange_seconds": self.key_exchange.as_secs_f64(),
                "other_seconds": elapsed.saturating_sub(measured).as_secs_f64(),
            })
        );
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Update {
    pub stage: String,
    pub completed: u64,
    pub total: Option<u64>,
    pub bytes_per_second: f64,
    pub elapsed_seconds: f64,
    pub finished: bool,
}

impl Update {
    pub fn parse(line: &str) -> Option<Self> {
        let update: Self = serde_json::from_str(line.strip_prefix(PREFIX)?).ok()?;
        (update.bytes_per_second.is_finite()
            && update.bytes_per_second >= 0.0
            && update.elapsed_seconds.is_finite()
            && update.elapsed_seconds >= 0.0
            && update.total.is_none_or(|total| update.completed <= total))
        .then_some(update)
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
    stage: String,
    total: Option<u64>,
    completed: u64,
    started: Instant,
    sampled_at: Instant,
    sampled_bytes: u64,
}

impl Progress {
    pub fn new(stage: impl Into<String>, total: Option<u64>, completed: u64) -> Self {
        let now = Instant::now();
        let progress = Self {
            stage: stage.into(),
            total,
            completed,
            started: now,
            sampled_at: now,
            sampled_bytes: completed,
        };
        progress.emit(&progress.update(now, false));
        progress
    }

    pub fn advance(&mut self, bytes: u64) {
        self.completed = self.completed.saturating_add(bytes);
        let now = Instant::now();
        if now.duration_since(self.sampled_at) >= INTERVAL {
            self.emit(&self.update(now, false));
            self.sampled_at = now;
            self.sampled_bytes = self.completed;
        }
    }

    pub fn finish(&mut self) {
        self.emit(&self.update(Instant::now(), true));
    }

    pub fn report(&self) {
        self.emit(&self.update(Instant::now(), false));
    }

    fn update(&self, now: Instant, finished: bool) -> Update {
        let elapsed = now.duration_since(self.sampled_at).as_secs_f64();
        Update {
            stage: self.stage.clone(),
            completed: self.completed,
            total: self.total,
            bytes_per_second: if elapsed > 0.0 {
                (self.completed - self.sampled_bytes) as f64 / elapsed
            } else {
                0.0
            },
            elapsed_seconds: now.duration_since(self.started).as_secs_f64(),
            finished,
        }
    }

    fn emit(&self, update: &Update) {
        if let Ok(json) = serde_json::to_string(update) {
            eprintln!("{PREFIX}{json}");
        }
    }
}

#[cfg(test)]
#[path = "../tests/unit/progress.rs"]
mod tests;
