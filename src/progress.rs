//! Transfer identities, byte counters and operation progress shared with the GUI.
use std::{
    cell::RefCell,
    io,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

pub const MAC_STARTUP_HINT: &str = "Check that the Mac starts. If it shows the Activate Mac screen, connect the Mac to Wi-Fi or Ethernet and complete activation.";
const INTERVAL: Duration = Duration::from_millis(500);
static NEXT_TRANSFER: AtomicU64 = AtomicU64::new(1);
thread_local! {
    static CURRENT: RefCell<Option<Context>> = const { RefCell::new(None) };
}
type CancelAction = Box<dyn FnOnce() + Send>;

/// One native operation: typed events, complete diagnostics and cooperative stop.
#[derive(Clone)]
pub struct Context {
    output: Arc<dyn Fn(Event) + Send + Sync>,
    logs: Option<crate::logging::Queue>,
    cancelled: Arc<AtomicBool>,
    cancel_actions: Arc<Mutex<Vec<CancelAction>>>,
}

impl Context {
    pub fn new(output: impl Fn(Event) + Send + Sync + 'static) -> Self {
        Self {
            output: Arc::new(output),
            logs: None,
            cancelled: Arc::new(AtomicBool::new(false)),
            cancel_actions: Arc::default(),
        }
    }

    /// Keep progress immediate while formatting and writing diagnostics separately.
    pub fn with_async_logs(mut self, flush: impl Fn() + Send + 'static) -> io::Result<Self> {
        let output = self.output.clone();
        self.logs = Some(crate::logging::Queue::new(move |record| match record {
            Some(record) => output(Event::Log(record)),
            None => flush(),
        })?);
        Ok(self)
    }

    /// Called at completion and before taking a complete journal snapshot.
    pub fn flush_logs(&self) -> io::Result<()> {
        match &self.logs {
            Some(logs) => logs.flush(),
            None => Ok(()),
        }
    }

    fn log(&self, record: crate::logging::Record) {
        let record = match &self.logs {
            Some(logs) => match logs.record(record) {
                Ok(()) => return,
                Err(record) => record,
            },
            None => record,
        };
        (self.output)(Event::Log(record));
    }

    pub fn run<T>(&self, task: impl FnOnce() -> T) -> T {
        struct Reset(Option<Context>);
        impl Drop for Reset {
            fn drop(&mut self) {
                CURRENT.with(|slot| slot.replace(self.0.take()));
            }
        }
        let _reset = Reset(CURRENT.with(|slot| slot.replace(Some(self.clone()))));
        task()
    }

    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
        let actions = std::mem::take(
            &mut *self
                .cancel_actions
                .lock()
                .unwrap_or_else(|e| e.into_inner()),
        );
        for action in actions {
            action();
        }
    }
    pub fn cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Acquire)
    }
}

pub(crate) fn active() -> bool {
    CURRENT.with(|slot| slot.borrow().is_some())
}

pub(crate) fn log_queue() -> Option<crate::logging::Queue> {
    CURRENT.with(|slot| {
        slot.borrow()
            .as_ref()
            .and_then(|context| context.logs.clone())
    })
}

pub(crate) fn log(record: crate::logging::Record) -> Result<(), crate::logging::Record> {
    let context = CURRENT.with(|slot| slot.borrow().clone());
    match context {
        Some(context) => {
            context.log(record);
            Ok(())
        }
        None => Err(record),
    }
}

/// Carry the current operation into its FDR, USB and request threads.
pub(crate) fn inherit<T>(task: impl FnOnce() -> T) -> impl FnOnce() -> T {
    let context = CURRENT.with(|slot| slot.borrow().clone());
    move || match context {
        Some(context) => context.run(task),
        None => task(),
    }
}

pub fn check_cancelled() -> io::Result<()> {
    if CURRENT.with(|slot| slot.borrow().as_ref().is_some_and(Context::cancelled)) {
        Err(io::Error::other("Operation stopped"))
    } else {
        Ok(())
    }
}

pub(crate) fn on_cancel(action: impl FnOnce() + Send + 'static) {
    let context = CURRENT.with(|slot| slot.borrow().clone());
    if let Some(context) = context {
        let mut actions = context
            .cancel_actions
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if context.cancelled() {
            drop(actions);
            action();
        } else {
            actions.push(Box::new(action));
        }
    }
}
/// Worker state is independent of human-readable logs and their retained history.
#[derive(Clone, Debug, PartialEq)]
pub enum Event {
    Log(crate::logging::Record),
    Transfer(Update),
    RestoreCompleted,
    ProvisioningWarning {
        message: String,
    },
    RebootRequired,
    Checkpoint {
        name: String,
        complete: bool,
    },
    OperationWeights {
        weights: Vec<(u64, u64)>,
        /// Completed weight units from restored, not percentages.
        progresses: Vec<(u64, u64)>,
    },
    OperationProgress {
        operation: u64,
        progress: i64,
    },
}

impl Event {
    pub fn emit(self) {
        let context = CURRENT.with(|slot| slot.borrow().clone());
        if let Some(context) = context {
            if let Self::Log(record) = self {
                context.log(record);
            } else {
                (context.output)(self);
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Update {
    pub id: u64,
    pub stage: String,
    pub completed: u64,
    pub total: Option<u64>,
    pub bytes_per_second: f64,
    pub elapsed_seconds: f64,
    /// This stream ended; its job result determines success, including retries.
    pub finished: bool,
}

impl Update {
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
        let total = total.filter(|total| *total >= completed);
        let now = Instant::now();
        let progress = Self {
            id: NEXT_TRANSFER.fetch_add(1, Ordering::Relaxed),
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
                "{}: starting, {}{}",
                progress.stage,
                human_bytes(completed),
                total
                    .map(|n| format!(" of {}", human_bytes(n)))
                    .unwrap_or_default()
            ),
        );
        progress
    }

    pub(crate) fn completed(&self) -> u64 {
        self.completed
    }

    pub fn advance(&mut self, bytes: u64) {
        if self.finished {
            return;
        }
        self.completed = self.completed.saturating_add(bytes);
        self.total = self.total.filter(|total| *total >= self.completed);
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
        if self.finished {
            return;
        }
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
        if !self.finished {
            Event::Transfer(self.update(Instant::now(), false)).emit();
        }
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
                "{}: complete, {size}, {:.1} s, {speed:.1} MiB/s",
                self.stage, self.elapsed_seconds
            )
        } else {
            format!(
                "{}: {size}{}, {:.1} MiB/s",
                self.stage,
                self.total
                    .map(|n| format!(" of {}", human_bytes(n)))
                    .unwrap_or_default(),
                self.bytes_per_second / 1048576.0
            )
        }
    }
}

pub fn human_bytes(bytes: u64) -> String {
    if bytes >= 1073741824 {
        format!("{:.2} GiB", bytes as f64 / 1073741824.0)
    } else if bytes >= 1048576 {
        format!("{:.1} MiB", bytes as f64 / 1048576.0)
    } else if bytes >= 1024 {
        format!("{:.1} KiB", bytes as f64 / 1024.0)
    } else {
        format!("{bytes} B")
    }
}

#[cfg(test)]
#[path = "../tests/unit/progress.rs"]
mod tests;
