//! One record format for terminal output, GUI workers and saved journals.
use serde::{Deserialize, Serialize};
use std::{
    cell::Cell,
    fmt::{self, Write as _},
    io::{self, Write},
    marker::PhantomData,
    rc::Rc,
    sync::{
        OnceLock,
        atomic::{AtomicU8, Ordering},
        mpsc,
    },
    time::{Duration, Instant},
};

static STARTED: OnceLock<Instant> = OnceLock::new();
static MIN_LEVEL: AtomicU8 = AtomicU8::new(Level::Info as u8);
static BACKGROUND: OnceLock<Queue> = OnceLock::new();
thread_local! {
    static FIRMWARE_TRANSFER: Cell<bool> = const { Cell::new(false) };
}
#[cfg(windows)]
static ELEVATED: OnceLock<std::sync::Mutex<std::fs::File>> = OnceLock::new();

/// Only a local named pipe can receive elevated logs, never an arbitrary file.
#[cfg(windows)]
pub fn connect_elevated(id: uuid::Uuid) -> io::Result<()> {
    use std::os::windows::fs::OpenOptionsExt;
    use windows_sys::Win32::Storage::FileSystem::SECURITY_IDENTIFICATION;
    let pipe = std::fs::OpenOptions::new()
        .write(true)
        // The unprivileged log reader must not impersonate the elevated writer.
        .security_qos_flags(SECURITY_IDENTIFICATION)
        .open(format!(r"\\.\pipe\zalivka-elevated-{id}"))?;
    ELEVATED
        .set(std::sync::Mutex::new(pipe))
        .map_err(|_| io::Error::other("elevated logging is already connected"))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
#[repr(u8)]
pub enum Level {
    Trace,
    Debug,
    Info,
    Warning,
    Error,
}

impl Level {
    pub fn label(self) -> &'static str {
        match self {
            Self::Trace => "TRACE",
            Self::Debug => "DEBUG",
            Self::Info => "INFO",
            Self::Warning => "WARN",
            Self::Error => "ERROR",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
pub struct Record {
    pub elapsed_ms: u64,
    pub level: Level,
    pub source: String,
    pub message: String,
}

impl Record {
    pub fn new(level: Level, source: impl Into<String>, message: impl fmt::Display) -> Self {
        let mut record = Self {
            elapsed_ms: elapsed_ms(),
            level,
            source: source.into(),
            message: message.to_string(),
        };
        record.normalize();
        record
    }

    pub fn normalize(&mut self) {
        // External diagnostics must stay on one row and cannot inject terminal controls.
        fn clean(text: &mut String) {
            if text.trim().len() == text.len()
                && !text.chars().any(|ch| ch.is_control() || ch == '\u{00b7}')
            {
                return;
            }
            let mut result = String::new();
            for ch in text.chars() {
                match ch {
                    '\n' => result.push_str(" / "),
                    '\r' | '\t' => result.push(' '),
                    '\u{00b7}' => result.push(','),
                    ch if ch.is_control() => {
                        let _ = write!(result, "\\u{{{:x}}}", ch as u32);
                    }
                    ch => result.push(ch),
                }
            }
            *text = result.trim().to_owned();
        }
        clean(&mut self.source);
        clean(&mut self.message);
    }

    pub fn write_to(&self, mut output: impl Write) -> io::Result<()> {
        writeln!(output, "{self}")
    }
}

impl fmt::Display for Record {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let seconds = self.elapsed_ms / 1000;
        write!(
            f,
            "{:02}:{:02}:{:02}.{:03} {:5} {:12} {}",
            seconds / 3600,
            seconds / 60 % 60,
            seconds % 60,
            self.elapsed_ms % 1000,
            self.level.label(),
            self.source,
            self.message
        )
    }
}

pub fn init(level: Level) {
    STARTED.get_or_init(Instant::now);
    MIN_LEVEL.store(level as u8, Ordering::Relaxed);
}

/// Monotonic timestamp captured by producers, before asynchronous formatting.
pub fn elapsed_ms() -> u64 {
    STARTED.get_or_init(Instant::now).elapsed().as_millis() as u64
}

enum Pending {
    Record(Record),
    Bytes {
        elapsed_ms: u64,
        source: String,
        context: String,
        data: Vec<u8>,
    },
    Plist {
        elapsed_ms: u64,
        source: &'static str,
        context: &'static str,
        value: plist::Value,
    },
    Flush(mpsc::Sender<()>),
}

/// Producers copy raw bytes once; only this consumer expands them into hex rows.
/// The queue never waits for disk/terminal I/O and does not discard diagnostics.
#[derive(Clone)]
pub(crate) struct Queue(mpsc::Sender<Pending>);

impl Queue {
    // None requests a buffered sink flush, including while the producer is idle.
    pub(crate) fn new(mut output: impl FnMut(Option<Record>) + Send + 'static) -> io::Result<Self> {
        let (tx, rx) = mpsc::channel();
        std::thread::Builder::new()
            .name("zalivka-journal".into())
            .spawn(move || {
                let mut dirty = false;
                let mut flushed = Instant::now();
                loop {
                    match rx.recv_timeout(Duration::from_millis(200)) {
                        Ok(Pending::Record(record)) => {
                            output(Some(record));
                            dirty = true;
                        }
                        Ok(Pending::Bytes {
                            elapsed_ms,
                            source,
                            context,
                            data,
                        }) => {
                            byte_records(elapsed_ms, &source, &context, &data, |record| {
                                output(Some(record));
                            });
                            dirty = true;
                        }
                        Ok(Pending::Plist {
                            elapsed_ms,
                            source,
                            context,
                            value,
                        }) => {
                            let mut record = Record::new(
                                Level::Trace,
                                source,
                                format_args!("{context}: {value:?}"),
                            );
                            record.elapsed_ms = elapsed_ms;
                            output(Some(record));
                            dirty = true;
                        }
                        Ok(Pending::Flush(done)) => {
                            output(None);
                            dirty = false;
                            flushed = Instant::now();
                            let _ = done.send(());
                        }
                        Err(mpsc::RecvTimeoutError::Disconnected) => {
                            output(None);
                            return;
                        }
                        Err(mpsc::RecvTimeoutError::Timeout) => {}
                    }
                    if dirty && flushed.elapsed() >= Duration::from_millis(200) {
                        output(None);
                        dirty = false;
                        flushed = Instant::now();
                    }
                }
            })?;
        Ok(Self(tx))
    }

    pub(crate) fn record(&self, record: Record) -> Result<(), Record> {
        self.0.send(Pending::Record(record)).map_err(|error| {
            let Pending::Record(record) = error.0 else {
                unreachable!()
            };
            record
        })
    }

    pub(crate) fn flush(&self) -> io::Result<()> {
        let (tx, rx) = mpsc::channel();
        self.0
            .send(Pending::Flush(tx))
            .map_err(|_| io::Error::other("journal thread stopped"))?;
        rx.recv()
            .map_err(|_| io::Error::other("journal thread stopped"))
    }
}

pub struct FlushGuard;

impl Drop for FlushGuard {
    fn drop(&mut self) {
        if let Some(queue) = BACKGROUND.get() {
            let _ = queue.flush();
        }
    }
}

/// Buffer CLI diagnostics off the transport threads and drain them before exit.
pub fn background() -> io::Result<FlushGuard> {
    if BACKGROUND.get().is_none() {
        let mut stderr = io::BufWriter::with_capacity(256 * 1024, io::stderr());
        let queue = Queue::new(move |record| match record {
            Some(record) => write_default(record, &mut stderr),
            None => {
                let _ = stderr.flush();
            }
        })?;
        let _ = BACKGROUND.set(queue);
    }
    Ok(FlushGuard)
}

fn queue() -> Option<Queue> {
    if crate::progress::active() {
        crate::progress::log_queue()
    } else {
        BACKGROUND.get().cloned()
    }
}

pub fn enabled(level: Level) -> bool {
    if level == Level::Trace && firmware_transfer_active() {
        return false;
    }
    level as u8 >= MIN_LEVEL.load(Ordering::Relaxed) || crate::progress::active()
}

pub(crate) fn firmware_transfer_active() -> bool {
    FIRMWARE_TRANSFER.with(Cell::get)
}

/// Suppress per-packet traces and payload formatting on this transfer thread.
/// FDR and other concurrent services keep their own complete diagnostics.
pub(crate) fn firmware_transfer() -> FirmwareTransfer {
    FirmwareTransfer {
        previous: FIRMWARE_TRANSFER.with(|active| active.replace(true)),
        thread: PhantomData,
    }
}

pub(crate) struct FirmwareTransfer {
    previous: bool,
    thread: PhantomData<Rc<()>>,
}

impl Drop for FirmwareTransfer {
    fn drop(&mut self) {
        FIRMWARE_TRANSFER.with(|active| active.set(self.previous));
    }
}

pub fn emit(level: Level, source: &str, message: fmt::Arguments<'_>) {
    if enabled(level) {
        publish(Record::new(level, source, message));
    }
}

/// Complete hex dumps in bounded records, including partial reads and binary data.
/// Check before allocating: ordinary restores must not pay for byte formatting.
pub fn bytes(source: &str, context: fmt::Arguments<'_>, bytes: &[u8]) {
    if !enabled(Level::Trace) {
        return;
    }
    let elapsed_ms = elapsed_ms();
    let context = context.to_string();
    if let Some(queue) = queue()
        && queue
            .0
            .send(Pending::Bytes {
                elapsed_ms,
                source: source.to_owned(),
                context: context.clone(),
                data: bytes.to_vec(),
            })
            .is_ok()
    {
        return;
    }
    byte_records(elapsed_ms, source, &context, bytes, publish);
}

fn byte_records(
    elapsed_ms: u64,
    source: &str,
    context: &str,
    bytes: &[u8],
    mut output: impl FnMut(Record),
) {
    for (index, chunk) in bytes.chunks(64).enumerate() {
        let mut record = Record::new(
            Level::Trace,
            source,
            format_args!(
                "{context} +{:08x} [{} B]: {}",
                index * 64,
                chunk.len(),
                hex::encode(chunk)
            ),
        );
        record.elapsed_ms = elapsed_ms;
        output(record);
    }
}

pub(crate) fn plist(source: &'static str, context: &'static str, value: &plist::Value) {
    if !enabled(Level::Trace) {
        return;
    }
    if let Some(queue) = queue()
        && queue
            .0
            .send(Pending::Plist {
                elapsed_ms: elapsed_ms(),
                source,
                context,
                value: value.clone(),
            })
            .is_ok()
    {
        return;
    }
    emit(Level::Trace, source, format_args!("{context}: {value:?}"));
}

pub fn publish(record: Record) {
    if !enabled(record.level) {
        return;
    }
    let record = match crate::progress::log(record) {
        Ok(()) => return,
        Err(record) => record,
    };
    let record = match BACKGROUND.get() {
        Some(queue) => match queue.record(record) {
            Ok(()) => return,
            Err(record) => record,
        },
        None => record,
    };
    write_default(record, io::stderr().lock());
}

fn write_default(record: Record, mut stderr: impl Write) {
    #[cfg(windows)]
    if let Some(pipe) = ELEVATED.get() {
        let mut pipe = pipe.lock().unwrap_or_else(|error| error.into_inner());
        if crate::progress::Event::Log(record.clone())
            .write_to(&mut *pipe)
            .is_ok()
        {
            return;
        }
    }
    let _ = record.write_to(&mut stderr);
}

#[macro_export]
macro_rules! log {
    ($level:ident, $source:literal, $($args:tt)*) => {
        if $crate::logging::enabled($crate::logging::Level::$level) {
            $crate::logging::emit($crate::logging::Level::$level, $source, format_args!($($args)*))
        }
    };
}

#[cfg(test)]
#[path = "../tests/unit/logging.rs"]
mod tests;
