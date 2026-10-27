//! One record format for terminal output, GUI workers and saved journals.
use serde::{Deserialize, Serialize};
use std::{
    fmt::{self, Write as _},
    io::{self, Write},
    sync::{
        OnceLock,
        atomic::{AtomicBool, Ordering},
    },
    time::Instant,
};

static STARTED: OnceLock<Instant> = OnceLock::new();
static VERBOSE: AtomicBool = AtomicBool::new(false);
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

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Level {
    Debug,
    Info,
    Warning,
    Error,
}

impl Level {
    pub fn label(self) -> &'static str {
        match self {
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
            elapsed_ms: STARTED.get_or_init(Instant::now).elapsed().as_millis() as u64,
            level,
            source: source.into(),
            message: message.to_string(),
        };
        record.normalize();
        record
    }

    pub fn normalize(&mut self) {
        // External diagnostics must stay on one row and cannot inject terminal controls.
        fn clean(text: &str) -> String {
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
            result.trim().to_owned()
        }
        self.source = clean(&self.source);
        self.message = clean(&self.message);
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

pub fn init(verbose: bool) {
    STARTED.get_or_init(Instant::now);
    VERBOSE.store(verbose, Ordering::Relaxed);
}

pub fn worker() -> bool {
    std::env::var_os(crate::progress::WORKER_EVENTS_ENV).is_some()
}

pub fn emit(level: Level, source: &str, message: fmt::Arguments<'_>) {
    publish(Record::new(level, source, message));
}

pub fn publish(record: Record) {
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
    if record.level == Level::Debug && !worker() && !VERBOSE.load(Ordering::Relaxed) {
        return;
    }
    if worker() {
        crate::progress::Event::Log(record).emit();
    } else {
        let _ = record.write_to(io::stderr().lock());
    }
}

#[macro_export]
macro_rules! log {
    ($level:ident, $source:literal, $($args:tt)*) => {
        $crate::logging::emit($crate::logging::Level::$level, $source, format_args!($($args)*))
    };
}

#[cfg(test)]
#[path = "../tests/unit/logging.rs"]
mod tests;
