//! Buffered disk journal and bounded GUI history for one operation.
use super::{Level, Record};
use anyhow::{Context, Result};
use std::{
    collections::VecDeque,
    fs::File,
    io::{BufWriter, Read, Write},
    path::{Path, PathBuf},
    sync::Mutex,
};

pub(super) struct Journal {
    pub(super) log: BufWriter<File>,
    started_ms: u64,
    error: Option<String>,
    pending: VecDeque<Record>,
}

impl Journal {
    pub(super) fn new(log: File) -> Self {
        Self {
            log: BufWriter::with_capacity(256 * 1024, log),
            started_ms: zalivka::logging::elapsed_ms(),
            error: None,
            pending: VecDeque::new(),
        }
    }

    /// Return whether new records need to wake a sleeping GUI.
    pub(super) fn record(&mut self, mut record: Record) -> bool {
        record.elapsed_ms = record.elapsed_ms.saturating_sub(self.started_ms);
        record.normalize();
        if self.error.is_none()
            && let Err(error) = record.write_to(&mut self.log)
        {
            self.error = Some(error.to_string());
            record
                .message
                .push_str(&format!(" / Disk journal incomplete: {error}"));
            record.level = record.level.max(Level::Warning);
        }
        let wake = self.pending.is_empty();
        self.pending.push_back(record);
        super::trim_logs(&mut self.pending);
        wake
    }

    /// Record the first flush failure once, retaining all later records in memory.
    pub(super) fn flush(&mut self) -> bool {
        if self.error.is_none()
            && let Err(error) = self.log.flush()
        {
            self.error = Some(error.to_string());
            self.record(Record::new(
                Level::Warning,
                "journal",
                format!("Disk journal incomplete: {error}"),
            ));
            return true;
        }
        false
    }

    pub(super) fn error(&self) -> Option<&String> {
        self.error.as_ref()
    }

    pub(super) fn drain(&mut self) -> (Vec<Record>, Option<String>) {
        (self.pending.drain(..).collect(), self.error.clone())
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
                if let Some(error) = journal.error() {
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
    fn write_and_flush_failures_report_once_and_keep_later_memory_records() {
        for capacity in [1, 256 * 1024] {
            let file = tempfile::NamedTempFile::new().unwrap();
            let mut journal = Journal::new(File::open(file.path()).unwrap());
            journal.log = BufWriter::with_capacity(capacity, File::open(file.path()).unwrap());
            journal.record(Record::new(Level::Debug, "test", "original record"));
            journal.flush();
            assert!(journal.error().is_some());
            for _ in 0..2 {
                journal.record(Record::new(Level::Error, "test", "later error"));
                assert!(!journal.flush());
            }
            let (records, error) = journal.drain();
            assert!(error.is_some());
            assert_eq!(
                records
                    .iter()
                    .filter(|record| record.message.contains("Disk journal incomplete"))
                    .count(),
                1
            );
            assert_eq!(records.iter().filter(|record| record.level == Level::Error && record.message == "later error").count(), 2);
            assert!(records[0].message.starts_with("original record"));
            assert!(std::fs::read(file.path()).unwrap().is_empty());
            assert!(journal.drain().0.is_empty());
            assert!(journal.error().is_some());
        }
    }

    #[test]
    fn trace_history_is_bounded_while_the_disk_journal_remains_complete() {
        let file = tempfile::NamedTempFile::new().unwrap();
        let mut journal = Journal::new(file.reopen().unwrap());
        journal.record(Record::new(Level::Info, "restore", "Starting stage"));
        for index in 0..8000 {
            journal.record(Record::new(Level::Trace, "fdr:conn", index));
        }
        assert!(!journal.flush());
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
