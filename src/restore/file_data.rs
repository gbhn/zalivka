//! Bounded FileData batches, payload accounting and failure handling.
use super::keys::{ImagePrefix, key_exchange};
use crate::{
    mux::{MuxStream, Session},
    net, wire,
};
use anyhow::{Result, ensure};
use std::io::Write;

pub(super) const FILE_DATA_BATCH: usize = 256 * 1024;
const FILE_DATA_CHUNK: usize = 8192;

#[derive(serde::Serialize)]
struct FileData<'a> {
    #[serde(rename = "FileData", serialize_with = "serialize_bytes")]
    bytes: &'a [u8],
}

fn serialize_bytes<S: serde::Serializer>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
    serializer.serialize_bytes(bytes)
}

pub(super) struct FileDataWriter<'a> {
    pub(super) progress: crate::progress::Progress,
    pub(super) stream: &'a mut MuxStream,
    pub(super) session: &'a Session,
    pub(super) assets: &'a net::AssetClient,
    pub(super) pending: Vec<u8>,
    pub(super) pending_payload: u64,
    pub(super) prefix: ImagePrefix,
    pub(super) key_requests: usize,
    failed: bool,
}
impl<'a> FileDataWriter<'a> {
    pub(super) fn new(
        stream: &'a mut MuxStream,
        session: &'a Session,
        assets: &'a net::AssetClient,
        name: &str,
        total: Option<u64>,
    ) -> Self {
        Self {
            progress: crate::progress::Progress::new(format!("Transferring {name}"), total, 0),
            stream,
            session,
            assets,
            pending: Vec::with_capacity(FILE_DATA_BATCH + FILE_DATA_CHUNK),
            pending_payload: 0,
            prefix: ImagePrefix::Collecting(Vec::new()),
            key_requests: 0,
            failed: false,
        }
    }
    fn write_chunk(&mut self, data: &[u8]) -> Result<usize> {
        let first = self.progress.completed() == 0;
        let n = data.len().min(FILE_DATA_CHUNK);
        let header_ready = self.prefix.observe(&data[..n])?;
        // Serialize the borrowed payload straight into the batch. No mutable
        // plist shape or intermediate payload allocation needs to be maintained.
        wire::append_binary(&mut self.pending, &FileData { bytes: &data[..n] })?;
        self.pending_payload += n as u64;
        // Preserve 8-KiB plist frames, but amortize synchronous USB writes.
        // Deliver the prefix immediately so a device waiting for an AEA key
        // can make its request before the next batch has accumulated.
        if first || matches!(self.prefix, ImagePrefix::Collecting(_)) || header_ready {
            self.flush_pending(true)?;
        } else if self.pending.len() >= FILE_DATA_BATCH {
            // Retain less than one mux packet for the next batch. Plist frames
            // may span mux packets; prefix/key exchanges still flush in full.
            self.flush_pending(false)?;
        }
        if self.prefix.is_aea() && (first || header_ready || self.stream.has_pending_input()?) {
            self.flush_pending(true)?;
            self.exchange_keys()?;
        }
        Ok(n)
    }
    fn exchange_keys(&mut self) -> Result<()> {
        self.progress.report();
        key_exchange(
            self.stream,
            self.session,
            &mut self.key_requests,
            |_| Ok(()),
            |request| self.prefix.response(request, self.assets),
        )
    }
    fn flush_pending(&mut self, complete: bool) -> Result<()> {
        let mut n = if complete {
            self.pending.len()
        } else {
            self.pending.len() / crate::mux::MAX_PAYLOAD * crate::mux::MAX_PAYLOAD
        };
        if n != 0 {
            let _trace = crate::logging::firmware_transfer();

            let sent = (|| -> Result<()> {
                if !self.prefix.is_aea() {
                    self.stream.write_all(&self.pending[..n])?;
                    return Ok(());
                }
                let mut written = 0;
                while written < n {
                    match self.stream.write_until_input(&self.pending[written..n])? {
                        Some(sent) => written += sent,
                        None => {
                            self.progress.report();
                            key_exchange(
                                self.stream,
                                self.session,
                                &mut self.key_requests,
                                |stream| {
                                    // An inline reply follows complete plist
                                    // frames. A separate DataPort needs no flush
                                    // and can reopen a blocked image window.
                                    let end = self.pending.len();
                                    stream.write_all(&self.pending[written..end])?;
                                    written = end;
                                    n = end;
                                    Ok(())
                                },
                                |request| self.prefix.response(request, self.assets),
                            )?;
                        }
                    }
                }
                Ok(())
            })();

            // write_all may fail after partial success. Never replay that batch.
            if let Err(error) = sent {
                self.pending.clear();
                self.pending_payload = 0;
                return Err(error);
            }
            drop(self.pending.drain(..n));
            // Remaining wire bytes bound the unsent payload from above. This
            // keeps progress conservative without storing per-frame metadata;
            // a full flush reports the exact payload count, including the tail.
            let payload = self
                .pending_payload
                .saturating_sub(self.pending.len() as u64);
            self.pending_payload -= payload;
            self.progress.advance(payload);
        }
        Ok(())
    }
    pub(super) fn finish(mut self) -> Result<()> {
        ensure!(!self.failed, "file transfer already failed");
        self.flush_pending(true)?;

        if self.prefix.is_aea() {
            if self.stream.has_pending_input()? {
                self.exchange_keys()?;
            }
            wire::send(
                &mut self.pending,
                &wire::dict([("FileDataDone", true.into())]),
            )?;
            self.flush_pending(true)?;
        } else {
            wire::send(self.stream, &wire::dict([("FileDataDone", true.into())]))?;
        }
        self.progress.finish();
        Ok(())
    }
}

impl Write for FileDataWriter<'_> {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        if self.failed {
            return Err(std::io::Error::other("file transfer already failed"));
        }
        if data.is_empty() {
            return Ok(0);
        }
        let result = self.write_chunk(data);
        self.failed = result.is_err();
        result.map_err(std::io::Error::other)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        if self.failed {
            return Err(std::io::Error::other("file transfer already failed"));
        }
        let result = self
            .flush_pending(true)
            .and_then(|()| Ok(self.stream.flush()?));
        self.failed = result.is_err();
        result.map_err(std::io::Error::other)
    }
}
pub(super) fn send_file_data(
    out: &mut MuxStream,
    session: &Session,
    assets: &net::AssetClient,
    name: &str,
    input: &[u8],
) -> Result<()> {
    let mut writer = FileDataWriter::new(out, session, assets, name, Some(input.len() as u64));
    writer.write_all(input)?;
    writer.finish()
}

#[cfg(test)]
#[path = "../../tests/unit/restore/file_data.rs"]
mod tests;
