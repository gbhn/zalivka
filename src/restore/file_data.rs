//! Bounded plist batches, AEA key exchange and transfer accounting.
use super::RESTORED_PORT;
use crate::{
    asr,
    mux::{MuxStream, Session},
    net, wire,
};
use anyhow::{Context, Result, ensure};
use plist::Value;
use std::{
    io::Write,
    time::{Duration, Instant},
};

pub(super) const FILE_DATA_BATCH: usize = 256 * 1024;
const FILE_DATA_CHUNK: usize = 8192;

pub(super) enum ImagePrefix {
    Collecting(Vec<u8>),
    Plain,
    Aea,
    Public {
        fcs: Box<crate::aea::PublicFcs>,
        key: Option<[u8; 32]>,
    },
}

impl ImagePrefix {
    /// Return true once the prefix is classified and its buffer can be released.
    fn observe(&mut self, data: &[u8]) -> Result<bool> {
        let Self::Collecting(prefix) = self else {
            return Ok(false);
        };
        let remaining = crate::aea::MAX_PREFIX - prefix.len();
        prefix.extend_from_slice(&data[..data.len().min(remaining)]);
        if prefix.len() < 4 {
            return Ok(false);
        }
        *self = if !prefix.starts_with(b"AEA1") {
            Self::Plain
        } else {
            match crate::aea::PublicFcs::from_prefix(prefix)? {
                crate::aea::Prefix::Incomplete => return Ok(false),
                crate::aea::Prefix::Unsupported => Self::Aea,
                crate::aea::Prefix::Public(fcs) => Self::Public { fcs, key: None },
            }
        };
        Ok(true)
    }

    fn is_aea(&self) -> bool {
        match self {
            Self::Collecting(prefix) => prefix.starts_with(b"AEA1"),
            Self::Plain => false,
            Self::Aea | Self::Public { .. } => true,
        }
    }

    fn response(&mut self, request: &Value, assets: &net::AssetClient) -> Result<Value> {
        if let Self::Public { fcs, key } = self
            && net::wrapped_key_request(request)?
        {
            let archive_key = if let Some(key) = *key {
                key
            } else {
                match fcs.fetch_key() {
                    Ok(found) => {
                        *key = Some(found);
                        found
                    }
                    Err(error) => {
                        return assets.response(request).with_context(|| {
                            format!("public FCS failed ({error:#}); WKMS fallback failed")
                        });
                    }
                }
            };
            return Ok(wire::dict([
                ("KeyData", Value::Data(archive_key.to_vec())),
                ("KeySource", "LocalUnwrapped".into()),
            ]));
        }
        assets.response(request)
    }
}

pub(super) struct FileDataWriter<'a> {
    pub(super) progress: crate::progress::Progress,
    pub(super) profile: crate::progress::TransferProfile,
    pub(super) stream: &'a mut MuxStream,
    pub(super) session: &'a Session,
    pub(super) assets: &'a net::AssetClient,
    pub(super) file_data: Value,
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
            progress: crate::progress::Progress::new(format!("Передача {name}"), total, 0),
            profile: crate::progress::TransferProfile::new(name),
            stream,
            session,
            assets,
            file_data: wire::dict([("FileData", Value::Data(Vec::with_capacity(FILE_DATA_CHUNK)))]),
            pending: Vec::with_capacity(FILE_DATA_BATCH + FILE_DATA_CHUNK),
            pending_payload: 0,
            prefix: ImagePrefix::Collecting(Vec::new()),
            key_requests: 0,
            failed: false,
        }
    }
    fn write_chunk(&mut self, data: &[u8]) -> Result<usize> {
        let started = Instant::now();
        let first = self.profile.bytes == 0;
        let n = data.len().min(FILE_DATA_CHUNK);
        let header_ready = self.prefix.observe(&data[..n])?;
        // Reuse the dictionary and payload allocation, and serialize straight
        // into the batch instead of allocating and copying another whole frame.
        let Value::Data(payload) = &mut self.file_data.as_dictionary_mut().unwrap()["FileData"]
        else {
            unreachable!("FileData buffer is always plist data")
        };
        payload.clear();
        payload.extend_from_slice(&data[..n]);
        let encoded = wire::append_binary(&mut self.pending, &self.file_data);
        self.profile.prepare += started.elapsed();
        encoded?;
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
            self.exchange_keys()?;
        }
        Ok(n)
    }
    fn exchange_keys(&mut self) -> Result<()> {
        self.flush_pending(true)?;
        self.progress.report();
        let timeout = self.stream.read_timeout();
        self.stream.set_read_timeout(Duration::from_secs(3));
        let started = Instant::now();
        let result = key_exchange(
            self.stream,
            self.session,
            &mut self.key_requests,
            |request| self.prefix.response(request, self.assets),
        );
        self.profile.key_exchange += started.elapsed();
        self.stream.set_read_timeout(timeout);
        result
    }
    fn flush_pending(&mut self, complete: bool) -> Result<()> {
        let n = if complete {
            self.pending.len()
        } else {
            self.pending.len() / crate::mux::MAX_PAYLOAD * crate::mux::MAX_PAYLOAD
        };
        if n != 0 {
            let started = Instant::now();
            let sent = self.stream.write_all(&self.pending[..n]);
            self.profile.write += started.elapsed();
            // write_all may fail after partial success. Never replay that batch.
            if let Err(error) = sent {
                self.pending.clear();
                self.pending_payload = 0;
                return Err(error.into());
            }
            drop(self.pending.drain(..n));
            // Remaining wire bytes bound the unsent payload from above. This
            // keeps progress conservative without storing per-frame metadata;
            // a full flush reports the exact payload count, including the tail.
            let payload = self
                .pending_payload
                .saturating_sub(self.pending.len() as u64);
            self.pending_payload -= payload;
            self.profile.bytes += payload;
            self.progress.advance(payload);
        }
        Ok(())
    }
    pub(super) fn finish(mut self) -> Result<()> {
        ensure!(!self.failed, "file transfer already failed");
        self.flush_pending(true)?;
        let started = Instant::now();
        let sent = wire::send(self.stream, &wire::dict([("FileDataDone", true.into())]));
        self.profile.write += started.elapsed();
        sent?;
        self.progress.finish();
        self.profile.finished = true;
        Ok(())
    }
}

pub(super) fn key_exchange(
    stream: &mut MuxStream,
    session: &Session,
    key_requests: &mut usize,
    mut reply: impl FnMut(&Value) -> Result<Value>,
) -> Result<()> {
    while let Some(request) = wire::try_receive(stream)? {
        *key_requests += 1;
        ensure!(*key_requests <= 64, "too many AEA key requests");
        let kind = wire::string(&request, &["MsgType"])
            .or_else(|_| wire::string(&request, &["DataType"]))?;
        let data_type = if matches!(kind, "DataRequestMsg" | "AsyncDataRequestMsg") {
            wire::string(&request, &["DataType"])?
        } else {
            kind
        };
        ensure!(
            matches!(data_type, "URLAsset" | "StreamedImageDecryptionKey"),
            "unexpected AEA data type {data_type} in {kind}"
        );
        let port = asr::data_port(&request, 0).context("invalid AEA DataPort")?;
        if kind == "AsyncDataRequestMsg" {
            ensure!(
                port != 0 && port != RESTORED_PORT,
                "asynchronous AEA {data_type} requires a separate DataPort"
            );
        }
        eprintln!("AEA requests {data_type} via {kind}, DataPort={port}");
        let response = reply(&request)?;
        if port != 0 {
            let mut service = session.connect_retry(port, Duration::from_secs(60))?;
            wire::send_binary(&mut service, &response)?;
        } else {
            wire::send_binary(stream, &response)?;
        }
        if !stream.has_pending_input()? {
            break;
        }
    }
    Ok(())
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
