//! Per-service reads, bounded writes, ACK waiting and transfer accounting.
use super::{ACK, MAX_PAYLOAD, RST, Session, WRITE_BATCH, yield_link};
use anyhow::Result;
use std::{
    io::{Read, Write},
    sync::atomic::Ordering,
    time::{Duration, Instant},
};

#[derive(Default)]
struct WriteProfile {
    bytes: u64,
    calls: u64,
    errors: u64,
    elapsed: Duration,

    usb_out: Duration,

    window_stalls: u64,

    event_waits: u64,
    event_wakeups: u64,
}

impl WriteProfile {
    fn record(&mut self, started: Instant, failed: bool) {
        self.elapsed += started.elapsed();
        self.calls += 1;
        self.errors += u64::from(failed);
    }
}

pub struct MuxStream {
    session: Session,
    source: u16,
    destination: u16,
    read_timeout: Duration,
    log_source: &'static str,
    received: u64,
    profile: WriteProfile,
}
impl MuxStream {
    pub(super) fn new(session: Session, source: u16, destination: u16) -> Self {
        Self {
            session,
            source,
            destination,
            read_timeout: Duration::from_secs(300),
            log_source: "usbmux:io",
            received: 0,
            profile: WriteProfile::default(),
        }
    }

    pub fn has_pending_input(&self) -> Result<bool> {
        let link = self.session.lock()?;
        Ok(link
            .channels
            .get(&self.source)
            .is_some_and(|c| !c.input.is_empty()))
    }
    pub fn set_read_timeout(&mut self, timeout: Duration) {
        crate::log!(
            Trace,
            "usbmux:io",
            "{} -> {}: read timeout={timeout:?}",
            self.source,
            self.destination
        );
        self.read_timeout = timeout;
    }
    pub(crate) fn set_log_source(&mut self, source: &'static str) {
        self.log_source = source;
    }
    pub(crate) fn local_port(&self) -> u16 {
        self.source
    }
    pub fn read_timeout(&self) -> Duration {
        self.read_timeout
    }

    // A write() remains one packet so its error cannot discard a partial
    // success. write_all() may send a bounded batch under one lock: its API
    // already reports an error after a partially written buffer.
    fn write_packets(
        &mut self,
        data: &[u8],
        limit: usize,
        stop_on_input: bool,
    ) -> std::io::Result<Option<usize>> {
        if data.is_empty() {
            return Ok(Some(0));
        }
        let deadline = Instant::now() + Duration::from_secs(300);
        let mut pending_polls = 0;
        loop {
            let mut link = self.session.lock()?;
            if link.cancelled.load(Ordering::Acquire) {
                return Err(std::io::Error::other("USB mux session cancelled"));
            }
            let c = link
                .channels
                .get_mut(&self.source)
                .ok_or_else(|| std::io::Error::other("mux channel closed"))?;
            c.firmware_transfer = crate::logging::firmware_transfer_active();
            if c.closed {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "device closed service",
                ));
            }
            let outstanding = c.seq.wrapping_sub(c.peer_ack);
            let available = c.window.saturating_sub(outstanding) as usize;
            if stop_on_input && available == 0 && !c.input.is_empty() {
                return Ok(None);
            }
            if available == 0 && pending_polls == 0 {
                crate::log!(
                    Trace,
                    "usbmux:tcp",
                    "{} -> {}: waiting for window; seq={}, ack={}, window={}",
                    self.source,
                    self.destination,
                    c.seq,
                    c.peer_ack,
                    c.window
                );
            }
            // The available window may be based on an old ACK while newer ACKs
            // are already queued. Drain ready input before sizing a USB burst,
            // so a stale window does not reduce it to one synchronous packet.
            // Never wait for more space when some is available: small windows
            // and peers delaying their next ACK must still make progress.
            if available != 0
                && available < data.len().min(limit)
                && outstanding != 0
                && pending_polls < 64
            {
                pending_polls += 1;
                let pumped = link.pump();
                if pumped.map_err(std::io::Error::other)? {
                    drop(link);
                    std::thread::yield_now();
                    continue;
                }
            }
            if available != 0 {
                let n = data.len().min(available).min(limit);
                // Keep intermediate batches on packet boundaries. A short tail
                // here would create another USB transfer at every window edge.
                // Small windows and the caller's final tail still go out now.
                let n = if n < data.len() && n >= MAX_PAYLOAD {
                    n / MAX_PAYLOAD * MAX_PAYLOAD
                } else {
                    n
                };
                let usb_before = link.usb_write_time;
                crate::logging::bytes(
                    self.log_source,
                    format_args!(
                        "{} -> {} TX offset={}",
                        self.source, self.destination, self.profile.bytes
                    ),
                    &data[..n],
                );
                let sent = link.send_data(self.source, &data[..n]);
                let usb = link.usb_write_time - usb_before;
                self.profile.usb_out += usb;
                if let Err(error) = sent {
                    crate::log!(
                        Trace,
                        "usbmux:io",
                        "{} -> {}: write failed: {error:#}",
                        self.source,
                        self.destination
                    );
                    return Err(std::io::Error::other(error));
                }
                self.profile.bytes += n as u64;
                return Ok(Some(n));
            }
            if Instant::now() >= deadline {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "mux send window timeout",
                ));
            }
            self.profile.window_stalls += 1;
            let pumped = link.pump();
            let progressed = pumped.map_err(std::io::Error::other)?;
            let ready = if progressed {
                None
            } else {
                link.usb.input_ready()
            };
            drop(link);
            let waited = if let Some(ready) = ready {
                self.profile.event_waits += 1;
                let waited = ready.wait(Duration::from_millis(1));
                if let Ok(true) = waited {
                    self.profile.event_wakeups += 1;
                }
                // Other channels still get a chance to acquire the link. Idle
                // readers retain their existing backoff against starvation.
                std::thread::yield_now();
                waited.map(|_| ()).map_err(std::io::Error::other)
            } else {
                yield_link(progressed);
                Ok(())
            };

            waited?;
        }
    }

    /// Yield a blocked file write to its incoming key request. Some(n) counts
    /// bytes committed once; None means input is ready and no bytes were sent.
    pub(crate) fn write_until_input(&mut self, data: &[u8]) -> std::io::Result<Option<usize>> {
        let started = Instant::now();
        let result = self.write_packets(data, WRITE_BATCH, true);
        self.profile.record(started, result.is_err());
        result
    }
}
impl Read for MuxStream {
    fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
        if out.is_empty() {
            return Ok(0);
        }
        let deadline = Instant::now() + self.read_timeout;
        loop {
            let mut link = self.session.lock()?;
            if link.cancelled.load(Ordering::Acquire) {
                return Err(std::io::Error::other("USB mux session cancelled"));
            }
            let c = link
                .channels
                .get_mut(&self.source)
                .ok_or_else(|| std::io::Error::other("mux channel closed"))?;
            c.firmware_transfer = crate::logging::firmware_transfer_active();
            if !c.input.is_empty() {
                let n = c.input.read(out)?;
                crate::logging::bytes(
                    self.log_source,
                    format_args!(
                        "{} -> {} RX offset={}",
                        self.destination, self.source, self.received
                    ),
                    &out[..n],
                );
                self.received += n as u64;
                c.consumed += n;
                if c.consumed >= 16384 {
                    c.consumed = 0;
                    // The bytes are already in the caller's buffer. Report
                    // that success; a failed ACK cancels the next operation.
                    let _ = link.send_tcp(self.source, ACK, &[]);
                }
                return Ok(n);
            }
            if c.closed {
                crate::log!(
                    Trace,
                    "usbmux:io",
                    "{} -> {}: EOF",
                    self.destination,
                    self.source
                );
                return Ok(0);
            }
            if Instant::now() >= deadline {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "mux read timeout",
                ));
            }
            let progressed = link.pump().map_err(std::io::Error::other)?;
            drop(link);
            yield_link(progressed);
        }
    }
}
impl Write for MuxStream {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        let started = Instant::now();
        let sent = self
            .write_packets(data, MAX_PAYLOAD, false)
            .map(|sent| sent.unwrap_or_default());
        self.profile.record(started, sent.is_err());
        sent
    }
    fn write_all(&mut self, mut data: &[u8]) -> std::io::Result<()> {
        let started = Instant::now();
        let result = (|| {
            while !data.is_empty() {
                let sent = self
                    .write_packets(data, WRITE_BATCH, false)?
                    .unwrap_or_default();
                data = &data[sent..];
            }
            Ok(())
        })();
        self.profile.record(started, result.is_err());
        result
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
impl Drop for MuxStream {
    fn drop(&mut self) {
        crate::log!(
            Trace,
            "usbmux:io",
            "{} -> {}: closing",
            self.source,
            self.destination
        );
        if let Ok(mut link) = self.session.lock()
            && link.channels.contains_key(&self.source)
        {
            let _ = link.send_tcp(self.source, RST, &[]);
            link.channels.remove(&self.source);
        }
        if self.profile.bytes >= 1024 * 1024 || self.profile.errors != 0 {
            let p = &self.profile;
            crate::log!(
                Trace,
                "usbmux:stats",
                "Profile {} -> {}: bytes={}, calls={}, errors={}, elapsed={:.3}s, usb={:.3}s, stalls={}, event_waits={}, wakeups={}",
                self.source,
                self.destination,
                p.bytes,
                p.calls,
                p.errors,
                p.elapsed.as_secs_f64(),
                p.usb_out.as_secs_f64(),
                p.window_stalls,
                p.event_waits,
                p.event_wakeups
            );
        }
    }
}

#[cfg(test)]
#[path = "../../tests/unit/mux/stream.rs"]
mod tests;
