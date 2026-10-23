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
    lock_wait: Duration,
    usb_out: Duration,
    packet_prepare: Duration,
    input_poll: Duration,
    window_wait: Duration,
    window_stalls: u64,
    empty_window_polls: u64,
    event_waits: u64,
    event_wakeups: u64,
    packets: u64,
    short_packets: u64,
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
    profile: WriteProfile,
}
impl MuxStream {
    pub(super) fn new(session: Session, source: u16, destination: u16) -> Self {
        Self {
            session,
            source,
            destination,
            read_timeout: Duration::from_secs(300),
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
        self.read_timeout = timeout;
    }
    pub fn read_timeout(&self) -> Duration {
        self.read_timeout
    }

    // A write() remains one packet so its error cannot discard a partial
    // success. write_all() may send a bounded batch under one lock: its API
    // already reports an error after a partially written buffer.
    fn write_packets(&mut self, data: &[u8], limit: usize) -> std::io::Result<usize> {
        if data.is_empty() {
            return Ok(0);
        }
        let deadline = Instant::now() + Duration::from_secs(300);
        let mut pending_polls = 0;
        loop {
            let started = Instant::now();
            let mut link = self.session.lock()?;
            self.profile.lock_wait += started.elapsed();
            if link.cancelled.load(Ordering::Acquire) {
                return Err(std::io::Error::other("USB mux session cancelled"));
            }
            let c = link
                .channels
                .get(&self.source)
                .ok_or_else(|| std::io::Error::other("mux channel closed"))?;
            if c.closed {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "device closed service",
                ));
            }
            let outstanding = c.seq.wrapping_sub(c.peer_ack);
            let available = c.window.saturating_sub(outstanding) as usize;
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
                let started = Instant::now();
                let pumped = link.pump();
                self.profile.input_poll += started.elapsed();
                if pumped.map_err(std::io::Error::other)? {
                    drop(link);
                    let started = Instant::now();
                    std::thread::yield_now();
                    self.profile.window_wait += started.elapsed();
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
                let started = Instant::now();
                let sent = link.send_data(self.source, &data[..n]);
                let elapsed = started.elapsed();
                let usb = link.usb_write_time - usb_before;
                self.profile.usb_out += usb;
                self.profile.packet_prepare += elapsed.saturating_sub(usb);
                sent.map_err(std::io::Error::other)?;
                self.profile.bytes += n as u64;
                self.profile.packets += n.div_ceil(MAX_PAYLOAD) as u64;
                self.profile.short_packets += u64::from(n % MAX_PAYLOAD != 0);
                return Ok(n);
            }
            if Instant::now() >= deadline {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "mux send window timeout",
                ));
            }
            self.profile.window_stalls += 1;
            let started = Instant::now();
            let pumped = link.pump();
            self.profile.input_poll += started.elapsed();
            let progressed = pumped.map_err(std::io::Error::other)?;
            self.profile.empty_window_polls += u64::from(!progressed);
            let ready = if progressed {
                None
            } else {
                link.usb.input_ready()
            };
            drop(link);
            let started = Instant::now();
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
            self.profile.window_wait += started.elapsed();
            waited?;
        }
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
            if !c.input.is_empty() {
                let n = c.input.read(out)?;
                c.consumed += n;
                if c.consumed >= 16384 {
                    c.consumed = 0;
                    link.send_tcp(self.source, ACK, &[])
                        .map_err(std::io::Error::other)?;
                }
                return Ok(n);
            }
            if c.closed {
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
        let sent = self.write_packets(data, MAX_PAYLOAD);
        self.profile.record(started, sent.is_err());
        sent
    }
    fn write_all(&mut self, mut data: &[u8]) -> std::io::Result<()> {
        let started = Instant::now();
        let result = (|| {
            while !data.is_empty() {
                let sent = self.write_packets(data, WRITE_BATCH)?;
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
        if let Ok(mut link) = self.session.lock()
            && link.channels.contains_key(&self.source)
        {
            let _ = link.send_tcp(self.source, RST, &[]);
            link.channels.remove(&self.source);
        }
        if self.profile.bytes >= 1024 * 1024 || self.profile.errors != 0 {
            let p = &self.profile;
            eprintln!(
                "ZALIVKA_MUX_PROFILE {}",
                serde_json::json!({
                    "source_port": self.source, "destination_port": self.destination,
                    "bytes": p.bytes, "write_calls": p.calls, "write_errors": p.errors,
                    "write_seconds": p.elapsed.as_secs_f64(),
                    "lock_wait_seconds": p.lock_wait.as_secs_f64(),
                    "usb_out_seconds": p.usb_out.as_secs_f64(),
                    "packet_prepare_seconds": p.packet_prepare.as_secs_f64(),
                    "input_poll_seconds": p.input_poll.as_secs_f64(),
                    "window_wait_seconds": p.window_wait.as_secs_f64(),
                    "window_stalls": p.window_stalls, "empty_window_polls": p.empty_window_polls,
                    "input_event_waits": p.event_waits, "input_event_wakeups": p.event_wakeups,
                    "data_packets": p.packets, "short_data_packets": p.short_packets,
                })
            );
        }
    }
}

#[cfg(test)]
#[path = "../../tests/unit/mux/stream.rs"]
mod tests;
