//! Direct USB multiplex transport. No usbmuxd daemon or MobileDevice library.
mod packet;
mod stream;
use crate::usb::MuxUsb;
use anyhow::{Context, Result, ensure};
use packet::encode_header;
pub use packet::{Packet, decode_packet, encode_packet};
use std::{
    collections::{BTreeMap, VecDeque},
    sync::{
        Arc, Mutex, MutexGuard,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};
pub use stream::MuxStream;

const HOST_MAGIC: u32 = 0xfeedface;
const DEVICE_MAGIC: u32 = 0xfaceface;
const MTU: usize = 3 * 16384;
// Leave the last USB packet short. An exact 48-KiB mux frame needs a separate
// zero-length OUT request, which is another synchronous Apple driver round trip.
// The mux header carries the actual length; its MTU remains an upper bound.
pub(crate) const MAX_PAYLOAD: usize = MTU - 36 - 1;
const WRITE_BATCH: usize = 256 * 1024;
const RECEIVE_WINDOW: usize = 256 * 1024;
const SYN: u8 = 2;
const RST: u8 = 4;
const ACK: u8 = 16;

/// An owned completion notification. Waiting does not consume input or borrow
/// the USB transport, so the shared link can be unlocked during the wait.
#[derive(Clone)]
pub struct InputReady(Arc<dyn Fn(Duration) -> Result<bool> + Send + Sync>);

impl InputReady {
    #[cfg(any(windows, test))]
    pub(crate) fn new(wait: impl Fn(Duration) -> Result<bool> + Send + Sync + 'static) -> Self {
        Self(Arc::new(wait))
    }

    pub(crate) fn wait(&self, timeout: Duration) -> Result<bool> {
        (self.0)(timeout)
    }
}

pub trait PacketTransport: Send {
    fn write_packet(&mut self, bytes: &[u8]) -> Result<()>;
    fn read_packet(&mut self) -> Result<Vec<u8>>;

    fn input_ready(&self) -> Option<InputReady> {
        None
    }

    /// Complete an ordered, bounded burst before returning. Backends may queue
    /// USB requests, but must drain/cancel them on error and never replay data.
    fn write_packets(&mut self, packets: &[Vec<u8>], cancelled: &AtomicBool) -> Result<()> {
        for packet in packets {
            ensure!(
                !cancelled.load(Ordering::Acquire),
                "USB mux session cancelled"
            );
            self.write_packet(packet)?;
        }
        Ok(())
    }
}
impl PacketTransport for MuxUsb {
    fn write_packet(&mut self, b: &[u8]) -> Result<()> {
        self.write_packet(b)
    }
    fn read_packet(&mut self) -> Result<Vec<u8>> {
        self.read_packet()
    }
    fn input_ready(&self) -> Option<InputReady> {
        self.input_ready()
    }
    fn write_packets(&mut self, packets: &[Vec<u8>], cancelled: &AtomicBool) -> Result<()> {
        self.write_packets(packets, cancelled)
    }
}

#[derive(Debug)]
struct Channel {
    destination: u16,
    seq: u32,
    ack: u32,
    peer_ack: u32,
    window: u32,
    connected: bool,
    closed: bool,
    input: VecDeque<u8>,
    consumed: usize,
}

impl Channel {
    fn tcp_header(&self, source: u16, flags: u8) -> [u8; 20] {
        let mut tcp = [0; 20];
        tcp[..2].copy_from_slice(&source.to_be_bytes());
        tcp[2..4].copy_from_slice(&self.destination.to_be_bytes());
        tcp[4..8].copy_from_slice(&self.seq.to_be_bytes());
        tcp[8..12].copy_from_slice(&self.ack.to_be_bytes());
        tcp[12] = 5 << 4;
        tcp[13] = flags;
        let window = ((RECEIVE_WINDOW - self.input.len()) >> 8) as u16;
        tcp[14..16].copy_from_slice(&window.to_be_bytes());
        tcp
    }
}

struct Link {
    usb: Box<dyn PacketTransport>,
    version: u32,
    tx: u16,
    rx: u16,
    buffer: Vec<u8>,
    output: Vec<u8>,
    output_batch: Vec<Vec<u8>>,
    usb_write_time: Duration,
    channels: BTreeMap<u16, Channel>,
    next_port: u16,
    cancelled: Arc<AtomicBool>,
    disconnected: bool,
}

#[derive(Clone)]
pub struct Session(Arc<Mutex<Link>>, Arc<AtomicBool>);

impl Session {
    pub fn new(usb: impl PacketTransport + 'static) -> Result<Self> {
        let cancelled = Arc::new(AtomicBool::new(false));
        let mut link = Link {
            disconnected: false,
            usb: Box::new(usb),
            version: 0,
            tx: 0,
            rx: 0xffff,
            buffer: vec![],
            output: Vec::with_capacity(MTU),
            output_batch: Vec::new(),
            usb_write_time: Duration::ZERO,
            channels: BTreeMap::new(),
            next_port: 1,
            cancelled: cancelled.clone(),
        };
        let mut version = 2u32.to_be_bytes().to_vec();
        version.extend_from_slice(&[0; 8]);
        link.send(0, &version, &[])?;
        let deadline = Instant::now() + Duration::from_secs(30);
        let packet = loop {
            if let Some(packet) = link.receive()? {
                break packet;
            }
            ensure!(
                Instant::now() < deadline,
                "USB mux version handshake timed out"
            );
            if let Some(ready) = link.usb.input_ready() {
                ready.wait(Duration::from_millis(1))?;
            } else {
                yield_link(false);
            }
        };
        let response = decode_packet(&packet, 0)?;
        ensure!(
            response.protocol == 0 && response.payload.len() == 12,
            "invalid USB mux version response"
        );
        link.version = u32::from_be_bytes(response.payload[..4].try_into()?);
        ensure!(
            matches!(link.version, 1 | 2),
            "unsupported USB mux version {}",
            link.version
        );
        if link.version == 2 {
            link.tx = 0;
            link.rx = 0xffff;
            link.send(2, &[7], &[])?;
        }
        Ok(Self(Arc::new(Mutex::new(link)), cancelled))
    }

    fn lock(&self) -> std::io::Result<MutexGuard<'_, Link>> {
        self.0
            .lock()
            .map_err(|_| std::io::Error::other("mux lock poisoned"))
    }

    pub fn connect(&self, destination: u16) -> Result<MuxStream> {
        self.connect_until(destination, Instant::now() + Duration::from_secs(30))
    }

    /// A service may send its data request before it starts listening. Retry only
    /// explicit refusals; transport and framing errors must not be hidden.
    pub fn connect_retry(&self, destination: u16, timeout: Duration) -> Result<MuxStream> {
        let deadline = Instant::now() + timeout;
        loop {
            ensure!(!self.1.load(Ordering::Acquire), "USB mux session cancelled");
            ensure!(Instant::now() < deadline, "service connection timed out");
            let attempt = deadline.min(Instant::now() + Duration::from_secs(30));
            match self.connect_until(destination, attempt) {
                Ok(stream) => return Ok(stream),
                Err(error)
                    if error
                        .downcast_ref::<std::io::Error>()
                        .is_some_and(|e| e.kind() == std::io::ErrorKind::ConnectionRefused) =>
                {
                    if Instant::now() >= deadline {
                        return Err(error);
                    }
                    std::thread::sleep(
                        Duration::from_millis(100)
                            .min(deadline.saturating_duration_since(Instant::now())),
                    );
                }
                Err(error) => return Err(error),
            }
        }
    }

    fn connect_until(&self, destination: u16, deadline: Instant) -> Result<MuxStream> {
        ensure!(destination != 0, "zero service port");
        let mut link = self.lock()?;
        ensure!(link.channels.len() < 64, "too many mux connections");
        let source = loop {
            let p = link.next_port;
            link.next_port = link.next_port.wrapping_add(1).max(1);
            if !link.channels.contains_key(&p) {
                break p;
            }
        };
        link.channels.insert(
            source,
            Channel {
                destination,
                seq: 0,
                ack: 0,
                peer_ack: 0,
                window: 0,
                connected: false,
                closed: false,
                input: VecDeque::new(),
                consumed: 0,
            },
        );
        let sent = link.send_tcp(source, SYN, &[]);
        drop(link);
        let stream = MuxStream::new(self.clone(), source, destination);
        sent?;
        loop {
            ensure!(!self.1.load(Ordering::Acquire), "USB mux session cancelled");
            let mut link = self.lock()?;
            let c = &link.channels[&source];
            if c.closed {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::ConnectionRefused,
                    format!("device refused service port {destination}"),
                )
                .into());
            }
            if c.connected {
                return Ok(stream);
            }
            ensure!(Instant::now() < deadline, "service connection timed out");
            let progressed = link.pump()?;
            drop(link);
            yield_link(progressed);
        }
    }

    pub fn cancel(&self) {
        self.1.store(true, Ordering::Release);
    }

    /// True only after the OS reported physical device removal, not a timeout,
    /// malformed plist, closed service, or firmware updater failure.
    pub fn disconnected(&self) -> bool {
        self.lock().map(|l| l.disconnected).unwrap_or(false)
    }
}

pub fn is_device_removal(error: &anyhow::Error) -> bool {
    error.chain().any(|e| {
        e.downcast_ref::<nusb::transfer::TransferError>()
            == Some(&nusb::transfer::TransferError::Disconnected)
            || e.downcast_ref::<nusb::Error>()
                .is_some_and(|e| e.kind() == nusb::ErrorKind::Disconnected)
    })
}

impl Link {
    /// A failed USB write may already be on the wire. Retire the whole session
    /// before another channel can reuse an uncertain mux/TCP sequence.
    fn finish_write(&mut self, sent: Result<()>, started: Instant, count: u16) -> Result<()> {
        self.usb_write_time += started.elapsed();
        if let Err(error) = sent {
            self.disconnected |= is_device_removal(&error);
            self.cancelled.store(true, Ordering::Release);
            return Err(error);
        }
        self.tx = self.tx.wrapping_add(count);
        Ok(())
    }

    fn send(&mut self, proto: u32, header: &[u8], data: &[u8]) -> Result<()> {
        ensure!(
            !self.cancelled.load(Ordering::Acquire),
            "USB mux session cancelled"
        );
        encode_header(
            &mut self.output,
            proto,
            self.version,
            self.tx,
            self.rx,
            header.len() + data.len(),
        )?;
        self.output.extend_from_slice(header);
        self.output.extend_from_slice(data);
        let started = Instant::now();
        let sent = self.usb.write_packet(&self.output);
        self.finish_write(sent, started, 1)
    }
    fn send_tcp(&mut self, source: u16, flags: u8, data: &[u8]) -> Result<()> {
        let tcp = self
            .channels
            .get(&source)
            .context("closed mux connection")?
            .tcp_header(source, flags);
        self.send(6, &tcp, data)
    }

    fn send_data(&mut self, source: u16, data: &[u8]) -> Result<()> {
        if data.len() <= MAX_PAYLOAD {
            self.send_tcp(source, ACK, data)?;
            let c = self
                .channels
                .get_mut(&source)
                .context("closed mux connection")?;
            c.seq = c.seq.wrapping_add(data.len() as u32);
            return Ok(());
        }
        ensure!(
            data.len() <= WRITE_BATCH,
            "USB mux burst exceeds batch limit"
        );
        let channel = self
            .channels
            .get(&source)
            .context("closed mux connection")?;
        let mut tcp = channel.tcp_header(source, ACK);
        let count = data.len().div_ceil(MAX_PAYLOAD);
        if self.output_batch.len() < count {
            self.output_batch
                .resize_with(count, || Vec::with_capacity(MTU));
        }
        let mut seq = channel.seq;
        for (index, (packet, payload)) in self.output_batch[..count]
            .iter_mut()
            .zip(data.chunks(MAX_PAYLOAD))
            .enumerate()
        {
            tcp[4..8].copy_from_slice(&seq.to_be_bytes());
            encode_header(
                packet,
                6,
                self.version,
                self.tx.wrapping_add(index as u16),
                self.rx,
                tcp.len() + payload.len(),
            )?;
            packet.extend_from_slice(&tcp);
            packet.extend_from_slice(payload);
            seq = seq.wrapping_add(payload.len() as u32);
        }
        let started = Instant::now();
        let sent = self
            .usb
            .write_packets(&self.output_batch[..count], &self.cancelled);
        self.finish_write(sent, started, count as u16)?;
        self.channels
            .get_mut(&source)
            .context("closed mux connection")?
            .seq = seq;
        Ok(())
    }
    fn receive(&mut self) -> Result<Option<Vec<u8>>> {
        loop {
            if self.buffer.len() >= 8 {
                let length = u32::from_be_bytes(self.buffer[4..8].try_into()?) as usize;
                ensure!(
                    (8..=65536).contains(&length),
                    "invalid USB mux packet length {length}"
                );
                if self.buffer.len() >= length {
                    return Ok(Some(self.buffer.drain(..length).collect()));
                }
            }
            let incoming = match self.usb.read_packet() {
                Ok(bytes) => bytes,
                Err(error) => {
                    self.disconnected |= is_device_removal(&error);
                    return Err(error);
                }
            };
            if incoming.is_empty() {
                return Ok(None);
            }
            ensure!(
                self.buffer.len() + incoming.len() <= 131072,
                "USB mux assembly buffer overflow"
            );
            self.buffer.extend(incoming);
        }
    }
    fn pump(&mut self) -> Result<bool> {
        let Some(bytes) = self.receive()? else {
            return Ok(false);
        };
        let packet = decode_packet(&bytes, self.version)?;
        self.rx = packet.rx;
        if packet.protocol == 1 {
            return Ok(true);
        }
        ensure!(
            packet.protocol == 6,
            "unexpected mux protocol {}",
            packet.protocol
        );
        let tcp = packet.payload;
        ensure!(tcp.len() >= 20, "truncated mux TCP header");
        let source = u16::from_be_bytes(tcp[2..4].try_into()?);
        let peer_port = u16::from_be_bytes(tcp[..2].try_into()?);
        let seq = u32::from_be_bytes(tcp[4..8].try_into()?);
        let ack = u32::from_be_bytes(tcp[8..12].try_into()?);
        let flags = tcp[13];
        let header_len = (tcp[12] >> 4) as usize * 4;
        ensure!(
            header_len >= 20 && header_len <= tcp.len(),
            "invalid mux TCP header size"
        );
        let data = &tcp[header_len..];
        let Some(c) = self.channels.get_mut(&source) else {
            return Ok(true);
        };
        ensure!(c.destination == peer_port, "mux TCP peer port mismatch");
        c.window = u32::from(u16::from_be_bytes(tcp[14..16].try_into()?)) << 8;
        if flags & RST != 0 {
            c.closed = true;
            return Ok(true);
        }
        if !c.connected {
            ensure!(
                flags == SYN | ACK && ack == 1 && data.is_empty(),
                "invalid mux TCP handshake"
            );
            c.seq = 1;
            c.peer_ack = 1;
            c.ack = seq.wrapping_add(1);
            c.connected = true;
            self.send_tcp(source, ACK, &[])?;
            return Ok(true);
        }
        ensure!(
            flags & ACK != 0 && flags & SYN == 0,
            "invalid mux TCP flags {flags:#x}"
        );
        ensure!(
            c.seq.wrapping_sub(ack) <= c.seq.wrapping_sub(c.peer_ack),
            "invalid mux TCP acknowledgement"
        );
        c.peer_ack = ack;
        if !data.is_empty() {
            ensure!(seq == c.ack, "out-of-order mux TCP data");
            ensure!(
                c.input.len() + data.len() <= RECEIVE_WINDOW,
                "device exceeded mux receive window"
            );
            c.input.extend(data);
            c.ack = c.ack.wrapping_add(data.len() as u32);
        }
        if flags & 1 != 0 {
            c.ack = c.ack.wrapping_add(1);
            c.closed = true;
        }
        if !data.is_empty() || flags & 1 != 0 {
            self.send_tcp(source, ACK, &[])?;
        }
        Ok(true)
    }
}

fn yield_link(progressed: bool) {
    if progressed {
        std::thread::yield_now();
    } else {
        // std::sync::Mutex is not fair: immediately polling USB again can starve
        // a writer waiting for this link, even when yield_now() is called.
        std::thread::sleep(Duration::from_millis(1));
    }
}
