//! Direct USB multiplex transport. No usbmuxd daemon or MobileDevice library.
mod channel;
mod packet;
mod stream;
use crate::usb::MuxUsb;
use anyhow::{Context, Result, ensure};
use bytes::{Bytes, BytesMut};
use channel::{Channel, State};
pub use packet::{Packet, decode_packet};
use packet::{TcpPacket, encode_header};
use std::{
    collections::BTreeMap,
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

struct Link {
    usb: Box<dyn PacketTransport>,
    version: u32,
    tx: u16,
    rx: u16,
    buffer: BytesMut,
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
        crate::log!(Trace, "usbmux", "Negotiating version");
        let cancelled = Arc::new(AtomicBool::new(false));
        let mut link = Link {
            disconnected: false,
            usb: Box::new(usb),
            version: 0,
            tx: 0,
            rx: 0xffff,
            buffer: BytesMut::new(),
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
        crate::log!(Debug, "usbmux", "Version {}", link.version);
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
        ensure!(!self.1.load(Ordering::Acquire), "USB mux session cancelled");
        let mut link = self.lock()?;
        ensure!(Instant::now() < deadline, "service connection timed out");
        ensure!(link.channels.len() < 64, "too many mux connections");
        let source = loop {
            let p = link.next_port;
            link.next_port = link.next_port.wrapping_add(1).max(1);
            if !link.channels.contains_key(&p) {
                break p;
            }
        };
        link.channels.insert(source, Channel::new(destination));
        let sent = link.send_tcp(source, SYN, &[]);
        crate::log!(Trace, "usbmux:tcp", "{source} -> {destination}: SYN");
        drop(link);
        let stream = MuxStream::new(self.clone(), source, destination);
        sent?;
        loop {
            ensure!(!self.1.load(Ordering::Acquire), "USB mux session cancelled");
            let mut link = self.lock()?;
            let c = &link.channels[&source];
            if c.state == State::Closed {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::ConnectionRefused,
                    format!("device refused service port {destination}"),
                )
                .into());
            }
            if c.state == State::Open {
                crate::log!(Trace, "usbmux:tcp", "{source} -> {destination}: connected");
                return Ok(stream);
            }
            ensure!(Instant::now() < deadline, "service connection timed out");
            let progressed = link.pump()?;
            drop(link);
            yield_link(progressed);
        }
    }

    pub fn cancel(&self) {
        crate::log!(Trace, "usbmux", "Cancelling session");
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
        #[cfg(windows)]
        if e.downcast_ref::<std::io::Error>().is_some_and(|error| {
            use windows_sys::Win32::Foundation::{
                ERROR_DEV_NOT_EXIST, ERROR_DEVICE_NOT_CONNECTED, ERROR_NO_SUCH_DEVICE,
            };
            error.raw_os_error().is_some_and(|code| {
                [
                    ERROR_DEVICE_NOT_CONNECTED,
                    ERROR_DEV_NOT_EXIST,
                    ERROR_NO_SUCH_DEVICE,
                ]
                .contains(&(code as u32))
            })
        }) {
            return true;
        }
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
        crate::log!(
            Trace,
            "usbmux:packet",
            "TX proto={proto}, tx={}, rx={}, bytes={}",
            self.tx,
            self.rx,
            self.output.len()
        );
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
        crate::log!(
            Trace,
            "usbmux:packet",
            "TX batch: packets={count}, bytes={}",
            data.len()
        );
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
    fn receive(&mut self) -> Result<Option<Bytes>> {
        loop {
            if self.buffer.len() >= 8 {
                let length = u32::from_be_bytes(self.buffer[4..8].try_into()?) as usize;
                ensure!(
                    (8..=65536).contains(&length),
                    "invalid USB mux packet length {length}"
                );
                if self.buffer.len() >= length {
                    return Ok(Some(self.buffer.split_to(length).freeze()));
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
            self.buffer.extend_from_slice(&incoming);
        }
    }
    fn pump(&mut self) -> Result<bool> {
        let result = self.pump_packet();
        if result.is_err() {
            // A consumed or malformed frame cannot be replayed by another
            // service. Retire the link just as after an uncertain USB write.
            self.cancelled.store(true, Ordering::Release);
        }
        result
    }

    fn pump_packet(&mut self) -> Result<bool> {
        let Some(bytes) = self.receive()? else {
            return Ok(false);
        };
        let packet = decode_packet(&bytes, self.version)?;
        // A different service thread can consume the firmware channel's ACKs.
        // Keep those packets quiet without suppressing that service's own trace.
        let source = packet
            .payload
            .get(2..4)
            .map(|port| u16::from_be_bytes([port[0], port[1]]));
        let firmware_transfer = packet.protocol == 6
            && source
                .and_then(|port| self.channels.get(&port))
                .is_some_and(|channel| channel.firmware_transfer);
        let _trace = firmware_transfer.then(crate::logging::firmware_transfer);
        crate::log!(
            Trace,
            "usbmux:packet",
            "RX proto={}, rx={}, bytes={}",
            packet.protocol,
            packet.rx,
            bytes.len()
        );
        self.rx = packet.rx;
        if packet.protocol == 1 {
            return Ok(true);
        }
        ensure!(
            packet.protocol == 6,
            "unexpected mux protocol {}",
            packet.protocol
        );
        let tcp = TcpPacket::parse(packet.payload)?;
        let source = tcp.destination;
        crate::log!(
            Trace,
            "usbmux:tcp",
            "{} -> {source}: flags={:#04x}, seq={}, ack={}, window={}, bytes={}",
            tcp.source,
            tcp.flags,
            tcp.seq,
            tcp.ack,
            tcp.window,
            tcp.data.len()
        );
        if let Some(channel) = self.channels.get_mut(&source)
            && channel.receive(&tcp)?
        {
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
