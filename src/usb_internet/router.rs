//! IPv4 gateway: per-flow TCP forwarding and a session-owned DNS resolver.
mod ethernet;
use super::dns;
use crate::proxy::socket as upstream;
#[cfg(test)]
use ethernet::udp_reply;
use ethernet::{CLIENT, Ethernet, GATEWAY, MAC, MAX_QUEUE, dhcp_reply};
use smoltcp::{
    iface::{Config, Interface, SocketHandle, SocketSet},
    phy::ChecksumCapabilities,
    socket::tcp,
    time::Instant,
    wire::*,
};
use std::{
    collections::HashMap,
    io::{self, Read, Write},
    net::Ipv4Addr,
    sync::mpsc::{self, Receiver},
    time::{Duration, Instant as Clock},
};
const MAX_FLOWS: usize = 64;
const BUFFER: usize = 65536;
const FLOW_TIMEOUT: Duration = Duration::from_secs(120);
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
struct Flow {
    source: Ipv4Addr,
    source_port: u16,
    destination: Ipv4Addr,
    destination_port: u16,
}

enum Upstream {
    Connecting(Receiver<io::Result<upstream::Stream>>),
    Network(upstream::Stream),
    Dns(dns::Tcp),
}
impl Upstream {
    fn poll(&mut self, resolver: &mut dns::Resolver) -> io::Result<bool> {
        if let Self::Connecting(result) = self {
            match result.try_recv() {
                Ok(result) => *self = Self::Network(result?),
                Err(mpsc::TryRecvError::Empty) => return Ok(false),
                Err(mpsc::TryRecvError::Disconnected) => {
                    return Err(io::Error::other("upstream connection worker stopped"));
                }
            }
        }
        let polled = match self {
            Self::Network(stream) => stream.poll(),
            Self::Dns(stream) => stream.poll(resolver),
            Self::Connecting(_) => return Ok(false),
        };
        match polled {
            Err(error) if idle(&error) => Ok(false),
            result => result.map(|()| true),
        }
    }

    fn shutdown_write(&mut self) -> io::Result<()> {
        match self {
            Self::Connecting(_) => Err(io::ErrorKind::WouldBlock.into()),
            Self::Network(stream) => stream.shutdown_write(),
            Self::Dns(stream) => {
                stream.shutdown_write();
                Ok(())
            }
        }
    }

    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::Connecting(_) => Err(io::ErrorKind::WouldBlock.into()),
            Self::Network(stream) => stream.read(out),
            Self::Dns(stream) => stream.read(out),
        }
    }

    fn write(&mut self, bytes: &[u8], resolver: &mut dns::Resolver) -> io::Result<usize> {
        match self {
            Self::Connecting(_) => Err(io::ErrorKind::WouldBlock.into()),
            Self::Network(stream) => stream.write(bytes),
            Self::Dns(stream) => stream.write(bytes, resolver),
        }
    }
}

struct Tcp {
    handle: SocketHandle,
    upstream: Upstream,
    write_closed: bool,
    last: Clock,
}

impl Tcp {
    fn poll(
        &mut self,
        socket: &mut tcp::Socket,
        resolver: &mut dns::Resolver,
        traffic: &mut (u64, u64),
    ) -> io::Result<()> {
        if !self.upstream.poll(resolver)? {
            return Ok(());
        }
        let external = matches!(self.upstream, Upstream::Network(_));
        if socket.can_recv() {
            let n = socket
                .recv(|bytes| match self.upstream.write(bytes, resolver) {
                    Ok(0) => (0, Err(io::ErrorKind::WriteZero.into())),
                    Ok(n) => (n, Ok(n)),
                    Err(error) if idle(&error) => (0, Ok(0)),
                    Err(error) => (0, Err(error)),
                })
                .map_err(io::Error::other)??;
            if n != 0 {
                self.last = Clock::now();
                if external {
                    traffic.0 += n as u64;
                }
            }
        }
        if matches!(
            socket.state(),
            tcp::State::CloseWait
                | tcp::State::Closing
                | tcp::State::LastAck
                | tcp::State::TimeWait
        ) && !socket.can_recv()
            && !self.write_closed
        {
            match self.upstream.shutdown_write() {
                // TLS may still be flushing close_notify. Its next poll completes it.
                Ok(()) => self.write_closed = true,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => self.write_closed = true,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) => return Err(error),
            }
        }
        if socket.can_send() {
            let read = socket
                .send(|bytes| match self.upstream.read(bytes) {
                    Ok(n) => (n, Ok(Some(n))),
                    Err(error) if idle(&error) => (0, Ok(None)),
                    Err(error) => (0, Err(error)),
                })
                .map_err(io::Error::other)??;
            match read {
                Some(0) => socket.close(),
                Some(n) => {
                    self.last = Clock::now();
                    if external {
                        traffic.1 += n as u64;
                    }
                }
                None => {}
            }
        }
        Ok(())
    }
}

fn idle(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
    )
}

pub(super) struct Router {
    ethernet: Ethernet,
    interface: Interface,
    sockets: SocketSet<'static>,
    tcp: HashMap<Flow, Tcp>,
    dns: dns::Resolver,
    started: Clock,
    traffic: (u64, u64),
}
impl Router {
    pub fn new() -> Self {
        let mut ethernet = Ethernet::default();
        let mut config = Config::new(MAC.into());
        config.random_seed = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64;
        let mut interface = Interface::new(config, &mut ethernet, Instant::ZERO);
        interface.update_ip_addrs(|a| {
            a.push(IpCidr::new(GATEWAY.into(), 24)).unwrap();
        });
        interface
            .routes_mut()
            .add_default_ipv4_route(GATEWAY)
            .unwrap();
        interface.set_any_ip(true);
        let sockets = SocketSet::new(vec![]);
        Self {
            ethernet,
            interface,
            sockets,
            tcp: HashMap::new(),
            dns: dns::Resolver::default(),
            started: Clock::now(),
            traffic: (0, 0),
        }
    }
    /// Internet payload bytes: upload from the Mac, then download to the Mac.
    pub fn bytes(&self) -> (u64, u64) {
        self.traffic
    }
    pub fn receive(&mut self, frame: Vec<u8>) {
        if self.ethernet.input.len() >= MAX_QUEUE {
            return;
        }
        let Ok(ethernet) = EthernetFrame::new_checked(&frame) else {
            return;
        };
        match ethernet.ethertype() {
            EthernetProtocol::Arp => {
                // AnyIP must answer only for the gateway, never the client's DHCP address.
                let Ok(packet) = ArpPacket::new_checked(ethernet.payload()) else {
                    return;
                };
                if !matches!(
                    ArpRepr::parse(&packet),
                    Ok(ArpRepr::EthernetIpv4 {
                        target_protocol_addr: GATEWAY,
                        ..
                    })
                ) {
                    return;
                }
            }
            EthernetProtocol::Ipv4 => {
                let Ok(ip) = Ipv4Packet::new_checked(ethernet.payload()) else {
                    return;
                };
                let checksums = ChecksumCapabilities::default();
                let Ok(header) = Ipv4Repr::parse(&ip, &checksums) else {
                    return;
                };
                // This gateway has no IPv4 reassembly. Never interpret a
                // fragment's bytes as a fresh TCP SYN or DNS/DHCP datagram.
                if ip.more_frags() || ip.frag_offset() != 0 {
                    return;
                }
                let flow = |source_port, destination_port| Flow {
                    source: header.src_addr,
                    source_port,
                    destination: header.dst_addr,
                    destination_port,
                };
                match header.next_header {
                    IpProtocol::Tcp => {
                        let Ok(packet) = TcpPacket::new_checked(ip.payload()) else {
                            return;
                        };
                        if packet.syn() && !packet.ack() {
                            // Validate the whole SYN before allocating a flow or
                            // starting a host connection. Other TCP packets go
                            // straight to the stack's normal validation path.
                            let Ok(syn) = TcpRepr::parse(
                                &packet,
                                &header.src_addr.into(),
                                &header.dst_addr.into(),
                                &checksums,
                            ) else {
                                return;
                            };
                            self.connect_tcp(flow(syn.src_port, syn.dst_port));
                        }
                    }
                    IpProtocol::Udp => {
                        let Ok(packet) = UdpPacket::new_checked(ip.payload()) else {
                            return;
                        };
                        let Ok(udp) = UdpRepr::parse(
                            &packet,
                            &header.src_addr.into(),
                            &header.dst_addr.into(),
                            &checksums,
                        ) else {
                            return;
                        };
                        self.receive_udp(
                            flow(udp.src_port, udp.dst_port),
                            ethernet.src_addr(),
                            packet.payload(),
                        );
                        return;
                    }
                    _ => {}
                }
            }
            _ => return,
        }
        self.ethernet.input.push_back(frame);
        // Process promptly so SYNs enter their individual TCP sockets.
        self.poll_stack();
    }

    fn connect_tcp(&mut self, key: Flow) {
        if key.source != CLIENT
            || key.source_port == 0
            || key.destination_port == 0
            || self.tcp.contains_key(&key)
            || self.tcp.len() >= MAX_FLOWS
            || (key.destination_port != 53 && !permitted(key.destination))
        {
            return;
        }
        let mut socket = tcp::Socket::new(
            tcp::SocketBuffer::new(vec![0; BUFFER]),
            tcp::SocketBuffer::new(vec![0; BUFFER]),
        );
        socket.set_timeout(Some(smoltcp::time::Duration::from_secs(
            FLOW_TIMEOUT.as_secs(),
        )));
        if socket
            .listen((key.destination, key.destination_port))
            .is_err()
        {
            return;
        }
        let upstream = if key.destination_port == 53 {
            Upstream::Dns(dns::Tcp::default())
        } else {
            let host = self.dns.host(key.destination).map(str::to_owned);
            if dns::synthetic(key.destination) && host.is_none() {
                return;
            }
            let host = host.unwrap_or_else(|| key.destination.to_string());
            let (tx, rx) = mpsc::sync_channel(1);
            if let Err(error) = std::thread::Builder::new()
                .name("usb-internet-connect".into())
                .spawn(move || {
                    let result = upstream::connect(&host, key.destination_port)
                        .map_err(|e| std::io::Error::other(format!("{e:#}")));
                    let _ = tx.send(result);
                })
            {
                crate::log!(
                    Warning,
                    "usb-internet",
                    "Не удалось запустить обработчик соединения: {error}"
                );
                return;
            }
            Upstream::Connecting(rx)
        };
        self.tcp.insert(
            key,
            Tcp {
                handle: self.sockets.add(socket),
                upstream,
                write_closed: false,
                last: Clock::now(),
            },
        );
    }

    fn receive_udp(&mut self, key: Flow, mac: EthernetAddress, bytes: &[u8]) {
        if self.ethernet.output.len() >= MAX_QUEUE {
            return;
        }
        if key.destination_port == 67 && key.source_port == 68 {
            if let Some(reply) = dhcp_reply(bytes) {
                self.ethernet.reply_udp(
                    Flow {
                        source: Ipv4Addr::BROADCAST,
                        source_port: 68,
                        destination: GATEWAY,
                        destination_port: 67,
                    },
                    EthernetAddress::BROADCAST,
                    &reply,
                );
                crate::log!(
                    Debug,
                    "usb-internet",
                    "Mac запросил IP-адрес; предложен {CLIENT}"
                );
            }
            return;
        }
        // Intercept even a hard-coded external DNS address. Other UDP (including
        // QUIC and multicast discovery) cannot bypass the TCP proxy policy.
        if key.source == CLIENT
            && key.source_port != 0
            && key.destination_port == 53
            && let Some(reply) = self.dns.reply(bytes)
        {
            self.ethernet.reply_udp(key, mac, &reply);
        }
    }

    pub fn poll(&mut self) {
        for (key, flow) in &mut self.tcp {
            let socket = self.sockets.get_mut::<tcp::Socket>(flow.handle);
            let connecting = matches!(flow.upstream, Upstream::Connecting(_));
            if let Err(error) = flow.poll(socket, &mut self.dns, &mut self.traffic) {
                crate::log!(
                    Warning,
                    "usb-internet",
                    "Ошибка соединения с {}:{}: {error}",
                    key.destination,
                    key.destination_port
                );
                socket.abort();
            } else if connecting && matches!(flow.upstream, Upstream::Network(_)) {
                crate::log!(
                    Debug,
                    "usb-internet",
                    "TCP-соединение установлено: {}:{}",
                    key.destination,
                    key.destination_port
                );
            }
            if flow.last.elapsed() > FLOW_TIMEOUT {
                socket.abort();
            }
        }
        // Poll before retiring flows: closed sockets must emit their pending RST first.
        self.poll_stack();
    }

    fn poll_stack(&mut self) {
        let now = Instant::from_millis(self.started.elapsed().as_millis() as i64);
        self.interface
            .poll(now, &mut self.ethernet, &mut self.sockets);
    }

    pub fn transmit(&mut self) -> Vec<Vec<u8>> {
        // poll() emits at most one segment per socket. Drain already-ready
        // segments so an active stream fills NCM blocks without another USB
        // read or idle wait. The Ethernet queue bounds the amount of work.
        let now = Instant::from_millis(self.started.elapsed().as_millis() as i64);
        while self.ethernet.output.len() < MAX_QUEUE {
            let before = self.ethernet.output.len();
            self.interface
                .poll_egress(now, &mut self.ethernet, &mut self.sockets);
            if self.ethernet.output.len() == before {
                break;
            }
        }
        // Retire the flow and its socket together, including sockets closed by
        // Interface::poll. A stale flow must never outlive or reuse its handle.
        let sockets = &mut self.sockets;
        self.tcp.retain(|_, flow| {
            if sockets.get::<tcp::Socket>(flow.handle).is_open() {
                true
            } else {
                sockets.remove(flow.handle);
                false
            }
        });
        self.ethernet.output.drain(..).collect()
    }
}
fn permitted(addr: Ipv4Addr) -> bool {
    !addr.is_unspecified()
        && !addr.is_loopback()
        && !addr.is_multicast()
        && !addr.is_broadcast()
        && addr != GATEWAY
        && addr != CLIENT
        && addr.octets()[0] != 0
        && !addr.is_link_local()
}
#[cfg(test)]
#[path = "../../tests/unit/usb_internet/router.rs"]
mod tests;
