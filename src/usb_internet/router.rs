//! A small, temporary IPv4 gateway. TCP/IP framing is delegated to smoltcp.
use super::dns;
use smoltcp::{
    iface::{Config, Interface, SocketHandle, SocketSet},
    phy::{self, DeviceCapabilities, Medium},
    socket::tcp,
    time::Instant,
    wire::*,
};
use std::{
    collections::{HashMap, VecDeque},
    io::{Read, Write},
    net::Ipv4Addr,
    sync::{
        Arc, Mutex,
        mpsc::{self, Receiver},
    },
    time::{Duration, Instant as Clock},
};
const GATEWAY: Ipv4Addr = Ipv4Addr::new(192, 168, 249, 1);
const CLIENT: Ipv4Addr = Ipv4Addr::new(192, 168, 249, 2);
const MAC: EthernetAddress = EthernetAddress([2, 0x5a, 0x41, 0x4c, 0x49, 1]);
const MAX_FLOWS: usize = 64;
const BUFFER: usize = 65536;
#[derive(Default)]
struct Ethernet {
    input: VecDeque<Vec<u8>>,
    output: VecDeque<Vec<u8>>,
}
struct Rx(Vec<u8>);
struct Tx<'a>(&'a mut VecDeque<Vec<u8>>);
impl phy::RxToken for Rx {
    fn consume<R, F: FnOnce(&[u8]) -> R>(self, f: F) -> R {
        f(&self.0)
    }
}
impl phy::TxToken for Tx<'_> {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, len: usize, f: F) -> R {
        let mut bytes = vec![0; len];
        let r = f(&mut bytes);
        self.0.push_back(bytes);
        r
    }
}
impl phy::Device for Ethernet {
    type RxToken<'a> = Rx;
    type TxToken<'a> = Tx<'a>;
    fn receive(&mut self, _: Instant) -> Option<(Rx, Tx<'_>)> {
        let bytes = self.input.pop_front()?;
        Some((Rx(bytes), Tx(&mut self.output)))
    }
    fn transmit(&mut self, _: Instant) -> Option<Tx<'_>> {
        (self.output.len() < 256).then_some(Tx(&mut self.output))
    }
    fn capabilities(&self) -> DeviceCapabilities {
        let mut c = DeviceCapabilities::default();
        c.medium = Medium::Ethernet;
        c.max_transmission_unit = 1514;
        c
    }
}
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
struct Flow {
    source: Ipv4Addr,
    source_port: u16,
    destination: Ipv4Addr,
    destination_port: u16,
}

enum Stream {
    Network(crate::proxy::socket::Stream),
    Dns(dns::Tcp),
}
impl Stream {
    fn poll(&mut self) -> std::io::Result<()> {
        match self {
            Self::Network(s) => s.poll(),
            Self::Dns(_) => Ok(()),
        }
    }
    fn shutdown_write(&mut self) -> std::io::Result<()> {
        match self {
            Self::Network(s) => s.shutdown_write(),
            Self::Dns(s) => {
                s.shutdown_write();
                Ok(())
            }
        }
    }
}
impl Read for Stream {
    fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Self::Network(s) => s.read(out),
            Self::Dns(s) => s.read(out),
        }
    }
}
impl Write for Stream {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        match self {
            Self::Network(s) => s.write(bytes),
            Self::Dns(s) => s.write(bytes),
        }
    }
    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            Self::Network(s) => s.flush(),
            Self::Dns(s) => s.flush(),
        }
    }
}
struct Tcp {
    handle: SocketHandle,
    connecting: Option<Receiver<std::io::Result<Stream>>>,
    stream: Option<Stream>,
    write_closed: bool,
    last: Clock,
}
pub(super) struct Router {
    ethernet: Ethernet,
    interface: Interface,
    sockets: SocketSet<'static>,
    tcp: HashMap<Flow, Tcp>,
    dns: Arc<Mutex<dns::Resolver>>,
    started: Clock,
    sent: u64,
    received: u64,
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
            dns: Arc::new(Mutex::new(dns::Resolver::default())),
            started: Clock::now(),
            sent: 0,
            received: 0,
        }
    }
    pub fn bytes(&self) -> (u64, u64) {
        (self.sent, self.received)
    }
    pub fn receive(&mut self, frame: Vec<u8>) {
        if self.ethernet.input.len() >= 256 {
            return;
        }
        if let Ok(ethernet) = EthernetFrame::new_checked(&frame) {
            // AnyIP is needed for transparent TCP, but answering probes for
            // the client's offered address would make DHCP report a conflict.
            if ethernet.ethertype() == EthernetProtocol::Arp
                && let Ok(packet) = ArpPacket::new_checked(ethernet.payload())
                && let Ok(ArpRepr::EthernetIpv4 {
                    target_protocol_addr,
                    ..
                }) = ArpRepr::parse(&packet)
                && target_protocol_addr != GATEWAY
            {
                return;
            }
            if ethernet.ethertype() == EthernetProtocol::Ipv4
                && let Ok(ip) = Ipv4Packet::new_checked(ethernet.payload())
            {
                if ip.more_frags() || ip.frag_offset() != 0 {
                    return;
                }
                if ip.next_header() == IpProtocol::Tcp
                    && ip.verify_checksum()
                    && let Ok(packet) = TcpPacket::new_checked(ip.payload())
                    && packet.syn()
                    && !packet.ack()
                    && packet.verify_checksum(&ip.src_addr().into(), &ip.dst_addr().into())
                {
                    let key = Flow {
                        source: ip.src_addr(),
                        source_port: packet.src_port(),
                        destination: ip.dst_addr(),
                        destination_port: packet.dst_port(),
                    };
                    self.connect_tcp(key);
                }
                if ip.next_header() == IpProtocol::Udp
                    && ip.verify_checksum()
                    && let Ok(packet) = UdpPacket::new_checked(ip.payload())
                    && packet.verify_checksum(&ip.src_addr().into(), &ip.dst_addr().into())
                {
                    let key = Flow {
                        source: ip.src_addr(),
                        source_port: packet.src_port(),
                        destination: ip.dst_addr(),
                        destination_port: packet.dst_port(),
                    };
                    self.receive_udp(key, ethernet.src_addr(), packet.payload());
                    return;
                }
            }
        }
        self.ethernet.input.push_back(frame);
        // Process promptly so SYNs enter their individual TCP sockets.
        let now = Instant::from_millis(self.started.elapsed().as_millis() as i64);
        self.interface
            .poll(now, &mut self.ethernet, &mut self.sockets);
    }

    fn connect_tcp(&mut self, key: Flow) {
        if key.destination_port == 0
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
        socket.set_timeout(Some(smoltcp::time::Duration::from_secs(120)));
        if socket
            .listen((key.destination, key.destination_port))
            .is_err()
        {
            return;
        }
        let (connecting, stream) = if key.destination_port == 53 {
            (None, Some(Stream::Dns(dns::Tcp::new(self.dns.clone()))))
        } else {
            let host = self
                .dns
                .lock()
                .unwrap()
                .host(key.destination)
                .map(str::to_owned);
            if dns::synthetic(key.destination) && host.is_none() {
                return;
            }
            let host = host.unwrap_or_else(|| key.destination.to_string());
            let (tx, rx) = mpsc::sync_channel(1);
            if let Err(error) = std::thread::Builder::new()
                .name("usb-internet-connect".into())
                .spawn(move || {
                    let result = crate::proxy::socket::connect(&host, key.destination_port)
                        .map(Stream::Network)
                        .map_err(|e| std::io::Error::other(format!("{e:#}")));
                    let _ = tx.send(result);
                })
            {
                eprintln!("USB internet: could not start connection worker: {error}");
                return;
            }
            (Some(rx), None)
        };
        self.tcp.insert(
            key,
            Tcp {
                handle: self.sockets.add(socket),
                connecting,
                stream,
                write_closed: false,
                last: Clock::now(),
            },
        );
    }

    fn receive_udp(&mut self, key: Flow, mac: EthernetAddress, bytes: &[u8]) {
        if key.destination_port == 67 && key.source_port == 68 {
            if let Some(reply) = dhcp_reply(bytes) {
                self.ethernet.output.extend(udp_reply(
                    Flow {
                        source: Ipv4Addr::BROADCAST,
                        source_port: 68,
                        destination: GATEWAY,
                        destination_port: 67,
                    },
                    EthernetAddress::BROADCAST,
                    &reply,
                ));
                eprintln!("USB internet: Mac requested an IPv4 address; offered {CLIENT}");
            }
            return;
        }
        // Intercept even a hard-coded external DNS address. Other UDP (including
        // QUIC and multicast discovery) cannot bypass the TCP proxy policy.
        if key.destination_port == 53
            && self.ethernet.output.len() < 192
            && let Some(reply) = self.dns.lock().unwrap().reply(bytes)
        {
            self.ethernet.output.extend(udp_reply(key, mac, &reply));
        }
    }

    pub fn poll(&mut self) {
        let sockets = &mut self.sockets;
        let sent = &mut self.sent;
        let received = &mut self.received;
        for (key, flow) in &mut self.tcp {
            let socket = sockets.get_mut::<tcp::Socket>(flow.handle);
            if let Some(rx) = &flow.connecting {
                match rx.try_recv() {
                    Ok(Ok(s)) => {
                        eprintln!(
                            "USB internet: TCP connected {}:{}",
                            key.destination, key.destination_port
                        );
                        flow.stream = Some(s);
                        flow.connecting = None;
                    }
                    Ok(Err(error)) => {
                        eprintln!(
                            "USB internet: connection to {}:{} failed: {error}",
                            key.destination, key.destination_port
                        );
                        socket.abort();
                        flow.connecting = None;
                    }
                    Err(mpsc::TryRecvError::Disconnected) => {
                        socket.abort();
                        flow.connecting = None;
                    }
                    Err(mpsc::TryRecvError::Empty) => {}
                }
            }
            if let Some(stream) = &mut flow.stream {
                let external = matches!(stream, Stream::Network(_));
                if stream.poll().is_err() {
                    socket.abort();
                }
                if socket.can_recv() {
                    let mut failed = false;
                    let _ = socket.recv(|bytes| match stream.write(bytes) {
                        Ok(n) => {
                            if external {
                                *sent += n as u64;
                            }
                            flow.last = Clock::now();
                            (n, ())
                        }
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => (0, ()),
                        Err(_) => {
                            failed = true;
                            (0, ())
                        }
                    });
                    if failed {
                        socket.abort();
                    }
                }
                if matches!(
                    socket.state(),
                    tcp::State::CloseWait
                        | tcp::State::Closing
                        | tcp::State::LastAck
                        | tcp::State::TimeWait
                ) && !socket.can_recv()
                    && !flow.write_closed
                {
                    let _ = stream.shutdown_write();
                    flow.write_closed = true;
                }
                if socket.can_send() {
                    let mut close = false;
                    let mut abort = false;
                    let _ = socket.send(|bytes| match stream.read(bytes) {
                        Ok(0) => {
                            close = true;
                            (0, ())
                        }
                        Ok(n) => {
                            if external {
                                *received += n as u64;
                            }
                            flow.last = Clock::now();
                            (n, ())
                        }
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => (0, ()),
                        Err(_) => {
                            abort = true;
                            (0, ())
                        }
                    });
                    if close {
                        socket.close();
                    }
                    if abort {
                        socket.abort();
                    }
                }
            }
            if flow.last.elapsed() > Duration::from_secs(120) {
                socket.abort();
            }
        }
        // Keep flows and sockets together until after network polling, which
        // can itself close sockets and must first emit any pending RST.
        let now = Instant::from_millis(self.started.elapsed().as_millis() as i64);
        self.interface
            .poll(now, &mut self.ethernet, &mut self.sockets);
    }
    pub fn transmit(&mut self) -> Vec<Vec<u8>> {
        // poll() emits at most one segment per socket. Drain already-ready
        // segments so an active stream fills NCM blocks without another USB
        // read or idle wait. The Ethernet queue bounds the amount of work.
        let now = Instant::from_millis(self.started.elapsed().as_millis() as i64);
        while self.ethernet.output.len() < 256 {
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
fn dhcp_reply(bytes: &[u8]) -> Option<Vec<u8>> {
    let packet = DhcpPacket::new_checked(bytes).ok()?;
    let mut repr = DhcpRepr::parse(&packet).ok()?;
    if repr.server_identifier.is_some_and(|a| a != GATEWAY) {
        return None;
    }
    eprintln!("USB internet DHCP: {:?}", repr.message_type);
    repr.message_type = match repr.message_type {
        DhcpMessageType::Discover => DhcpMessageType::Offer,
        DhcpMessageType::Request => {
            if repr.requested_ip.is_some_and(|a| a != CLIENT) {
                return None;
            }
            DhcpMessageType::Ack
        }
        _ => return None,
    };
    repr.your_ip = CLIENT;
    repr.server_ip = GATEWAY;
    repr.router = Some(GATEWAY);
    repr.subnet_mask = Some(Ipv4Addr::new(255, 255, 255, 0));
    repr.server_identifier = Some(GATEWAY);
    repr.lease_duration = Some(120);
    repr.renew_duration = None;
    repr.rebind_duration = None;
    repr.requested_ip = None;
    repr.client_identifier = None;
    repr.parameter_request_list = None;
    repr.max_size = None;
    repr.additional_options = &[];
    // The Mac asks this local resolver; Windows owns all upstream resolution.
    let mut dns = repr.dns_servers.take().unwrap_or_default();
    dns.clear();
    let _ = dns.push(GATEWAY);
    repr.dns_servers = Some(dns);
    let mut out = vec![0; repr.buffer_len()];
    repr.emit(&mut DhcpPacket::new_unchecked(&mut out)).ok()?;
    Some(out)
}

fn udp_reply(key: Flow, mac: EthernetAddress, payload: &[u8]) -> Vec<Vec<u8>> {
    let mut datagram = vec![0; 8 + payload.len()];
    let mut udp = UdpPacket::new_unchecked(&mut datagram);
    udp.set_src_port(key.destination_port);
    udp.set_dst_port(key.source_port);
    udp.set_len((8 + payload.len()) as u16);
    udp.payload_mut().copy_from_slice(payload);
    udp.fill_checksum(&key.destination.into(), &key.source.into());
    let mut result = vec![];
    let ident = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .subsec_nanos() as u16;
    for (index, chunk) in datagram.chunks(1480).enumerate() {
        let mut bytes = vec![0; 14 + 20 + chunk.len()];
        let mut ether = EthernetFrame::new_unchecked(&mut bytes);
        ether.set_dst_addr(mac);
        ether.set_src_addr(MAC);
        ether.set_ethertype(EthernetProtocol::Ipv4);
        let mut ip = Ipv4Packet::new_unchecked(ether.payload_mut());
        ip.set_version(4);
        ip.set_header_len(20);
        ip.set_total_len((20 + chunk.len()) as u16);
        ip.set_ident(ident);
        ip.set_more_frags((index + 1) * 1480 < datagram.len());
        ip.set_frag_offset((index * 1480) as u16);
        ip.set_hop_limit(64);
        ip.set_next_header(IpProtocol::Udp);
        ip.set_src_addr(key.destination);
        ip.set_dst_addr(key.source);
        ip.payload_mut().copy_from_slice(chunk);
        ip.fill_checksum();
        result.push(bytes);
    }
    result
}

#[cfg(test)]
#[path = "../../tests/unit/usb_internet/router.rs"]
mod tests;
