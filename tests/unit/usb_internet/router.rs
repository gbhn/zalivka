use super::*;
use std::net::{TcpListener, TcpStream};
const PEER: EthernetAddress = EthernetAddress([2, 0, 0, 0, 0, 2]);
const DNS_QUERY: &[u8] =
    b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x01x\x07invalid\x00\x00\x01\x00\x01";

struct Client {
    ethernet: Ethernet,
    interface: Interface,
    sockets: SocketSet<'static>,
    handle: SocketHandle,
}

impl Client {
    fn new() -> Self {
        let mut ethernet = Ethernet::default();
        let mut interface = Interface::new(Config::new(PEER.into()), &mut ethernet, Instant::ZERO);
        interface
            .update_ip_addrs(|addresses| addresses.push(IpCidr::new(CLIENT.into(), 24)).unwrap());
        interface
            .routes_mut()
            .add_default_ipv4_route(GATEWAY)
            .unwrap();
        let mut sockets = SocketSet::new(vec![]);
        let handle = sockets.add(tcp::Socket::new(
            tcp::SocketBuffer::new(vec![0; BUFFER]),
            tcp::SocketBuffer::new(vec![0; BUFFER]),
        ));
        Self {
            ethernet,
            interface,
            sockets,
            handle,
        }
    }

    fn connect(&mut self, destination: Ipv4Addr, port: u16, source: u16) {
        self.sockets
            .get_mut::<tcp::Socket>(self.handle)
            .connect(self.interface.context(), (destination, port), source)
            .unwrap();
    }

    fn socket(&mut self) -> &mut tcp::Socket<'static> {
        self.sockets.get_mut::<tcp::Socket>(self.handle)
    }

    fn exchange(&mut self, router: &mut Router) {
        let now = Instant::from_millis(router.started.elapsed().as_millis() as i64);
        self.interface
            .poll(now, &mut self.ethernet, &mut self.sockets);
        for frame in self.ethernet.output.drain(..) {
            router.receive(frame);
        }
        router.poll();
        self.ethernet.input.extend(router.transmit());
    }
}

fn attach(router: &mut Router, key: Flow, upstream: Upstream) -> SocketHandle {
    let mut socket = tcp::Socket::new(
        tcp::SocketBuffer::new(vec![0; BUFFER]),
        tcp::SocketBuffer::new(vec![0; BUFFER]),
    );
    socket
        .listen((key.destination, key.destination_port))
        .unwrap();
    let handle = router.sockets.add(socket);
    router.tcp.insert(
        key,
        Tcp {
            handle,
            upstream,
            write_closed: false,
            last: Clock::now(),
        },
    );
    handle
}

fn dhcp_request() -> Vec<u8> {
    let mut request = vec![0; 244];
    request[0..4].copy_from_slice(&[1, 1, 6, 0]);
    request[4..8].copy_from_slice(&0x12345678u32.to_be_bytes());
    request[28..34].copy_from_slice(&PEER.0);
    request[236..240].copy_from_slice(&[99, 130, 83, 99]);
    request[240..].copy_from_slice(&[53, 1, 1, 255]);
    request
}

fn frame_udp(
    source: Ipv4Addr,
    source_port: u16,
    destination: Ipv4Addr,
    destination_port: u16,
    bytes: &[u8],
) -> Vec<u8> {
    udp_reply(
        Flow {
            source: destination,
            source_port: destination_port,
            destination: source,
            destination_port: source_port,
        },
        MAC,
        bytes,
    )
    .remove(0)
}

#[test]
fn invalid_tcp_syns_do_not_allocate_flows() {
    for (source_port, destination_port, version, fin) in [
        (50000, 0, 4, false),
        (0, 53, 4, false),
        (50000, 53, 4, true),
        (50000, 53, 6, false),
    ] {
        let mut frame = vec![0; 14 + 20 + 20];
        let mut ethernet = EthernetFrame::new_unchecked(&mut frame);
        ethernet.set_src_addr(PEER);
        ethernet.set_dst_addr(MAC);
        ethernet.set_ethertype(EthernetProtocol::Ipv4);
        let mut ip = Ipv4Packet::new_unchecked(ethernet.payload_mut());
        ip.set_version(version);
        ip.set_header_len(20);
        ip.set_total_len(40);
        ip.set_hop_limit(64);
        ip.set_next_header(IpProtocol::Tcp);
        ip.set_src_addr(CLIENT);
        ip.set_dst_addr(GATEWAY);
        let mut tcp = TcpPacket::new_unchecked(ip.payload_mut());
        tcp.set_src_port(source_port);
        tcp.set_dst_port(destination_port);
        tcp.set_header_len(20);
        tcp.set_syn(true);
        tcp.set_fin(fin);
        tcp.fill_checksum(&CLIENT.into(), &GATEWAY.into());
        ip.fill_checksum();

        let mut router = Router::new();
        router.receive(frame);
        router.poll();
        router.transmit();
        assert!(router.tcp.is_empty());
        assert_eq!(router.sockets.iter().count(), 0);
    }
}

#[test]
fn dhcp_assigns_address_and_does_not_answer_clients_arp_probe() {
    let request = dhcp_request();
    let mut router = Router::new();
    router.receive(frame_udp(
        Ipv4Addr::UNSPECIFIED,
        68,
        Ipv4Addr::BROADCAST,
        67,
        &request,
    ));
    let replies = router.transmit();
    assert_eq!(replies.len(), 1);
    let ether = EthernetFrame::new_checked(&replies[0]).unwrap();
    let ip = Ipv4Packet::new_checked(ether.payload()).unwrap();
    assert!(ip.verify_checksum());
    let udp = UdpPacket::new_checked(ip.payload()).unwrap();
    assert!(udp.verify_checksum(&GATEWAY.into(), &Ipv4Addr::BROADCAST.into()));
    let dhcp = DhcpPacket::new_checked(udp.payload()).unwrap();
    let dhcp = DhcpRepr::parse(&dhcp).unwrap();
    assert_eq!(dhcp.transaction_id, 0x12345678);
    assert_eq!(dhcp.message_type, DhcpMessageType::Offer);
    assert_eq!(dhcp.your_ip, CLIENT);
    assert_eq!(dhcp.router, Some(GATEWAY));
    assert_eq!(dhcp.dns_servers.unwrap().as_slice(), &[GATEWAY]);
    for (target, expected) in [(CLIENT, 0), (GATEWAY, 1)] {
        let mut bytes = vec![0; 42];
        let mut ether = EthernetFrame::new_unchecked(&mut bytes);
        ether.set_src_addr(PEER);
        ether.set_dst_addr(EthernetAddress::BROADCAST);
        ether.set_ethertype(EthernetProtocol::Arp);
        ArpRepr::EthernetIpv4 {
            operation: ArpOperation::Request,
            source_hardware_addr: PEER,
            source_protocol_addr: if target == CLIENT {
                Ipv4Addr::UNSPECIFIED
            } else {
                CLIENT
            },
            target_hardware_addr: EthernetAddress::default(),
            target_protocol_addr: target,
        }
        .emit(&mut ArpPacket::new_unchecked(ether.payload_mut()));
        router.receive(bytes);
        router.poll();
        assert_eq!(router.transmit().len(), expected);
    }
}
#[test]
fn udp_dns_is_local_and_other_datagrams_are_not_forwarded() {
    let mut router = Router::new();
    let key = Flow {
        source: CLIENT,
        source_port: 50000,
        destination: Ipv4Addr::new(1, 1, 1, 1),
        destination_port: 53,
    };
    let query = DNS_QUERY;
    router.receive(frame_udp(
        CLIENT,
        key.source_port,
        key.destination,
        53,
        query,
    ));
    router.poll();
    let frames = router.transmit();
    assert_eq!(frames.len(), 1);
    let ether = EthernetFrame::new_checked(&frames[0]).unwrap();
    let ip = Ipv4Packet::new_checked(ether.payload()).unwrap();
    let udp = UdpPacket::new_checked(ip.payload()).unwrap();
    assert_eq!(ip.src_addr(), key.destination);
    assert_eq!(ip.dst_addr(), CLIENT);
    assert!(ip.verify_checksum());
    assert!(udp.verify_checksum(&key.destination.into(), &CLIENT.into()));
    assert_eq!(&udp.payload()[udp.payload().len() - 4..], &[198, 18, 0, 1]);
    assert_eq!(
        router.dns.host(Ipv4Addr::new(198, 18, 0, 1)),
        Some("x.invalid")
    );
    for port in [443, 123, 5353] {
        router.receive(frame_udp(CLIENT, 50000, key.destination, port, b"blocked"));
        router.poll();
        assert!(router.transmit().is_empty());
    }
    // Check a larger response independently: some CI/WSL loopback paths
    // discard fragmented UDP even before it reaches the receiving socket.
    let response = vec![0x5a; 5000];
    let frames = udp_reply(key, PEER, &response);
    assert!(frames.len() > 1);
    let mut datagram = vec![];
    let mut ident = None;
    for (index, bytes) in frames.iter().enumerate() {
        assert!(bytes.len() <= 1514);
        let ether = EthernetFrame::new_checked(bytes).unwrap();
        assert_eq!(ether.dst_addr(), PEER);
        let ip = Ipv4Packet::new_checked(ether.payload()).unwrap();
        assert_eq!(ip.src_addr(), key.destination);
        assert_eq!(ip.dst_addr(), CLIENT);
        assert!(ip.verify_checksum());
        assert_eq!(ip.frag_offset() as usize, datagram.len());
        assert_eq!(ip.more_frags(), index + 1 < frames.len());
        if let Some(ident) = ident {
            assert_eq!(ip.ident(), ident);
        }
        ident = Some(ip.ident());
        datagram.extend_from_slice(ip.payload());
    }
    let udp = UdpPacket::new_checked(&datagram).unwrap();
    assert_eq!(udp.src_port(), 53);
    assert_eq!(udp.dst_port(), 50000);
    assert!(udp.verify_checksum(&key.destination.into(), &CLIENT.into()));
    assert_eq!(udp.payload(), response);
    assert_eq!(router.bytes(), (0, 0));
}
#[test]
fn tcp_dns_to_the_gateway_or_a_hard_coded_server_stays_local() {
    for destination in [GATEWAY, Ipv4Addr::new(8, 8, 8, 8)] {
        let mut router = Router::new();
        let mut client = Client::new();
        client.connect(destination, 53, 50000);
        let query = DNS_QUERY;
        let mut request = (query.len() as u16).to_be_bytes().to_vec();
        request.extend(query);
        let started = Clock::now();
        let mut sent = 0;
        let mut reply = vec![];
        loop {
            assert!(
                started.elapsed() < Duration::from_secs(3),
                "local TCP DNS timed out"
            );
            client.exchange(&mut router);
            let socket = client.socket();
            if socket.can_send() && sent < request.len() {
                sent += socket.send_slice(&request[sent..]).unwrap();
                if sent == request.len() {
                    socket.close();
                }
            }
            if socket.can_recv() {
                socket
                    .recv(|bytes| {
                        reply.extend_from_slice(bytes);
                        (bytes.len(), ())
                    })
                    .unwrap();
            }
            if reply.len() >= 2
                && reply.len() == 2 + u16::from_be_bytes([reply[0], reply[1]]) as usize
            {
                break;
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        assert_eq!(&reply[2..4], &[0x12, 0x34]);
        assert_eq!(&reply[reply.len() - 4..], &[198, 18, 0, 1]);
        assert!(
            router
                .tcp
                .values()
                .all(|flow| matches!(flow.upstream, Upstream::Dns(_)))
        );
        assert_eq!(router.bytes(), (0, 0));
    }
}

#[test]
fn tcp_reclaims_timed_out_reset_and_failed_connections_before_reusing_handles() {
    let mut router = Router::new();
    let destination = Ipv4Addr::new(203, 0, 113, 1);
    let mut client = Client::new();
    let mut previous_handle = None;
    for index in 0..MAX_FLOWS * 3 {
        let key = Flow {
            source: CLIENT,
            source_port: 45678 + (index % 2) as u16,
            destination,
            destination_port: 443,
        };
        let (_pending, rx) = mpsc::sync_channel(1);
        let handle = attach(&mut router, key, Upstream::Connecting(rx));
        if let Some(previous) = previous_handle {
            assert_eq!(handle, previous, "closed socket storage must be reusable");
        }
        previous_handle = Some(handle);
        client.connect(destination, 443, key.source_port);
        for _ in 0..32 {
            client.exchange(&mut router);
            if router.sockets.get::<tcp::Socket>(handle).state() == tcp::State::Established
                && client.socket().state() == tcp::State::Established
            {
                break;
            }
        }
        assert_eq!(
            router.sockets.get::<tcp::Socket>(handle).state(),
            tcp::State::Established
        );
        match index % 3 {
            0 => {
                // Interface::poll can close a socket after the proxy inspects it.
                router
                    .sockets
                    .get_mut::<tcp::Socket>(handle)
                    .set_timeout(Some(smoltcp::time::Duration::from_millis(1)));
                router.started -= Duration::from_secs(1);
            }
            1 => {
                client.socket().abort();
                let now = Instant::from_millis(router.started.elapsed().as_millis() as i64);
                client
                    .interface
                    .poll(now, &mut client.ethernet, &mut client.sockets);
                for frame in client.ethernet.output.drain(..) {
                    router.receive(frame);
                }
            }
            _ => {
                let (tx, rx) = mpsc::sync_channel(1);
                tx.send(Err(io::ErrorKind::ConnectionRefused.into()))
                    .unwrap();
                router.tcp.get_mut(&key).unwrap().upstream = Upstream::Connecting(rx);
            }
        }
        router.poll();
        assert_eq!(
            router.sockets.get::<tcp::Socket>(handle).state(),
            tcp::State::Closed
        );
        let frames = router.transmit();
        if index % 3 != 1 {
            assert!(
                frames.iter().any(|frame| {
                    let ether = EthernetFrame::new_checked(frame).unwrap();
                    if ether.ethertype() != EthernetProtocol::Ipv4 {
                        return false;
                    }
                    let ip = Ipv4Packet::new_checked(ether.payload()).unwrap();
                    ip.next_header() == IpProtocol::Tcp
                        && TcpPacket::new_checked(ip.payload()).unwrap().rst()
                }),
                "the final TCP reset must reach the peer"
            );
        }
        router.poll();
        assert!(router.tcp.is_empty());
        assert_eq!(router.sockets.iter().count(), 0);
        client.ethernet.input.extend(frames);
        let now = Instant::from_millis(router.started.elapsed().as_millis() as i64);
        client
            .interface
            .poll(now, &mut client.ethernet, &mut client.sockets);
        assert!(!client.socket().is_open());
    }
}

#[test]
fn tcp_preserves_buffered_payload_across_connect_and_half_close_with_a_real_upstream_socket() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let connection = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    connection.set_nonblocking(true).unwrap();
    let payload: Vec<_> = (0..262144).map(|n| (n % 251) as u8).collect();
    let expected = payload.clone();
    let server = std::thread::spawn(move || {
        let (mut socket, _) = listener.accept().unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        socket
            .set_write_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut received = vec![];
        socket.read_to_end(&mut received).unwrap();
        assert!(
            received == expected,
            "upstream payload mismatch: {} bytes",
            received.len()
        );
        socket.write_all(&received).unwrap();
    });
    let mut router = Router::new();
    let destination = Ipv4Addr::new(203, 0, 113, 1);
    let key = Flow {
        source: CLIENT,
        source_port: 45678,
        destination,
        destination_port: 443,
    };
    let (completed, pending) = mpsc::sync_channel(1);
    let handle = attach(&mut router, key, Upstream::Connecting(pending));
    let mut connection = Some(upstream::Stream::from_tcp(connection));
    let mut client = Client::new();
    client.connect(destination, 443, key.source_port);
    let mut sent = 0;
    let mut received = vec![];
    let mut closed = false;
    let started = Clock::now();
    while received.len() < payload.len() {
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "TCP proxy timeout: sent {sent}, received {}",
            received.len()
        );
        client.exchange(&mut router);
        if connection.is_some() && router.sockets.get::<tcp::Socket>(handle).can_recv() {
            assert!(matches!(router.tcp[&key].upstream, Upstream::Connecting(_)));
            completed.send(Ok(connection.take().unwrap())).unwrap();
        }
        let socket = client.socket();
        if socket.can_send() && sent < payload.len() {
            sent += socket.send_slice(&payload[sent..]).unwrap();
        }
        if sent == payload.len() && !closed {
            socket.close();
            closed = true;
        }
        if socket.can_recv() {
            socket
                .recv(|data| {
                    received.extend_from_slice(data);
                    (data.len(), ())
                })
                .unwrap();
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    assert!(
        connection.is_none(),
        "the connection must have completed after buffering client bytes"
    );
    assert!(
        received == payload,
        "client payload mismatch: {} bytes",
        received.len()
    );
    assert_eq!(router.bytes(), (payload.len() as u64, payload.len() as u64));
    server.join().unwrap();
}

#[test]
fn dhcp_and_dns_floods_cannot_grow_the_ethernet_queue_without_bound() {
    let mut router = Router::new();
    let request = dhcp_request();
    for _ in 0..MAX_QUEUE * 3 {
        router.receive(frame_udp(
            Ipv4Addr::UNSPECIFIED,
            68,
            Ipv4Addr::BROADCAST,
            67,
            &request,
        ));
    }
    assert_eq!(router.ethernet.output.len(), MAX_QUEUE);
    let query = DNS_QUERY;
    router.receive(frame_udp(CLIENT, 50000, GATEWAY, 53, query));
    assert_eq!(router.ethernet.output.len(), MAX_QUEUE);
    assert_eq!(router.dns.host(Ipv4Addr::new(198, 18, 0, 1)), None);
    assert_eq!(router.transmit().len(), MAX_QUEUE);
    router.receive(frame_udp(CLIENT, 50000, GATEWAY, 53, query));
    let replies = router.transmit();
    assert_eq!(replies.len(), 1);
    let ethernet = EthernetFrame::new_checked(&replies[0]).unwrap();
    let ip = Ipv4Packet::new_checked(ethernet.payload()).unwrap();
    let udp = UdpPacket::new_checked(ip.payload()).unwrap();
    assert_eq!(&udp.payload()[udp.payload().len() - 4..], &[198, 18, 0, 1]);
}

#[test]
#[ignore = "synthetic USB internet throughput benchmark; no physical USB or external network"]
fn benchmark_usb_internet_batching() {
    fn run(batched: bool) -> (Duration, usize, usize) {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let connection = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        connection.set_nonblocking(true).unwrap();
        let payload: Vec<u8> = (0..8 * 1024 * 1024).map(|n| (n % 251) as u8).collect();
        let data = payload.clone();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_write_timeout(Some(Duration::from_secs(30)))
                .unwrap();
            stream.write_all(&data).unwrap();
        });
        let mut router = Router::new();
        let destination = Ipv4Addr::new(203, 0, 113, 1);
        let key = Flow {
            source: CLIENT,
            source_port: 45678,
            destination,
            destination_port: 443,
        };
        attach(
            &mut router,
            key,
            Upstream::Network(upstream::Stream::from_tcp(connection)),
        );
        let mut client = Client::new();
        client.connect(destination, 443, key.source_port);
        let params = super::super::ncm::Parameters {
            input_size: 32768,
            output_size: 32764,
            divisor: 4,
            remainder: 0,
            alignment: 4,
            max_datagrams: if batched { 128 } else { 1 },
        };
        let mut received = vec![];
        let mut transfers = 0;
        let mut frame_count = 0;
        let mut active = false;
        let started = Clock::now();
        while received.len() < payload.len() {
            assert!(
                started.elapsed() < Duration::from_secs(40),
                "gateway benchmark timeout: {} bytes",
                received.len()
            );
            // Fixed host-call overhead is a model, not a USB hardware measurement.
            if !batched || !active {
                std::thread::sleep(Duration::from_millis(2));
            }
            let now = Instant::from_millis(started.elapsed().as_millis() as i64);
            client
                .interface
                .poll(now, &mut client.ethernet, &mut client.sockets);
            active = !client.ethernet.output.is_empty();
            for frame in client.ethernet.output.drain(..) {
                router.receive(frame);
            }
            router.poll();
            let frames = if batched {
                router.transmit()
            } else {
                // Previous loop: one stack egress pass, then one USB
                // transfer per Ethernet frame.
                router.ethernet.output.drain(..).collect()
            };
            active |= !frames.is_empty();
            frame_count += frames.len();
            let mut offset = 0;
            while offset < frames.len() {
                let (ntb, count) = params.encode(&frames[offset..], transfers as u16).unwrap();
                std::thread::sleep(Duration::from_micros(250));
                client
                    .ethernet
                    .input
                    .extend(super::super::ncm::decode(&ntb).unwrap());
                offset += count;
                transfers += 1;
            }
            let socket = client.socket();
            if socket.can_recv() {
                socket
                    .recv(|bytes| {
                        received.extend_from_slice(bytes);
                        (bytes.len(), ())
                    })
                    .unwrap();
            }
        }
        assert!(received == payload, "gateway benchmark data corruption");
        assert_eq!(router.bytes(), (0, payload.len() as u64));
        server.join().unwrap();
        (started.elapsed(), transfers, frame_count)
    }
    let before = run(false);
    let after = run(true);
    println!(
        "USB_INTERNET_BENCH bytes={} fixed_call_us=250 before_ms={:.3} after_ms={:.3} speedup={:.3} before_usb_calls={} after_usb_calls={} before_frames={} after_frames={}",
        8 * 1024 * 1024,
        before.0.as_secs_f64() * 1000.0,
        after.0.as_secs_f64() * 1000.0,
        before.0.as_secs_f64() / after.0.as_secs_f64(),
        before.1,
        after.1,
        before.2,
        after.2
    );
    assert!(
        after.1 * 5 < before.1,
        "batching did not reduce USB calls enough"
    );
}
