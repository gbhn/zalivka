//! Local experiment: real FDR relay and WinHTTP PAC, simulated device USB.
//! The client consumes SOCKS as a byte stream, independently of host writes.
use super::{auto_proxy, pac_server};
use crate::{mux, test_mux};
use anyhow::Result;
use rustls::{
    ClientConfig, ClientConnection, RootCertStore, ServerConfig, ServerConnection, StreamOwned,
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName},
};
use std::{
    collections::VecDeque,
    io::{self, Read, Write},
    net::{TcpListener, TcpStream},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    thread,
    time::{Duration, Instant},
};

const PORT: u16 = 49154;

#[derive(Clone, Copy, PartialEq)]
enum Mode {
    Rust,
    BusyRust,
    NativeCurl,
    NativeCurlNoGssapi,
}

impl Mode {
    fn independent(self) -> bool {
        matches!(self, Self::NativeCurl | Self::NativeCurlNoGssapi)
    }
}

struct Usb {
    input: mpsc::Receiver<Vec<u8>>,
    output: mpsc::Sender<Vec<u8>>,
    noise_input: mpsc::Sender<Vec<u8>>,
    noise_seq: u32,
    pending: VecDeque<u8>,
    fragment: usize,
}
impl mux::PacketTransport for Usb {
    fn write_packet(&mut self, bytes: &[u8]) -> Result<()> {
        if bytes.starts_with(&6u32.to_be_bytes()) {
            let packet = mux::decode_packet(bytes, 2)?;
            let tcp = packet.payload;
            if tcp[2..4] == 62078u16.to_be_bytes() {
                let source = u16::from_be_bytes(tcp[..2].try_into()?);
                let seq = u32::from_be_bytes(tcp[4..8].try_into()?);
                let data = &tcp[usize::from(tcp[12] >> 4) * 4..];
                if tcp[13] & 2 != 0 {
                    self.noise_input
                        .send(test_mux::tcp(62078, source, 0, seq + 1, 0x12, &[]))?;
                    self.noise_seq = 1;
                } else if !data.is_empty() {
                    self.noise_input.send(test_mux::tcp(
                        62078,
                        source,
                        self.noise_seq,
                        seq + data.len() as u32,
                        0x10,
                        data,
                    ))?;
                    self.noise_seq += data.len() as u32;
                }
                return Ok(());
            }
        }
        self.output.send(bytes.to_vec())?;
        Ok(())
    }
    fn read_packet(&mut self) -> Result<Vec<u8>> {
        if self.pending.is_empty() {
            match self.input.recv_timeout(Duration::from_millis(2)) {
                Ok(bytes) => self.pending.extend(bytes),
                Err(mpsc::RecvTimeoutError::Timeout) => return Ok(vec![]),
                Err(error) => return Err(error.into()),
            }
            while self.pending.len() < 65536 {
                let Ok(bytes) = self.input.try_recv() else {
                    break;
                };
                self.pending.extend(bytes);
            }
        }
        let count = self.pending.len().min(self.fragment);
        Ok(self.pending.drain(..count).collect())
    }
}

struct Device {
    input: mpsc::Receiver<Vec<u8>>,
    output: mpsc::Sender<Vec<u8>>,
    buffer: VecDeque<u8>,
    source: u16,
    seq: u32,
    ack: u32,
    fragment: usize,
    closed: bool,
    handshake: bool,
    read_wait: Duration,
    reset_reason: Option<&'static [u8]>,
    reply_segments: Vec<usize>,
}
impl Device {
    fn send(&self, flags: u8, data: &[u8]) -> io::Result<()> {
        self.output
            .send(test_mux::tcp(
                PORT,
                self.source,
                self.seq,
                self.ack,
                flags,
                data,
            ))
            .map_err(io::Error::other)
    }
    fn receive(&mut self) -> io::Result<()> {
        loop {
            let bytes = self
                .input
                .recv_timeout(self.read_wait)
                .map_err(|error| match error {
                    mpsc::RecvTimeoutError::Timeout => io::ErrorKind::TimedOut.into(),
                    error => io::Error::other(error),
                })?;
            if !bytes.starts_with(&6u32.to_be_bytes()) {
                continue;
            }
            let packet = mux::decode_packet(&bytes, 2).map_err(io::Error::other)?;
            if packet.protocol != 6 {
                continue;
            }
            let tcp = packet.payload;
            assert_eq!(u16::from_be_bytes(tcp[2..4].try_into().unwrap()), PORT);
            let source = u16::from_be_bytes(tcp[..2].try_into().unwrap());
            let seq = u32::from_be_bytes(tcp[4..8].try_into().unwrap());
            let flags = tcp[13];
            let data = &tcp[usize::from(tcp[12] >> 4) * 4..];
            if flags & 2 != 0 {
                self.source = source;
                self.ack = seq + 1;
                self.send(0x12, &[])?;
                self.seq = 1;
                return Ok(());
            }
            assert_eq!(source, self.source);
            if flags & 4 != 0 {
                self.closed = true;
                return Ok(());
            }
            if !data.is_empty() {
                assert_eq!(seq, self.ack);
                self.ack += data.len() as u32;
                self.buffer.extend(data);
                if self.handshake {
                    self.reply_segments.push(data.len());
                }
                self.send(0x10, &[])?;
            }
            if flags & 1 != 0 {
                self.closed = true;
            }
            return Ok(());
        }
    }
}
impl Read for Device {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if out.is_empty() {
            return Ok(0);
        }
        while self.buffer.is_empty() && !self.closed {
            self.receive()?;
        }
        let n = out.len().min(self.buffer.len()).min(self.fragment);
        self.buffer.read(&mut out[..n])
    }
}
impl Write for Device {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        for part in bytes.chunks(self.fragment) {
            self.send(0x10, part)?;
            self.seq += part.len() as u32;
        }
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
impl Drop for Device {
    fn drop(&mut self) {
        if self.source != 0 && !self.closed {
            let _ = if let Some(reason) = self.reset_reason {
                self.send(0x04, reason)
            } else {
                self.send(0x11, &[])
            };
            // Keep the device transport alive for the host's FIN ACK and RST.
            // Dropping the receiver here would invent a USB write failure.
            while let Ok(bytes) = self.input.recv_timeout(Duration::from_secs(10)) {
                if let Ok(packet) = mux::decode_packet(&bytes, 2)
                    && packet.protocol == 6
                    && packet.payload[13] & 4 != 0
                {
                    break;
                }
            }
        }
    }
}

struct Counted(TcpStream, u64, u64);
impl Read for Counted {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        let n = self.0.read(bytes)?;
        self.1 += n as u64;
        Ok(n)
    }
}
impl Write for Counted {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let n = self.0.write(bytes)?;
        self.2 += n as u64;
        Ok(n)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.0.flush()
    }
}

fn accept(listener: TcpListener) -> TcpStream {
    listener.set_nonblocking(true).unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        match listener.accept() {
            Ok((stream, _)) => {
                stream.set_nonblocking(false).unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(10)))
                    .unwrap();
                stream
                    .set_write_timeout(Some(Duration::from_secs(10)))
                    .unwrap();
                return stream;
            }
            Err(error)
                if error.kind() == io::ErrorKind::WouldBlock && Instant::now() < deadline =>
            {
                thread::sleep(Duration::from_millis(1));
            }
            Err(error) => panic!("local proxy accept: {error}"),
        }
    }
}

fn tls_configs() -> (Arc<ServerConfig>, Arc<ClientConfig>) {
    let provider = Arc::new(oxitls_rustcrypto_provider::provider());
    let certificate =
        CertificateDer::from(include_bytes!("../../fixtures/proxy/fdr-lab.der").to_vec());
    let server = Arc::new(
        ServerConfig::builder_with_provider(provider.clone())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                vec![certificate.clone()],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
                    include_bytes!("../../fixtures/proxy/localhost-key.der").to_vec(),
                )),
            )
            .unwrap(),
    );
    let mut roots = RootCertStore::empty();
    roots.add(certificate).unwrap();
    let client = Arc::new(
        ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    );
    (server, client)
}

#[test]
#[ignore = "local FDR laboratory; explicit PAC, simulated USB, no Apple or real Mac"]
fn pac_connect_tls_matrix() {
    crate::logging::init(crate::logging::Level::Debug);
    let (server, client) = tls_configs();
    for greeting in [false, true] {
        for fragment in [1, 4096] {
            for delay_ms in [0, 250, 1250] {
                run_case(
                    greeting,
                    fragment,
                    delay_ms,
                    false,
                    server.clone(),
                    client.clone(),
                    Mode::Rust,
                );
            }
        }
    }
    // Negative controls: the simulated client sends FIN or RST after CONNECT.
    // They must reproduce the logged zero-byte EOF without a handshake defect.
    for delay_ms in [0, 250] {
        run_case(
            true,
            1,
            delay_ms,
            true,
            server.clone(),
            client.clone(),
            Mode::Rust,
        );
    }
    // Let another service continuously read/write on the same USB-mux link.
    // Split physical input inside headers and coalesce frames from both peers.
    for greeting in [false, true] {
        for delay_ms in [0, 250, 1250] {
            run_case(
                greeting,
                1,
                delay_ms,
                false,
                server.clone(),
                client.clone(),
                Mode::BusyRust,
            );
        }
    }
}

#[test]
#[ignore = "independent Windows curl SOCKS/HTTPS reproduction through local PAC and simulated USB"]
fn native_curl_method_list_reproduction() {
    crate::logging::init(crate::logging::Level::Debug);
    let (server, client) = tls_configs();
    run_case(
        true,
        4096,
        0,
        false,
        server.clone(),
        client.clone(),
        Mode::NativeCurlNoGssapi,
    );
    for delay_ms in [0, 1250] {
        run_case(
            true,
            4096,
            delay_ms,
            false,
            server.clone(),
            client.clone(),
            Mode::NativeCurl,
        );
    }
}

fn curl_through_device(
    mut device: Device,
    request: Vec<u8>,
    expected: Vec<u8>,
    no_gssapi: bool,
) -> Vec<usize> {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let curl = thread::spawn(move || {
        let mut certificate = tempfile::NamedTempFile::new().unwrap();
        certificate
            .write_all(include_bytes!("../../fixtures/proxy/fdr-lab.pem"))
            .unwrap();
        certificate.flush().unwrap();
        let mut body = tempfile::NamedTempFile::new().unwrap();
        body.write_all(&request).unwrap();
        body.flush().unwrap();
        let curl = std::path::PathBuf::from(std::env::var_os("SystemRoot").unwrap())
            .join("System32/curl.exe");
        let mut command = std::process::Command::new(curl);
        if no_gssapi {
            command.arg("--socks5-basic");
        }
        let output = command
            .args([
                "--silent",
                "--show-error",
                "--socks5-hostname",
                &address.to_string(),
                "--noproxy",
                "",
                "--max-time",
                "15",
                "--header",
                "Expect:",
                "--cacert",
            ])
            .arg(certificate.path())
            .arg("--data-binary")
            .arg(format!("@{}", body.path().display()))
            .arg("https://tbsc.apple.com/lab")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "curl {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(output.stdout, expected);
    });
    let mut socket = accept(listener);
    socket
        .set_read_timeout(Some(Duration::from_millis(5)))
        .unwrap();
    device.read_wait = Duration::from_millis(5);
    let deadline = Instant::now() + Duration::from_secs(20);
    let mut prefix = vec![];
    let mut returned = 0;
    let mut buffer = vec![0; 32768];
    while Instant::now() < deadline {
        match socket.read(&mut buffer) {
            Ok(0) => break,
            Ok(n) => {
                let take = n.min(32 - prefix.len());
                prefix.extend_from_slice(&buffer[..take]);
                device.write_all(&buffer[..n]).unwrap();
            }
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) => {}
            Err(error) => panic!("curl bridge read: {error}"),
        }
        match device.read(&mut buffer) {
            Ok(0) => break,
            Ok(n) => {
                socket.write_all(&buffer[..n]).unwrap();
                returned += n;
                if returned >= 23 {
                    device.handshake = false;
                }
            }
            Err(error) if error.kind() == io::ErrorKind::TimedOut => {}
            Err(error) => panic!("curl bridge mux read: {error}"),
        }
    }
    println!("FDR_CURL_PREFIX {}", hex::encode(prefix));
    drop(socket);
    curl.join().unwrap();
    device.reply_segments.clone()
}

fn run_case(
    greeting: bool,
    fragment: usize,
    delay_ms: u64,
    close_before_tls: bool,
    server_config: Arc<ServerConfig>,
    client_config: Arc<ClientConfig>,
    mode: Mode,
) {
    let noise = mode == Mode::BusyRust;
    let started = Instant::now();
    let request: Vec<_> = (0..32768).map(|n| (n % 251) as u8).collect();
    let response: Vec<_> = (0..16384).map(|n| (n % 239) as u8).collect();
    let expected_request = request.clone();
    let expected_response = response.clone();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let proxy = thread::spawn(move || {
        let mut socket = accept(listener);
        let mut header = vec![];
        while !header.ends_with(b"\r\n\r\n") {
            let mut byte = [0];
            socket.read_exact(&mut byte).unwrap();
            header.push(byte[0]);
            assert!(header.len() < 16384);
        }
        assert!(header.starts_with(b"CONNECT tbsc.apple.com:443 HTTP/1.1\r\n"));
        thread::sleep(Duration::from_millis(delay_ms));
        socket
            .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
            .unwrap();
        let mut tls = StreamOwned::new(
            ServerConnection::new(server_config).unwrap(),
            Counted(socket, 0, 0),
        );
        if close_before_tls {
            assert!(tls.read(&mut [0]).is_err());
            assert_eq!((tls.sock.1, tls.sock.2), (0, 0));
        } else {
            if mode.independent() {
                let mut header = vec![];
                while !header.ends_with(b"\r\n\r\n") {
                    let mut byte = [0];
                    tls.read_exact(&mut byte).unwrap();
                    header.push(byte[0]);
                    assert!(header.len() < 16384);
                }
                assert!(header.starts_with(b"POST /lab HTTP/1.1\r\n"));
                assert!(
                    String::from_utf8(header)
                        .unwrap()
                        .to_ascii_lowercase()
                        .contains(&format!("content-length: {}\r\n", expected_request.len()))
                );
            }
            let mut bytes = vec![0; expected_request.len()];
            tls.read_exact(&mut bytes).unwrap();
            assert_eq!(bytes, expected_request);
            if mode.independent() {
                write!(
                    tls,
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    response.len()
                )
                .unwrap();
            }
            tls.write_all(&response).unwrap();
            tls.flush().unwrap();
            // Application data was verified; the synthetic device then closes
            // its mux channel rather than performing another TLS exchange.
            let _ = tls.read(&mut [0]);
        }
        (tls.sock.1, tls.sock.2)
    });
    let (pac, pac_server) = pac_server(&format!(
        "function FindProxyForURL(url, host) {{ return 'PROXY {address}'; }}"
    ));
    let (to_host, host_input) = mpsc::channel();
    let noise_input = to_host.clone();
    let (to_device, device_input) = mpsc::channel();
    to_host.send(test_mux::version_packet()).unwrap();
    let device = thread::spawn(move || {
        let mut device = Device {
            input: device_input,
            output: to_host,
            buffer: VecDeque::new(),
            source: 0,
            seq: 0,
            ack: 0,
            fragment,
            closed: false,
            handshake: true,
            read_wait: Duration::from_secs(10),
            reset_reason: None,
            reply_segments: vec![],
        };
        while device.source == 0 {
            device.receive().unwrap();
        }
        if mode.independent() {
            return curl_through_device(
                device,
                request,
                expected_response,
                mode == Mode::NativeCurlNoGssapi,
            );
        }
        if greeting {
            device.write_all(&[5, 1, 0]).unwrap();
            let mut method = [0; 2];
            device.read_exact(&mut method).unwrap();
            assert_eq!(method, [5, 0]);
        }
        let host = b"tbsc.apple.com";
        let mut connect = vec![5, 1, 0, 3, host.len() as u8];
        connect.extend_from_slice(host);
        connect.extend_from_slice(&443u16.to_be_bytes());
        device.write_all(&connect).unwrap();
        let mut header = [0; 4];
        device.read_exact(&mut header).unwrap();
        assert_eq!(header, [5, 0, 0, 3]);
        let mut length = [0];
        device.read_exact(&mut length).unwrap();
        let mut bound_address = vec![0; usize::from(length[0]) + 2];
        device.read_exact(&mut bound_address).unwrap();
        let segments = device.reply_segments.clone();
        if close_before_tls && delay_ms != 0 {
            device.reset_reason = Some(b"lab client cancelled before TLS");
        }
        if !close_before_tls {
            device.handshake = false;
            device.fragment = 4096;
            let mut tls = StreamOwned::new(
                ClientConnection::new(client_config, ServerName::try_from("localhost").unwrap())
                    .unwrap(),
                device,
            );
            tls.write_all(&request).unwrap();
            tls.flush().unwrap();
            let mut bytes = vec![0; expected_response.len()];
            tls.read_exact(&mut bytes).unwrap();
            assert_eq!(bytes, expected_response);
        }
        segments
    });
    let session = mux::Session::new(Usb {
        input: host_input,
        output: to_device,
        noise_input,
        noise_seq: 0,
        pending: VecDeque::new(),
        fragment: if noise { 7 } else { 65536 },
    })
    .unwrap();
    let stop_noise = Arc::new(AtomicBool::new(false));
    let noise_worker = noise.then(|| {
        let mut main = session.connect(62078).unwrap();
        main.set_read_timeout(Duration::from_secs(10));
        let stop = stop_noise.clone();
        thread::spawn(move || {
            let mut count = 0u64;
            while !stop.load(Ordering::Relaxed) {
                let mut data = vec![0xa5; 8192];
                data[..8].copy_from_slice(&count.to_le_bytes());
                main.write_all(&data).unwrap();
                let mut reply = vec![0; data.len()];
                main.read_exact(&mut reply).unwrap();
                assert_eq!(data, reply);
                count += 1;
                thread::sleep(Duration::from_millis(1));
            }
            count
        })
    });
    let stream = session.connect(PORT).unwrap();
    let result = crate::fdr::handle_connection(stream, &AtomicBool::new(false), |host, port| {
        let uri = format!("https://{host}:{port}/").parse()?;
        let proxy = auto_proxy(&uri, false, &pac)?;
        assert_eq!(
            proxy.as_ref().map(|p| (p.host(), p.port())),
            Some(("127.0.0.1", address.port()))
        );
        crate::proxy::socket::connect_blocking(host, port, proxy)
    });
    stop_noise.store(true, Ordering::Relaxed);
    if let Err(error) = &result {
        eprintln!("FDR_LAB_RELAY_ERROR {error:#}");
    }
    let main_round_trips = noise_worker
        .map(|worker| worker.join().unwrap())
        .unwrap_or(0);
    assert!(!noise || main_round_trips > 0);
    let segments = device.join().unwrap();
    assert_eq!(
        segments,
        if greeting { vec![2, 21] } else { vec![2, 19] },
        "CONNECT reply must be sent in one mux payload after method selection"
    );
    pac_server.join().unwrap();
    let (from_device, from_server) = proxy.join().unwrap();
    result.unwrap();
    println!(
        "FDR_LAB {}",
        serde_json::json!({
            "build": crate::VERSION,
            "greeting": greeting, "request_fragment": fragment, "proxy_delay_ms": delay_ms,
            "close_before_tls": close_before_tls, "host_handshake_segments": segments,
            "tls_from_device": from_device, "tls_from_server": from_server,
            "application_request_verified": !close_before_tls, "application_response_verified": !close_before_tls,
            "seconds": started.elapsed().as_secs_f64(), "real_usb": false, "wpad_discovery": false,
            "native_winhttp_pac": true, "real_tls": !close_before_tls,
            "concurrent_main": noise, "main_round_trips": main_round_trips,
            "usb_read_fragment": if noise { 7 } else { 65536 },
            "independent_client": mode.independent(),
            "curl_no_gssapi": mode == Mode::NativeCurlNoGssapi,
        })
    );
}
