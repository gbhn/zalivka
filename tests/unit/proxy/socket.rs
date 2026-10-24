use super::*;
use std::{net::TcpListener, thread};
fn listener() -> TcpListener {
    TcpListener::bind("127.0.0.1:0").unwrap()
}
fn accept(listener: TcpListener) -> TcpStream {
    listener.set_nonblocking(true).unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    let stream = loop {
        match listener.accept() {
            Ok((s, _)) => break s,
            Err(e) if e.kind() == io::ErrorKind::WouldBlock && Instant::now() < deadline => {
                thread::sleep(Duration::from_millis(1))
            }
            Err(e) => panic!("proxy accept failed: {e}"),
        }
    };
    stream.set_nonblocking(false).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    stream
        .set_write_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    stream
}
fn header(stream: &mut impl Read) -> String {
    let mut bytes = vec![];
    while !bytes.ends_with(b"\r\n\r\n") {
        let mut b = [0];
        stream.read_exact(&mut b).unwrap();
        bytes.push(b[0]);
        assert!(bytes.len() < 16384);
    }
    String::from_utf8(bytes).unwrap()
}
fn read_bytes(stream: &mut Stream, count: usize) -> Vec<u8> {
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut bytes = vec![];
    while bytes.len() < count {
        assert!(
            Instant::now() < deadline,
            "proxy read timed out: {} bytes",
            bytes.len()
        );
        stream.poll().unwrap();
        let mut out = vec![0; count - bytes.len()];
        match stream.read(&mut out) {
            Ok(0) => panic!("unexpected tunnel EOF"),
            Ok(n) => bytes.extend_from_slice(&out[..n]),
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock
                        | io::ErrorKind::TimedOut
                        | io::ErrorKind::Interrupted
                ) =>
            {
                thread::sleep(Duration::from_millis(1))
            }
            Err(e) => panic!("proxy read failed: {e}"),
        }
    }
    bytes
}
#[test]
fn http_tunnel_preserves_buffered_data_large_payload_and_half_close() {
    for connect in [connect_blocking, connect_via] {
        let proxy_listener = listener();
        let proxy = Proxy::new(&format!(
            "http://user:pass@{}",
            proxy_listener.local_addr().unwrap()
        ))
        .unwrap();
        let payload: Vec<_> = (0..262144).map(|n| (n % 251) as u8).collect();
        let expected = payload.clone();
        let server = thread::spawn(move || {
            let mut s = accept(proxy_listener);
            let h = header(&mut s);
            assert!(h.starts_with("CONNECT does-not-resolve.invalid:443 HTTP/1.1\r\n"));
            assert!(h.contains("Proxy-Authorization: Basic dXNlcjpwYXNz\r\n"));
            s.write_all(b"HTTP/1.1 200 Connection established\r\n\r\nhello")
                .unwrap();
            let mut bytes = vec![];
            s.read_to_end(&mut bytes).unwrap();
            assert!(bytes == expected);
            s.write_all(&bytes).unwrap();
        });
        let mut stream = connect("does-not-resolve.invalid", 443, Some(proxy)).unwrap();
        assert_eq!(read_bytes(&mut stream, 5), b"hello");
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut sent = 0;
        while sent < payload.len() {
            assert!(Instant::now() < deadline);
            match stream.write(&payload[sent..]) {
                Ok(n) => sent += n,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(1))
                }
                Err(e) => panic!("proxy write failed: {e}"),
            }
        }
        stream.shutdown_write().unwrap();
        assert!(read_bytes(&mut stream, payload.len()) == payload);
        server.join().unwrap();
    }
}
#[test]
fn refused_proxy_never_connects_to_the_target_directly() {
    for connect in [connect_blocking, connect_via] {
        let target = listener();
        target.set_nonblocking(true).unwrap();
        let proxy_listener = listener();
        let proxy =
            Proxy::new(&format!("http://{}", proxy_listener.local_addr().unwrap())).unwrap();
        let server = thread::spawn(move || {
            let mut s = accept(proxy_listener);
            let _ = header(&mut s);
            s.write_all(b"HTTP/1.1 407 Proxy Authentication Required\r\n\r\n")
                .unwrap();
        });
        let result = connect(
            "127.0.0.1",
            target.local_addr().unwrap().port(),
            Some(proxy),
        );
        assert!(result.err().unwrap().to_string().contains("407"));
        assert_eq!(
            target.accept().unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        server.join().unwrap();
    }
}
#[test]
fn http_tunnels_reject_malformed_headers_and_bytes_after_an_early_terminator() {
    for connect in [connect_blocking, connect_via] {
        for reply in [
            &b"NOT-HTTP 200 OK\r\n\r\n"[..],
            b"HTTP/1.2 200 OK\r\n\r\n",
            b"HTTP/1.1 0200 OK\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nInvalid Header: value\r\n\r\n",
            b"HTTP/1.1 200 OK\n\nopaque-target-bytes\r\n\r\n",
        ] {
            let proxy_listener = listener();
            let proxy =
                Proxy::new(&format!("http://{}", proxy_listener.local_addr().unwrap())).unwrap();
            let server = thread::spawn(move || {
                let mut stream = accept(proxy_listener);
                let _ = header(&mut stream);
                stream.write_all(reply).unwrap();
            });
            assert!(
                connect("does-not-resolve.invalid", 443, Some(proxy)).is_err(),
                "{reply:?}"
            );
            server.join().unwrap();
        }
    }
}

#[test]
fn socks5h_authenticates_and_sends_the_unresolved_domain() {
    for connect in [connect_blocking, connect_via] {
        let proxy_listener = listener();
        let proxy = Proxy::new(&format!(
            "socks5h://user:pass@{}",
            proxy_listener.local_addr().unwrap()
        ))
        .unwrap();
        let server = thread::spawn(move || {
            let mut s = accept(proxy_listener);
            let mut greeting = [0; 3];
            s.read_exact(&mut greeting).unwrap();
            assert_eq!(greeting, [5, 1, 2]);
            s.write_all(&[5, 2]).unwrap();
            let mut auth = [0; 11];
            s.read_exact(&mut auth).unwrap();
            assert_eq!(&auth, b"\x01\x04user\x04pass");
            s.write_all(&[1, 0]).unwrap();
            let mut head = [0; 5];
            s.read_exact(&mut head).unwrap();
            assert_eq!(&head[..4], &[5, 1, 0, 3]);
            let mut host = vec![0; head[4] as usize];
            s.read_exact(&mut host).unwrap();
            assert_eq!(host, b"does-not-resolve.invalid");
            let mut port = [0; 2];
            s.read_exact(&mut port).unwrap();
            assert_eq!(u16::from_be_bytes(port), 5223);
            s.write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 0]).unwrap();
            s.write_all(b"opaque").unwrap();
        });
        let mut s = connect("does-not-resolve.invalid", 5223, Some(proxy)).unwrap();
        assert_eq!(read_bytes(&mut s, 6), b"opaque");
        server.join().unwrap();
    }
}
#[test]
fn socks4a_preserves_the_domain_and_user_id() {
    for connect in [connect_blocking, connect_via] {
        let proxy_listener = listener();
        let proxy = Proxy::new(&format!(
            "socks4a://user@{}",
            proxy_listener.local_addr().unwrap()
        ))
        .unwrap();
        let server = thread::spawn(move || {
            let mut s = accept(proxy_listener);
            let mut request = [0; 8];
            s.read_exact(&mut request).unwrap();
            assert_eq!(request, [4, 1, 1, 187, 0, 0, 0, 1]);
            let mut bytes = vec![];
            for _ in 0..2 {
                loop {
                    let mut b = [0];
                    s.read_exact(&mut b).unwrap();
                    bytes.push(b[0]);
                    if b[0] == 0 {
                        break;
                    }
                }
            }
            assert_eq!(&bytes, b"user\0does-not-resolve.invalid\0");
            s.write_all(&[0, 90, 0, 0, 0, 0, 0, 0]).unwrap();
            s.write_all(b"ok").unwrap();
        });
        let mut s = connect("does-not-resolve.invalid", 443, Some(proxy)).unwrap();
        assert_eq!(read_bytes(&mut s, 2), b"ok");
        server.join().unwrap();
    }
}
#[test]
fn https_proxy_verifies_the_certificate_and_preserves_target_bytes() {
    use rustls::{
        ServerConfig, ServerConnection,
        pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
    };
    let cert = CertificateDer::from(include_bytes!("../../fixtures/proxy/localhost.der").to_vec());
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
        include_bytes!("../../fixtures/proxy/localhost-key.der").to_vec(),
    ));
    let server_config = Arc::new(
        ServerConfig::builder_with_provider(Arc::new(oxitls_rustcrypto_provider::provider()))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![cert.clone()], key)
            .unwrap(),
    );
    let mut roots = RootCertStore::empty();
    roots.add(cert).unwrap();
    let trusted = Arc::new(
        ClientConfig::builder_with_provider(Arc::new(oxitls_rustcrypto_provider::provider()))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    );
    for (host, config, success) in [
        ("localhost", trusted.clone(), true),
        ("wrong.invalid", trusted, false),
        ("localhost", tls_config(), false),
    ] {
        let l = listener();
        let address = l.local_addr().unwrap();
        let config_server = server_config.clone();
        let server = thread::spawn(move || {
            let mut tls =
                StreamOwned::new(ServerConnection::new(config_server).unwrap(), accept(l));
            while tls.conn.is_handshaking() {
                if tls.conn.complete_io(&mut tls.sock).is_err() {
                    return;
                }
            }
            if success {
                assert!(header(&mut tls).starts_with("CONNECT does-not-resolve.invalid:443"));
                tls.write_all(b"HTTP/1.1 200 OK\r\n\r\n\x16\x03\x03\x00\x02")
                    .unwrap();
                tls.flush().unwrap();
            }
        });
        let transport = tls_transport(
            tcp_connect("127.0.0.1", address.port(), TIMEOUT).unwrap(),
            host,
            config,
        );
        if success {
            let mut stream = Stream {
                transport: transport.unwrap(),
                shutdown_pending: false,
            };
            let proxy = Proxy::new("https://localhost:443").unwrap();
            http_connect(
                &mut stream,
                "does-not-resolve.invalid",
                443,
                &proxy,
                TIMEOUT,
            )
            .unwrap();
            stream.tcp().set_nonblocking(true).unwrap();
            assert_eq!(read_bytes(&mut stream, 5), [0x16, 3, 3, 0, 2]);
        } else {
            assert!(transport.is_err());
        }
        server.join().unwrap();
    }
}

impl Stream {
    pub(crate) fn from_tcp(stream: TcpStream) -> Self {
        Self {
            transport: Transport::Tcp(stream),
            shutdown_pending: false,
        }
    }
}
