use super::*;
use std::{net::TcpListener, thread};

#[test]
fn empty_tls_read_does_not_start_a_handshake_or_touch_the_socket() {
    let listener = listener();
    let socket = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    socket.set_nonblocking(true).unwrap();
    let (mut peer, _) = listener.accept().unwrap();
    peer.set_nonblocking(true).unwrap();
    let connection = ClientConnection::new(
        tls_config().unwrap(),
        ServerName::try_from("localhost").unwrap(),
    )
    .unwrap();
    let mut stream = Stream::Tls(Box::new(StreamOwned::new(connection, socket)));
    assert_eq!(stream.read(&mut []).unwrap(), 0);
    assert_eq!(
        peer.read(&mut [0]).unwrap_err().kind(),
        io::ErrorKind::WouldBlock
    );
}
fn listener() -> TcpListener {
    TcpListener::bind("127.0.0.1:0").unwrap()
}

#[test]
fn ipv6_targets_use_socks_address_bytes_with_local_and_remote_resolution() {
    for protocol in ["socks5", "socks5h"] {
        let listener = listener();
        let proxy =
            Proxy::new(&format!("{protocol}://{}", listener.local_addr().unwrap())).unwrap();
        let server = thread::spawn(move || {
            let mut socket = accept(listener);
            let mut greeting = [0; 3];
            socket.read_exact(&mut greeting).unwrap();
            assert_eq!(greeting, [5, 1, 0]);
            socket.write_all(&[5, 0]).unwrap();
            let mut request = [0; 22];
            socket.read_exact(&mut request).unwrap();
            assert_eq!(&request[..4], &[5, 1, 0, 4]);
            assert_eq!(&request[4..20], &std::net::Ipv6Addr::LOCALHOST.octets());
            assert_eq!(&request[20..], &443u16.to_be_bytes());
            socket.write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 0]).unwrap();
        });
        let mut stream = connect_blocking("[::1]", 443, Some(proxy)).unwrap();
        assert_eq!(stream.read(&mut []).unwrap(), 0);
        server.join().unwrap();
    }
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
fn http_tunnel_preserves_buffered_data_and_large_payload() {
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
        let mut bytes = vec![0; expected.len()];
        s.read_exact(&mut bytes).unwrap();
        assert!(bytes == expected);
        s.write_all(&bytes).unwrap();
    });
    let mut stream = connect_blocking("does-not-resolve.invalid", 443, Some(proxy)).unwrap();
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
    assert!(read_bytes(&mut stream, payload.len()) == payload);
    server.join().unwrap();
}
#[test]
fn refused_proxy_never_connects_to_the_target_directly() {
    let target = listener();
    target.set_nonblocking(true).unwrap();
    let proxy_listener = listener();
    let proxy = Proxy::new(&format!("http://{}", proxy_listener.local_addr().unwrap())).unwrap();
    let server = thread::spawn(move || {
        let mut s = accept(proxy_listener);
        let _ = header(&mut s);
        s.write_all(b"HTTP/1.1 407 Proxy Authentication Required\r\n\r\n")
            .unwrap();
    });
    let result = connect_blocking(
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
#[test]
fn http_tunnels_reject_malformed_headers_and_bytes_after_an_early_terminator() {
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
            connect_blocking("does-not-resolve.invalid", 443, Some(proxy)).is_err(),
            "{reply:?}"
        );
        server.join().unwrap();
    }
}

#[test]
fn socks5h_authenticates_and_sends_the_unresolved_domain() {
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
    let mut s = connect_blocking("does-not-resolve.invalid", 5223, Some(proxy)).unwrap();
    assert_eq!(read_bytes(&mut s, 6), b"opaque");
    server.join().unwrap();
}
#[test]
fn socks4a_preserves_the_domain_and_user_id() {
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
    let mut s = connect_blocking("does-not-resolve.invalid", 443, Some(proxy)).unwrap();
    assert_eq!(read_bytes(&mut s, 2), b"ok");
    server.join().unwrap();
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
        ("localhost", tls_config().unwrap(), false),
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
            tcp_connect("127.0.0.1", address.port(), Duration::from_secs(5)).unwrap(),
            host,
            config,
        );
        if success {
            let mut stream = transport.unwrap();
            let proxy = Proxy::new("https://localhost:443").unwrap();
            http_connect(
                &mut stream,
                "does-not-resolve.invalid",
                443,
                &proxy,
                Duration::from_secs(5),
            )
            .unwrap();
            assert_eq!(read_bytes(&mut stream, 5), [0x16, 3, 3, 0, 2]);
        } else {
            assert!(transport.is_err());
        }
        server.join().unwrap();
    }
}

#[test]
fn every_successful_connect_status_starts_an_opaque_tunnel() {
    for status in [201, 204, 299] {
        let proxy_listener = listener();
        let proxy =
            Proxy::new(&format!("http://{}", proxy_listener.local_addr().unwrap())).unwrap();
        let server = thread::spawn(move || {
            let mut socket = accept(proxy_listener);
            header(&mut socket);
            write!(socket, "HTTP/1.1 {status} Tunnel ready\r\n\r\nopaque").unwrap();
        });
        let mut stream = connect_blocking("does-not-resolve.invalid", 443, Some(proxy)).unwrap();
        assert_eq!(read_bytes(&mut stream, 6), b"opaque");
        server.join().unwrap();
    }
}
