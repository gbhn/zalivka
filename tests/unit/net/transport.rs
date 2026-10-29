use super::*;

#[test]
fn pac_routes_fail_over_before_sending_a_post_and_do_not_replay_a_sent_post() {
    for lose_response in [false, true] {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let unused = TcpListener::bind("127.0.0.1:0").unwrap();
        let offline = unused.local_addr().unwrap();
        drop(unused);
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            if !lose_response {
                assert!(read_header(&mut stream).starts_with("CONNECT gs.apple.com:80 "));
                stream.write_all(b"HTTP/1.1 200 OK\r\n\r\n").unwrap();
            }
            assert!(read_header(&mut stream).starts_with("POST /TSS/controller HTTP/1.1"));
            let mut body = [0; 6];
            stream.read_exact(&mut body).unwrap();
            assert_eq!(&body, b"ticket");
            if !lose_response {
                stream
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK")
                    .unwrap();
            }
        });
        let guard = TcpListener::bind("127.0.0.1:0").unwrap();
        guard.set_nonblocking(true).unwrap();
        let uri = if lose_response {
            format!("http://{address}/TSS/controller")
        } else {
            "http://gs.apple.com/TSS/controller".into()
        };
        let proxy = |address| Some(ureq::Proxy::new(&format!("http://{address}")).unwrap());
        let routes = if lose_response {
            vec![None, proxy(guard.local_addr().unwrap())]
        } else {
            vec![proxy(offline), proxy(address)]
        };
        let client = agent();
        let request = Request::post(uri).body(b"ticket".to_vec()).unwrap();
        let response =
            crate::proxy::try_routes(routes, |proxy| send_http_via(&client, &request, proxy));
        if lose_response {
            assert!(response.is_err());
        } else {
            assert_eq!(response.unwrap().body_mut().read_to_string().unwrap(), "OK");
        }
        server.join().unwrap();
        assert_eq!(
            guard.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
    }
}

#[test]
fn destination_tls_and_connection_reuse_work_through_every_proxy_route() {
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

    let certificate = include_bytes!("../../fixtures/proxy/localhost.der");
    let server_config = Arc::new(
        rustls::ServerConfig::builder_with_provider(Arc::new(
            oxitls_rustcrypto_provider::provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![CertificateDer::from(certificate.as_slice())],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
                include_bytes!("../../fixtures/proxy/localhost-key.der").to_vec(),
            )),
        )
        .unwrap(),
    );

    fn serve_tls(stream: impl Read + Write, config: Arc<rustls::ServerConfig>) {
        let connection = rustls::ServerConnection::new(config).unwrap();
        let mut stream = rustls::StreamOwned::new(connection, stream);
        for number in 1..=2 {
            assert!(read_header(&mut stream).starts_with(&format!("GET /{number} HTTP/1.1")));
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK")
                .unwrap();
            stream.flush().unwrap();
        }
    }

    for route in [
        "direct",
        "http",
        "https",
        "socks5h",
        "http-bypass",
        "socks-bypass",
    ] {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let destination = format!("localhost:{}", address.port());
        let expected = destination.clone();
        let config = server_config.clone();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            stream
                .set_write_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            match route {
                "http" => {
                    assert!(read_header(&mut stream).starts_with(&format!("CONNECT {expected} ")));
                    stream.write_all(b"HTTP/1.1 200 OK\r\n\r\n").unwrap();
                    serve_tls(stream, config);
                }
                "https" => {
                    let connection = rustls::ServerConnection::new(config.clone()).unwrap();
                    let mut proxy = rustls::StreamOwned::new(connection, stream);
                    assert!(read_header(&mut proxy).starts_with(&format!("CONNECT {expected} ")));
                    proxy.write_all(b"HTTP/1.1 200 OK\r\n\r\n").unwrap();
                    proxy.flush().unwrap();
                    serve_tls(proxy, config);
                }
                "socks5h" => {
                    let mut greeting = [0; 3];
                    stream.read_exact(&mut greeting).unwrap();
                    assert_eq!(greeting, [5, 1, 0]);
                    stream.write_all(&[5, 0]).unwrap();
                    let mut target = [0; 16];
                    stream.read_exact(&mut target).unwrap();
                    assert_eq!(&target[..5], &[5, 1, 0, 3, 9]);
                    assert_eq!(&target[5..14], b"localhost");
                    assert_eq!(&target[14..], &address.port().to_be_bytes());
                    stream.write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 0]).unwrap();
                    serve_tls(stream, config);
                }
                _ => serve_tls(stream, config),
            }
        });
        let proxy = match route {
            "direct" => None,
            "http-bypass" | "socks-bypass" => Some(
                ureq::Proxy::builder(if route == "http-bypass" {
                    ureq::ProxyProtocol::Http
                } else {
                    ureq::ProxyProtocol::Socks5h
                })
                .host("does-not-resolve.invalid")
                .port(1)
                .no_proxy("localhost")
                .build()
                .unwrap(),
            ),
            _ => Some(ureq::Proxy::new(&format!("{route}://{address}")).unwrap()),
        };
        let config = agent_config(
            Some(Duration::from_secs(5)),
            ureq::tls::RootCerts::new_with_certs(&[ureq::tls::Certificate::from_der(certificate)]),
        );
        let client = configured_agent(config.clone(), crate::proxy::HttpConnector::new(config));
        for number in 1..=2 {
            let request = Request::get(format!("https://{destination}/{number}"))
                .body(Vec::new())
                .unwrap();
            let mut response = send_http_via(&client, &request, proxy.clone())
                .unwrap_or_else(|error| panic!("{route}: {error:#}"));
            assert_eq!(
                response.body_mut().read_to_string().unwrap(),
                "OK",
                "{route}"
            );
        }
        server.join().unwrap();
    }
}

#[test]
fn cancellation_interrupts_proxy_and_tls_handshakes_for_public_and_tss_clients() {
    use std::sync::mpsc;

    for tss in [false, true] {
        for route in ["direct-tls", "http", "https", "socks5h"] {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let address = listener.local_addr().unwrap();
            let (ready, receiving) = mpsc::channel();
            let server = thread::spawn(move || {
                let (mut stream, _) = listener.accept().unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                match route {
                    "http" => assert!(read_header(&mut stream).starts_with("CONNECT ")),
                    "socks5h" => {
                        let mut greeting = [0; 3];
                        stream.read_exact(&mut greeting).unwrap();
                        assert_eq!(greeting, [5, 1, 0]);
                    }
                    _ => {
                        let mut record = [0; 5];
                        stream.read_exact(&mut record).unwrap();
                        assert_eq!(record[0], 22); // TLS handshake record.
                    }
                }
                ready.send(()).unwrap();
                if let Err(error) = stream.read_to_end(&mut Vec::new()) {
                    assert!(
                        matches!(
                            error.kind(),
                            std::io::ErrorKind::ConnectionReset
                                | std::io::ErrorKind::ConnectionAborted
                        ),
                        "{route}: {error}"
                    );
                }
            });
            let context = crate::progress::Context::new(|_| {});
            let operation = context.clone();
            let (completed, finishing) = mpsc::channel();
            let worker = thread::spawn(move || {
                operation.run(|| {
                    let client = if tss { tss_agent() } else { agent() };
                    let (url, proxy) = if route == "direct-tls" {
                        (format!("https://{address}/"), None)
                    } else {
                        (
                            "https://does-not-resolve.invalid/".into(),
                            Some(ureq::Proxy::new(&format!("{route}://{address}")).unwrap()),
                        )
                    };
                    let request = Request::get(url).body(Vec::new()).unwrap();
                    completed
                        .send(send_http_via(&client, &request, proxy).is_err())
                        .unwrap();
                });
            });
            receiving.recv_timeout(Duration::from_secs(5)).unwrap();
            context.cancel();
            assert!(
                finishing.recv_timeout(Duration::from_secs(2)).unwrap(),
                "{route}; TSS={tss}"
            );
            worker.join().unwrap();
            server.join().unwrap();
        }
    }
}

#[test]
fn firmware_body_has_an_inactivity_timeout_and_retains_no_total_deadline() {
    let client = agent_with_body_timeout(None);
    assert_eq!(
        client.config().timeout_per_read(),
        Some(Duration::from_secs(120))
    );
    assert_eq!(client.config().timeouts().recv_body, None);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        read_header(&mut stream);
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\nx")
            .unwrap();
        let _ = stream.read(&mut [0]);
    });
    let request = Request::get(format!("http://{address}/firmware"))
        .body(())
        .unwrap();
    let request = client
        .configure_request(request)
        .timeout_per_read(Some(Duration::from_millis(50)))
        .build();
    let mut response = client.run(request).unwrap();
    let error = response
        .body_mut()
        .as_reader()
        .read_to_end(&mut Vec::new())
        .unwrap_err();
    assert!(retryable_download(&error.into()));
    drop(response);
    client.shutdown();
    server.join().unwrap();
}

#[test]
fn native_cancellation_interrupts_a_stalled_http_body_without_killing_the_process() {
    use std::sync::mpsc;
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let (ready, receiving) = mpsc::channel();
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        read_header(&mut stream);
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 1000\r\n\r\ndata")
            .unwrap();
        ready.send(()).unwrap();
        let _ = stream.read(&mut [0]);
    });
    let context = crate::progress::Context::new(|_| {});
    let operation = context.clone();
    let (completed, finishing) = mpsc::channel();
    let worker = thread::spawn(move || {
        operation.run(|| {
            let client = agent();
            let request = Request::get(format!("http://{address}/download"))
                .body(Vec::new())
                .unwrap();
            let result = send_http_via(&client, &request, None).and_then(|mut response| {
                response
                    .body_mut()
                    .as_reader()
                    .read_exact(&mut [0; 1000])
                    .map_err(anyhow::Error::from)
            });
            completed.send(result.is_err()).unwrap();
        });
    });
    receiving.recv_timeout(Duration::from_secs(5)).unwrap();
    context.cancel();
    assert!(finishing.recv_timeout(Duration::from_secs(2)).unwrap());
    worker.join().unwrap();
    server.join().unwrap();
}

#[cfg(windows)]
#[test]
fn http_requests_automatically_answer_negotiate_using_the_current_windows_user() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let proxy = ureq::Proxy::new(&format!("http://{}", listener.local_addr().unwrap())).unwrap();
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let first = read_header(&mut stream);
        assert!(first.starts_with("CONNECT apple.example:80 "));
        assert!(!first.to_lowercase().contains("proxy-authorization"));
        stream.write_all(b"HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Negotiate\r\nContent-Length: 0\r\n\r\n").unwrap();
        let retry = read_header(&mut stream);
        assert!(retry.contains("Proxy-Authorization: Negotiate "));
        assert!(!retry.contains("Proxy-Authorization: Basic"));
        stream
            .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
            .unwrap();
        let request = read_header(&mut stream);
        assert!(request.starts_with("GET /asset HTTP/1.1"));
        assert!(!request.to_lowercase().contains("proxy-authorization"));
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK")
            .unwrap();
    });
    let request = Request::get("http://apple.example/asset")
        .body(Vec::new())
        .unwrap();
    let mut reply = send_http_via(&agent(), &request, Some(proxy)).unwrap();
    assert_eq!(reply.body_mut().read_to_string().unwrap(), "OK");
    server.join().unwrap();
}

#[test]
fn https_proxy_uses_its_own_roots_with_tss_destination_trust() {
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    let certificate = include_bytes!("../../fixtures/proxy/localhost.der");
    let server_config = rustls::ServerConfig::builder_with_provider(Arc::new(
        oxitls_rustcrypto_provider::provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(
        vec![CertificateDer::from(certificate.as_slice())],
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
            include_bytes!("../../fixtures/proxy/localhost-key.der").to_vec(),
        )),
    )
    .unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let proxy = ureq::Proxy::new(&format!("https://{}", listener.local_addr().unwrap())).unwrap();
    let server = thread::spawn(move || {
        listener.set_nonblocking(true).unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        let stream = loop {
            match listener.accept() {
                Ok((stream, _)) => break stream,
                Err(error)
                    if error.kind() == std::io::ErrorKind::WouldBlock
                        && std::time::Instant::now() < deadline =>
                {
                    thread::sleep(Duration::from_millis(10));
                }
                Err(error) => panic!("HTTPS proxy accept failed: {error}"),
            }
        };
        stream.set_nonblocking(false).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let connection = rustls::ServerConnection::new(Arc::new(server_config)).unwrap();
        let mut stream = rustls::StreamOwned::new(connection, stream);
        for expected in ["CONNECT does-not-resolve.invalid:80 ", "POST /sign "] {
            assert!(read_header(&mut stream).starts_with(expected));
            if expected.starts_with("CONNECT") {
                stream
                    .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
                    .unwrap();
                stream.flush().unwrap();
            }
        }
        let mut body = [0; 4];
        stream.read_exact(&mut body).unwrap();
        assert_eq!(body, *b"sign");
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK")
            .unwrap();
        stream.flush().unwrap();
    });
    let tls = ureq::tls::TlsConfig::builder()
        .root_certs(ureq::tls::RootCerts::new_with_certs(&[
            ureq::tls::Certificate::from_der(certificate),
        ]))
        .unversioned_rustls_crypto_provider(Arc::new(oxitls_rustcrypto_provider::provider()))
        .build();
    let proxy_config = ureq::Agent::config_builder()
        .tls_config(tls)
        .proxy(None)
        .build();
    let client = ureq::Agent::with_parts(
        tss_agent().config().clone(),
        crate::proxy::HttpConnector::new(proxy_config),
        ureq::unversioned::resolver::DefaultResolver::default(),
    );
    let request = Request::post("http://does-not-resolve.invalid/sign")
        .body(b"sign".to_vec())
        .unwrap();
    let mut response = send_http_via(&client, &request, Some(proxy)).unwrap();
    assert_eq!(response.body_mut().read_to_string().unwrap(), "OK");
    server.join().unwrap();
}

#[test]
fn http_proxy_tunnels_get_post_and_range_requests() {
    for method in [Method::GET, Method::POST] {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let proxy =
            ureq::Proxy::new(&format!("http://{}", listener.local_addr().unwrap())).unwrap();
        listener.set_nonblocking(true).unwrap();
        let expected_method = method.clone();
        let server = thread::spawn(move || {
            let deadline = std::time::Instant::now() + Duration::from_secs(5);
            let mut stream = loop {
                match listener.accept() {
                    Ok((stream, _)) => break stream,
                    Err(error)
                        if error.kind() == std::io::ErrorKind::WouldBlock
                            && std::time::Instant::now() < deadline =>
                    {
                        thread::sleep(Duration::from_millis(10))
                    }
                    Err(error) => panic!("HTTP proxy accept failed: {error}"),
                }
            };
            stream.set_nonblocking(false).unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            assert!(
                read_header(&mut stream)
                    .to_ascii_lowercase()
                    .starts_with("connect does-not-resolve.invalid:80 http/1.1\r\n")
            );
            stream
                .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
                .unwrap();
            let headers = read_header(&mut stream).to_ascii_lowercase();
            assert!(headers.starts_with(
                &format!("{expected_method} /asset HTTP/1.1\r\n").to_ascii_lowercase()
            ));
            assert!(headers.contains("range: bytes=8-\r\n"));
            if expected_method == Method::POST {
                let mut body = [0; 4];
                stream.read_exact(&mut body).unwrap();
                assert_eq!(body, *b"sign");
            }
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nreply",
                )
                .unwrap();
        });
        let body = if method == Method::POST {
            b"sign".to_vec()
        } else {
            vec![]
        };
        let request = Request::builder()
            .method(method)
            .uri("http://does-not-resolve.invalid/asset")
            .header("Range", "bytes=8-")
            .body(body)
            .unwrap();
        let mut response = send_http_via(&agent(), &request, Some(proxy)).unwrap();
        assert_eq!(response.body_mut().read_to_string().unwrap(), "reply");
        server.join().unwrap();
    }
}

#[test]
fn tss_tls_validates_apple_chain_hostname_signature_and_expiration() {
    use rustls::{
        RootCertStore,
        client::WebPkiServerVerifier,
        client::danger::ServerCertVerifier,
        pki_types::{CertificateDer, ServerName, UnixTime},
    };
    let agent = tss_agent();
    let tls = agent.config().tls_config();
    assert!(!tls.disable_verification());
    assert!(tls.use_sni());
    let ureq::tls::RootCerts::Specific(certificates) = tls.root_certs() else {
        panic!("TSS must use its explicit Apple trust anchor");
    };
    let mut roots = RootCertStore::empty();
    for certificate in certificates.iter() {
        roots.add(CertificateDer::from(certificate.der())).unwrap();
    }
    let verifier = WebPkiServerVerifier::builder_with_provider(
        Arc::new(roots),
        Arc::new(oxitls_rustcrypto_provider::provider()),
    )
    .build()
    .unwrap();
    let leaf =
        CertificateDer::from(include_bytes!("../../fixtures/tss/gs-2026-04-28.der").as_slice());
    let intermediates = [CertificateDer::from(
        include_bytes!("../../fixtures/tss/apple-server-auth-ca.der").as_slice(),
    )];
    let host = ServerName::try_from("gs.apple.com").unwrap();
    // Fixed capture date: this fixture remains reproducible after the leaf expires.
    let now = UnixTime::since_unix_epoch(Duration::from_secs(1_792_454_400));
    verifier
        .verify_server_cert(&leaf, &intermediates, &host, &[], now)
        .unwrap();
    let wrong_host = ServerName::try_from("updates.cdn-apple.com").unwrap();
    assert!(
        verifier
            .verify_server_cert(&leaf, &intermediates, &wrong_host, &[], now)
            .is_err()
    );
    assert!(
        verifier
            .verify_server_cert(&leaf, &[], &host, &[], now)
            .is_err()
    );
    let mut tampered = leaf.to_vec();
    *tampered.last_mut().unwrap() ^= 1;
    assert!(
        verifier
            .verify_server_cert(&tampered.into(), &intermediates, &host, &[], now)
            .is_err()
    );
    let expired = UnixTime::since_unix_epoch(Duration::from_secs(1_794_528_000));
    assert!(
        verifier
            .verify_server_cert(&leaf, &intermediates, &host, &[], expired)
            .is_err()
    );
    // This extra root must never broaden the normal CDN/asset trust configuration.
    #[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
    assert!(matches!(
        super::agent().config().tls_config().root_certs(),
        ureq::tls::RootCerts::WebPki
    ));
    #[cfg(any(windows, target_os = "linux", target_os = "macos"))]
    assert!(matches!(
        super::agent().config().tls_config().root_certs(),
        ureq::tls::RootCerts::PlatformVerifier
    ));
}

#[test]
#[ignore = "requires HTTPS access to Apple's TSS; no USB or signing request"]
fn live_tss_https_uses_verified_apple_private_pki() {
    let request = Request::get("https://gs.apple.com/TSS/controller?action=2")
        .body(vec![])
        .unwrap();
    let response = super::send_http(&tss_agent(), &request).unwrap();
    println!(
        "Apple TSS TLS certificate and hostname verified; HTTP {}",
        response.status()
    );
}

#[test]
fn redirects_resolve_relative_paths_queries_and_only_allow_apple_https() {
    let base = "https://updates.cdn-apple.com/a/b/file?old=1";
    for (location, expected) in [
        ("next", "https://updates.cdn-apple.com/a/b/next"),
        (
            "../next?new=1",
            "https://updates.cdn-apple.com/a/next?new=1",
        ),
        ("../../../../next", "https://updates.cdn-apple.com/next"),
        ("./", "https://updates.cdn-apple.com/a/b/"),
        (".", "https://updates.cdn-apple.com/a/b/"),
        ("..", "https://updates.cdn-apple.com/a/"),
        ("", base),
        ("../../../..", "https://updates.cdn-apple.com/"),
        ("/a//b/../c", "https://updates.cdn-apple.com/a//c"),
        (
            "/a/%2e%2e/%2F?x=%23",
            "https://updates.cdn-apple.com/a/%2e%2e/%2F?x=%23",
        ),
        (
            "/absolute/./path/../file",
            "https://updates.cdn-apple.com/absolute/file",
        ),
        (
            "?new=2#fragment",
            "https://updates.cdn-apple.com/a/b/file?new=2",
        ),
        ("#fragment", base),
        ("//gs.apple.com/key", "https://gs.apple.com/key"),
        ("https://gs.apple.com/key", "https://gs.apple.com/key"),
        (
            "%2e%2e/next",
            "https://updates.cdn-apple.com/a/b/%2e%2e/next",
        ),
        (
            ".%2E/next?x=%2f",
            "https://updates.cdn-apple.com/a/b/.%2E/next?x=%2f",
        ),
        ("%2E./next", "https://updates.cdn-apple.com/a/b/%2E./next"),
        (
            "https://gs.apple.com/a/../key?x=%23",
            "https://gs.apple.com/key?x=%23",
        ),
    ] {
        assert_eq!(
            redirect_url(base, location).unwrap(),
            expected,
            "{location}"
        );
    }
    for location in [
        "http://gs.apple.com/key",
        "//evil.invalid/key",
        "https://apple.com.evil.invalid/key",
        "https://gs.apple.com:8443/key",
        "https://user:password@gs.apple.com/key",
        "/invalid%zz/key",
        "\\\\gs.apple.com/key",
        "file:///tmp/firmware",
    ] {
        assert!(redirect_url(base, location).is_err(), "{location}");
    }
}

#[test]
fn post_redirects_preserve_307_payload_and_drop_credentials_on_host_change() {
    let original = Request::post("https://gs.apple.com/key")
        .header("Authorization", "test-secret")
        .header("Cookie", "test-cookie")
        .header("Content-Type", "application/octet-stream")
        .header("Content-Length", "3")
        .header("Content-Encoding", "gzip")
        .header("Expect", "100-continue")
        .body(vec![0, 1, 255])
        .unwrap();
    let mut request = original.clone();
    redirect_request(&mut request, StatusCode::TEMPORARY_REDIRECT, "next").unwrap();
    assert_eq!(request.method(), Method::POST);
    assert_eq!(request.body(), original.body());
    assert!(request.headers().contains_key("authorization"));
    assert_eq!(request.headers()["content-length"], "3");
    assert_eq!(request.headers()["content-encoding"], "gzip");
    redirect_request(
        &mut request,
        StatusCode::TEMPORARY_REDIRECT,
        "https://GS.APPLE.COM:443/next",
    )
    .unwrap();
    assert!(request.headers().contains_key("authorization"));
    redirect_request(
        &mut request,
        StatusCode::PERMANENT_REDIRECT,
        "https://updates.cdn-apple.com/key",
    )
    .unwrap();
    assert_eq!(request.method(), Method::POST);
    assert_eq!(request.body(), original.body());
    assert!(!request.headers().contains_key("authorization"));
    assert!(!request.headers().contains_key("cookie"));
    for status in [
        StatusCode::MOVED_PERMANENTLY,
        StatusCode::FOUND,
        StatusCode::SEE_OTHER,
    ] {
        let mut request = original.clone();
        redirect_request(&mut request, status, "/result").unwrap();
        assert_eq!(request.method(), Method::GET);
        assert!(request.body().is_empty());
        assert!(!request.headers().contains_key("content-type"));
        for name in ["content-length", "content-encoding", "expect"] {
            assert!(!request.headers().contains_key(name));
        }
    }
}
#[test]
fn apple_hostnames_require_valid_dns_labels() {
    for host in [
        ".apple.com",
        "x..apple.com",
        "-x.apple.com",
        "x-.apple.com",
        "_.apple.com",
    ] {
        assert!(
            super::validate_apple_url(&format!("https://{host}/")).is_err(),
            "{host}"
        );
    }
    assert!(super::validate_apple_url(&format!("https://{}.apple.com/", "a".repeat(64))).is_err());
    for host in ["apple.com", "a-b.apple.com", "updates.cdn-apple.com"] {
        super::validate_apple_url(&format!("https://{host}/")).unwrap();
    }
}
