use super::*;
use rustls::pki_types::UnixTime;

#[test]
fn native_verifier_rejects_unknown_roots_and_validates_names_with_extra_roots() {
    let certificate =
        CertificateDer::from(include_bytes!("../../fixtures/proxy/localhost.der").as_slice());
    let host = ServerName::try_from("localhost").unwrap();
    let now = UnixTime::now();
    assert!(
        verifier(None)
            .unwrap()
            .verify_server_cert(&certificate, &[], &host, &[], now)
            .is_err()
    );
    let trusted = verifier(Some(certificate.clone())).unwrap();
    trusted
        .verify_server_cert(&certificate, &[], &host, &[], now)
        .unwrap();
    let other = ServerName::try_from("untrusted.example").unwrap();
    assert!(
        trusted
            .verify_server_cert(&certificate, &[], &other, &[], now)
            .is_err()
    );
}

#[test]
fn native_tls_transport_exchanges_http_data_and_reuses_a_verified_connection() {
    use std::{net::TcpListener, thread, time::Duration};
    use ureq::unversioned::transport::{Connector, TcpConnector};

    #[derive(Debug)]
    struct Client(Arc<ClientConfig>);
    impl Connector for Client {
        type Out = Box<dyn Transport>;
        fn connect(
            &self,
            details: &ConnectionDetails,
            chained: Option<()>,
        ) -> Result<Option<Self::Out>, ureq::Error> {
            let raw = TcpConnector::default()
                .connect(details, chained)?
                .ok_or(ureq::Error::ConnectionFailed)?;
            connect_with_config(details, raw.boxed(), self.0.clone()).map(Some)
        }
    }
    let certificate =
        CertificateDer::from(include_bytes!("../../fixtures/proxy/localhost.der").as_slice());
    let server_config = crate::test_net::tls_server_config();
    let client_config = config(Some(certificate)).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = thread::spawn(move || {
        let (socket, _) = listener.accept().unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        socket
            .set_write_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let connection = rustls::ServerConnection::new(server_config).unwrap();
        let mut stream = StreamOwned::new(connection, socket);
        for number in 1..=2 {
            assert!(
                crate::test_net::read_header(&mut stream)
                    .starts_with(&format!("GET /{number} HTTP/1.1"))
            );
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK")
                .unwrap();
            stream.flush().unwrap();
        }
    });
    let agent = ureq::Agent::with_parts(
        ureq::Agent::config_builder()
            .proxy(None)
            .tls_config(crate::net::tls_config(
                ureq::tls::RootCerts::PlatformVerifier,
            ))
            .build(),
        Client(client_config),
        ureq::unversioned::resolver::DefaultResolver::default(),
    );
    for number in 1..=2 {
        let mut response = agent
            .get(format!("https://localhost:{port}/{number}"))
            .call()
            .unwrap();
        assert_eq!(response.body_mut().read_to_string().unwrap(), "OK");
    }
    server.join().unwrap();
}

#[test]
fn tss_tls_validates_apple_chain_hostname_signature_and_expiration() {
    use rustls::pki_types::UnixTime;
    use std::time::Duration;
    let verifier = verifier(Some(CertificateDer::from(
        include_bytes!("../../../certs/AppleIncRootCertificate.cer").as_slice(),
    )))
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
    // Native chain engines may recover intermediates from their own cache.
    #[cfg(not(any(windows, target_os = "macos")))]
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
        super::super::agent().config().tls_config().root_certs(),
        ureq::tls::RootCerts::WebPki
    ));
    #[cfg(any(windows, target_os = "linux", target_os = "macos"))]
    assert!(matches!(
        super::super::agent().config().tls_config().root_certs(),
        ureq::tls::RootCerts::PlatformVerifier
    ));
}

#[test]
fn tss_does_not_inherit_a_trusted_https_proxys_certificate() {
    use std::{net::TcpListener, thread};

    let certificate = include_bytes!("../../fixtures/proxy/localhost.der");
    let server_config = crate::test_net::tls_server_config();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let server = thread::spawn(move || {
        let socket = crate::test_net::accept(&listener);
        let mut proxy = StreamOwned::new(
            rustls::ServerConnection::new(server_config.clone()).unwrap(),
            socket,
        );
        assert!(crate::test_net::read_header(&mut proxy).starts_with("CONNECT localhost:443 "));
        proxy
            .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
            .unwrap();
        proxy.flush().unwrap();
        // The proxy is trusted, but its certificate cannot authenticate the origin.
        let mut destination =
            StreamOwned::new(rustls::ServerConnection::new(server_config).unwrap(), proxy);
        assert!(destination.conn.complete_io(&mut destination.sock).is_err());
    });
    let proxy_config = ureq::Agent::config_builder()
        .proxy(None)
        .tls_config(crate::net::tls_config(
            ureq::tls::RootCerts::new_with_certs(&[ureq::tls::Certificate::from_der(certificate)]),
        ))
        .build();
    let client = crate::net::configured_agent(
        crate::net::tss_agent().config().clone(),
        crate::proxy::HttpConnector::for_tss(proxy_config),
    );
    let request = ureq::http::Request::get("https://localhost/ticket")
        .body(Vec::new())
        .unwrap();
    let proxy = ureq::Proxy::new(&format!("https://{address}")).unwrap();
    assert!(crate::net::send_http_via(&client, &request, Some(proxy)).is_err());
    server.join().unwrap();
}
