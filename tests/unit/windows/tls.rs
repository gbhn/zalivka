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
fn native_tss_also_validates_apple_private_chain_at_the_capture_date() {
    let root = CertificateDer::from(
        include_bytes!("../../../certs/AppleIncRootCertificate.cer").as_slice(),
    );
    let verifier = verifier(Some(root)).unwrap();
    let leaf =
        CertificateDer::from(include_bytes!("../../fixtures/tss/gs-2026-04-28.der").as_slice());
    let intermediate = CertificateDer::from(
        include_bytes!("../../fixtures/tss/apple-server-auth-ca.der").as_slice(),
    );
    let now = UnixTime::since_unix_epoch(std::time::Duration::from_secs(1_792_454_400));
    let host = ServerName::try_from("gs.apple.com").unwrap();
    verifier
        .verify_server_cert(&leaf, std::slice::from_ref(&intermediate), &host, &[], now)
        .unwrap();
    let wrong = ServerName::try_from("wkms-public.apple.com").unwrap();
    assert!(
        verifier
            .verify_server_cert(&leaf, &[intermediate], &wrong, &[], now)
            .is_err()
    );
}

#[test]
fn native_tls_transport_exchanges_http_data_and_reuses_a_verified_connection() {
    use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
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
    let server_config = rustls::ServerConfig::builder_with_provider(Arc::new(
        oxitls_rustcrypto_provider::provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(
        vec![certificate.clone()],
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
            include_bytes!("../../fixtures/proxy/localhost-key.der").to_vec(),
        )),
    )
    .unwrap();
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
        let connection = rustls::ServerConnection::new(Arc::new(server_config)).unwrap();
        let mut stream = StreamOwned::new(connection, socket);
        for number in 1..=2 {
            let mut header = Vec::new();
            while !header.ends_with(b"\r\n\r\n") {
                let mut byte = [0];
                stream.read_exact(&mut byte).unwrap();
                header.push(byte[0]);
                assert!(header.len() < 8192);
            }
            assert!(
                String::from_utf8(header)
                    .unwrap()
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
