use super::*;
use libgssapi::{
    context::ServerCtx,
    credential::{Cred, CredUsage},
};
use std::{
    io::{Read, Write},
    net::TcpListener,
    process::Command,
    sync::Arc,
    thread,
    time::Duration,
};

fn header(stream: &mut impl Read) -> String {
    let mut bytes = Vec::new();
    while !bytes.ends_with(b"\r\n\r\n") {
        assert!(bytes.len() < 128 * 1024);
        let mut byte = [0];
        stream.read_exact(&mut byte).unwrap();
        bytes.push(byte[0]);
    }
    String::from_utf8(bytes).unwrap()
}

#[test]
fn invalid_tokens_and_unfinished_mutual_authentication_are_rejected() {
    let mut auth = Negotiate::new("Negotiate", "localhost").unwrap();
    assert!(
        auth.step(Some("not-base64!"))
            .unwrap_err()
            .to_string()
            .contains("token encoding")
    );
    assert!(auth.finish().is_err());
    assert!(Negotiate::new("Basic", "localhost").is_err());
}

#[test]
#[ignore = "isolated local MIT Kerberos realm; needs KDC/kinit test tools, no domain or external network"]
fn kerberos_authenticates_http_and_fdr_tunnels() {
    const NAME: &str = "proxy::negotiate::tests::kerberos_authenticates_http_and_fdr_tunnels";
    if std::env::var_os("ZALIVKA_KERBEROS_READY").is_none() {
        let status = Command::new("python3")
            .arg(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/support/kerberos.py"
            ))
            .env(
                "ZALIVKA_KERBEROS_TEST_BIN",
                std::env::current_exe().unwrap(),
            )
            .env("ZALIVKA_KERBEROS_TEST_NAME", NAME)
            .status()
            .unwrap();
        assert!(status.success());
        return;
    }
    for http in [false, true] {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            stream
                .set_write_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let name = Name::new(
                b"HTTP/127.0.0.1@ZALIVKA.TEST",
                Some(libgssapi::oid::GSS_NT_KRB5_PRINCIPAL),
            )
            .unwrap();
            let credential = Cred::acquire(Some(&name), None, CredUsage::Accept, None)
                .unwrap_or_else(|error| panic!("GSS acceptor credentials: {error}"));
            let mut context = ServerCtx::new(Some(credential));
            let first = header(&mut stream);
            assert!(first.starts_with("CONNECT "));
            assert!(!first.contains("Proxy-Authorization"));
            stream.write_all(b"HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Negotiate\r\nContent-Length: 0\r\n\r\n").unwrap();
            loop {
                let request = header(&mut stream);
                let token = request
                    .lines()
                    .find_map(|line| line.strip_prefix("Proxy-Authorization: Negotiate "))
                    .unwrap();
                let token = BASE64_STANDARD.decode(token).unwrap();
                let output = context.step(&token, None).unwrap();
                let token = output
                    .as_deref()
                    .map(|value| {
                        format!(
                            "Proxy-Authenticate: Negotiate {}\r\n",
                            BASE64_STANDARD.encode(value)
                        )
                    })
                    .unwrap_or_default();
                if context.is_complete() {
                    write!(stream, "HTTP/1.1 200 Connection established\r\n{token}\r\n").unwrap();
                    break;
                }
                write!(
                    stream,
                    "HTTP/1.1 407 Proxy Authentication Required\r\n{token}Content-Length: 0\r\n\r\n"
                )
                .unwrap();
            }
            if http {
                use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
                let config = rustls::ServerConfig::builder_with_provider(Arc::new(
                    oxitls_rustcrypto_provider::provider(),
                ))
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_no_client_auth()
                .with_single_cert(
                    vec![CertificateDer::from(
                        include_bytes!("../../fixtures/proxy/localhost.der").as_slice(),
                    )],
                    PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
                        include_bytes!("../../fixtures/proxy/localhost-key.der").to_vec(),
                    )),
                )
                .unwrap();
                let mut tls = rustls::StreamOwned::new(
                    rustls::ServerConnection::new(Arc::new(config)).unwrap(),
                    stream,
                );
                assert!(header(&mut tls).starts_with("GET /ticket HTTP/1.1"));
                tls.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK")
                    .unwrap();
                tls.flush().unwrap();
            } else {
                let mut bytes = [0; 4];
                stream.read_exact(&mut bytes).unwrap();
                assert_eq!(&bytes, b"PING");
                stream.write_all(b"PONG").unwrap();
            }
        });
        let proxy = ureq::Proxy::new(&format!("http://127.0.0.1:{}", address.port())).unwrap();
        if http {
            let config = ureq::Agent::config_builder()
                .proxy(None)
                .tls_config(crate::net::tls_config(
                    ureq::tls::RootCerts::new_with_certs(&[ureq::tls::Certificate::from_der(
                        include_bytes!("../../fixtures/proxy/localhost.der"),
                    )]),
                ))
                .build();
            let client = ureq::Agent::with_parts(
                config.clone(),
                crate::proxy::HttpConnector::new(config),
                ureq::unversioned::resolver::DefaultResolver::default(),
            );
            let request = ureq::http::Request::get("https://localhost/ticket")
                .body(Vec::new())
                .unwrap();
            let mut response = crate::net::send_http_via(&client, &request, Some(proxy)).unwrap();
            assert_eq!(response.body_mut().read_to_string().unwrap(), "OK");
        } else {
            let mut stream =
                crate::proxy::socket::connect_blocking("gs.apple.com", 443, Some(proxy)).unwrap();
            stream.write_all(b"PING").unwrap();
            let mut bytes = [0; 4];
            stream.read_exact(&mut bytes).unwrap();
            assert_eq!(&bytes, b"PONG");
        }
        server.join().unwrap();
    }
}
