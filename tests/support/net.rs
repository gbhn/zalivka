//! Loopback helpers shared by HTTP, TLS and proxy unit tests.
use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose, PKCS_ECDSA_P256_SHA256,
};
use rustls::{
    ServerConfig,
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
};
use std::{
    io::{self, Read},
    net::{TcpListener, TcpStream},
    sync::{Arc, OnceLock},
    thread,
    time::{Duration, Instant},
};
use time::{Duration as Validity, OffsetDateTime};

struct Loopback {
    root: CertificateDer<'static>,
    leaf: CertificateDer<'static>,
    key: PrivateKeyDer<'static>,
}

/// macOS refuses to trust TLS server certificates with an over-long validity
/// period, reporting them as "not standards compliant". The loopback identity
/// is therefore minted for the current run instead of being checked in with a
/// fixed lifetime that either expires or violates Apple's 398-day limit.
fn loopback() -> &'static Loopback {
    static LOOPBACK: OnceLock<Loopback> = OnceLock::new();
    LOOPBACK.get_or_init(|| generate_loopback().expect("generating a loopback TLS identity"))
}

fn generate_loopback() -> Result<Loopback, rcgen::Error> {
    let now = OffsetDateTime::now_utc();
    // One year stays below Apple's 398-day limit for TLS server certificates.
    let not_before = now - Validity::minutes(5);
    let not_after = now + Validity::days(365);

    let mut authority_params = CertificateParams::new(Vec::new())?;
    authority_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    authority_params
        .distinguished_name
        .push(DnType::CommonName, "Zalivka loopback test root");
    authority_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    authority_params.not_before = not_before;
    authority_params.not_after = not_after;
    let authority_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
    let authority = authority_params.self_signed(&authority_key)?;

    let mut server_params =
        CertificateParams::new(vec!["localhost".to_owned(), "127.0.0.1".to_owned()])?;
    server_params
        .distinguished_name
        .push(DnType::CommonName, "localhost");
    server_params.is_ca = IsCa::ExplicitNoCa;
    server_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    server_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    server_params.use_authority_key_identifier_extension = true;
    server_params.not_before = not_before;
    server_params.not_after = not_after;
    let server_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
    let server = server_params.signed_by(
        &server_key,
        &Issuer::from_params(&authority_params, &authority_key),
    )?;

    Ok(Loopback {
        root: authority.der().clone(),
        leaf: server.der().clone(),
        key: PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(server_key.serialize_der())),
    })
}

/// Trust anchor for [`localhost_leaf`]; it is signed by this certificate.
pub fn localhost_root() -> CertificateDer<'static> {
    loopback().root.clone()
}

/// Server certificate presented by [`tls_server_config`] and validated as
/// `localhost` or `127.0.0.1`.
pub fn localhost_leaf() -> CertificateDer<'static> {
    loopback().leaf.clone()
}

pub fn tls_server_config() -> Arc<ServerConfig> {
    Arc::new(
        ServerConfig::builder_with_provider(Arc::new(oxitls_rustcrypto_provider::provider()))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![loopback().leaf.clone()], loopback().key.clone_key())
            .unwrap(),
    )
}

pub fn accept(listener: &TcpListener) -> TcpStream {
    listener.set_nonblocking(true).unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    let stream = loop {
        match listener.accept() {
            Ok((stream, _)) => break stream,
            Err(error)
                if error.kind() == io::ErrorKind::WouldBlock && Instant::now() < deadline =>
            {
                thread::sleep(Duration::from_millis(1));
            }
            Err(error) => panic!("local server accept failed: {error}"),
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

// Read only headers: a following HTTP body or tunneled bytes must remain unread.
pub fn read_header(stream: &mut impl Read) -> String {
    let mut bytes = Vec::new();
    while !bytes.ends_with(b"\r\n\r\n") {
        let mut byte = [0];
        stream.read_exact(&mut byte).unwrap();
        bytes.push(byte[0]);
        assert!(bytes.len() < 65536);
    }
    String::from_utf8(bytes).unwrap()
}
