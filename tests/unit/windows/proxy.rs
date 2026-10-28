use super::*;
use std::{
    io::{Read, Write},
    net::TcpListener,
    thread,
    time::{Duration, Instant},
};

#[path = "fdr_lab.rs"]
mod fdr_lab;

fn pac_server(script: &str) -> (String, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let url = format!("http://{}/proxy.pac", listener.local_addr().unwrap());
    let script = script.to_owned();
    let server = thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut stream = loop {
            match listener.accept() {
                Ok((stream, _)) => break stream,
                Err(error)
                    if error.kind() == std::io::ErrorKind::WouldBlock
                        && Instant::now() < deadline =>
                {
                    thread::sleep(Duration::from_millis(10));
                }
                Err(error) => panic!("Windows did not request the PAC fixture: {error}"),
            }
        };
        stream.set_nonblocking(false).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut request = Vec::new();
        while !request.ends_with(b"\r\n\r\n") {
            let mut byte = [0];
            stream.read_exact(&mut byte).unwrap();
            request.push(byte[0]);
            assert!(request.len() < 65536);
        }
        write!(stream, "HTTP/1.1 200 OK\r\nContent-Type: application/x-ns-proxy-autoconfig\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{script}", script.len()).unwrap();
    });
    (url, server)
}

#[test]
fn native_pac_resolves_each_url_and_explicit_direct() {
    let (pac, server) = pac_server(
        r#"function FindProxyForURL(url, host) {
            if (host == "gs.apple.com") return "PROXY 127.0.0.1:3128";
            return "DIRECT";
        }"#,
    );
    let proxy = auto_proxy(
        &"https://gs.apple.com/TSS/controller?action=2"
            .parse()
            .unwrap(),
        false,
        &pac,
    )
    .unwrap()
    .unwrap();
    assert_eq!((proxy.host(), proxy.port()), ("127.0.0.1", 3128));
    server.join().unwrap();
    // A second destination uses the cached PAC, but reevaluates its rule.
    assert!(
        auto_proxy(
            &"https://updates.cdn-apple.com/file.ipsw".parse().unwrap(),
            false,
            &pac
        )
        .unwrap()
        .is_none()
    );
}

#[test]
fn native_invalid_pac_returns_an_error() {
    let (pac, server) = pac_server("this is not a valid PAC script");
    assert!(auto_proxy(&"https://gs.apple.com/".parse().unwrap(), false, &pac).is_err());
    server.join().unwrap();
}

#[test]
fn native_pac_choice_opens_an_fdr_tunnel_without_target_dns() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    listener.set_nonblocking(true).unwrap();
    let tunnel = thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut stream = loop {
            match listener.accept() {
                Ok((s, _)) => break s,
                Err(e)
                    if e.kind() == std::io::ErrorKind::WouldBlock && Instant::now() < deadline =>
                {
                    thread::sleep(Duration::from_millis(1))
                }
                Err(e) => panic!("PAC-selected proxy was not used: {e}"),
            }
        };
        stream.set_nonblocking(false).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut request = vec![];
        while !request.ends_with(b"\r\n\r\n") {
            let mut byte = [0];
            stream.read_exact(&mut byte).unwrap();
            request.push(byte[0]);
            assert!(request.len() < 16384);
        }
        assert!(request.starts_with(b"CONNECT does-not-resolve.invalid:443 HTTP/1.1\r\n"));
        stream.write_all(b"HTTP/1.1 200 OK\r\n\r\nPAC").unwrap();
    });
    let (pac, server) = pac_server(&format!(
        "function FindProxyForURL(url, host) {{ return 'PROXY {address}'; }}"
    ));
    let proxy = auto_proxy(
        &"https://does-not-resolve.invalid:443/".parse().unwrap(),
        false,
        &pac,
    )
    .unwrap();
    let mut stream =
        crate::proxy::socket::connect_blocking("does-not-resolve.invalid", 443, proxy).unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut reply = vec![];
    while reply.len() < 3 {
        assert!(Instant::now() < deadline);
        let mut bytes = [0; 3];
        match stream.read(&mut bytes) {
            Ok(0) => panic!("PAC tunnel closed before its reply"),
            Ok(n) => reply.extend_from_slice(&bytes[..n]),
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock
                        | std::io::ErrorKind::TimedOut
                        | std::io::ErrorKind::Interrupted
                ) =>
            {
                thread::sleep(Duration::from_millis(1))
            }
            Err(e) => panic!("PAC tunnel read failed: {e}"),
        }
    }
    assert_eq!(reply, b"PAC");
    server.join().unwrap();
    tunnel.join().unwrap();
}
