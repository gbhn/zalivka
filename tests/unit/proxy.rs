use super::*;
use std::{
    net::{TcpListener, TcpStream},
    thread,
    time::Duration as StdDuration,
};

#[test]
fn environment_policy_is_scheme_specific_and_invalid_config_does_not_bypass() {
    let values = std::collections::HashMap::from([
        ("HTTP_PROXY", "http://web:8080"),
        ("HTTPS_PROXY", "socks5h://secure:1080"),
        ("ALL_PROXY", "http://fallback:3128"),
        ("NO_PROXY", "*.internal"),
    ]);
    let read = |name: &str| values.get(name).map(|v| v.to_string());
    for (url, host) in [
        ("http://external.invalid/", "web"),
        ("https://external.invalid/", "secure"),
    ] {
        assert_eq!(
            environment_proxy(&url.parse().unwrap(), read)
                .unwrap()
                .unwrap()
                .host(),
            host
        );
    }
    assert!(
        environment_proxy(&"https://host.internal/".parse().unwrap(), read)
            .unwrap()
            .is_none()
    );
    let invalid = |name: &str| (name == "HTTPS_PROXY").then(|| "invalid proxy address".to_owned());
    assert!(environment_proxy(&"https://external.invalid/".parse().unwrap(), invalid).is_err());
}

#[test]
fn tunnel_destination_selects_the_same_environment_and_windows_proxy() {
    let read = |name: &str| match name {
        "HTTP_PROXY" => Some("http://web:8080".to_owned()),
        "HTTPS_PROXY" => Some("http://secure:3128".to_owned()),
        _ => None,
    };
    for (port, expected) in [(80, "web"), (443, "secure"), (5223, "secure")] {
        let uri = target_uri("example.apple.com", port).unwrap();
        assert_eq!(uri.host(), Some("example.apple.com"));
        assert_eq!(uri.port_u16(), Some(port));
        assert_eq!(
            environment_proxy(&uri, read).unwrap().unwrap().host(),
            expected
        );
        assert_eq!(
            from_windows_list(&uri, "http=web:8080;https=secure:3128", "")
                .unwrap()
                .unwrap()
                .host(),
            expected
        );
    }
}

#[test]
fn windows_proxy_list_selects_destination_scheme_and_transport() {
    let uri: Uri = "https://gs.apple.com/TSS/controller?action=2"
        .parse()
        .unwrap();
    for (list, protocol, host, port) in [
        (
            "proxy.example:8080",
            ureq::ProxyProtocol::Http,
            "proxy.example",
            8080,
        ),
        (
            "http=web:80;https=secure:3128;socks=sock:1080",
            ureq::ProxyProtocol::Http,
            "secure",
            3128,
        ),
        (
            "HTTPS=https://secure:443",
            ureq::ProxyProtocol::Https,
            "secure",
            443,
        ),
        (
            "socks=sock:1080",
            ureq::ProxyProtocol::Socks4A,
            "sock",
            1080,
        ),
        (
            "socks5h://sock:1081",
            ureq::ProxyProtocol::Socks5h,
            "sock",
            1081,
        ),
        (
            "proxy1:80;proxy2:81",
            ureq::ProxyProtocol::Http,
            "proxy1",
            80,
        ),
    ] {
        let proxy = from_windows_list(&uri, list, "").unwrap().unwrap();
        assert_eq!(
            (proxy.protocol(), proxy.host(), proxy.port()),
            (protocol, host, port),
            "{list}"
        );
    }
    for list in ["", "DIRECT", "http=web:80;ftp=ftp:21"] {
        assert!(
            from_windows_list(&uri, list, "").unwrap().is_none(),
            "{list}"
        );
    }
    assert!(from_windows_list(&uri, "https=", "").is_err());
}

#[test]
fn windows_exceptions_honor_wildcards_scheme_port_and_local_names() {
    for (url, bypass, expected) in [
        ("https://gs.apple.com/", "*.APPLE.COM", true),
        ("https://gs.apple.com/", "gs.*.com:443", true),
        ("https://gs.apple.com/", "gs.apple.com:80", false),
        ("https://gs.apple.com/", "http://*.apple.com", false),
        ("https://gs.apple.com/", "https://gs.apple.com:443", true),
        ("https://gs.apple.com/", "gs.apple.?om", true),
        (
            "https://gs.apple.com/",
            "localhost;other.example *.cdn-apple.com",
            false,
        ),
        ("https://gs.apple.com/", "*", true),
        ("https://gs.apple.com/", "", false),
        ("https://intranet/", "<local>", true),
        ("https://gs.apple.com/", "<local>", false),
        ("https://[::1]/", "[::1]:443", true),
    ] {
        let uri = url.parse().unwrap();
        assert_eq!(windows_bypass(&uri, bypass), expected, "{url}: {bypass}");
        assert_eq!(
            from_windows_list(&uri, "proxy:80", bypass)
                .unwrap()
                .is_none(),
            expected
        );
    }
}

fn listener() -> TcpListener {
    TcpListener::bind("127.0.0.1:0").unwrap()
}

fn accept(listener: TcpListener) -> TcpStream {
    listener.set_nonblocking(true).unwrap();
    let deadline = std::time::Instant::now() + StdDuration::from_secs(5);
    let stream = loop {
        match listener.accept() {
            Ok((stream, _)) => break stream,
            Err(error)
                if error.kind() == io::ErrorKind::WouldBlock
                    && std::time::Instant::now() < deadline =>
            {
                thread::sleep(StdDuration::from_millis(10));
            }
            Err(error) => panic!("proxy test accept failed: {error}"),
        }
    };
    stream.set_nonblocking(false).unwrap();
    stream
        .set_read_timeout(Some(StdDuration::from_secs(5)))
        .unwrap();
    stream
}

#[test]
fn fdr_connect_tunnel_preserves_opaque_bytes_and_buffered_reply() {
    for port in [80, 443] {
        let listener = listener();
        let proxy = Proxy::new(&format!(
            "http://user:pass@{}",
            listener.local_addr().unwrap()
        ))
        .unwrap();
        let server = thread::spawn(move || {
            let mut stream = accept(listener);
            let mut headers = Vec::new();
            while !headers.ends_with(b"\r\n\r\n") {
                let mut byte = [0];
                stream.read_exact(&mut byte).unwrap();
                headers.push(byte[0]);
                assert!(headers.len() < 65536);
            }
            let headers = String::from_utf8(headers).unwrap();
            assert!(headers.starts_with(&format!(
                "CONNECT does-not-resolve.invalid:{port} HTTP/1.1\r\n"
            )));
            assert!(headers.contains("Proxy-Authorization: Basic dXNlcjpwYXNz\r\n"));
            stream
                .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n\x16\x03\x03\x00\x02")
                .unwrap();
            let mut bytes = [0; 5];
            stream.read_exact(&mut bytes).unwrap();
            assert_eq!(bytes, [0x16, 3, 1, 0, 0]);
        });
        let mut tunnel = connect_via(
            &target_uri("does-not-resolve.invalid", port).unwrap(),
            Some(proxy),
        )
        .unwrap();
        let mut bytes = [0; 5];
        tunnel.read_exact(&mut bytes).unwrap();
        assert_eq!(bytes, [0x16, 3, 3, 0, 2]);
        tunnel.write_all(&[0x16, 3, 1, 0, 0]).unwrap();
        server.join().unwrap();
    }
}

#[test]
fn fdr_socks5h_tunnel_sends_hostname_without_local_dns() {
    let listener = listener();
    let proxy = Proxy::new(&format!("socks5h://{}", listener.local_addr().unwrap())).unwrap();
    let server = thread::spawn(move || {
        let mut stream = accept(listener);
        let mut greeting = [0; 3];
        stream.read_exact(&mut greeting).unwrap();
        assert_eq!(greeting, [5, 1, 0]);
        stream.write_all(&[5, 0]).unwrap();
        let mut request = [0; 5];
        stream.read_exact(&mut request).unwrap();
        assert_eq!(&request[..4], &[5, 1, 0, 3]);
        let mut host = vec![0; request[4] as usize];
        stream.read_exact(&mut host).unwrap();
        assert_eq!(host, b"does-not-resolve.invalid");
        let mut port = [0; 2];
        stream.read_exact(&mut port).unwrap();
        assert_eq!(u16::from_be_bytes(port), 443);
        stream.write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 0]).unwrap();
        let mut data = [0; 3];
        stream.read_exact(&mut data).unwrap();
        assert_eq!(data, *b"FDR");
        stream.write_all(b"ACK").unwrap();
    });
    let mut tunnel = connect_via(
        &"https://does-not-resolve.invalid/".parse().unwrap(),
        Some(proxy),
    )
    .unwrap();
    tunnel.write_all(b"FDR").unwrap();
    let mut reply = [0; 3];
    tunnel.read_exact(&mut reply).unwrap();
    assert_eq!(reply, *b"ACK");
    server.join().unwrap();
}

#[test]
fn fdr_direct_connection_retains_short_read_timeout() {
    let listener = listener();
    let uri = format!("https://{}/", listener.local_addr().unwrap())
        .parse()
        .unwrap();
    let mut tunnel = connect_via(&uri, None).unwrap();
    let mut stream = accept(listener);
    let mut byte = [0];
    assert_eq!(
        tunnel.read(&mut byte).unwrap_err().kind(),
        io::ErrorKind::TimedOut
    );
    stream.write_all(b"x").unwrap();
    tunnel.read_exact(&mut byte).unwrap();
    assert_eq!(byte, *b"x");
}
