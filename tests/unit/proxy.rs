use super::*;
use std::io::{self, Read, Write};

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

#[test]
fn fdr_direct_connection_retains_short_read_timeout() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let uri = format!("https://{}/", listener.local_addr().unwrap())
        .parse()
        .unwrap();
    let mut tunnel = connect_via(&uri, None).unwrap();
    let (mut stream, _) = listener.accept().unwrap();
    let mut byte = [0];
    assert_eq!(
        tunnel.read(&mut byte).unwrap_err().kind(),
        io::ErrorKind::TimedOut
    );
    stream.write_all(b"x").unwrap();
    tunnel.read_exact(&mut byte).unwrap();
    assert_eq!(byte, *b"x");
}

#[test]
fn tunnel_hosts_cannot_change_authority_path_or_port() {
    for host in [
        "",
        "apple.com/other",
        "apple.com?x",
        "apple.com#fragment",
        "user@apple.com",
        "apple.com:80",
        "apple.com:443/path",
        "host\r\nInjected: x",
    ] {
        assert!(target_uri(host, 443).is_err(), "{host:?}");
    }
    assert!(target_uri("apple.com", 0).is_err());
    for host in ["apple.com", "127.0.0.1", "[::1]"] {
        assert_eq!(
            target_uri(host, 443).unwrap().authority().unwrap().as_str(),
            format!("{host}:443")
        );
    }
}
#[test]
fn proxy_environment_trims_addresses_and_falls_back_from_empty_uppercase_bypass() {
    let read = |name: &str| match name {
        "HTTPS_PROXY" => Some("  http://proxy.invalid:8080  ".into()),
        "NO_PROXY" => Some("  ".into()),
        "no_proxy" => Some(", ,gs.apple.com,,".into()),
        _ => None,
    };
    assert!(
        environment_proxy(&"https://gs.apple.com/".parse().unwrap(), read)
            .unwrap()
            .is_none()
    );
    assert_eq!(
        environment_proxy(&"https://mesu.apple.com/".parse().unwrap(), read)
            .unwrap()
            .unwrap()
            .host(),
        "proxy.invalid"
    );
}

#[test]
fn system_routes_preserve_order_explicit_direct_and_unspecified_socks_fallback() {
    let routes = routes_from_strings(vec![
        "http://one.example:3128".into(),
        "socks://two.example:1080".into(),
        "direct://".into(),
    ])
    .unwrap();
    assert_eq!(routes.len(), 4);
    assert_eq!(routes[0].as_ref().unwrap().host(), "one.example");
    assert_eq!(
        routes[1].as_ref().unwrap().protocol(),
        ureq::ProxyProtocol::Socks5h
    );
    assert_eq!(
        routes[2].as_ref().unwrap().protocol(),
        ureq::ProxyProtocol::Socks4A
    );
    assert!(routes[3].is_none());
    let socks = routes_from_strings(vec!["socks5://remote.example:1080".into()]).unwrap();
    assert_eq!(
        socks[0].as_ref().unwrap().protocol(),
        ureq::ProxyProtocol::Socks5h
    );
    assert!(routes_from_strings(vec![]).is_err());
    assert!(routes_from_strings(vec!["bad proxy address".into()]).is_err());
}

#[test]
fn pac_failover_only_retries_connection_failures_and_never_invents_direct() {
    let proxies = || {
        vec![
            Some(Proxy::new("http://one.example:1").unwrap()),
            Some(Proxy::new("http://two.example:2").unwrap()),
        ]
    };
    let mut calls = Vec::new();
    let result = try_routes(proxies(), |proxy| {
        let proxy = proxy.unwrap();
        calls.push(proxy.host().to_owned());
        if proxy.port() == 1 {
            Err(ConnectFailure(anyhow::anyhow!("connection refused")).into())
        } else {
            Ok(7)
        }
    })
    .unwrap();
    assert_eq!(result, 7);
    assert_eq!(calls, ["one.example", "two.example"]);
    calls.clear();
    let error = try_routes(proxies(), |proxy| {
        calls.push(proxy.unwrap().host().to_owned());
        Err::<(), _>(anyhow::anyhow!("POST already sent; response lost"))
    })
    .unwrap_err();
    assert_eq!(calls, ["one.example"]);
    assert!(error.to_string().contains("POST already sent"));
    let mut count = 0;
    assert!(
        try_routes(proxies(), |proxy| {
            assert!(proxy.is_some());
            count += 1;
            Err::<(), _>(ConnectFailure(anyhow::anyhow!("offline")).into())
        })
        .is_err()
    );
    assert_eq!(count, 2);
}

#[test]
fn fdr_uses_the_next_pac_proxy_without_resolving_or_inspecting_the_target() {
    use std::{net::TcpListener, thread, time::Duration};
    let offline = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = offline.local_addr().unwrap();
    drop(offline);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let available = listener.local_addr().unwrap();
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut header = Vec::new();
        while !header.ends_with(b"\r\n\r\n") {
            let mut byte = [0];
            stream.read_exact(&mut byte).unwrap();
            header.push(byte[0]);
            assert!(header.len() < 4096);
        }
        assert!(header.starts_with(b"CONNECT fdr.does-not-resolve.invalid:443 "));
        stream
            .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
            .unwrap();
        let mut bytes = [0; 4];
        stream.read_exact(&mut bytes).unwrap();
        assert_eq!(&bytes, b"PING");
        stream.write_all(b"PONG").unwrap();
    });
    let routes = routes_from_strings(vec![
        format!("http://{address}"),
        format!("http://{available}"),
    ])
    .unwrap();
    let uri = target_uri("fdr.does-not-resolve.invalid", 443).unwrap();
    let mut stream = try_routes(routes, |proxy| connect_via(&uri, proxy)).unwrap();
    stream.write_all(b"PING").unwrap();
    let mut bytes = [0; 4];
    stream.read_exact(&mut bytes).unwrap();
    assert_eq!(&bytes, b"PONG");
    server.join().unwrap();
}
