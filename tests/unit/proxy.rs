use super::*;

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
