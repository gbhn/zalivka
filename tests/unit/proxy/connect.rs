use super::*;
use std::io::{self, Cursor};

struct Script {
    input: Cursor<Vec<u8>>,
    output: Vec<u8>,
}
impl Script {
    fn new(input: impl AsRef<[u8]>) -> Self {
        Self {
            input: Cursor::new(input.as_ref().to_vec()),
            output: Vec::new(),
        }
    }
}
impl Read for Script {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        self.input.read(out)
    }
}
impl Write for Script {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        self.output.write(data)
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
impl Connection for Script {
    fn timeout(&mut self, _: Duration) -> Result<()> {
        Ok(())
    }
}

#[test]
fn negotiate_consumes_challenge_bodies_and_preserves_tunnel_bytes() {
    let proxy = Proxy::new("http://proxy.example:3128").unwrap();
    let mut stream = Script::new(concat!(
        "HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"example\", Negotiate\r\nContent-Length: 4\r\n\r\nbody",
        "HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Negotiate c2VydmVy\r\nTransfer-Encoding: chunked\r\n\r\n4;extension=x\r\nbody\r\n0\r\nX-Trace: test\r\n\r\n",
        "HTTP/1.1 200 Connection established\r\nProxy-Authenticate: Negotiate ZmluYWw=\r\nContent-Length: 10000\r\n\r\nopaque"
    ));
    let mut calls = Vec::new();
    handshake(
        &mut stream,
        ("wkms-public.apple.com", 443),
        &proxy,
        Duration::from_secs(1),
        |_| panic!("must use the same connection"),
        |scheme, token| {
            calls.push((scheme.to_owned(), token.map(str::to_owned)));
            Ok(if token == Some("ZmluYWw=") {
                ""
            } else {
                "Y2xpZW50"
            }
            .into())
        },
    )
    .unwrap();
    assert_eq!(
        calls,
        [
            ("Negotiate".into(), None),
            ("Negotiate".into(), Some("c2VydmVy".into())),
            ("Negotiate".into(), Some("ZmluYWw=".into()))
        ]
    );
    let requests = String::from_utf8(stream.output.clone()).unwrap();
    let first_end = requests.find("\r\n\r\n").unwrap();
    assert!(!requests[..first_end].contains("Proxy-Authorization:"));
    assert_eq!(
        requests
            .matches("Proxy-Authorization: Negotiate Y2xpZW50")
            .count(),
        2
    );
    let mut tail = String::new();
    stream.read_to_string(&mut tail).unwrap();
    assert_eq!(tail, "opaque");
}

#[test]
fn initial_close_reconnects_before_sspi_but_mid_handshake_close_fails() {
    let proxy = Proxy::new("http://proxy.example:3128").unwrap();
    let mut stream = Script::new(
        "HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Negotiate\r\nConnection: close\r\n\r\n",
    );
    let mut reconnects = 0;
    handshake(
        &mut stream,
        ("apple.com", 443),
        &proxy,
        Duration::from_secs(1),
        |_| {
            reconnects += 1;
            Ok(Script::new("HTTP/1.1 200 OK\r\n\r\n"))
        },
        |_, _| Ok("Y2xpZW50".into()),
    )
    .unwrap();
    assert_eq!(reconnects, 1);
    assert!(
        String::from_utf8(stream.output)
            .unwrap()
            .contains("Proxy-Authorization: Negotiate")
    );

    let mut stream = Script::new(concat!(
        "HTTP/1.1 407 Authentication Required\r\nProxy-Authenticate: NTLM\r\nContent-Length: 0\r\n\r\n",
        "HTTP/1.1 407 Authentication Required\r\nProxy-Authenticate: NTLM c2VydmVy\r\nConnection: close\r\n\r\n"
    ));
    let result = handshake(
        &mut stream,
        ("apple.com", 443),
        &proxy,
        Duration::from_secs(1),
        |_| panic!("must not continue an NTLM context on a different connection"),
        |_, _| Ok("Y2xpZW50".into()),
    );
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("persistent connections")
    );
}

#[test]
fn credentials_are_sent_only_for_offered_proxy_schemes_and_explicit_credentials_are_honored() {
    for (address, reply) in [
        (
            "http://proxy.example:3128",
            "HTTP/1.1 401 Authentication Required\r\nWWW-Authenticate: Negotiate\r\n\r\n",
        ),
        (
            "http://proxy.example:3128",
            "HTTP/1.1 407 Authentication Required\r\nProxy-Authenticate: Basic realm=\"one, Negotiate, two\"\r\n\r\n",
        ),
        (
            "http://user:password@proxy.example:3128",
            "HTTP/1.1 407 Authentication Required\r\nProxy-Authenticate: Negotiate\r\n\r\n",
        ),
    ] {
        let proxy = Proxy::new(address).unwrap();
        let mut stream = Script::new(reply);
        assert!(
            handshake(
                &mut stream,
                ("apple.com", 443),
                &proxy,
                Duration::from_secs(1),
                |_| panic!("must not reconnect"),
                |_, _| panic!("must not use default credentials")
            )
            .is_err()
        );
        assert!(
            !String::from_utf8(stream.output)
                .unwrap()
                .contains("Proxy-Authorization: Negotiate")
        );
    }
}

#[test]
fn refusal_and_malformed_framing_never_loop_or_expose_auth_tokens() {
    let proxy = Proxy::new("http://proxy.example:3128").unwrap();
    for body in [
        "Content-Length: 1\r\nContent-Length: 2\r\n\r\nxx",
        "Content-Length: 0\r\nTransfer-Encoding: chunked\r\n\r\n",
        "Transfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n\r\n",
        "Transfer-Encoding: gzip\r\n\r\n",
        "Content-Length: 1048577\r\n\r\n",
        "Transfer-Encoding: chunked\r\n\r\nffffffffffffffffffff\r\n",
    ] {
        let mut stream = Script::new(format!(
            "HTTP/1.1 407 Authentication Required\r\nProxy-Authenticate: Negotiate\r\n{body}"
        ));
        assert!(
            handshake(
                &mut stream,
                ("apple.com", 443),
                &proxy,
                Duration::from_secs(1),
                |_| panic!("must not reconnect"),
                |_, _| panic!("must reject framing before authenticating")
            )
            .is_err()
        );
    }
    let mut stream = Script::new(concat!(
        "HTTP/1.1 407 Authentication Required\r\nProxy-Authenticate: Negotiate\r\nContent-Length: 0\r\n\r\n",
        "HTTP/1.1 407 Authentication Required\r\nProxy-Authenticate: Negotiate\r\nContent-Length: 0\r\n\r\n"
    ));
    let error = handshake(
        &mut stream,
        ("apple.com", 443),
        &proxy,
        Duration::from_secs(1),
        |_| panic!("must not reconnect"),
        |_, _| Ok("c2VjcmV0".into()),
    )
    .unwrap_err()
    .to_string();
    assert!(error.contains("rejected current-user"));
    assert!(!error.contains("c2VjcmV0"));
}

#[test]
fn http10_keep_alive_preserves_authentication_and_exchanges_are_bounded() {
    let proxy = Proxy::new("http://proxy.example:3128").unwrap();
    let reply = "HTTP/1.0 407 Proxy Authentication Required\r\nProxy-Authenticate: Negotiate c2VydmVy\r\nConnection: unused, KeEp-ALive\r\nProxy-Connection: unused\r\nContent-Length: 0\r\nContent-Length: 00\r\n\r\n";
    let mut stream = Script::new(format!("{}HTTP/1.0 200 OK\r\n\r\n", reply.repeat(2)));
    let mut calls = 0;
    handshake(
        &mut stream,
        ("apple.com", 443),
        &proxy,
        Duration::from_secs(1),
        |_| panic!("HTTP/1.0 keep-alive must remain connected"),
        |_, _| {
            calls += 1;
            Ok("Y2xpZW50".into())
        },
    )
    .unwrap();
    assert_eq!(calls, 2);

    let mut stream = Script::new(reply.repeat(9));
    let mut calls = 0;
    let error = handshake(
        &mut stream,
        ("apple.com", 443),
        &proxy,
        Duration::from_secs(1),
        |_| panic!("must remain connected"),
        |_, _| {
            calls += 1;
            Ok("Y2xpZW50".into())
        },
    )
    .unwrap_err();
    assert!(error.to_string().contains("exceeded 8 exchanges"));
    assert_eq!(calls, 8);
    assert_eq!(
        String::from_utf8(stream.output)
            .unwrap()
            .matches("CONNECT ")
            .count(),
        8
    );
}
