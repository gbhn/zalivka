//! Shared proxy policy for HTTP requests and the opaque restoreOS FDR tunnel.
use anyhow::{Context, Result};
use std::{
    io::{self, Read, Write},
    sync::Arc,
};
use ureq::unversioned::{
    resolver::{DefaultResolver, Resolver},
    transport::{
        ConnectProxyConnector, ConnectionDetails, Connector, DefaultConnector, NextTimeout,
        SocksConnector, TcpConnector, Transport, TransportAdapter,
        time::{Duration, Instant},
    },
};
use ureq::{Proxy, http::Uri};

pub(crate) mod socket;

pub(crate) fn for_url(uri: &Uri) -> Result<Option<Proxy>> {
    #[cfg(windows)]
    if let Some(proxy) = crate::windows::proxy::for_url(uri)? {
        // An explicit DIRECT/PAC bypass must also bypass environment proxies.
        return Ok(proxy);
    }
    environment_proxy(uri, |name| std::env::var(name).ok())
}

fn environment_proxy(uri: &Uri, read: impl Fn(&str) -> Option<String>) -> Result<Option<Proxy>> {
    let names = if uri.scheme_str() == Some("http") {
        ["HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy"]
    } else {
        ["HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy"]
    };
    let Some((name, address)) = names.iter().find_map(|name| {
        read(name)
            .filter(|v| !v.trim().is_empty())
            .map(|value| (name, value))
    }) else {
        return Ok(None);
    };
    let proxy = Proxy::new(&address)
        .with_context(|| format!("invalid {name}; direct fallback is disabled"))?;
    let mut builder = Proxy::builder(proxy.protocol())
        .host(proxy.host())
        .port(proxy.port())
        .resolve_target(proxy.resolve_target());
    if let Some(user) = proxy.username() {
        builder = builder.username(user);
    }
    if let Some(password) = proxy.password() {
        builder = builder.password(password);
    }
    if let Some(bypass) = read("NO_PROXY").or_else(|| read("no_proxy")) {
        for pattern in bypass.split(',') {
            builder = builder.no_proxy(pattern.trim());
        }
    }
    let proxy = builder.build()?;
    Ok((!proxy.is_no_proxy(uri)).then_some(proxy))
}

/// Keep the HTTPS proxy's trust roots separate from Apple's private TSS PKI.
#[derive(Debug)]
pub(crate) struct HttpConnector {
    target: DefaultConnector,
    proxy_config: Arc<ureq::config::Config>,
}

impl HttpConnector {
    pub(crate) fn new(proxy_config: ureq::config::Config) -> Self {
        Self {
            target: DefaultConnector::default(),
            proxy_config: Arc::new(proxy_config),
        }
    }
}

impl Connector for HttpConnector {
    type Out = Box<dyn Transport>;

    fn connect(
        &self,
        details: &ConnectionDetails,
        chained: Option<()>,
    ) -> Result<Option<Self::Out>, ureq::Error> {
        let proxy_config = self.proxy_config.clone();
        let target_details = ConnectionDetails {
            uri: details.uri,
            addrs: details.addrs.clone(),
            config: details.config,
            request_level: details.request_level,
            resolver: details.resolver,
            now: details.now,
            timeout: details.timeout,
            current_time: details.current_time.clone(),
            run_connector: Arc::new(move |details| {
                let proxy_details = ConnectionDetails {
                    uri: details.uri,
                    addrs: details.addrs.clone(),
                    config: &proxy_config,
                    request_level: true,
                    resolver: details.resolver,
                    now: details.now,
                    timeout: details.timeout,
                    current_time: details.current_time.clone(),
                    run_connector: details.run_connector.clone(),
                };
                DefaultConnector::default()
                    .connect(&proxy_details, None)?
                    .ok_or(ureq::Error::ConnectionFailed)
            }),
        };
        self.target.connect(&target_details, chained)
    }
}

pub(crate) fn connect(host: &str, port: u16) -> Result<Tunnel> {
    let uri: Uri = format!("https://{host}:{port}/").parse()?;
    connect_via(&uri, for_url(&uri)?)
}

fn connect_via(uri: &Uri, proxy: Option<Proxy>) -> Result<Tunnel> {
    // Reuse ureq's HTTP(S) CONNECT and SOCKS implementations. The target TLS
    // session belongs to restoreOS: only TLS to an HTTPS proxy is terminated here.
    let config = ureq::Agent::config_builder()
        .tls_config(crate::net::agent().config().tls_config().clone())
        .proxy(proxy)
        .build();
    let resolver = DefaultResolver::default();
    let timeout = NextTimeout {
        after: Duration::from_secs(30),
        reason: ureq::Timeout::Connect,
    };
    let addrs = if config.proxy().is_none_or(|p| p.resolve_target()) {
        resolver.resolve(uri, &config, timeout)?
    } else {
        // Domain names are resolved by CONNECT/SOCKS4a/SOCKS5h proxies.
        resolver.empty()
    };
    let details = ConnectionDetails {
        uri,
        addrs,
        config: &config,
        request_level: false,
        resolver: &resolver,
        now: Instant::now(),
        timeout,
        current_time: Arc::new(Instant::now),
        run_connector: Arc::new(|details| {
            DefaultConnector::default()
                .connect(details, None)?
                .ok_or(ureq::Error::ConnectionFailed)
        }),
    };
    let transport =
        ().chain(SocksConnector::default())
            .chain(ConnectProxyConnector::default())
            .chain(TcpConnector::default())
            .connect(&details, None)?
            .context("proxy did not establish an FDR tunnel")?;
    Ok(Tunnel(TransportAdapter::new(transport.boxed())))
}

pub(crate) struct Tunnel(TransportAdapter);

impl Read for Tunnel {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.0.set_timeout(NextTimeout {
            after: Duration::from_millis(100),
            reason: ureq::Timeout::RecvBody,
        });
        self.0.read(buffer).map_err(|error| {
            if matches!(
                error
                    .get_ref()
                    .and_then(|e| e.downcast_ref::<ureq::Error>()),
                Some(ureq::Error::Timeout(_))
            ) {
                io::Error::new(io::ErrorKind::TimedOut, error)
            } else {
                error
            }
        })
    }
}

impl Write for Tunnel {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        self.0.set_timeout(NextTimeout {
            after: Duration::from_secs(30),
            reason: ureq::Timeout::SendBody,
        });
        self.0.write(buffer)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.0.flush()
    }
}

/// Windows proxy lists distinguish the destination scheme (https=) from the
/// proxy transport (http://). A SOCKS entry is the fallback for other schemes.
#[cfg(any(windows, test))]
pub(crate) fn from_windows_list(uri: &Uri, list: &str, bypass: &str) -> Result<Option<Proxy>> {
    if windows_bypass(uri, bypass) {
        return Ok(None);
    }
    let entries: Vec<_> = list
        .split(|c: char| c == ';' || c.is_whitespace())
        .filter(|entry| !entry.is_empty())
        .collect();
    let scheme = uri
        .scheme_str()
        .context("proxy destination has no scheme")?;
    let selected = entries
        .iter()
        .find_map(|entry| {
            let (key, value) = entry.split_once('=')?;
            key.eq_ignore_ascii_case(scheme).then_some((value, false))
        })
        .or_else(|| {
            entries
                .iter()
                .find(|entry| !entry.contains('='))
                .map(|entry| (*entry, false))
        })
        .or_else(|| {
            entries.iter().find_map(|entry| {
                let (key, value) = entry.split_once('=')?;
                key.eq_ignore_ascii_case("socks").then_some((value, true))
            })
        });
    let Some((server, socks)) = selected else {
        return Ok(None);
    };
    if server.eq_ignore_ascii_case("DIRECT") {
        return Ok(None);
    }
    let server = if server.contains("://") {
        server.to_owned()
    } else {
        format!("{}://{server}", if socks { "socks4a" } else { "http" })
    };
    Ok(Some(
        Proxy::new(&server).context("invalid Windows proxy address")?,
    ))
}

#[cfg(any(windows, test))]
fn windows_bypass(uri: &Uri, bypass: &str) -> bool {
    let host = uri.host().unwrap_or("").to_ascii_lowercase();
    let port = uri
        .port_u16()
        .unwrap_or(if uri.scheme_str() == Some("https") {
            443
        } else {
            80
        });
    let address = format!("{host}:{port}");
    bypass
        .split(|c: char| c == ';' || c.is_whitespace())
        .any(|pattern| {
            let pattern = pattern.to_ascii_lowercase();
            if pattern == "<local>" {
                return !host.contains(['.', ':']);
            }
            let pattern = if let Some((scheme, pattern)) = pattern.split_once("://") {
                if Some(scheme) != uri.scheme_str() {
                    return false;
                }
                pattern
            } else {
                &pattern
            };
            !pattern.is_empty()
                && (wildcard(pattern.as_bytes(), host.as_bytes())
                    || wildcard(pattern.as_bytes(), address.as_bytes()))
        })
}

#[cfg(any(windows, test))]
fn wildcard(pattern: &[u8], text: &[u8]) -> bool {
    let (mut p, mut t, mut star) = (0, 0, None);
    while t < text.len() {
        if p < pattern.len() && (pattern[p] == b'?' || pattern[p] == text[t]) {
            p += 1;
            t += 1;
        } else if p < pattern.len() && pattern[p] == b'*' {
            star = Some((p, t));
            p += 1;
        } else if let Some((s, last)) = star {
            t = last + 1;
            star = Some((s, t));
            p = s + 1;
        } else {
            return false;
        }
    }
    pattern[p..].iter().all(|b| *b == b'*')
}

#[cfg(test)]
#[path = "../tests/unit/proxy.rs"]
mod tests;
