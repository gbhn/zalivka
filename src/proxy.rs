//! Shared proxy policy for HTTP requests and the opaque restoreOS FDR tunnel.
use anyhow::{Context, Result, ensure};
use std::{
    io::{self, Read, Write},
    sync::Arc,
};
use ureq::unversioned::transport::{ConnectionDetails, Connector, DefaultConnector, Transport};
use ureq::{Proxy, http::Uri};

mod connect;
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
    let proxy = Proxy::new(address.trim())
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
    if let Some(bypass) = read("NO_PROXY")
        .filter(|value| !value.trim().is_empty())
        .or_else(|| read("no_proxy"))
    {
        for pattern in bypass
            .split(',')
            .map(str::trim)
            .filter(|value| !value.is_empty())
        {
            builder = builder.no_proxy(pattern);
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
    #[cfg(windows)]
    windows_tss: bool,
}

impl HttpConnector {
    pub(crate) fn new(proxy_config: ureq::config::Config) -> Self {
        Self {
            target: DefaultConnector::default(),
            proxy_config: Arc::new(proxy_config),
            #[cfg(windows)]
            windows_tss: false,
        }
    }

    #[cfg(windows)]
    pub(crate) fn for_tss(proxy_config: ureq::config::Config) -> Self {
        Self {
            windows_tss: true,
            ..Self::new(proxy_config)
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
        if chained.is_none()
            && let Some(proxy) = details.config.proxy()
            && matches!(
                proxy.protocol(),
                ureq::ProxyProtocol::Http | ureq::ProxyProtocol::Https
            )
            && !proxy.is_no_proxy(details.uri)
        {
            return self.connect_http(details, proxy).map(Some);
        }
        #[cfg(windows)]
        if self.windows_tss && details.needs_tls() {
            // HTTP proxies were handled above. Remaining paths are direct or
            // SOCKS; establish their transport before native TSS TLS validation.
            use ureq::unversioned::transport::{SocksConnector, TcpConnector};
            let raw =
                ().chain(SocksConnector::default())
                    .chain(TcpConnector::default())
                    .connect(details, None)?
                    .ok_or(ureq::Error::ConnectionFailed)?;
            return crate::windows::tls::connect_tss(details, raw.boxed()).map(Some);
        }
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

impl HttpConnector {
    fn connect_http(
        &self,
        details: &ConnectionDetails,
        proxy: &Proxy,
    ) -> Result<Box<dyn Transport>, ureq::Error> {
        use std::time::Duration;
        use ureq::unversioned::transport::{RustlsConnector, TransportAdapter};
        let timeout = details
            .timeout
            .not_zero()
            .map(|duration| *duration)
            .unwrap_or(Duration::from_secs(30));
        let make = |remaining: Duration| -> anyhow::Result<_> {
            let timeout = ureq::unversioned::transport::NextTimeout {
                after: remaining.into(),
                reason: details.timeout.reason,
            };
            let addrs = details
                .resolver
                .resolve(proxy.uri(), &self.proxy_config, timeout)?;
            let proxy_details = ConnectionDetails {
                uri: proxy.uri(),
                addrs,
                config: &self.proxy_config,
                request_level: true,
                resolver: details.resolver,
                now: details.now,
                timeout,
                current_time: details.current_time.clone(),
                run_connector: details.run_connector.clone(),
            };
            let transport = DefaultConnector::default()
                .connect(&proxy_details, None)?
                .context("connecting configured HTTP proxy")?;
            Ok(TransportAdapter::new(transport))
        };
        let result = (|| -> anyhow::Result<_> {
            let mut stream = make(timeout)?;
            let host = details
                .uri
                .host()
                .context("HTTP proxy target has no hostname")?;
            let port = details
                .uri
                .port_u16()
                .unwrap_or(if details.needs_tls() { 443 } else { 80 });
            connect::connect(&mut stream, (host, port), proxy, timeout, make)?;
            Ok(TunnelTransport(stream.into_inner()))
        })()
        .map_err(|error| ureq::Error::Other(error.into()))?;
        // TLS to the proxy is already verified against its own roots. Add a
        // separate TLS layer to the destination using the request's trust roots.
        #[cfg(windows)]
        if self.windows_tss && details.needs_tls() {
            return crate::windows::tls::connect_tss(details, result.boxed());
        }
        RustlsConnector::default()
            .connect(details, Some(result))?
            .map(Transport::boxed)
            .ok_or(ureq::Error::ConnectionFailed)
    }
}

impl<T: Transport> connect::Connection for ureq::unversioned::transport::TransportAdapter<T> {
    fn timeout(&mut self, remaining: std::time::Duration) -> anyhow::Result<()> {
        self.set_timeout(ureq::unversioned::transport::NextTimeout {
            after: remaining.into(),
            reason: ureq::Timeout::Connect,
        });
        Ok(())
    }
}

#[derive(Debug)]
struct TunnelTransport(Box<dyn Transport>);
impl Transport for TunnelTransport {
    fn buffers(&mut self) -> &mut dyn ureq::unversioned::transport::Buffers {
        self.0.buffers()
    }
    fn transmit_output(
        &mut self,
        amount: usize,
        timeout: ureq::unversioned::transport::NextTimeout,
    ) -> Result<(), ureq::Error> {
        self.0.transmit_output(amount, timeout)
    }
    fn await_input(
        &mut self,
        timeout: ureq::unversioned::transport::NextTimeout,
    ) -> Result<bool, ureq::Error> {
        self.0.await_input(timeout)
    }
    fn is_open(&mut self) -> bool {
        self.0.is_open()
    }
    // TLS, if any, currently terminates at the proxy rather than the target.
    fn is_tls(&self) -> bool {
        false
    }
}

pub(crate) fn connect(host: &str, port: u16) -> Result<Tunnel> {
    let uri = target_uri(host, port)?;
    connect_via(&uri, for_url(&uri)?)
}

/// A tunnel exposes the destination port, but no HTTP path or target TLS session.
fn target_uri(host: &str, port: u16) -> Result<Uri> {
    ensure!(port != 0 && !host.is_empty(), "invalid tunnel destination");
    let authority = format!("{host}:{port}");
    let uri: Uri = format!(
        "{}://{host}:{port}/",
        if port == 80 { "http" } else { "https" }
    )
    .parse()?;
    ensure!(
        uri.authority()
            .is_some_and(|value| value.as_str() == authority)
            && uri.host() == Some(host)
            && uri.port_u16() == Some(port)
            && !authority.contains('@')
            && uri.path() == "/"
            && uri.query().is_none(),
        "invalid tunnel hostname"
    );
    Ok(uri)
}

fn connect_via(uri: &Uri, proxy: Option<Proxy>) -> Result<Tunnel> {
    let host = uri.host().context("tunnel destination has no host")?;
    let port = uri
        .port_u16()
        .unwrap_or(if uri.scheme_str() == Some("http") {
            80
        } else {
            443
        });
    // The destination's TLS remains opaque to the proxy tunnel.
    Ok(Tunnel(socket::connect_blocking(host, port, proxy)?))
}

pub(crate) struct Tunnel(socket::Stream);

impl Read for Tunnel {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.0.read(buffer).map_err(|error| {
            // Unix reports an expired SO_RCVTIMEO as WouldBlock. Keep the FDR
            // idle-read contract the same across host operating systems.
            if error.kind() == io::ErrorKind::WouldBlock {
                io::Error::new(io::ErrorKind::TimedOut, error)
            } else {
                error
            }
        })
    }
}

impl Write for Tunnel {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
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
