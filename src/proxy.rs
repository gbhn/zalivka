//! Shared proxy policy for HTTP requests and the opaque restoreOS FDR tunnel.
use anyhow::{Context, Result, ensure};
use ureq::unversioned::transport::{
    ConnectionDetails, Connector, DefaultConnector, RustlsConnector, SocksConnector, TcpConnector,
    Transport,
};
use ureq::{Proxy, http::Uri};

mod connect;
pub(crate) mod socket;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
#[allow(unsafe_code)]
mod macos;
#[cfg(any(target_os = "linux", target_os = "macos"))]
mod negotiate;

pub(crate) fn for_url(uri: &Uri) -> Result<Vec<Option<Proxy>>> {
    crate::progress::check_cancelled()?;
    #[cfg(windows)]
    if let Some(proxy) = crate::windows::proxy::for_url(uri)? {
        return Ok(vec![proxy]);
    }
    // An explicitly configured environment proxy overrides desktop settings.
    // NO_PROXY is an explicit DIRECT decision, not an absent configuration.
    if proxy_variables(uri)
        .iter()
        .any(|name| std::env::var(name).is_ok_and(|v| !v.trim().is_empty()))
    {
        return Ok(vec![environment_proxy(uri, |name| {
            std::env::var(name).ok()
        })?]);
    }
    #[cfg(target_os = "linux")]
    return linux::for_url(uri);
    #[cfg(target_os = "macos")]
    return macos::for_url(uri);
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    Ok(vec![None])
}

fn proxy_variables(uri: &Uri) -> [&'static str; 4] {
    if uri.scheme_str() == Some("http") {
        ["HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy"]
    } else {
        ["HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy"]
    }
}

/// This marker is produced only before HTTP request bytes can reach a server.
/// PAC failover must never replay a partially sent POST or response.
#[derive(Debug)]
pub(crate) struct ConnectFailure(pub(crate) anyhow::Error);
impl std::fmt::Display for ConnectFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("connecting proxy route")
    }
}
impl std::error::Error for ConnectFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.0.as_ref())
    }
}

pub(crate) fn try_routes<T>(
    routes: Vec<Option<Proxy>>,
    mut connect: impl FnMut(Option<Proxy>) -> Result<T>,
) -> Result<T> {
    ensure!(
        !routes.is_empty(),
        "proxy resolver returned no routes; direct fallback is disabled"
    );
    let mut routes = routes.into_iter().peekable();
    while let Some(proxy) = routes.next() {
        crate::progress::check_cancelled()?;
        match connect(proxy) {
            Ok(value) => return Ok(value),
            Err(error)
                if routes.peek().is_some() && error.chain().any(|e| e.is::<ConnectFailure>()) =>
            {
                crate::log!(
                    Warning,
                    "proxy",
                    "Connection failed: {error:#}; trying the next configured proxy route"
                );
            }
            Err(error) => return Err(error),
        }
    }
    unreachable!()
}

#[cfg(any(target_os = "linux", test))]
fn routes_from_strings(values: Vec<String>) -> Result<Vec<Option<Proxy>>> {
    ensure!(
        !values.is_empty() && values.len() <= 32,
        "invalid system proxy route list; direct fallback is disabled"
    );
    let mut routes = Vec::new();
    for value in values {
        if value == "direct://" {
            routes.push(None);
        } else if let Some(address) = value.strip_prefix("socks://") {
            // An unspecified SOCKS version means v5, then v4 (remote DNS).
            for scheme in ["socks5h", "socks4a"] {
                routes.push(Some(Proxy::new(&format!("{scheme}://{address}"))?));
            }
        } else if let Some(address) = value.strip_prefix("socks5://") {
            // Native/PAC SOCKS5 routes resolve the destination at the proxy.
            // Preserve that behavior; explicit env socks5:// still means local DNS.
            routes.push(Some(Proxy::new(&format!("socks5h://{address}"))?));
        } else {
            routes.push(Some(
                Proxy::new(&value).context("invalid system proxy URI")?,
            ));
        }
    }
    Ok(routes)
}

fn environment_proxy(uri: &Uri, read: impl Fn(&str) -> Option<String>) -> Result<Option<Proxy>> {
    let names = proxy_variables(uri);
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
    tls: RustlsConnector,
    proxy_config: ureq::config::Config,
    tss: bool,
}

impl HttpConnector {
    pub(crate) fn new(proxy_config: ureq::config::Config) -> Self {
        Self {
            tls: RustlsConnector::default(),
            proxy_config,
            tss: false,
        }
    }

    pub(crate) fn for_tss(proxy_config: ureq::config::Config) -> Self {
        Self {
            tss: true,
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
        self.connect_route(details, chained).map_err(|error| {
            let error = match error {
                ureq::Error::Other(error) => anyhow::Error::from_boxed(error),
                error => error.into(),
            };
            ureq::Error::Other(ConnectFailure(error).into())
        })
    }
}

impl HttpConnector {
    fn connect_route(
        &self,
        details: &ConnectionDetails,
        chained: Option<()>,
    ) -> Result<Option<Box<dyn Transport>>, ureq::Error> {
        let transport = if chained.is_none()
            && let Some(proxy) = details.config.proxy()
            && matches!(
                proxy.protocol(),
                ureq::ProxyProtocol::Http | ureq::ProxyProtocol::Https
            )
            && !proxy.is_no_proxy(details.uri)
        {
            self.connect_http(details, proxy)?
        } else {
            ().chain(SocksConnector::default())
                .chain(TcpConnector::default())
                .connect(details, chained)?
                .ok_or(ureq::Error::ConnectionFailed)?
                .boxed()
        };
        // Every route arrives here with a transport to the destination. TLS to
        // an HTTPS proxy belongs to the tunnel, not to the destination server.
        if self.tss && details.needs_tls() {
            return crate::net::tls::connect_tss(details, transport).map(Some);
        }
        Ok(self
            .tls
            .connect(details, Some(transport))?
            .map(Transport::boxed))
    }
}

impl HttpConnector {
    fn connect_http(
        &self,
        details: &ConnectionDetails,
        proxy: &Proxy,
    ) -> Result<Box<dyn Transport>, ureq::Error> {
        use std::time::Duration;
        use ureq::unversioned::transport::TransportAdapter;
        let timeout = details
            .timeout
            .not_zero()
            .map(|duration| *duration)
            .unwrap_or(Duration::from_secs(30));
        let make = |remaining: Duration| -> anyhow::Result<_> {
            let timeout = ureq::unversioned::transport::NextTimeout {
                after: remaining.into(),
                ..details.timeout
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
                register_shutdown: details.register_shutdown.clone(),
            };
            let transport = DefaultConnector::default()
                .connect(&proxy_details, None)?
                .context("connecting configured HTTP proxy")?;
            Ok(TransportAdapter::new(
                transport,
                details.current_time.clone(),
            ))
        };
        (|| -> anyhow::Result<_> {
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
            Ok(TunnelTransport(stream.into_inner()).boxed())
        })()
        .map_err(|error| ureq::Error::Other(error.into()))
    }
}

impl<T: Transport> connect::Connection for ureq::unversioned::transport::TransportAdapter<T> {
    fn timeout(&mut self, remaining: std::time::Duration) -> anyhow::Result<()> {
        self.set_timeout(ureq::unversioned::transport::NextTimeout {
            after: remaining.into(),
            reason: ureq::Timeout::Connect,
            ..Default::default()
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

pub(crate) fn connect(host: &str, port: u16) -> Result<socket::Stream> {
    let uri = target_uri(host, port)?;
    try_routes(for_url(&uri)?, |proxy| connect_via(&uri, proxy))
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

fn connect_via(uri: &Uri, proxy: Option<Proxy>) -> Result<socket::Stream> {
    let host = uri.host().context("tunnel destination has no host")?;
    let port = uri
        .port_u16()
        .unwrap_or(if uri.scheme_str() == Some("http") {
            80
        } else {
            443
        });
    // The destination's TLS remains opaque to the proxy tunnel.
    socket::connect_blocking(host, port, proxy).map_err(|error| ConnectFailure(error).into())
}

/// Windows proxy lists distinguish the destination scheme (https=) from the
/// proxy transport (http://). A SOCKS entry is the fallback for other schemes.
#[cfg(any(windows, test))]
pub(crate) fn from_windows_list(uri: &Uri, list: &str, bypass: &str) -> Result<Option<Proxy>> {
    if windows_bypass(uri, bypass) {
        return Ok(None);
    }
    let entries = list
        .split(|c: char| c == ';' || c.is_whitespace())
        .filter(|entry| !entry.is_empty());
    let scheme = uri
        .scheme_str()
        .context("proxy destination has no scheme")?;
    let selected = entries
        .clone()
        .find_map(|entry| {
            let (key, value) = entry.split_once('=')?;
            key.eq_ignore_ascii_case(scheme).then_some((value, false))
        })
        .or_else(|| {
            entries
                .clone()
                .find(|entry| !entry.contains('='))
                .map(|entry| (entry, false))
        })
        .or_else(|| {
            entries.clone().find_map(|entry| {
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
