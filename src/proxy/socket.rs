//! Blocking TCP tunnels for FDR, including HTTP, HTTPS and SOCKS proxies.
use anyhow::{Context, Result, bail, ensure};
#[cfg(any(not(windows), test))]
use rustls::RootCertStore;
use rustls::{ClientConfig, ClientConnection, StreamOwned, pki_types::ServerName};
#[cfg(not(windows))]
use std::sync::OnceLock;
use std::{
    io::{self, Read, Write},
    net::{IpAddr, TcpStream, ToSocketAddrs},
    sync::Arc,
    time::{Duration, Instant},
};
use ureq::{Proxy, ProxyProtocol};

enum Transport {
    Tcp(TcpStream),
    Tls(Box<StreamOwned<ClientConnection, TcpStream>>),
}
pub(crate) struct Stream {
    transport: Transport,
}
impl Stream {
    fn tcp(&self) -> &TcpStream {
        match &self.transport {
            Transport::Tcp(s) => s,
            Transport::Tls(s) => &s.sock,
        }
    }
}
impl Read for Stream {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if out.is_empty() {
            return Ok(0);
        }
        match &mut self.transport {
            Transport::Tcp(s) => s.read(out),
            Transport::Tls(s) => s.read(out),
        }
    }
}
impl Write for Stream {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        match &mut self.transport {
            Transport::Tcp(s) => s.write(bytes),
            Transport::Tls(s) => s.write(bytes),
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        match &mut self.transport {
            Transport::Tcp(s) => s.flush(),
            Transport::Tls(s) => s.flush(),
        }
    }
}

fn tls_config() -> Result<Arc<ClientConfig>> {
    #[cfg(windows)]
    {
        crate::windows::tls::config(None)
    }
    #[cfg(not(windows))]
    {
        static CONFIG: OnceLock<Arc<ClientConfig>> = OnceLock::new();
        Ok(CONFIG
            .get_or_init(|| {
                let roots =
                    RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
                Arc::new(
                    ClientConfig::builder_with_provider(Arc::new(
                        oxitls_rustcrypto_provider::provider(),
                    ))
                    .with_safe_default_protocol_versions()
                    .unwrap()
                    .with_root_certificates(roots)
                    .with_no_client_auth(),
                )
            })
            .clone())
    }
}

fn socket_host(host: &str) -> &str {
    host.strip_prefix('[')
        .and_then(|host| host.strip_suffix(']'))
        .unwrap_or(host)
}

fn tcp_connect(host: &str, port: u16, timeout: Duration) -> Result<TcpStream> {
    let deadline = Instant::now() + timeout;
    let host = socket_host(host);
    let addresses = (host, port)
        .to_socket_addrs()
        .context("resolving upstream on the Windows host")?;
    let mut error = None;
    for address in addresses {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break;
        }
        match TcpStream::connect_timeout(&address, remaining.min(Duration::from_secs(3))) {
            Ok(stream) => {
                stream.set_read_timeout(Some(timeout))?;
                stream.set_write_timeout(Some(timeout))?;
                stream.set_nodelay(true)?;
                return Ok(stream);
            }
            Err(e) => error = Some(e),
        }
    }
    Err(error
        .unwrap_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "upstream connection timed out"))
        .into())
}
pub(crate) fn connect_blocking(host: &str, port: u16, proxy: Option<Proxy>) -> Result<Stream> {
    let stream = open(host, port, proxy, Duration::from_secs(30))?;
    stream
        .tcp()
        .set_read_timeout(Some(Duration::from_millis(100)))?;
    Ok(stream)
}

fn open(host: &str, port: u16, proxy: Option<Proxy>, timeout: Duration) -> Result<Stream> {
    super::target_uri(host, port)?;
    let mut stream = if let Some(proxy) = proxy {
        crate::log!(
            Debug,
            "proxy",
            "Соединение с {host}:{port} через прокси {:?}",
            proxy.protocol()
        );
        let mut stream = proxy_stream(&proxy, timeout)?;
        match proxy.protocol() {
            ProxyProtocol::Http | ProxyProtocol::Https => {
                http_connect(&mut stream, host, port, &proxy, timeout)?
            }
            ProxyProtocol::Socks4
            | ProxyProtocol::Socks4A
            | ProxyProtocol::Socks5
            | ProxyProtocol::Socks5h => socks_connect(&mut stream, host, port, &proxy)?,
            _ => bail!("unsupported proxy protocol"),
        }
        stream
    } else {
        crate::log!(Debug, "proxy", "Прямое соединение с {host}:{port}");
        Stream {
            transport: Transport::Tcp(tcp_connect(host, port, timeout)?),
        }
    };
    stream.flush()?;
    Ok(stream)
}

fn proxy_stream(proxy: &Proxy, timeout: Duration) -> Result<Stream> {
    let tcp =
        tcp_connect(proxy.host(), proxy.port(), timeout).context("connecting configured proxy")?;
    let transport = if proxy.protocol() == ProxyProtocol::Https {
        tls_transport(tcp, proxy.host(), tls_config()?)?
    } else {
        Transport::Tcp(tcp)
    };
    Ok(Stream { transport })
}

impl super::connect::Connection for Stream {
    fn timeout(&mut self, remaining: Duration) -> Result<()> {
        self.tcp().set_read_timeout(Some(remaining))?;
        self.tcp().set_write_timeout(Some(remaining))?;
        Ok(())
    }
}
fn tls_transport(tcp: TcpStream, host: &str, config: Arc<ClientConfig>) -> Result<Transport> {
    let host = socket_host(host);
    let name = ServerName::try_from(host.to_owned()).context("invalid HTTPS proxy hostname")?;
    let mut tls = StreamOwned::new(ClientConnection::new(config, name)?, tcp);
    while tls.conn.is_handshaking() {
        tls.conn.complete_io(&mut tls.sock)?;
    }
    Ok(Transport::Tls(Box::new(tls)))
}
fn http_connect(
    stream: &mut Stream,
    host: &str,
    port: u16,
    proxy: &Proxy,
    timeout: Duration,
) -> Result<()> {
    super::connect::connect(stream, (host, port), proxy, timeout, |remaining| {
        proxy_stream(proxy, remaining)
    })
}
fn socks_connect(stream: &mut Stream, host: &str, port: u16, proxy: &Proxy) -> Result<()> {
    let host = socket_host(host);
    let target = if proxy.resolve_target() {
        Some(
            (host, port)
                .to_socket_addrs()?
                .find(|a| proxy.protocol() != ProxyProtocol::Socks4 || a.is_ipv4())
                .context("no address for SOCKS target")?
                .ip(),
        )
    } else {
        host.parse::<IpAddr>().ok()
    };
    if matches!(
        proxy.protocol(),
        ProxyProtocol::Socks4 | ProxyProtocol::Socks4A
    ) {
        ensure!(
            !proxy.username().unwrap_or("").contains('\0'),
            "invalid SOCKS4 user ID"
        );
        let mut request = vec![4, 1];
        request.extend(port.to_be_bytes());
        match target {
            Some(IpAddr::V4(ip)) => request.extend(ip.octets()),
            Some(IpAddr::V6(_)) => bail!("SOCKS4 cannot connect to IPv6"),
            None => request.extend([0, 0, 0, 1]),
        }
        request.extend(proxy.username().unwrap_or("").bytes());
        request.push(0);
        if target.is_none() {
            request.extend(host.bytes());
            request.push(0);
        }
        stream.write_all(&request)?;
        let mut reply = [0; 8];
        stream.read_exact(&mut reply)?;
        ensure!(
            reply[0] == 0 && reply[1] == 90,
            "SOCKS4 proxy refused connection"
        );
        return Ok(());
    }
    let authenticated = proxy.username().is_some() || proxy.password().is_some();
    stream.write_all(if authenticated {
        &[5, 1, 2]
    } else {
        &[5, 1, 0]
    })?;
    let mut reply = [0; 2];
    stream.read_exact(&mut reply)?;
    ensure!(
        reply == [5, if authenticated { 2 } else { 0 }],
        "SOCKS5 proxy rejected authentication method"
    );
    if authenticated {
        let user = proxy.username().unwrap_or("").as_bytes();
        let pass = proxy.password().unwrap_or("").as_bytes();
        ensure!(
            user.len() <= 255 && pass.len() <= 255,
            "SOCKS5 credentials exceed 255 bytes"
        );
        let mut auth = vec![1, user.len() as u8];
        auth.extend(user);
        auth.push(pass.len() as u8);
        auth.extend(pass);
        stream.write_all(&auth)?;
        stream.read_exact(&mut reply)?;
        ensure!(reply == [1, 0], "SOCKS5 proxy authentication failed");
    }
    let mut request = vec![5, 1, 0];
    match target {
        Some(IpAddr::V4(ip)) => {
            request.push(1);
            request.extend(ip.octets());
        }
        Some(IpAddr::V6(ip)) => {
            request.push(4);
            request.extend(ip.octets());
        }
        None => {
            ensure!(host.len() <= 255, "SOCKS hostname exceeds 255 bytes");
            request.extend([3, host.len() as u8]);
            request.extend(host.bytes());
        }
    }
    request.extend(port.to_be_bytes());
    stream.write_all(&request)?;
    let mut reply = [0; 4];
    stream.read_exact(&mut reply)?;
    ensure!(reply[..3] == [5, 0, 0], "SOCKS5 proxy refused connection");
    let length = match reply[3] {
        1 => 4,
        4 => 16,
        3 => {
            let mut n = [0];
            stream.read_exact(&mut n)?;
            n[0] as usize
        }
        _ => bail!("invalid SOCKS5 reply address"),
    };
    let mut address = vec![0; length + 2];
    stream.read_exact(&mut address)?;
    Ok(())
}

#[cfg(test)]
#[path = "../../tests/unit/proxy/socket.rs"]
mod tests;
