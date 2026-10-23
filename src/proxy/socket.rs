//! Nonblocking TCP tunnels for USB forwarding, using the shared Windows policy.
use anyhow::{Context, Result, bail, ensure};
use base64::{Engine, prelude::BASE64_STANDARD};
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned, pki_types::ServerName};
use std::{
    io::{self, Read, Write},
    net::{IpAddr, Shutdown, TcpStream, ToSocketAddrs},
    sync::{Arc, OnceLock},
    time::{Duration, Instant},
};
use ureq::{Proxy, ProxyProtocol, http::Uri};

const TIMEOUT: Duration = Duration::from_secs(10);
enum Transport {
    Tcp(TcpStream),
    Tls(Box<StreamOwned<ClientConnection, TcpStream>>),
}
pub(crate) struct Stream {
    transport: Transport,
    shutdown_pending: bool,
}
impl Stream {
    fn tcp(&self) -> &TcpStream {
        match &self.transport {
            Transport::Tcp(s) => s,
            Transport::Tls(s) => &s.sock,
        }
    }
    pub(crate) fn shutdown_write(&mut self) -> io::Result<()> {
        if !self.shutdown_pending {
            self.shutdown_pending = true;
            if let Transport::Tls(s) = &mut self.transport {
                s.conn.send_close_notify();
            }
        }
        self.flush()
    }
    pub(crate) fn poll(&mut self) -> io::Result<()> {
        match self.flush() {
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => Ok(()),
            result => result,
        }
    }
}
impl Read for Stream {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
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
            Transport::Tcp(s) => s.flush()?,
            Transport::Tls(s) => s.flush()?,
        }
        if self.shutdown_pending {
            self.tcp().shutdown(Shutdown::Write)?;
            self.shutdown_pending = false;
        }
        Ok(())
    }
}

fn tls_config() -> Arc<ClientConfig> {
    static CONFIG: OnceLock<Arc<ClientConfig>> = OnceLock::new();
    CONFIG
        .get_or_init(|| {
            let roots = RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
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
        .clone()
}

pub(crate) fn connect(host: &str, port: u16) -> Result<Stream> {
    // A transparent stream exposes its origin, not the encrypted HTTP path.
    let uri: Uri = format!(
        "{}://{host}:{port}/",
        if port == 80 { "http" } else { "https" }
    )
    .parse()?;
    connect_via(host, port, super::for_url(&uri)?)
}
fn tcp_connect(host: &str, port: u16) -> Result<TcpStream> {
    let deadline = Instant::now() + TIMEOUT;
    let host = host.trim_start_matches('[').trim_end_matches(']');
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
                stream.set_read_timeout(Some(TIMEOUT))?;
                stream.set_write_timeout(Some(TIMEOUT))?;
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
pub(crate) fn connect_via(host: &str, port: u16, proxy: Option<Proxy>) -> Result<Stream> {
    let mut stream = if let Some(proxy) = proxy {
        eprintln!(
            "USB internet: route {host}:{port} via {:?} proxy",
            proxy.protocol()
        );
        let tcp = tcp_connect(proxy.host(), proxy.port()).context("connecting configured proxy")?;
        let transport = if proxy.protocol() == ProxyProtocol::Https {
            tls_transport(tcp, proxy.host(), tls_config())?
        } else {
            Transport::Tcp(tcp)
        };
        let mut stream = Stream {
            transport,
            shutdown_pending: false,
        };
        match proxy.protocol() {
            ProxyProtocol::Http | ProxyProtocol::Https => {
                http_connect(&mut stream, host, port, &proxy)?
            }
            ProxyProtocol::Socks4
            | ProxyProtocol::Socks4A
            | ProxyProtocol::Socks5
            | ProxyProtocol::Socks5h => socks_connect(&mut stream, host, port, &proxy)?,
            _ => bail!("unsupported proxy protocol"),
        }
        stream
    } else {
        eprintln!("USB internet: route {host}:{port} directly from the Windows host");
        Stream {
            transport: Transport::Tcp(tcp_connect(host, port)?),
            shutdown_pending: false,
        }
    };
    stream.tcp().set_read_timeout(None)?;
    stream.tcp().set_write_timeout(None)?;
    stream.tcp().set_nonblocking(true)?;
    stream.poll()?;
    Ok(stream)
}
fn tls_transport(tcp: TcpStream, host: &str, config: Arc<ClientConfig>) -> Result<Transport> {
    let name = ServerName::try_from(host.to_owned()).context("invalid HTTPS proxy hostname")?;
    let mut tls = StreamOwned::new(ClientConnection::new(config, name)?, tcp);
    while tls.conn.is_handshaking() {
        tls.conn.complete_io(&mut tls.sock)?;
    }
    Ok(Transport::Tls(Box::new(tls)))
}
fn http_connect(stream: &mut Stream, host: &str, port: u16, proxy: &Proxy) -> Result<()> {
    write!(
        stream,
        "CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n"
    )?;
    if proxy.username().is_some() || proxy.password().is_some() {
        let token = BASE64_STANDARD.encode(format!(
            "{}:{}",
            proxy.username().unwrap_or(""),
            proxy.password().unwrap_or("")
        ));
        write!(stream, "Proxy-Authorization: Basic {token}\r\n")?;
    }
    stream.write_all(b"\r\n")?;
    stream.flush()?;
    let mut header = vec![];
    let deadline = Instant::now() + TIMEOUT;
    // Read only the header; opaque target bytes in the same packet must survive.
    while !header.ends_with(b"\r\n\r\n") {
        ensure!(header.len() < 16384, "proxy response header exceeds 16 KiB");
        let remaining = deadline.saturating_duration_since(Instant::now());
        ensure!(!remaining.is_zero(), "proxy response header timed out");
        stream.tcp().set_read_timeout(Some(remaining))?;
        let mut byte = [0];
        stream.read_exact(&mut byte)?;
        header.push(byte[0]);
    }
    let status = std::str::from_utf8(&header)?
        .lines()
        .next()
        .context("empty proxy response")?;
    let mut parts = status.split_whitespace();
    ensure!(
        matches!(parts.next(), Some("HTTP/1.0" | "HTTP/1.1")),
        "invalid HTTP proxy response"
    );
    let code = parts
        .next()
        .context("missing proxy status")?
        .parse::<u16>()?;
    ensure!(
        code == 200,
        "proxy refused CONNECT (HTTP {code}); direct fallback is disabled"
    );
    Ok(())
}
fn socks_connect(stream: &mut Stream, host: &str, port: u16, proxy: &Proxy) -> Result<()> {
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
