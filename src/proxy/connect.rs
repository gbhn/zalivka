//! HTTP CONNECT authentication shared by HTTP and FDR tunnels.
use anyhow::{Context, Result, bail, ensure};
use base64::{Engine, prelude::BASE64_STANDARD};
use std::{
    io::{Read, Write},
    time::{Duration, Instant},
};
use ureq::Proxy;

pub(super) trait Connection: Read + Write {
    fn timeout(&mut self, remaining: Duration) -> Result<()>;
}

pub(super) fn connect<S: Connection>(
    stream: &mut S,
    target: (&str, u16),
    proxy: &Proxy,
    timeout: Duration,
    reconnect: impl FnMut(Duration) -> Result<S>,
) -> Result<()> {
    #[cfg(windows)]
    let mut auth: Option<crate::windows::negotiate::Negotiate> = None;
    handshake(
        stream,
        target,
        proxy,
        timeout,
        reconnect,
        |scheme, challenge| {
            #[cfg(windows)]
            {
                if auth.is_none() {
                    auth = Some(crate::windows::negotiate::Negotiate::new(
                        scheme,
                        proxy.host(),
                    )?);
                }
                auth.as_mut().unwrap().step(challenge)
            }
            #[cfg(not(windows))]
            {
                let _ = challenge;
                bail!("HTTP 407: {scheme} proxy authentication requires Windows SSPI")
            }
        },
    )
}

fn remaining(deadline: Instant) -> Result<Duration> {
    let duration = deadline.saturating_duration_since(Instant::now());
    ensure!(!duration.is_zero(), "HTTP proxy CONNECT timed out");
    Ok(duration)
}

fn header(stream: &mut impl Connection, deadline: Instant) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    while !bytes.ends_with(b"\r\n\r\n") {
        ensure!(
            bytes.len() < 131072,
            "proxy response header exceeds 128 KiB"
        );
        stream.timeout(remaining(deadline)?)?;
        let mut byte = [0];
        stream
            .read_exact(&mut byte)
            .context("reading HTTP proxy response")?;
        bytes.push(byte[0]);
    }
    Ok(bytes)
}

// Split combined challenges without mistaking a quoted Basic realm for a scheme.
fn challenges(value: &str) -> Vec<(&str, Option<&str>)> {
    let mut quoted = false;
    let mut escaped = false;
    let mut start = 0;
    let mut values = Vec::new();
    for (index, byte) in value.bytes().chain(Some(b',')).enumerate() {
        if escaped {
            escaped = false;
            continue;
        }
        if quoted && byte == b'\\' {
            escaped = true;
            continue;
        }
        if byte == b'"' {
            quoted = !quoted;
        }
        if byte == b',' && !quoted {
            let part = value[start..index].trim();
            let (scheme, token) = part.split_once(char::is_whitespace).unwrap_or((part, ""));
            values.push((scheme, (!token.trim().is_empty()).then_some(token.trim())));
            start = index + 1;
        }
    }
    values
}

fn discard(stream: &mut impl Connection, mut length: usize, deadline: Instant) -> Result<()> {
    ensure!(
        length <= 1024 * 1024,
        "proxy authentication response body exceeds 1 MiB"
    );
    let mut buffer = [0; 8192];
    while length > 0 {
        stream.timeout(remaining(deadline)?)?;
        let size = length.min(buffer.len());
        stream
            .read_exact(&mut buffer[..size])
            .context("reading proxy authentication response body")?;
        length -= size;
    }
    Ok(())
}

fn line(stream: &mut impl Connection, deadline: Instant) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    while !bytes.ends_with(b"\r\n") {
        ensure!(bytes.len() < 8192, "proxy chunk/trailer line exceeds 8 KiB");
        stream.timeout(remaining(deadline)?)?;
        let mut byte = [0];
        stream.read_exact(&mut byte)?;
        bytes.push(byte[0]);
    }
    Ok(bytes)
}

fn discard_chunked(stream: &mut impl Connection, deadline: Instant) -> Result<()> {
    let mut total = 0usize;
    loop {
        let bytes = line(stream, deadline)?;
        let text = std::str::from_utf8(&bytes)?;
        let size = usize::from_str_radix(text.trim().split(';').next().unwrap_or(""), 16)
            .context("invalid proxy chunk length")?;
        total = total
            .checked_add(size)
            .context("proxy chunk length overflow")?;
        ensure!(
            total <= 1024 * 1024,
            "proxy authentication body exceeds 1 MiB"
        );
        if size == 0 {
            for _ in 0..64 {
                if line(stream, deadline)? == b"\r\n" {
                    return Ok(());
                }
            }
            bail!("too many proxy response trailers");
        }
        discard(stream, size, deadline)?;
        ensure!(
            line(stream, deadline)? == b"\r\n",
            "invalid proxy chunk terminator"
        );
    }
}

fn handshake<S: Connection>(
    stream: &mut S,
    target: (&str, u16),
    proxy: &Proxy,
    timeout: Duration,
    mut reconnect: impl FnMut(Duration) -> Result<S>,
    mut authenticate: impl FnMut(&str, Option<&str>) -> Result<String>,
) -> Result<()> {
    let deadline = Instant::now() + timeout;
    let explicit = proxy.username().is_some() || proxy.password().is_some();
    let mut authorization = explicit.then(|| {
        format!(
            "Basic {}",
            BASE64_STANDARD.encode(format!(
                "{}:{}",
                proxy.username().unwrap_or(""),
                proxy.password().unwrap_or("")
            ))
        )
    });
    let mut selected: Option<&str> = None;
    for round in 0..8 {
        crate::log!(
            Trace,
            "proxy:connect",
            "{}:{} -> {}:{}: round={}; auth={}",
            proxy.host(),
            proxy.port(),
            target.0,
            target.1,
            round + 1,
            selected.unwrap_or(if explicit { "Basic" } else { "none" })
        );
        stream.timeout(remaining(deadline)?)?;
        write!(
            stream,
            "CONNECT {}:{} HTTP/1.1\r\nHost: {}:{}\r\nProxy-Connection: Keep-Alive\r\n",
            target.0, target.1, target.0, target.1
        )?;
        if let Some(authorization) = &authorization {
            write!(stream, "Proxy-Authorization: {authorization}\r\n")?;
        }
        stream.write_all(b"\r\n")?;
        stream.flush()?;
        let bytes = header(stream, deadline)?;
        let mut fields =
            vec![httparse::EMPTY_HEADER; bytes.iter().filter(|b| **b == b'\n').count() - 2];
        let mut response = httparse::Response::new(&mut fields);
        ensure!(
            matches!(response.parse(&bytes)?, httparse::Status::Complete(end) if end == bytes.len())
                && matches!(response.version, Some(0 | 1)),
            "invalid HTTP proxy response"
        );
        let code = response.code.context("missing proxy status")?;
        crate::log!(
            Trace,
            "proxy:connect",
            "{}:{}: HTTP {code}; header={} B",
            proxy.host(),
            proxy.port(),
            bytes.len()
        );
        let offered: Vec<_> = response
            .headers
            .iter()
            .filter(|h| h.name.eq_ignore_ascii_case("proxy-authenticate"))
            .map(|h| String::from_utf8_lossy(h.value).into_owned())
            .collect();
        let offered: Vec<_> = offered.iter().flat_map(|value| challenges(value)).collect();
        if (200..300).contains(&code) {
            if let Some(scheme) = selected {
                if let Some((_, Some(token))) = offered
                    .iter()
                    .find(|(name, _)| name.eq_ignore_ascii_case(scheme))
                {
                    ensure!(
                        authenticate(scheme, Some(token))?.is_empty(),
                        "proxy authentication requires another exchange after CONNECT success"
                    );
                }
                crate::log!(
                    Info,
                    "proxy:auth",
                    "{}:{}: {scheme}; authentication complete",
                    proxy.host(),
                    proxy.port()
                );
            }
            return Ok(());
        }
        let schemes: Vec<_> = offered.iter().map(|(name, _)| *name).collect();
        ensure!(
            code == 407 && !explicit,
            "proxy refused CONNECT (HTTP {code}; schemes={schemes:?}); direct fallback is disabled"
        );
        let scheme = selected.or_else(|| ["Negotiate", "NTLM"].into_iter().find(|scheme| offered.iter().any(|(name, _)| name.eq_ignore_ascii_case(scheme))))
            .context("HTTP 407: proxy does not offer Negotiate or NTLM; current-user authentication is unavailable")?;
        let (_, challenge) = offered
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case(scheme))
            .context("HTTP 407: proxy changed its authentication scheme")?;
        if selected.is_some() {
            ensure!(
                challenge.is_some(),
                "HTTP 407: proxy rejected current-user {scheme} authentication"
            );
        }
        crate::log!(
            Info,
            "proxy",
            "Proxy {}:{}: HTTP 407; scheme={scheme}",
            proxy.host(),
            proxy.port()
        );
        let connection_values: Vec<_> = response
            .headers
            .iter()
            .filter(|h| {
                h.name.eq_ignore_ascii_case("connection")
                    || h.name.eq_ignore_ascii_case("proxy-connection")
            })
            .flat_map(|h| {
                String::from_utf8_lossy(h.value)
                    .split(',')
                    .map(|v| v.trim().to_ascii_lowercase())
                    .collect::<Vec<_>>()
            })
            .collect();
        let close = connection_values.iter().any(|value| value == "close")
            || (response.version == Some(0)
                && !connection_values.iter().any(|value| value == "keep-alive"));
        let lengths: Vec<_> = response
            .headers
            .iter()
            .filter(|h| h.name.eq_ignore_ascii_case("content-length"))
            .map(|h| {
                std::str::from_utf8(h.value)?
                    .trim()
                    .parse::<usize>()
                    .map_err(anyhow::Error::from)
            })
            .collect::<Result<_>>()?;
        ensure!(
            lengths.windows(2).all(|pair| pair[0] == pair[1]),
            "conflicting proxy Content-Length values"
        );
        let encodings: Vec<_> = response
            .headers
            .iter()
            .filter(|h| h.name.eq_ignore_ascii_case("transfer-encoding"))
            .map(|h| std::str::from_utf8(h.value))
            .collect::<std::result::Result<_, _>>()?;
        let chunked = !encodings.is_empty();
        ensure!(
            !chunked
                || (encodings.len() == 1
                    && encodings[0].eq_ignore_ascii_case("chunked")
                    && lengths.is_empty()),
            "unsupported proxy authentication body framing"
        );
        if close || (lengths.is_empty() && !chunked) {
            crate::log!(
                Trace,
                "proxy:connect",
                "Reconnecting; close={close}, length={lengths:?}, chunked={chunked}"
            );
            ensure!(
                selected.is_none(),
                "HTTP 407: proxy closed the connection during {scheme}; persistent connections are required"
            );
            *stream = reconnect(remaining(deadline)?)?;
        } else if chunked {
            discard_chunked(stream, deadline)?;
        } else {
            discard(stream, lengths[0], deadline)?;
        }
        let token = authenticate(scheme, *challenge)?;
        crate::log!(
            Trace,
            "proxy:auth",
            "{scheme}: round={}; challenge={} chars, response={} chars",
            round + 1,
            challenge.map_or(0, str::len),
            token.len()
        );
        ensure!(
            !token.is_empty()
                && token
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"+/=".contains(&b)),
            "invalid SSPI output token"
        );
        authorization = Some(format!("{scheme} {token}"));
        selected = Some(scheme);
    }
    bail!("HTTP 407: proxy authentication exceeded 8 exchanges; direct fallback is disabled")
}

#[cfg(test)]
#[path = "../../tests/unit/proxy/connect.rs"]
mod tests;
