//! Bounded decoding of restored asset requests; ureq owns transport framing.
use super::apple_url;
use crate::wire;
use anyhow::{Context, Result, ensure};
use plist::Value;
use ureq::http::{Method, Request};

const MAX_BODY: usize = 16 * 1024 * 1024;
const MAX_HEADERS: usize = 65536;

pub(super) fn asset_request(args: &Value) -> Result<Request<Vec<u8>>> {
    if let Some(serialized) = wire::dictionary(args)?.get("SerializedRequest") {
        return serialized_asset_request(
            serialized
                .as_data()
                .context("SerializedRequest must be data")?,
        );
    }
    let url = apple_url(wire::string(args, &["RequestURL"])?)?;
    let (method, body) = match wire::string(args, &["RequestMethod"])? {
        "GET" => (Method::GET, Vec::new()),
        "POST" => {
            let body = wire::get(args, &["RequestBody"])?
                .as_data()
                .context("asset POST has no body")?;
            ensure!(body.len() <= MAX_BODY, "asset request body too large");
            (Method::POST, body.to_vec())
        }
        method => anyhow::bail!("unsupported asset HTTP method {method}"),
    };
    let mut request = Request::builder().method(method).uri(url);
    if let Some(headers) = wire::dictionary(args)?.get("RequestAdditionalHeaders") {
        for (name, value) in wire::dictionary(headers)? {
            let name: ureq::http::HeaderName = name.parse()?;
            ensure!(
                !matches!(
                    name.as_str(),
                    "host" | "connection" | "content-length" | "transfer-encoding"
                ),
                "asset request overrides HTTP framing"
            );
            request = request.header(
                name,
                value.as_string().context("invalid asset request header")?,
            );
        }
    }
    Ok(request.body(body)?)
}

// Apple's URLAsset handler passes these bytes to CFHTTPMessageAppendBytes:
// an HTTP request, not a plist/NSKeyedArchiver object. Decode the bounded
// GET/POST form and let ureq generate the actual transport framing.
pub(super) fn serialized_asset_request(bytes: &[u8]) -> Result<Request<Vec<u8>>> {
    ensure!(
        bytes.len() <= wire::MAX_PLIST,
        "serialized HTTP request too large"
    );
    let end = bytes[..bytes.len().min(MAX_HEADERS)]
        .windows(4)
        .position(|part| part == b"\r\n\r\n")
        .context("SerializedRequest has missing or oversized HTTP headers")?;
    let body = &bytes[end + 4..];
    let mut lines = std::str::from_utf8(&bytes[..end])?.split("\r\n");
    let mut parts = lines.next().unwrap_or("").splitn(3, ' ');
    let method = parts.next().unwrap_or("");
    let target = parts
        .next()
        .context("SerializedRequest has no HTTP target")?;
    let version = parts.next().unwrap_or("");
    ensure!(
        matches!(method, "GET" | "POST") && matches!(version, "HTTP/1.0" | "HTTP/1.1"),
        "unsupported SerializedRequest HTTP request line"
    );
    let mut host = None;
    let mut length = None;
    let mut chunked = false;
    let mut request = Request::builder().method(method);
    for line in lines {
        let (name, value) = line
            .split_once(':')
            .context("invalid serialized HTTP header")?;
        let name: ureq::http::HeaderName = name.parse()?;
        let value = value.trim_matches([' ', '\t']);
        let checked: ureq::http::HeaderValue = value.parse()?;
        match name.as_str() {
            "host" => {
                ensure!(host.replace(value).is_none(), "duplicate serialized Host");
            }
            "content-length" => {
                ensure!(
                    !value.is_empty() && value.bytes().all(|b| b.is_ascii_digit()),
                    "invalid serialized Content-Length"
                );
                ensure!(
                    length.replace(value.parse::<usize>()?).is_none(),
                    "duplicate serialized Content-Length"
                );
            }
            "transfer-encoding" => {
                ensure!(
                    !chunked && value.eq_ignore_ascii_case("chunked"),
                    "unsupported or duplicate serialized Transfer-Encoding"
                );
                chunked = true;
            }
            "connection" | "trailer" | "te" => {}
            _ => request = request.header(name, checked),
        }
    }
    let body = if chunked {
        ensure!(
            length.is_none(),
            "serialized request combines Content-Length and Transfer-Encoding"
        );
        ensure!(version == "HTTP/1.1", "chunked request requires HTTP/1.1");
        decode_http_chunks(body)?
    } else {
        ensure!(body.len() <= MAX_BODY, "asset request body too large");
        ensure!(
            length.is_none_or(|n| n == body.len()),
            "serialized HTTP body length mismatch"
        );
        body.to_vec()
    };
    ensure!(
        method == "POST" || body.is_empty(),
        "serialized GET has a body"
    );
    let url = if target.starts_with('/') && !target.starts_with("//") {
        format!(
            "https://{}{}",
            host.context("serialized request has no Host")?,
            target
        )
    } else {
        target.to_owned()
    };
    ensure!(
        !url.contains('#'),
        "serialized request URL contains a fragment"
    );
    let uri = apple_url(&url)?;
    if let Some(host) = host {
        let destination = uri.host().context("serialized request URL has no host")?;
        ensure!(
            host.eq_ignore_ascii_case(destination)
                || host.eq_ignore_ascii_case(&format!("{destination}:443")),
            "serialized Host differs from the Apple HTTPS URL"
        );
    }
    Ok(request.uri(uri).body(body)?)
}

fn http_line<'a>(input: &mut &'a [u8]) -> Result<&'a [u8]> {
    let end = input[..input.len().min(MAX_HEADERS)]
        .windows(2)
        .position(|part| part == b"\r\n")
        .context("truncated or oversized chunked HTTP line")?;
    let line = &input[..end];
    *input = &input[end + 2..];
    Ok(line)
}

fn http_token(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte)
}

fn http_ows(input: &[u8]) -> &[u8] {
    &input[input
        .iter()
        .take_while(|b| matches!(b, b' ' | b'\t'))
        .count()..]
}

fn http_chunk_size(line: &[u8]) -> Result<usize> {
    let digits = line.iter().take_while(|b| b.is_ascii_hexdigit()).count();
    ensure!(digits != 0, "invalid HTTP chunk size");
    let size = usize::from_str_radix(std::str::from_utf8(&line[..digits])?, 16)
        .context("HTTP chunk size overflow")?;
    let mut rest = &line[digits..];
    // RFC 9112 section 7.1.1: unknown extensions are ignored, but their
    // syntax must still be valid (including quoted strings and escapes).
    while !rest.is_empty() {
        rest = http_ows(rest);
        ensure!(rest.first() == Some(&b';'), "invalid HTTP chunk extension");
        rest = http_ows(&rest[1..]);
        let name = rest.iter().take_while(|b| http_token(**b)).count();
        ensure!(name != 0, "missing HTTP chunk extension name");
        rest = &rest[name..];
        let value = http_ows(rest);
        if value.first() != Some(&b'=') {
            continue;
        }
        rest = http_ows(&value[1..]);
        if rest.first() == Some(&b'"') {
            rest = &rest[1..];
            loop {
                let byte = *rest.first().context("unterminated HTTP chunk extension")?;
                rest = &rest[1..];
                match byte {
                    b'"' => break,
                    b'\\' => {
                        let escaped = *rest.first().context("truncated HTTP chunk escape")?;
                        ensure!(
                            escaped == b'\t' || escaped >= b' ' && escaped != 127,
                            "invalid HTTP chunk escape"
                        );
                        rest = &rest[1..];
                    }
                    b'\t' | b' ' | b'!' | b'#'..=b'[' | b']'..=b'~' | 128..=255 => {}
                    _ => anyhow::bail!("invalid quoted HTTP chunk extension"),
                }
            }
        } else {
            let value = rest.iter().take_while(|b| http_token(**b)).count();
            ensure!(value != 0, "missing HTTP chunk extension value");
            rest = &rest[value..];
        }
    }
    Ok(size)
}

pub(super) fn decode_http_chunks(mut input: &[u8]) -> Result<Vec<u8>> {
    let mut decoded = Vec::new();
    loop {
        let size = http_chunk_size(http_line(&mut input)?)?;
        if size == 0 {
            let start = input.len();
            loop {
                let trailer = http_line(&mut input)?;
                ensure!(
                    start - input.len() <= MAX_HEADERS,
                    "HTTP trailers too large"
                );
                if trailer.is_empty() {
                    ensure!(input.is_empty(), "data after the terminal HTTP chunk");
                    return Ok(decoded);
                }
                let colon = trailer
                    .iter()
                    .position(|b| *b == b':')
                    .context("invalid HTTP trailer")?;
                let name = ureq::http::HeaderName::from_bytes(&trailer[..colon])?;
                ensure!(
                    ![
                        "host",
                        "content-length",
                        "transfer-encoding",
                        "connection",
                        "trailer",
                        "authorization",
                        "proxy-authorization",
                        "content-encoding",
                        "content-type",
                        "content-range"
                    ]
                    .contains(&name.as_str()),
                    "forbidden HTTP trailer field"
                );
                ureq::http::HeaderValue::from_bytes(&trailer[colon + 1..])?;
                // Unknown trailer fields can be discarded under RFC 9112
                // section 7.1.2; do not promote them to request headers.
            }
        }
        ensure!(
            size <= MAX_BODY - decoded.len(),
            "decoded asset request body too large"
        );
        let data = input.get(..size).context("truncated HTTP chunk data")?;
        ensure!(
            input.get(size..size + 2) == Some(b"\r\n"),
            "HTTP chunk has no trailing CRLF"
        );
        decoded.extend_from_slice(data);
        input = &input[size + 2..];
    }
}
