//! Host-scoped authorization and restored asset replies.
use super::{agent, fetch, request::asset_request, validate_apple_url};
use crate::wire;
use anyhow::{Context, Result, ensure};
use plist::Value;
use std::path::Path;
use std::sync::Arc;
use ureq::http::{Request, Response};

/// Host-scoped credentials supplied by the operator. Never sent to restored.
#[derive(Clone)]
pub struct AssetClient {
    // Agent clones share connections across synchronous and asynchronous requests.
    agent: ureq::Agent,
    tokens: Arc<std::collections::HashMap<String, ureq::http::HeaderValue>>,
    apple_connect: Option<ureq::http::HeaderValue>,
}

impl Default for AssetClient {
    fn default() -> Self {
        Self {
            agent: agent(),
            tokens: Arc::default(),
            apple_connect: None,
        }
    }
}

impl AssetClient {
    pub fn from_files(tokens: Option<&Path>, apple_connect: Option<&Path>) -> Result<Self> {
        let mut values = std::collections::HashMap::new();
        if let Some(path) = tokens {
            let data = read_auth_file(path)?;
            let plist = Value::from_reader(std::io::Cursor::new(data))
                .context("authorization tokens file is not a plist")?;
            for (host, token) in wire::dictionary(&plist)? {
                let host = host.to_ascii_lowercase();
                validate_apple_url(&format!("https://{host}/"))?;
                ensure!(
                    !host.contains(['/', ':', '@', '?', '#']),
                    "authorization token key must be an Apple hostname"
                );
                let token = token
                    .as_string()
                    .context("authorization token must be a string")?;
                ensure!(
                    values.insert(host, bearer_token(token)?).is_none(),
                    "duplicate authorization token hostname"
                );
            }
        }
        let apple_connect = apple_connect
            .map(|path| -> Result<_> {
                let bytes = read_auth_file(path)?;
                ensure!(
                    bytes.starts_with(b"DAWTKN"),
                    "AppleConnect data has no DAWTKN prefix"
                );
                bearer_token(std::str::from_utf8(&bytes).context("AppleConnect data is not UTF-8")?)
            })
            .transpose()?;
        Ok(Self {
            tokens: Arc::new(values),
            apple_connect,
            ..Self::default()
        })
    }

    pub(super) fn authorize(
        &self,
        request: &mut Request<Vec<u8>>,
        wrapped_key: bool,
    ) -> Result<()> {
        validate_apple_url(&request.uri().to_string())?;
        if wrapped_key && !request.headers().contains_key("authorization") {
            let host = request
                .uri()
                .host()
                .context("WKMS request has no host")?
                .to_ascii_lowercase();
            let fallback = if host.starts_with("wkms.") && host.ends_with(".apple.com") {
                self.apple_connect.as_ref()
            } else {
                None
            };
            if let Some(token) = self.tokens.get(&host).or(fallback) {
                request.headers_mut().insert("authorization", token.clone());
            }
        }
        Ok(())
    }

    pub fn response(&self, message: &Value) -> Result<Value> {
        let wrapped_key = wrapped_key_request(message)?;
        let mut request = asset_request(wire::get(message, &["Arguments"])?)?;
        self.authorize(&mut request, wrapped_key)?;
        let reply = fetch(request, &self.agent)?;
        if wrapped_key && matches!(reply.status().as_u16(), 401 | 403) {
            anyhow::bail!(
                "Apple WKMS requires valid authorization; supply --authorization-tokens or --apple-connect-data from an authorized AppleConnect session (HTTP {})",
                reply.status().as_u16()
            );
        }
        asset_reply(reply, wrapped_key)
    }
}

fn read_auth_file(path: &Path) -> Result<Vec<u8>> {
    let file = std::fs::File::open(path).context("opening WKMS authorization file")?;
    crate::storage::read_limited(file, 1024 * 1024, "WKMS authorization file exceeds 1 MiB")
}

fn bearer_token(token: &str) -> Result<ureq::http::HeaderValue> {
    ensure!(
        !token.is_empty() && token.len() <= 65536 && token.bytes().all(|b| (33..127).contains(&b)),
        "invalid WKMS bearer token"
    );
    let mut header = ureq::http::HeaderValue::from_str(&format!("Bearer {token}"))
        .context("invalid WKMS authorization header")?;
    header.set_sensitive(true);
    Ok(header)
}

pub(crate) fn wrapped_key_request(message: &Value) -> Result<bool> {
    let kind =
        wire::string(message, &["DataType"]).or_else(|_| wire::string(message, &["MsgType"]))?;
    if kind != "StreamedImageDecryptionKey" {
        return Ok(false);
    }
    let args = wire::get(message, &["Arguments"])?;
    let Some(identifier) = wire::dictionary(args)?.get("ArchiveIdentifier") else {
        // The original HTTP proxy contract has no archive identifier.
        return Ok(false);
    };
    ensure!(
        identifier.as_string().is_some_and(|id| !id.is_empty()),
        "WKMS ArchiveIdentifier must be a nonempty string"
    );
    ensure!(
        wire::string(args, &["RequestMethod"])? == "POST",
        "WKMS key request must use POST"
    );
    Ok(true)
}

pub(super) fn asset_reply(mut response: Response<ureq::Body>, wrapped_key: bool) -> Result<Value> {
    let status = u64::from(response.status().as_u16());
    ensure!(
        !wrapped_key || response.status().is_success(),
        "Apple WKMS key request returned HTTP {status}"
    );
    let body = crate::storage::read_limited(
        response.body_mut().as_reader(),
        32 * 1024 * 1024,
        "asset response exceeds 32 MiB",
    )?;
    if wrapped_key {
        ensure!(
            !body.is_empty(),
            "Apple WKMS returned an empty key response"
        );
        // Verified in restored_external/restored_update from 26A434, and
        // restored_external from 24A335. The device unwraps the server's body
        // itself. Only LocalUnwrapped bypasses that step; never label a WKMS
        // response as a plaintext archive key. Apple's Windows host uses the
        // KeySource value Remote.
        return Ok(wire::dict([
            ("KeyData", Value::Data(body)),
            ("KeySource", "Remote".into()),
        ]));
    }
    let headers = Value::Dictionary(
        response
            .headers()
            .iter()
            .map(|(k, v)| Ok((k.to_string(), Value::String(v.to_str()?.to_owned()))))
            .collect::<Result<plist::Dictionary>>()?,
    );
    Ok(wire::dict([
        ("ResponseBody", Value::Data(body)),
        ("ResponseBodyDone", true.into()),
        ("ResponseHeaders", headers),
        ("ResponseStatus", status.into()),
    ]))
}

#[cfg(test)]
#[path = "../../tests/unit/net/client.rs"]
mod tests;
