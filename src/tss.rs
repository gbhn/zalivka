//! Apple TSS transport and response validation.
mod request;
use crate::{img4, net, wire};
use anyhow::{Context, Result, ensure};
use plist::Value;
pub use request::{apply_rules, local_policy_request, recovery_request, request};
pub(crate) use request::{host_fields, updater_fields};

const TSS_URL: &str = "https://gs.apple.com/TSS/controller?action=2";

pub fn send(request: &Value) -> Result<Value> {
    let response = send_raw(request)?;
    validate_ticket(request, &response)?;
    Ok(response)
}

/// Check server-generated measurements before using the ticket to boot a device.
pub fn validate_ticket<'a>(request: &Value, response: &'a Value) -> Result<&'a [u8]> {
    let ticket = ticket(response)?;
    for (name, entry) in wire::dictionary(request)? {
        let Some(entry) = entry.as_dictionary() else {
            continue;
        };
        if name.len() != 4
            || !name.is_ascii()
            || entry.get("Trusted").and_then(Value::as_boolean) != Some(true)
            || !entry
                .get("Digest")
                .and_then(Value::as_data)
                .is_some_and(|digest| digest.is_empty())
        {
            continue;
        }
        let object: &[u8; 4] = name.as_bytes().try_into()?;
        let digest = img4::manifest_data(ticket, object, b"DGST")
            .with_context(|| format!("validating server-generated {name} measurement"))?;
        ensure!(
            digest.is_some_and(|digest| !digest.is_empty()),
            "Apple ticket is missing the server-generated {name} digest; refusing to boot"
        );
    }
    Ok(ticket)
}

pub fn send_raw(request: &Value) -> Result<Value> {
    let body = wire::xml(request)?;
    let request = ureq::http::Request::post(TSS_URL)
        .header("Content-Type", "text/xml")
        .body(body)?;
    let mut response =
        net::send_http(&net::tss_agent(), &request).context("Apple TSS request failed")?;
    ensure!(
        response.status().is_success(),
        "Apple TSS returned {}",
        response.status()
    );
    let data = crate::storage::read_limited(
        response.body_mut().as_reader(),
        16 * 1024 * 1024,
        "TSS response too large",
    )?;
    parse_response(&data)
}

pub fn parse_response(data: &[u8]) -> Result<Value> {
    let text = std::str::from_utf8(data).context("TSS response is not UTF-8")?;
    let response = text.split_once("&REQUEST_STRING=");
    let header = response.map_or(text, |(header, _)| header);
    let mut status = header
        .split('&')
        .filter_map(|field| field.strip_prefix("STATUS="));
    ensure!(
        status.next() == Some("0") && status.next().is_none(),
        "Apple refused personalization: {header}"
    );
    let (_, plist) = response.context("TSS response has no REQUEST_STRING")?;
    let value =
        Value::from_reader(std::io::Cursor::new(plist.as_bytes())).context("invalid TSS plist")?;
    Ok(value)
}

pub fn ticket(response: &Value) -> Result<&[u8]> {
    wire::get(response, &["ApImg4Ticket"])?
        .as_data()
        .filter(|d| !d.is_empty())
        .context("Apple returned no ApImg4Ticket")
}
