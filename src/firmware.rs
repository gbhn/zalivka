//! Firmware updater personalization for the auxiliary controllers in Macs.
mod canary;
mod containers;
mod legacy;
mod payload;
mod request;
use crate::{
    ipsw::{Identity, Ipsw},
    wire,
};
use anyhow::{Context, Result};
pub use canary::canary_response;
pub use containers::{Ftab, payload_ranges, tcon_metadata_matches};
use payload::payload;
use plist::Value;
use std::io::Write;

pub struct Update {
    pub request: Value,
    pub response_tags: Vec<String>,
    pub firmware: Option<Value>,
}

impl Update {
    pub fn finish(self, mut response: Value) -> Result<Value> {
        if let Some(bytes) = self.firmware {
            let fields = response
                .as_dictionary_mut()
                .context("invalid updater TSS response")?;
            if !fields.contains_key("FirmwareData") {
                fields.insert("FirmwareData".into(), bytes);
            }
        }
        for tag in self.response_tags {
            wire::get(&response, &[&tag])
                .with_context(|| format!("Apple returned no requested firmware tag {tag}"))?;
        }
        Ok(response)
    }
}

pub fn prepare(ipsw: &mut Ipsw, id: &Identity, arguments: &Value) -> Result<Update> {
    let updater = request::Request::parse(arguments)?;
    let request = updater.signing_request(id)?;
    let firmware = if updater
        .response_tags
        .iter()
        .any(|tag| tag == "FirmwareData")
    {
        payload(ipsw, id, &updater)?
    } else {
        None
    };
    Ok(Update {
        request,
        firmware,
        response_tags: updater.response_tags,
    })
}

fn chunk_size(arguments: &Value) -> Result<usize> {
    Ok(wire::dictionary(arguments)?
        .get("DataChunkSize")
        .map(wire::number)
        .transpose()?
        .unwrap_or(0)
        .min(256 * 1024) as usize)
}

/// Optional chunk framing carries tickets first, followed by data and DataDone.
pub fn send_response(out: &mut impl Write, mut response: Value, arguments: &Value) -> Result<()> {
    let size = chunk_size(arguments)?;
    let fields = response
        .as_dictionary_mut()
        .context("invalid updater response")?;
    let bytes = match fields.get_mut("FirmwareData") {
        Some(Value::Data(bytes)) if size != 0 => std::mem::take(bytes),
        _ => return wire::send(out, &wire::dict([("FirmwareResponseData", response)])),
    };
    fields.remove("FirmwareData");
    wire::send(
        out,
        &wire::dict([
            ("FirmwareResponseData", response),
            ("DataSize", (bytes.len() as u64).into()),
        ]),
    )?;
    for chunk in bytes.chunks(size) {
        wire::send(
            out,
            &wire::dict([("FirmwareResponseData", Value::Data(chunk.to_vec()))]),
        )?;
    }
    wire::send(
        out,
        &wire::dict([
            ("FirmwareResponseData", Value::Data(vec![])),
            ("DataDone", true.into()),
        ]),
    )
}
