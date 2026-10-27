//! Firmware updater personalization for the auxiliary controllers in Macs.
mod canary;
mod containers;
mod request;
use crate::{device::DeviceInfo, ipsw::Identity, wire};
use anyhow::{Context, Result};
pub use canary::canary_response;
pub use containers::payload_ranges;
pub(crate) use containers::{MAX_PLIST_BUNDLE, plist_prefix, verify_plist_bundle};
use plist::Value;
use std::io::Write;

pub struct Update {
    pub request: Value,
    pub response_tags: Vec<String>,
    payload: Option<Vec<u8>>,
}

impl Update {
    pub fn finish(self, mut response: Value) -> Result<Value> {
        for tag in &self.response_tags {
            let value = wire::get(&response, &[tag])
                .with_context(|| format!("Apple returned no requested firmware tag {tag}"))?;
            if tag != "FirmwareData"
                && wire::optional_boolean(&self.request, &[&format!("@{tag}")])? == Some(true)
            {
                anyhow::ensure!(
                    value.as_data().is_some_and(|data| !data.is_empty()),
                    "Apple returned an invalid or empty firmware ticket {tag}"
                );
            }
        }
        if let Some(payload) = self.payload {
            let fields = response
                .as_dictionary_mut()
                .context("invalid updater response")?;
            anyhow::ensure!(
                !fields.contains_key("FirmwareData"),
                "namespace response unexpectedly contains FirmwareData"
            );
            fields.insert("FirmwareData".into(), Value::Data(payload));
        }
        Ok(response)
    }
}

/// Prefer explicit device-generated requests; simple namespace requests can use
/// one verified plist payload bundle. Updater names never select behavior.
pub fn prepare(
    ipsw: &mut crate::ipsw::Ipsw,
    id: &Identity,
    device: &DeviceInfo,
    arguments: &Value,
) -> Result<Update> {
    if wire::optional(arguments, &["DeviceGeneratedRequest"])?.is_none()
        && wire::optional(arguments, &["DeviceGeneratedTags"])?.is_none()
    {
        let inferred = request::namespace_request(id, arguments)?;
        let payload = ipsw.plist_component(id, &inferred.component)?;
        return Ok(Update {
            request: inferred.request,
            response_tags: vec![inferred.ticket],
            payload: Some(payload),
        });
    }
    let updater = request::Request::parse(arguments)?;
    Ok(Update {
        request: updater.signing_request(id, device)?,
        response_tags: updater.response_tags,
        payload: None,
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
