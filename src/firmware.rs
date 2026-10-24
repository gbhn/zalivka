//! Firmware updater personalization for the auxiliary controllers in Macs.
mod canary;
mod containers;
mod payload;
use crate::{
    ipsw::{Identity, Ipsw},
    tss, wire,
};
use anyhow::{Context, Result, ensure};
pub use canary::canary_response;
pub use containers::{Ftab, payload_ranges, tcon_metadata_matches};
use payload::payload;
use plist::{Dictionary, Value};
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
    ensure!(
        wire::string(arguments, &["MessageArgType"])? == "FirmwareResponseData",
        "invalid firmware updater message type"
    );
    let updater = wire::string(arguments, &["MessageArgUpdaterName"])?;
    let info = wire::dictionary(wire::get(arguments, &["MessageArgInfo"])?)?;
    chunk_size(arguments)?;
    let tags = wire::dictionary(arguments)?
        .get("DeviceGeneratedTags")
        .map(wire::dictionary)
        .transpose()?;
    let response_tags: Vec<String> =
        if let Some(tags) = tags.and_then(|tags| tags.get("ResponseTags")) {
            tags.as_array()
                .context("invalid updater ResponseTags")?
                .iter()
                .map(|v| Ok(v.as_string().context("invalid response tag")?.to_owned()))
                .collect::<Result<_>>()?
        } else {
            ensure!(
                tags.is_none_or(|tags| !tags.contains_key("BuildIdentityTags")),
                "modern updater has no ResponseTags"
            );
            legacy_response_tags(updater, info, arguments)?
        };
    ensure!(
        !response_tags.is_empty(),
        "firmware updater supplied no response tags"
    );
    let wants_data = response_tags.iter().any(|t| t == "FirmwareData");
    let request = if let Some(tags) = tags.and_then(|tags| tags.get("BuildIdentityTags")) {
        device_request(id, info, arguments, tags)?
    } else {
        legacy_request(id, updater, info, arguments, &response_tags)?
    };
    let firmware = if wants_data {
        payload(ipsw, id, updater, info, arguments, &response_tags)?
    } else {
        None
    };
    Ok(Update {
        request,
        firmware,
        response_tags,
    })
}

fn legacy_request(
    id: &Identity,
    updater: &str,
    info: &Dictionary,
    arguments: &Value,
    response_tags: &[String],
) -> Result<Value> {
    let mut parameters = wire::dictionary(&id.value)?.clone();
    parameters.extend(info.clone());
    parameters.insert("ApProductionMode".into(), true.into());
    parameters.insert("ApSecurityMode".into(), true.into());
    let mut request = tss::host_fields();
    match updater {
        "SE" => {
            request.insert("@BBTicket".into(), true.into());
            if wire::get(arguments, &["DeviceGeneratedRequest", "@SE2,Ticket"]).is_err() {
                request.insert("@SE,Ticket".into(), true.into());
            }
            for key in ["SE,ChipID", "SE,ID", "SE,Nonce", "SE,RootKeyIdentifier"] {
                request.insert(
                    key.into(),
                    parameters
                        .get(key)
                        .with_context(|| format!("missing {key}"))?
                        .clone(),
                );
            }
            components(&mut request, id, "SE,", &parameters)?;
            let is_dev = parameters
                .get("SE,IsDev")
                .and_then(Value::as_boolean)
                .unwrap_or(false);
            for (key, value) in &mut request {
                if key.starts_with("SE,")
                    && let Some(component) = value.as_dictionary_mut()
                {
                    let keys = if is_dev {
                        ["ProductionCMAC", "ProductionUpdatePayloadHash"]
                    } else {
                        ["DevelopmentCMAC", "DevelopmentUpdatePayloadHash"]
                    };
                    for key in keys {
                        component.remove(key);
                    }
                }
            }
        }
        "AppleTCON" => {
            request.insert("@BBTicket".into(), true.into());
            request.insert("@Baobab,Ticket".into(), true.into());
            copy_prefix(&mut request, &parameters, "Baobab,");
            components(&mut request, id, "Baobab,", &parameters)?;
            let production = parameters
                .get("Baobab,ProductionMode")
                .and_then(Value::as_boolean)
                .unwrap_or(false);
            for (key, value) in &mut request {
                if key.starts_with("Baobab,")
                    && let Some(component) = value.as_dictionary_mut()
                {
                    component.insert("EPRO".into(), production.into());
                }
            }
        }
        "AppleTypeCRetimer" => {
            let item = retimer_info(info, response_tags)?;
            let tag = wire::number(wire::get(item, &["TagNumber"])?)?;
            let ticket_name = wire::string(item, &["TicketName"])?;
            ensure!(
                tag <= 255 && ticket_name.starts_with("Timer,"),
                "invalid retimer tag/ticket"
            );
            request.insert("@BBTicket".into(), true.into());
            request.insert(format!("@{ticket_name}"), true.into());
            let hardware = wire::dictionary(wire::get(item, &["HardwareID"])?)?;
            for (target, source) in [
                ("ChipID", "ChipID"),
                ("BoardID", "BoardID"),
                ("ECID", "ECID"),
                ("Nonce", "Nonce"),
                ("SecurityMode", "SecurityMode"),
                ("SecurityDomain", "SecurityDomain"),
                ("ProductionMode", "ProductionStatus"),
            ] {
                let value = hardware
                    .get(source)
                    .with_context(|| format!("retimer HardwareID has no {source}"))?;
                parameters.insert(format!("Timer,{target},{tag}"), value.clone());
            }
            if let Some(ap) = info.get("APInfo").and_then(Value::as_dictionary) {
                parameters.extend(ap.clone());
            }
            copy_prefix(&mut request, &parameters, "Timer,");
            components(&mut request, id, "Timer,", &parameters)?;
        }
        "Rose" => {
            request.insert("@BBTicket".into(), true.into());
            request.insert("@Rap,Ticket".into(), true.into());
            copy_prefix(&mut request, &parameters, "Rap,");
            components(&mut request, id, "Rap,", &parameters)?;
        }
        "T200" => {
            request.insert("@BBTicket".into(), true.into());
            request.insert("@BMU,Ticket".into(), true.into());
            if let Some(board) = parameters.get("BMU,BoardID") {
                request.insert("BMU,BoardID".into(), board.clone());
            }
            for key in ["ChipID", "Nonce", "ProductionMode", "UniqueID"] {
                if let Some(value) = parameters.get(key) {
                    request.insert(format!("BMU,{key}"), value.clone());
                }
            }
            components(&mut request, id, "BMU,", &parameters)?;
        }
        "Cryptex1" | "Cryptex1LocalPolicy" => {
            if let Ok(generated) = wire::get(arguments, &["DeviceGeneratedRequest"]) {
                parameters.extend(wire::dictionary(generated)?.clone());
            }
            for key in [
                "ApECID",
                "ApChipID",
                "ApBoardID",
                "ApSecurityDomain",
                "UniqueBuildID",
                "ApSecurityMode",
                "ApProductionMode",
            ] {
                if let Some(v) = parameters.get(key) {
                    let value = if ["ApChipID", "ApBoardID", "ApSecurityDomain"].contains(&key) {
                        Value::Integer(wire::number(v)?.into())
                    } else {
                        v.clone()
                    };
                    request.insert(key.into(), value);
                }
            }
            if updater == "Cryptex1LocalPolicy" {
                request.insert("@ApImg4Ticket".into(), true.into());
                wire::copy_keys(
                    &mut request,
                    &parameters,
                    &[
                        "Ap,LocalBoot",
                        "Ap,LocalPolicy",
                        "Ap,NextStageIM4MHash",
                        "Ap,RecoveryOSPolicyNonceHash",
                        "Ap,VolumeUUID",
                        "ApNonce",
                        "Ap,NextStageCryptex1IM4MHash",
                    ],
                );
            } else {
                request.insert("@Cryptex1,Ticket".into(), true.into());
                copy_prefix(&mut request, &parameters, "Cryptex1");
            }
            ensure!(
                !response_tags.iter().any(|tag| tag == "FirmwareData"),
                "Cryptex updater requested an unexpected raw FirmwareData payload"
            );
        }
        _ => {
            let generated = wire::dictionary(wire::get(arguments, &["DeviceGeneratedRequest"])?)?;
            ensure!(
                !generated.is_empty(),
                "empty device-generated firmware request"
            );
        }
    }
    if let Ok(generated) = wire::get(arguments, &["DeviceGeneratedRequest"]) {
        request.extend(wire::dictionary(generated)?.clone());
    }
    Ok(Value::Dictionary(request))
}

fn device_request(
    id: &Identity,
    info: &Dictionary,
    arguments: &Value,
    tags: &Value,
) -> Result<Value> {
    let generated = wire::dictionary(wire::get(arguments, &["DeviceGeneratedRequest"])?)?;
    ensure!(
        !generated.is_empty(),
        "empty device-generated firmware request"
    );
    let mut request = tss::host_fields();
    wire::copy_keys(
        &mut request,
        info,
        &[
            "ApECID",
            "UniqueBuildID",
            "ApChipID",
            "ApBoardID",
            "ApSecurityDomain",
        ],
    );
    let names = tags
        .as_array()
        .context("invalid updater BuildIdentityTags")?;
    for name in ["ApChipID", "ApBoardID"].into_iter().map(Ok).chain(
        names
            .iter()
            .map(|name| name.as_string().context("invalid updater BuildIdentityTag")),
    ) {
        let name = name?;
        if let Some(value) = wire::dictionary(&id.value)?.get(name) {
            let value = if value
                .as_string()
                .is_some_and(|s| s.starts_with("0x") || s.starts_with("0X"))
            {
                wire::number(value)?.into()
            } else {
                value.clone()
            };
            request.insert(name.into(), value);
        }
    }
    request.insert("@BBTicket".into(), true.into());
    request.insert("ApSecurityMode".into(), true.into());
    let mut production = None;
    if !generated.contains_key("ApProductionMode") {
        for (key, value) in info
            .iter()
            .filter(|(key, _)| key.ends_with("ProductionMode"))
        {
            let value = value
                .as_boolean()
                .or_else(|| {
                    value
                        .as_unsigned_integer()
                        .filter(|n| *n <= 1)
                        .map(|n| n != 0)
                })
                .with_context(|| format!("invalid {key}"))?;
            ensure!(
                production.is_none_or(|previous| previous == value),
                "conflicting updater production modes"
            );
            production = Some(value);
        }
    }
    request.insert("ApProductionMode".into(), production.unwrap_or(true).into());
    request.extend(generated.clone());
    request.remove("RequiresUIDMode");
    Ok(Value::Dictionary(request))
}

fn legacy_response_tags(
    updater: &str,
    info: &Dictionary,
    arguments: &Value,
) -> Result<Vec<String>> {
    let ticket = match updater {
        "SE" if wire::get(arguments, &["DeviceGeneratedRequest", "@SE2,Ticket"]).is_ok() => {
            "SE2,Ticket"
        }
        "SE" => "SE,Ticket",
        "AppleTCON" => "Baobab,Ticket",
        "Rose" => "Rap,Ticket",
        "T200" => "BMU,Ticket",
        "Cryptex1" => "Cryptex1,Ticket",
        "Cryptex1LocalPolicy" => "ApImg4Ticket",
        "AppleTypeCRetimer" => wire::string(retimer_info(info, &[])?, &["TicketName"])?,
        _ => anyhow::bail!("{updater} has no device-generated ResponseTags"),
    };
    let mut tags = vec![ticket.to_owned()];
    if !matches!(updater, "Cryptex1" | "Cryptex1LocalPolicy") {
        tags.push("FirmwareData".into());
    }
    Ok(tags)
}

fn retimer_info<'a>(info: &'a Dictionary, response_tags: &[String]) -> Result<&'a Value> {
    let items = info
        .get("InfoArray")
        .and_then(Value::as_array)
        .context("retimer has no InfoArray")?;
    let mut selected = None;
    for item in items {
        let ticket = wire::string(item, &["TicketName"])?;
        if response_tags.iter().any(|tag| tag == ticket)
            || (response_tags.is_empty() && items.len() == 1)
        {
            ensure!(
                selected.is_none(),
                "ambiguous retimer tickets for one firmware payload"
            );
            selected = Some(item);
        }
    }
    selected.context("retimer InfoArray has no matching requested ticket")
}

fn chunk_size(arguments: &Value) -> Result<Option<usize>> {
    wire::dictionary(arguments)?
        .get("DataChunkSize")
        .map(|size| Ok((wire::number(size)?.min(256 * 1024)) as usize))
        .transpose()
}

/// Optional chunk framing carries tickets first, followed by data and DataDone.
pub fn send_response(out: &mut impl Write, mut response: Value, arguments: &Value) -> Result<()> {
    let size = chunk_size(arguments)?.unwrap_or(0);
    let fields = response
        .as_dictionary_mut()
        .context("invalid updater response")?;
    if size == 0
        || fields
            .get("FirmwareData")
            .and_then(Value::as_data)
            .is_none()
    {
        return wire::send(out, &wire::dict([("FirmwareResponseData", response)]));
    }
    let Value::Data(bytes) = fields.remove("FirmwareData").unwrap() else {
        unreachable!()
    };
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

fn copy_prefix(request: &mut Dictionary, parameters: &Dictionary, prefix: &str) {
    request.extend(
        parameters
            .iter()
            .filter(|(key, _)| key.starts_with(prefix))
            .map(|(key, value)| (key.clone(), value.clone())),
    );
}
fn components(
    request: &mut Dictionary,
    id: &Identity,
    prefix: &str,
    parameters: &Dictionary,
) -> Result<()> {
    for (key, value) in id.manifest()? {
        if !key.starts_with(prefix) {
            continue;
        }
        request.insert(
            key.clone(),
            Value::Dictionary(tss::component_request(value, parameters)?),
        );
    }
    Ok(())
}
