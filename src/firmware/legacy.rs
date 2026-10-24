//! Legacy updater ticket names, hardware fields and manifest component requests.
use super::request::{Request, retimer_info};
use crate::{ipsw::Identity, tss, wire};
use anyhow::{Context, Result, ensure};
use plist::{Dictionary, Value};

pub(super) fn response_tags(
    name: &str,
    info: &Dictionary,
    generated: Option<&Dictionary>,
) -> Result<Vec<String>> {
    let mut tags = vec![ticket(name, info, generated, &[])?.to_owned()];
    if !matches!(name, "Cryptex1" | "Cryptex1LocalPolicy") {
        tags.push("FirmwareData".into());
    }
    Ok(tags)
}

pub(super) fn request(updater: &Request<'_>, id: &Identity) -> Result<Value> {
    let info = updater.info;
    let generated = updater.generated;
    let response_tags = &updater.response_tags;
    let name = updater.name;
    let mut parameters = wire::dictionary(&id.value)?.clone();
    parameters.extend(info.clone());
    parameters.insert("ApProductionMode".into(), true.into());
    parameters.insert("ApSecurityMode".into(), true.into());
    let mut request = tss::host_fields();
    let prefix = match name {
        "SE" => Some("SE,"),
        "AppleTCON" => Some("Baobab,"),
        "AppleTypeCRetimer" => Some("Timer,"),
        "Rose" => Some("Rap,"),
        "T200" => Some("BMU,"),
        _ => None,
    };
    if prefix.is_some() || matches!(name, "Cryptex1" | "Cryptex1LocalPolicy") {
        let ticket = ticket(name, info, generated, response_tags)?;
        request.insert(format!("@{ticket}"), true.into());
        if prefix.is_some() {
            request.insert("@BBTicket".into(), true.into());
        }
    }
    match name {
        "SE" => {
            for key in ["SE,ChipID", "SE,ID", "SE,Nonce", "SE,RootKeyIdentifier"] {
                request.insert(
                    key.into(),
                    parameters
                        .get(key)
                        .with_context(|| format!("missing {key}"))?
                        .clone(),
                );
            }
        }
        "AppleTypeCRetimer" => {
            let item = updater.retimer_info()?;
            let tag = wire::number(wire::get(item, &["TagNumber"])?)?;
            let ticket_name = wire::string(item, &["TicketName"])?;
            ensure!(
                tag <= 255 && ticket_name.starts_with("Timer,"),
                "invalid retimer tag/ticket"
            );
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
        }
        "T200" => {
            wire::copy_keys(&mut request, &parameters, &["BMU,BoardID"]);
            for key in ["ChipID", "Nonce", "ProductionMode", "UniqueID"] {
                if let Some(value) = parameters.get(key) {
                    request.insert(format!("BMU,{key}"), value.clone());
                }
            }
        }
        "Cryptex1" | "Cryptex1LocalPolicy" => {
            if let Some(generated) = generated {
                parameters.extend(generated.clone());
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
            if name == "Cryptex1LocalPolicy" {
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
                copy_prefix(&mut request, &parameters, "Cryptex1");
            }
            ensure!(
                !response_tags.iter().any(|tag| tag == "FirmwareData"),
                "Cryptex updater requested an unexpected raw FirmwareData payload"
            );
        }
        "AppleTCON" | "Rose" => {}
        _ => {
            let generated = generated.context("missing DeviceGeneratedRequest")?;
            ensure!(
                !generated.is_empty(),
                "empty device-generated firmware request"
            );
        }
    }
    if let Some(prefix) = prefix {
        if !matches!(name, "SE" | "T200") {
            copy_prefix(&mut request, &parameters, prefix);
        }
        for (component_name, value) in id.manifest()? {
            if !component_name.starts_with(prefix) {
                continue;
            }
            let mut component = tss::component_request(value, &parameters)?;
            match name {
                "SE" => {
                    let keys =
                        if parameters.get("SE,IsDev").and_then(Value::as_boolean) == Some(true) {
                            ["ProductionCMAC", "ProductionUpdatePayloadHash"]
                        } else {
                            ["DevelopmentCMAC", "DevelopmentUpdatePayloadHash"]
                        };
                    for key in keys {
                        component.remove(key);
                    }
                }
                "AppleTCON" => {
                    let production = parameters
                        .get("Baobab,ProductionMode")
                        .and_then(Value::as_boolean)
                        .unwrap_or(false);
                    component.insert("EPRO".into(), production.into());
                }
                _ => {}
            }
            request.insert(component_name.clone(), Value::Dictionary(component));
        }
    }
    if let Some(generated) = generated {
        request.extend(generated.clone());
    }
    Ok(Value::Dictionary(request))
}

fn ticket<'a>(
    name: &str,
    info: &'a Dictionary,
    generated: Option<&Dictionary>,
    response_tags: &[String],
) -> Result<&'a str> {
    Ok(match name {
        "SE" if generated.is_some_and(|fields| fields.contains_key("@SE2,Ticket")) => "SE2,Ticket",
        "SE" => "SE,Ticket",
        "AppleTCON" => "Baobab,Ticket",
        "Rose" => "Rap,Ticket",
        "T200" => "BMU,Ticket",
        "Cryptex1" => "Cryptex1,Ticket",
        "Cryptex1LocalPolicy" => "ApImg4Ticket",
        "AppleTypeCRetimer" => wire::string(retimer_info(info, response_tags)?, &["TicketName"])?,
        _ => anyhow::bail!("{} has no device-generated ResponseTags", name),
    })
}

fn copy_prefix(request: &mut Dictionary, parameters: &Dictionary, prefix: &str) {
    request.extend(
        parameters
            .iter()
            .filter(|(key, _)| key.starts_with(prefix))
            .map(|(key, value)| (key.clone(), value.clone())),
    );
}
