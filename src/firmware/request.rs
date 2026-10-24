//! Validated firmware updater metadata and modern/legacy TSS requests.
use super::chunk_size;
use crate::{ipsw::Identity, tss, wire};
use anyhow::{Context, Result, ensure};
use plist::{Dictionary, Value};

/// One interpretation of the device's metadata, shared by signing and payload assembly.
pub(super) struct Request<'a> {
    pub name: &'a str,
    pub info: &'a Dictionary,
    generated: Option<&'a Dictionary>,
    pub response_tags: Vec<String>,
    build_identity_tags: Option<&'a Value>,
}

impl<'a> Request<'a> {
    pub fn parse(arguments: &'a Value) -> Result<Self> {
        ensure!(
            wire::string(arguments, &["MessageArgType"])? == "FirmwareResponseData",
            "invalid firmware updater message type"
        );
        let name = wire::string(arguments, &["MessageArgUpdaterName"])?;
        let info = wire::dictionary(wire::get(arguments, &["MessageArgInfo"])?)?;
        chunk_size(arguments)?;
        let fields = wire::dictionary(arguments)?;
        let generated = fields
            .get("DeviceGeneratedRequest")
            .map(wire::dictionary)
            .transpose()?;
        let tags = fields
            .get("DeviceGeneratedTags")
            .map(wire::dictionary)
            .transpose()?;
        let build_identity_tags = tags.and_then(|tags| tags.get("BuildIdentityTags"));
        let mut updater = Self {
            name,
            info,
            generated,
            response_tags: Vec::new(),
            build_identity_tags,
        };
        updater.response_tags = if let Some(tags) = tags.and_then(|tags| tags.get("ResponseTags")) {
            tags.as_array()
                .context("invalid updater ResponseTags")?
                .iter()
                .map(|v| Ok(v.as_string().context("invalid response tag")?.to_owned()))
                .collect::<Result<Vec<_>>>()?
        } else {
            ensure!(
                build_identity_tags.is_none(),
                "modern updater has no ResponseTags"
            );
            updater.legacy_response_tags()?
        };
        ensure!(
            !updater.response_tags.is_empty(),
            "firmware updater supplied no response tags"
        );
        Ok(updater)
    }

    pub fn signing_request(&self, id: &Identity) -> Result<Value> {
        if let Some(tags) = self.build_identity_tags {
            self.device_request(id, tags)
        } else {
            self.legacy_request(id)
        }
    }

    pub fn generated(&self) -> Result<&'a Dictionary> {
        self.generated.context("missing DeviceGeneratedRequest")
    }

    pub fn retimer_info(&self) -> Result<&'a Value> {
        let items = self
            .info
            .get("InfoArray")
            .and_then(Value::as_array)
            .context("retimer has no InfoArray")?;
        let mut selected = None;
        for item in items {
            let ticket = wire::string(item, &["TicketName"])?;
            if self.response_tags.iter().any(|tag| tag == ticket)
                || (self.response_tags.is_empty() && items.len() == 1)
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

    fn legacy_request(&self, id: &Identity) -> Result<Value> {
        let updater = self.name;
        let info = self.info;
        let generated = self.generated;
        let response_tags = &self.response_tags;
        let mut parameters = wire::dictionary(&id.value)?.clone();
        parameters.extend(info.clone());
        parameters.insert("ApProductionMode".into(), true.into());
        parameters.insert("ApSecurityMode".into(), true.into());
        let mut request = tss::host_fields();
        let prefix = match updater {
            "SE" => Some("SE,"),
            "AppleTCON" => Some("Baobab,"),
            "AppleTypeCRetimer" => Some("Timer,"),
            "Rose" => Some("Rap,"),
            "T200" => Some("BMU,"),
            _ => None,
        };
        if prefix.is_some() || matches!(updater, "Cryptex1" | "Cryptex1LocalPolicy") {
            let ticket = self.legacy_ticket()?;
            request.insert(format!("@{ticket}"), true.into());
            if prefix.is_some() {
                request.insert("@BBTicket".into(), true.into());
            }
        }
        match updater {
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
                let item = self.retimer_info()?;
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
                        let value = if ["ApChipID", "ApBoardID", "ApSecurityDomain"].contains(&key)
                        {
                            Value::Integer(wire::number(v)?.into())
                        } else {
                            v.clone()
                        };
                        request.insert(key.into(), value);
                    }
                }
                if updater == "Cryptex1LocalPolicy" {
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
            if !matches!(updater, "SE" | "T200") {
                copy_prefix(&mut request, &parameters, prefix);
            }
            for (name, value) in id.manifest()? {
                if !name.starts_with(prefix) {
                    continue;
                }
                let mut component = tss::component_request(value, &parameters)?;
                match updater {
                    "SE" => {
                        let keys = if parameters.get("SE,IsDev").and_then(Value::as_boolean)
                            == Some(true)
                        {
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
                request.insert(name.clone(), Value::Dictionary(component));
            }
        }
        if let Some(generated) = generated {
            request.extend(generated.clone());
        }
        Ok(Value::Dictionary(request))
    }

    fn device_request(&self, id: &Identity, tags: &Value) -> Result<Value> {
        let generated = self.generated()?;
        let info = self.info;
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

    fn legacy_response_tags(&self) -> Result<Vec<String>> {
        let mut tags = vec![self.legacy_ticket()?.to_owned()];
        if !matches!(self.name, "Cryptex1" | "Cryptex1LocalPolicy") {
            tags.push("FirmwareData".into());
        }
        Ok(tags)
    }

    fn legacy_ticket(&self) -> Result<&str> {
        Ok(match self.name {
            "SE" if self
                .generated
                .is_some_and(|fields| fields.contains_key("@SE2,Ticket")) =>
            {
                "SE2,Ticket"
            }
            "SE" => "SE,Ticket",
            "AppleTCON" => "Baobab,Ticket",
            "Rose" => "Rap,Ticket",
            "T200" => "BMU,Ticket",
            "Cryptex1" => "Cryptex1,Ticket",
            "Cryptex1LocalPolicy" => "ApImg4Ticket",
            "AppleTypeCRetimer" => wire::string(self.retimer_info()?, &["TicketName"])?,
            _ => anyhow::bail!("{} has no device-generated ResponseTags", self.name),
        })
    }
}

fn copy_prefix(request: &mut Dictionary, parameters: &Dictionary, prefix: &str) {
    request.extend(
        parameters
            .iter()
            .filter(|(key, _)| key.starts_with(prefix))
            .map(|(key, value)| (key.clone(), value.clone())),
    );
}
