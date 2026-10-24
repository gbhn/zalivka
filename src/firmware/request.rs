//! Parse complete updater metadata before signing or reading firmware payloads.
use super::{chunk_size, legacy};
use crate::{ipsw::Identity, tss, wire};
use anyhow::{Context, Result, ensure};
use plist::{Dictionary, Value};

/// One interpretation of the device's metadata, shared by signing and payload assembly.
pub(super) struct Request<'a> {
    pub name: &'a str,
    pub info: &'a Dictionary,
    pub(super) generated: Option<&'a Dictionary>,
    pub response_tags: Vec<String>,
    build_identity_tags: Option<Vec<&'a str>>,
}

impl<'a> Request<'a> {
    pub fn parse(arguments: &'a Value) -> Result<Self> {
        ensure!(
            wire::string(arguments, &["MessageArgType"])? == "FirmwareResponseData",
            "invalid firmware updater message type"
        );
        chunk_size(arguments)?;
        let fields = wire::dictionary(arguments)?;
        let name = wire::string(arguments, &["MessageArgUpdaterName"])?;
        let info = wire::dictionary(wire::get(arguments, &["MessageArgInfo"])?)?;
        let generated = fields
            .get("DeviceGeneratedRequest")
            .map(wire::dictionary)
            .transpose()?;
        let tags = fields
            .get("DeviceGeneratedTags")
            .map(wire::dictionary)
            .transpose()?;
        let build_identity_tags = tags
            .and_then(|tags| tags.get("BuildIdentityTags"))
            .map(|tags| {
                tags.as_array()
                    .context("invalid updater BuildIdentityTags")?
                    .iter()
                    .map(|tag| tag.as_string().context("invalid updater BuildIdentityTag"))
                    .collect::<Result<Vec<_>>>()
            })
            .transpose()?;
        let response_tags = if let Some(tags) = tags.and_then(|tags| tags.get("ResponseTags")) {
            tags.as_array()
                .context("invalid updater ResponseTags")?
                .iter()
                .map(|tag| Ok(tag.as_string().context("invalid response tag")?.to_owned()))
                .collect::<Result<Vec<_>>>()?
        } else {
            ensure!(
                build_identity_tags.is_none(),
                "modern updater has no ResponseTags"
            );
            legacy::response_tags(name, info, generated)?
        };
        ensure!(
            !response_tags.is_empty(),
            "firmware updater supplied no response tags"
        );
        Ok(Self {
            name,
            info,
            generated,
            response_tags,
            build_identity_tags,
        })
    }

    pub fn signing_request(&self, id: &Identity) -> Result<Value> {
        match &self.build_identity_tags {
            Some(tags) => self.device_request(id, tags),
            None => legacy::request(self, id),
        }
    }

    pub fn generated(&self) -> Result<&'a Dictionary> {
        self.generated.context("missing DeviceGeneratedRequest")
    }

    pub fn retimer_info(&self) -> Result<&'a Value> {
        retimer_info(self.info, &self.response_tags)
    }

    fn device_request(&self, id: &Identity, tags: &[&str]) -> Result<Value> {
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
        for name in ["ApChipID", "ApBoardID"]
            .into_iter()
            .chain(tags.iter().copied())
        {
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
}

pub(super) fn retimer_info<'a>(
    info: &'a Dictionary,
    response_tags: &[String],
) -> Result<&'a Value> {
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

#[cfg(test)]
#[path = "../../tests/unit/firmware/request.rs"]
mod tests;
