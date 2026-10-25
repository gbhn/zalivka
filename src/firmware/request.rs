//! Bind updater metadata without controller or model tables.
use super::chunk_size;
use crate::{device::DeviceInfo, ipsw::Identity, tss, wire};
use anyhow::{Context, Result, ensure};
use plist::{Dictionary, Value};
use std::collections::BTreeSet;

pub(super) struct NamespaceRequest {
    pub request: Value,
    pub component: String,
    pub ticket: String,
}

pub(super) fn namespace_request(id: &Identity, arguments: &Value) -> Result<NamespaceRequest> {
    ensure!(
        wire::string(arguments, &["MessageArgType"])? == "FirmwareResponseData",
        "invalid firmware updater message type"
    );
    chunk_size(arguments)?;
    let info = wire::dictionary(wire::get(arguments, &["MessageArgInfo"])?)?;
    let namespaces = info
        .keys()
        .filter_map(|key| key.split_once(',').map(|(prefix, _)| prefix))
        .collect::<BTreeSet<_>>();
    ensure!(
        namespaces.len() == 1,
        "DeviceGeneratedRequest is absent and updater namespace is missing or ambiguous"
    );
    let namespace = *namespaces.first().unwrap();
    ensure!(!namespace.is_empty(), "empty updater namespace");
    let prefix = format!("{namespace},");
    ensure!(
        info.keys().all(|name| name.starts_with(&prefix)),
        "updater info contains fields outside its namespace"
    );
    let mut components = id
        .manifest()?
        .iter()
        .filter(|(name, _)| name.starts_with(&prefix));
    let (component, value) = components
        .next()
        .context("updater namespace has no manifest component")?;
    ensure!(
        components.next().is_none(),
        "updater namespace selects multiple manifest components"
    );
    id.path(component)?;
    let mut parameters = Dictionary::new();
    for (key, value) in wire::dictionary(&id.value)? {
        if key.starts_with(&prefix) {
            parameters.insert(key.clone(), value.clone());
        }
    }
    ensure!(
        !parameters.is_empty(),
        "updater namespace has no identity parameters"
    );
    for (key, value) in info {
        if let Some(declared) = parameters.get(key) {
            ensure!(
                declared == value,
                "device and IPSW disagree on updater field {key}"
            );
        }
        parameters.insert(key.clone(), value.clone());
    }
    let production = info
        .get(&format!("{prefix}ProductionMode"))
        .and_then(Value::as_boolean)
        .context("namespace updater requires explicit production mode")?;
    let mut entry = wire::dictionary(value)?.clone();
    entry.remove("Info");
    if let Some(rules) = wire::optional(value, &["Info", "RestoreRequestRules"])? {
        tss::apply_rules(&mut entry, rules, &parameters)?;
    }
    if let Some(value) = entry.get("EPRO") {
        ensure!(
            value.as_boolean() == Some(production),
            "updater EPRO disagrees with device production mode"
        );
    }
    entry.insert("EPRO".into(), production.into());
    let ticket = format!("{prefix}Ticket");
    let mut request = tss::host_fields();
    request.extend(parameters);
    request.insert("@BBTicket".into(), true.into());
    request.insert(format!("@{ticket}"), true.into());
    request.insert(component.clone(), Value::Dictionary(entry));
    Ok(NamespaceRequest {
        request: Value::Dictionary(request),
        component: component.clone(),
        ticket,
    })
}

pub(super) struct Request<'a> {
    generated: &'a Dictionary,
    build_identity_tags: Vec<&'a str>,
    pub response_tags: Vec<String>,
}

fn tags(value: &Value) -> Result<Vec<&str>> {
    let mut seen = BTreeSet::new();
    value
        .as_array()
        .context("expected tag array")?
        .iter()
        .map(|value| {
            let name = value
                .as_string()
                .filter(|name| !name.is_empty())
                .context("expected nonempty tag name")?;
            ensure!(seen.insert(name), "duplicate tag {name}");
            Ok(name)
        })
        .collect()
}

impl<'a> Request<'a> {
    pub fn parse(arguments: &'a Value) -> Result<Self> {
        ensure!(
            wire::string(arguments, &["MessageArgType"])? == "FirmwareResponseData",
            "invalid firmware updater message type"
        );
        chunk_size(arguments)?;
        let generated = wire::dictionary(
            wire::get(arguments, &["DeviceGeneratedRequest"])
                .context("strict restore requires DeviceGeneratedRequest")?,
        )?;
        ensure!(!generated.is_empty(), "empty DeviceGeneratedRequest");
        let build_identity_tags = tags(
            wire::get(arguments, &["DeviceGeneratedTags", "BuildIdentityTags"])
                .context("strict restore requires explicit BuildIdentityTags")?,
        )
        .context("invalid updater BuildIdentityTags")?;
        let response_tags = tags(
            wire::get(arguments, &["DeviceGeneratedTags", "ResponseTags"])
                .context("strict restore requires explicit ResponseTags")?,
        )
        .context("invalid updater ResponseTags")?
        .into_iter()
        .map(str::to_owned)
        .collect::<Vec<_>>();
        ensure!(
            !response_tags.is_empty(),
            "firmware updater supplied no response tags"
        );
        Ok(Self {
            generated,
            build_identity_tags,
            response_tags,
        })
    }

    pub fn signing_request(&self, id: &Identity, device: &DeviceInfo) -> Result<Value> {
        let mut request = tss::updater_fields(device)?;
        let identity = wire::dictionary(&id.value)?;
        // BuildIdentityTags selects available fields; it is not a required-field
        // schema. DeviceGeneratedRequest remains authoritative, including types.
        for name in &self.build_identity_tags {
            if let Some(value) = self.generated.get(name).or_else(|| identity.get(name)) {
                request.insert((*name).into(), value.clone());
            }
        }
        request.extend(self.generated.clone());
        Ok(Value::Dictionary(request))
    }
}

#[cfg(test)]
#[path = "../../tests/unit/firmware/request.rs"]
mod tests;
