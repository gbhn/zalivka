//! Bind updater metadata without controller or model tables.
use super::Update;
use crate::{
    device::DeviceInfo,
    ipsw::{Identity, Ipsw},
    tss, wire,
};
use anyhow::{Context, Result, ensure};
use plist::{Dictionary, Value};
use std::collections::BTreeSet;

pub(super) fn namespace_update(
    ipsw: &mut Ipsw,
    id: &Identity,
    arguments: &Value,
) -> Result<Update> {
    let info = wire::dictionary(wire::get(arguments, &["MessageArgInfo"])?)?;
    let namespace = info
        .keys()
        .next()
        .and_then(|key| key.split_once(',').map(|(prefix, _)| prefix))
        .context(
            "DeviceGeneratedRequest is absent and updater namespace is missing or ambiguous",
        )?;
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
    let payload = ipsw.plist_component(id, component)?;
    Ok(Update {
        request: Value::Dictionary(request),
        response_tags: vec![ticket],
        payload: Some(payload),
    })
}

pub(super) fn tags(value: &Value) -> Result<Vec<&str>> {
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

pub(super) fn generated_update(
    id: &Identity,
    device: &DeviceInfo,
    arguments: &Value,
) -> Result<Update> {
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
    let common = tss::updater_fields(device)?;
    let mut request = generated.clone();
    let identity = wire::dictionary(&id.value)?;
    // BuildIdentityTags selects available fields; it is not a required-field
    // schema. Preserve device-generated types while checking AP consistency.
    for name in build_identity_tags {
        if let Some(value) = identity.get(name) {
            request.entry(name).or_insert_with(|| value.clone());
        }
    }
    for (name, expected) in common {
        let Some(value) = request.get(&name) else {
            request.insert(name, expected);
            continue;
        };
        let matches = if let Some(expected) = expected.as_boolean() {
            value.as_boolean() == Some(expected)
        } else if let Some(expected) = expected.as_unsigned_integer() {
            wire::number(value).with_context(|| format!("invalid updater AP field {name}"))?
                == expected
        } else {
            continue;
        };
        ensure!(matches, "updater field {name} disagrees with connected AP");
    }
    Ok(Update {
        request: Value::Dictionary(request),
        response_tags,
        payload: None,
    })
}

#[cfg(test)]
#[path = "../../tests/unit/firmware/request.rs"]
mod tests;
