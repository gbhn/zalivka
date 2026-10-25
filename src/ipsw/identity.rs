//! Manifest identities and selection of erase, upgrade and recoveryOS variants.
use super::{Ipsw, component_path};
use crate::{device::DeviceInfo, wire};
use anyhow::{Context, Result, bail, ensure};
use plist::Value;
use serde::Serialize;
use std::collections::{HashMap, HashSet};

fn recovery_variant(value: &Value) -> Result<Option<&str>> {
    let info = wire::dictionary(wire::get(value, &["Info"])?)?;
    let mut selected = None;
    for key in ["MacOSVariant", "RecoveryVariant"] {
        if let Some(value) = info.get(key) {
            let variant = value
                .as_string()
                .filter(|value| !value.is_empty())
                .with_context(|| format!("invalid recoveryOS variant name in {key}"))?;
            ensure!(
                selected.is_none_or(|previous| previous == variant),
                "conflicting MacOSVariant and RecoveryVariant"
            );
            selected = Some(variant);
        }
    }
    Ok(selected)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub enum Behavior {
    Erase,
    Update,
}
impl Behavior {
    pub fn name(self) -> &'static str {
        match self {
            Self::Erase => "Erase",
            Self::Update => "Update",
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct IdentitySummary {
    pub index: usize,
    pub chip_id: u64,
    pub board_id: u64,
    pub device_class: String,
    pub variant: String,
    pub restore_behavior: String,
    pub macos_variant: Option<String>,
    pub components: usize,
}

#[derive(Clone, Debug)]
pub struct Identity {
    pub index: usize,
    pub value: Value,
    pub(super) file_types: HashMap<String, Option<[u8; 4]>>,
}

impl Identity {
    pub fn new(index: usize, value: Value) -> Self {
        Self {
            index,
            value,
            file_types: HashMap::new(),
        }
    }

    pub fn manifest(&self) -> Result<&plist::Dictionary> {
        wire::dictionary(wire::get(&self.value, &["Manifest"])?)
    }
    pub fn info(&self, key: &str) -> Result<&Value> {
        wire::get(&self.value, &["Info", key])
    }
    pub fn path(&self, name: &str) -> Result<&str> {
        component_path(wire::get(&self.value, &["Manifest", name])?)?
            .with_context(|| format!("missing component path {name}"))
    }
    pub fn component_by_type(&self, tag: &[u8; 4]) -> Result<Option<&str>> {
        let mut selected = None;
        for name in self.manifest()?.keys() {
            if self.payload_type(name)? == Some(*tag) {
                ensure!(selected.is_none(), "ambiguous Img4PayloadType {tag:?}");
                selected = Some(name.as_str());
            }
        }
        Ok(selected)
    }

    /// An explicit manifest override takes precedence over the file's IM4P tag.
    pub fn payload_type(&self, name: &str) -> Result<Option<[u8; 4]>> {
        let entry = wire::get(&self.value, &["Manifest", name])?;
        if let Some(tag) = crate::img4::component_tag(name, Some(entry))? {
            return Ok(Some(tag));
        }
        Ok(component_path(entry)?
            .and_then(|path| self.file_types.get(path))
            .copied()
            .flatten())
    }

    pub fn require_component_type(&self, tag: &[u8; 4]) -> Result<&str> {
        self.component_by_type(tag)?.with_context(|| {
            format!(
                "IPSW has no component with payload type {} from manifest or IM4P",
                String::from_utf8_lossy(tag)
            )
        })
    }
    pub fn is_macos(&self) -> Result<bool> {
        recovery_variant(&self.value)?;
        Ok(wire::optional(&self.value, &["Info", "MacOSVariant"])?
            .map(|value| {
                value
                    .as_string()
                    .filter(|value| !value.is_empty())
                    .context("invalid MacOSVariant")
            })
            .transpose()?
            .is_some())
    }
    pub fn behavior(&self) -> Result<Behavior> {
        match self.info("RestoreBehavior")?.as_string() {
            Some("Erase") => Ok(Behavior::Erase),
            Some("Update") => Ok(Behavior::Update),
            value => bail!("invalid restore behavior {value:?}"),
        }
    }
    pub fn validate_behavior(&self, behavior: Behavior) -> Result<()> {
        ensure!(
            self.behavior()? == behavior,
            "selected identity does not match requested behavior"
        );
        Ok(())
    }
    pub fn summary(&self) -> Result<IdentitySummary> {
        IdentitySummary::from_value(self.index, &self.value)
    }
}

impl IdentitySummary {
    fn from_value(index: usize, value: &Value) -> Result<Self> {
        recovery_variant(value)?;
        let info = |key| wire::get(value, &["Info", key]);
        Ok(Self {
            index,
            chip_id: wire::number(wire::get(value, &["ApChipID"])?)?,
            board_id: wire::number(wire::get(value, &["ApBoardID"])?)?,
            device_class: info("DeviceClass")?
                .as_string()
                .context("invalid DeviceClass")?
                .into(),
            variant: info("Variant")?
                .as_string()
                .filter(|value| !value.is_empty())
                .context("invalid Variant")?
                .into(),
            restore_behavior: info("RestoreBehavior")?
                .as_string()
                .filter(|value| !value.is_empty())
                .context("invalid RestoreBehavior")?
                .into(),
            macos_variant: wire::optional(value, &["Info", "MacOSVariant"])?
                .map(|value| {
                    value
                        .as_string()
                        .filter(|value| !value.is_empty())
                        .context("invalid MacOSVariant")
                        .map(str::to_owned)
                })
                .transpose()?,
            components: wire::dictionary(wire::get(value, &["Manifest"])?)?.len(),
        })
    }
}

impl Ipsw {
    pub(super) fn identity_values(&self) -> impl Iterator<Item = (usize, &Value)> {
        self.manifest
            .as_dictionary()
            .and_then(|d| d.get("BuildIdentities"))
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .enumerate()
    }

    pub fn identities(&self) -> Vec<Identity> {
        self.identity_values()
            .map(|(index, value)| Identity::new(index, value.clone()))
            .collect()
    }

    pub fn identity_summaries(&self) -> impl Iterator<Item = Result<IdentitySummary>> {
        self.identity_values()
            .map(|(index, value)| IdentitySummary::from_value(index, value))
    }

    pub fn identity(&self, index: usize) -> Result<Identity> {
        let (_, value) = self
            .identity_values()
            .nth(index)
            .context("identity index does not exist")?;
        Ok(Identity::new(index, value.clone()))
    }

    pub fn select_behavior(
        &self,
        device: &DeviceInfo,
        index: Option<usize>,
        behavior: Behavior,
    ) -> Result<Identity> {
        self.matching_identity(device, index, None, behavior)?
            .with_context(|| {
                format!(
                    "IPSW has no matching {} identity for CPID {:04x}, BDID {:02x}",
                    behavior.name(),
                    device.chip_id,
                    device.board_id
                )
            })
    }

    /// Absence is valid for bridgeOS; ambiguity and malformed identities are errors.
    pub fn recovery_identity(
        &self,
        device: &DeviceInfo,
        restore: &Identity,
    ) -> Result<Option<Identity>> {
        let Some(variant) = recovery_variant(&restore.value)? else {
            return Ok(None);
        };
        let identity = self
            .matching_identity(device, None, Some(variant), Behavior::Erase)?
            .with_context(|| {
                format!("declared recoveryOS variant {variant:?} is absent from IPSW")
            })?;
        Ok(Some(identity))
    }

    fn matching_identity(
        &self,
        device: &DeviceInfo,
        index: Option<usize>,
        variant: Option<&str>,
        behavior: Behavior,
    ) -> Result<Option<Identity>> {
        let mut matches = Vec::new();
        for (i, value) in self.identity_values() {
            let summary = IdentitySummary::from_value(i, value)?;
            if summary.chip_id != u64::from(device.chip_id)
                || summary.board_id != u64::from(device.board_id)
            {
                continue;
            }
            if index.is_some_and(|index| summary.index != index) {
                continue;
            }
            if let Some(variant) = variant {
                if summary.variant != variant {
                    continue;
                }
            } else if summary.restore_behavior != behavior.name() {
                continue;
            }
            matches.push((i, value, summary));
        }
        if index.is_none() && variant.is_none() && matches.len() > 1 {
            // A restore identity can explicitly name its companion variant.
            // That referenced identity is not a competing DFU entry point.
            let referenced = matches
                .iter()
                .filter_map(|(_, value, _)| recovery_variant(value).transpose())
                .collect::<Result<HashSet<_>>>()?;
            matches.retain(|(_, _, summary)| !referenced.contains(summary.variant.as_str()));
            ensure!(
                !matches.is_empty(),
                "matching {} build identities form a variant reference cycle; specify --identity",
                behavior.name()
            );
        }
        match matches.len() {
            1 => {
                let (index, value, _) = &matches[0];
                Ok(Some(Identity::new(*index, (*value).clone())))
            }
            0 => Ok(None),
            _ => bail!(
                "ambiguous {} build identities {:?}{}",
                variant.unwrap_or(behavior.name()),
                matches
                    .iter()
                    .map(|(index, _, _)| *index)
                    .collect::<Vec<_>>(),
                if variant.is_some() {
                    ""
                } else {
                    "; specify --identity"
                }
            ),
        }
    }
}
