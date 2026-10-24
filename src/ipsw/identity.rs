//! Manifest identities and selection of erase, upgrade and recoveryOS variants.
use super::Ipsw;
use crate::{device::DeviceInfo, wire};
use anyhow::{Context, Result, bail, ensure};
use plist::Value;
use serde::Serialize;

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
    pub fn variant(self) -> &'static str {
        match self {
            Self::Erase => "Erase Install",
            Self::Update => "Upgrade Install",
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
}

impl Identity {
    pub fn manifest(&self) -> Result<&plist::Dictionary> {
        wire::dictionary(wire::get(&self.value, &["Manifest"])?)
    }
    pub fn info(&self, key: &str) -> Result<&Value> {
        wire::get(&self.value, &["Info", key])
    }
    pub fn path(&self, name: &str) -> Result<&str> {
        wire::string(&self.value, &["Manifest", name, "Info", "Path"])
    }
    pub fn has(&self, name: &str) -> bool {
        self.path(name).is_ok()
    }
    pub fn is_macos(&self) -> bool {
        self.info("MacOSVariant").is_ok()
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
            self.behavior()? == behavior
                && self
                    .info("Variant")?
                    .as_string()
                    .is_some_and(|variant| variant.contains(behavior.variant())),
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
        let info = |key| wire::get(value, &["Info", key]);
        Ok(Self {
            index,
            chip_id: wire::number(wire::get(value, &["ApChipID"])?)?,
            board_id: wire::number(wire::get(value, &["ApBoardID"])?)?,
            device_class: info("DeviceClass")?
                .as_string()
                .context("invalid DeviceClass")?
                .into(),
            variant: info("Variant")?.as_string().unwrap_or("").into(),
            restore_behavior: info("RestoreBehavior")?.as_string().unwrap_or("").into(),
            macos_variant: info("MacOSVariant")
                .ok()
                .and_then(Value::as_string)
                .map(str::to_owned),
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
            .map(|(index, value)| Identity {
                index,
                value: value.clone(),
            })
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
        Ok(Identity {
            index,
            value: value.clone(),
        })
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
        let info = wire::dictionary(wire::get(&restore.value, &["Info"])?)?;
        let Some(variant) = info
            .get("MacOSVariant")
            .or_else(|| info.get("RecoveryVariant"))
        else {
            return Ok(None);
        };
        let variant = variant
            .as_string()
            .context("invalid recoveryOS variant name")?;
        ensure!(!variant.is_empty(), "empty recoveryOS variant name");
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
            } else if summary.restore_behavior != behavior.name()
                || !summary.variant.contains(behavior.variant())
                || (index.is_none() && summary.variant.contains("Research"))
            {
                continue;
            }
            matches.push((i, value));
        }
        match matches.len() {
            1 => {
                let (index, value) = matches[0];
                Ok(Some(Identity {
                    index,
                    value: value.clone(),
                }))
            }
            0 => Ok(None),
            _ => bail!(
                "ambiguous {} build identities {:?}{}",
                variant.unwrap_or(behavior.name()),
                matches.iter().map(|(index, _)| *index).collect::<Vec<_>>(),
                if variant.is_some() {
                    ""
                } else {
                    "; specify --identity"
                }
            ),
        }
    }
}
