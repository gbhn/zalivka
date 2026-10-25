//! RecoveryOS assets, version metadata and local-policy personalization.
use super::{ContextState, images::personalized_images};
use crate::{img4, tss, wire};
use anyhow::{Context, Result};
use plist::{Dictionary, Value};

impl ContextState {
    pub(super) fn recovery_assets(&mut self, component: Option<&str>) -> Result<Value> {
        let no_asset = || wire::dict([("RecoveryOSNoAssetFound", true.into())]);
        let Some(recovery) = self.recovery.as_ref() else {
            return Ok(no_asset());
        };
        let id = &recovery.identity;
        let ticket = &recovery.ticket;
        let images = if let Some(name) = component {
            if !id.manifest()?.contains_key(name) {
                return Ok(no_asset());
            }
            Value::Data(self.ipsw.personalized(id, name, ticket)?)
        } else {
            let mut names = Vec::new();
            for (name, entry) in id.manifest()? {
                let loaded =
                    wire::optional_boolean(entry, &["Info", "IsLoadedByiBoot"])?.unwrap_or(false);
                let stage1 = wire::optional_boolean(entry, &["Info", "IsLoadedByiBootStage1"])?
                    .unwrap_or(false);
                if loaded || stage1 {
                    names.push(name.as_str());
                }
            }
            if names.is_empty() {
                return Ok(no_asset());
            }
            Value::Dictionary(personalized_images(
                &mut self.ipsw,
                id,
                ticket,
                names.into_iter(),
            )?)
        };
        Ok(wire::dict([("AdditionalBootImages", images)]))
    }

    pub(super) fn recovery_version(&self) -> Result<Value> {
        let id = &self
            .recovery
            .as_ref()
            .context("missing recovery identity")?
            .identity;
        let mut version = Dictionary::new();
        for key in ["BuildNumber", "Variant", "BuildTrain"] {
            if let Ok(value) = id.info(key) {
                version.insert(key.into(), value.clone());
            }
        }
        if let Ok(value) = id.info("ProductMarketingVersion") {
            version.insert("ProductVersion".into(), value.clone());
        }
        Ok(wire::dict([(
            "RecoveryOSVersionData",
            Value::Data(wire::xml(&Value::Dictionary(version))?),
        )]))
    }

    pub(super) fn recovery_local_policy(&self, message: &Value) -> Result<Value> {
        self.recovery
            .as_ref()
            .context("missing recoveryOS local-policy identity")?;
        let args = wire::get(message, &["Arguments"])?;
        let local = tss::send(&tss::local_policy_request(
            &self.device,
            tss::ticket(&self.restore.ticket)?,
            Some(args),
        )?)
        .context("personalizing RecoveryOS Ap,LocalPolicy")?;
        let bytes = img4::personalize(&img4::empty_local_policy(), tss::ticket(&local)?)?;
        Ok(wire::dict([("Ap,LocalPolicy", Value::Data(bytes))]))
    }
}
