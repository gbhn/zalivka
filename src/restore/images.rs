//! Filesystem transfer, boot objects and manifest-selected image collections.
use super::ContextState;
use crate::{
    asr,
    ipsw::{Identity, Ipsw},
    mux::MuxStream,
    wire,
};
use anyhow::{Context, Result, ensure};
use plist::{Dictionary, Value};
use std::io::Write;

impl ContextState {
    pub(super) fn serve_asr(&mut self, stream: &mut MuxStream, message: &Value) -> Result<()> {
        let id = if wire::string(message, &["DataType"])? == "RecoveryOSASRImage"
            || wire::boolean(message, &["Arguments", "IsRecoveryOS"])
        {
            &self
                .recovery
                .as_ref()
                .context("device requested a recoveryOS identity absent from this IPSW")?
                .identity
        } else {
            &self.restore.identity
        };
        let path = id.path("OS")?;
        let length = self.ipsw.size(path)?;
        if let Some(mut image) = self.ipsw.stored_image(path)? {
            asr::transfer(stream, &mut image, length)
        } else {
            eprintln!("Expanding compressed filesystem to a temporary file ({length} bytes)");
            crate::storage::require(&std::env::temp_dir(), length)?;
            let mut image = tempfile::tempfile()?;
            ensure!(
                self.ipsw.stream(path, &mut image)? == length,
                "truncated filesystem"
            );
            asr::transfer(stream, &mut image, length)
        }
    }

    pub(super) fn bootability(&mut self, out: &mut impl Write) -> Result<()> {
        let mut count = 0;
        for path in self.ipsw.files()? {
            let Some(relative) = path
                .strip_prefix("BootabilityBundle/")
                .or_else(|| path.strip_prefix("BootabilityBundleV2/"))
            else {
                continue;
            };
            let name = if let Some(name) = relative.strip_prefix("Restore/Bootability/") {
                name
            } else if relative == "Restore/Firmware/Bootability.dmg.trustcache" {
                "Bootability.trustcache"
            } else {
                continue;
            };
            if name.is_empty() {
                continue;
            }
            let mode = self.ipsw.unix_mode(&path)?;
            let size = self.ipsw.size(&path)?;
            cpio_header(out, name, mode, size)?;
            ensure!(
                self.ipsw.stream(&path, out)? == size,
                "truncated Bootability entry"
            );
            count += 1;
        }
        ensure!(count > 0, "IPSW has no BootabilityBundle");
        cpio_header(out, "TRAILER!!!", 0, 0)
    }
}

pub fn cpio_header(out: &mut impl Write, name: &str, mode: u32, size: u64) -> Result<()> {
    ensure!(
        name.len() < 0o777777 && size <= 0o77777777777 && mode <= 0o777777,
        "CPIO entry exceeds odc field sizes"
    );
    let header = format!(
        "070707{0:06o}{0:06o}{mode:06o}{0:06o}{0:06o}{1:06o}{0:06o}{0:011o}{namesize:06o}{size:011o}",
        0,
        1,
        namesize = name.len() + 1
    );
    ensure!(
        header.len() == 76 && !name.contains('\0'),
        "invalid CPIO header"
    );
    out.write_all(header.as_bytes())?;
    out.write_all(name.as_bytes())?;
    out.write_all(&[0])?;
    Ok(())
}

pub(super) fn boot_object_path(id: &Identity, name: &str, message: &Value) -> Result<String> {
    Ok(match name {
        "__RestoreVersion__" => "RestoreVersion.plist".into(),
        "__SystemVersion__" => "SystemVersion.plist".into(),
        "__GlobalManifest__" => {
            let variant = wire::string(message, &["Arguments", "Variant"])
                .or_else(|_| wire::string(&id.value, &["Info", "MacOSVariant"]))?;
            let class = wire::string(&id.value, &["Info", "DeviceClass"])?;
            let prefix =
                wire::string(message, &["Arguments", "GlobalManifestPrefix"]).unwrap_or("apticket");
            let suffix =
                wire::string(message, &["Arguments", "GlobalManifestSuffix"]).unwrap_or("");
            format!("Firmware/Manifests/restore/{variant}/{prefix}.{class}{suffix}.im4m")
        }
        component => id.path(component)?.into(),
    })
}

pub(super) fn image_data(
    ipsw: &mut Ipsw,
    id: &Identity,
    ticket: &Value,
    kind: &str,
    message: &Value,
) -> Result<Value> {
    let (list, image_type, key) = match kind {
        "FUDData" => ("FUDImageList", "IsFUDFirmware", "FUDImageData"),
        "EANData" => ("EANImageList", "IsEarlyAccessFirmware", "EANData"),
        _ => (
            "ImageList",
            wire::string(message, &["Arguments", "ImageType"])?,
            "ImageData",
        ),
    };
    let mut names = id
        .manifest()?
        .iter()
        .filter(|(_, v)| wire::boolean(v, &["Info", image_type]))
        .map(|(k, _)| k.as_str());
    if wire::boolean(message, &["Arguments", list]) {
        return Ok(wire::dict([(
            list,
            Value::Array(names.map(Value::from).collect()),
        )]));
    }
    if let Ok(name) = wire::string(message, &["Arguments", "ImageName"]) {
        ensure!(
            names.any(|candidate| candidate == name),
            "requested image does not match {image_type}"
        );
        return Ok(wire::dict([
            (key, Value::Data(ipsw.personalized(id, name, ticket)?)),
            ("ImageName", name.into()),
        ]));
    }
    Ok(wire::dict([(
        key,
        Value::Dictionary(personalized_images(ipsw, id, ticket, names)?),
    )]))
}

pub(super) fn personalized_images<'a>(
    ipsw: &mut Ipsw,
    id: &Identity,
    ticket: &Value,
    names: impl Iterator<Item = &'a str>,
) -> Result<Dictionary> {
    names
        .map(|name| {
            Ok((
                name.to_owned(),
                Value::Data(ipsw.personalized(id, name, ticket)?),
            ))
        })
        .collect()
}

pub(super) fn nor_data(
    ipsw: &mut Ipsw,
    id: &Identity,
    ticket: &Value,
    message: &Value,
) -> Result<Value> {
    let mut names: Vec<&str> = id
        .manifest()?
        .iter()
        .filter(|(_, v)| {
            wire::boolean(v, &["Info", "IsFirmwarePayload"])
                || (wire::boolean(v, &["Info", "IsSecondaryFirmwarePayload"])
                    && wire::boolean(v, &["Info", "IsLoadedByiBoot"]))
        })
        .map(|(k, _)| k.as_str())
        .filter(|k| *k != "LLB" && *k != "RestoreSEP")
        .collect();
    names.sort_by_key(|n| !n.starts_with("iBoot"));
    let flash_v1 = wire::get(message, &["Arguments", "FlashVersion1"]).is_ok();
    let images = if flash_v1 {
        Value::Dictionary(personalized_images(ipsw, id, ticket, names.into_iter())?)
    } else {
        Value::Array(
            names
                .into_iter()
                .map(|name| ipsw.personalized(id, name, ticket).map(Value::Data))
                .collect::<Result<_>>()?,
        )
    };
    let mut d = Dictionary::new();
    d.insert(
        "LlbImageData".into(),
        Value::Data(ipsw.personalized(id, "LLB", ticket)?),
    );
    d.insert("NorImageData".into(), images);
    for (name, key) in [
        ("RestoreSEP", "RestoreSEPImageData"),
        ("SEP", "SEPImageData"),
    ] {
        if id.has(name) {
            d.insert(
                key.into(),
                Value::Data(ipsw.personalized(id, name, ticket)?),
            );
        }
    }
    Ok(Value::Dictionary(d))
}
