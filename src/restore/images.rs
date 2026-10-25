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

pub(super) fn serve_asr(ipsw: &mut Ipsw, id: &Identity, stream: &mut MuxStream) -> Result<()> {
    let path = id.path("OS")?;
    let length = ipsw.size(path)?;
    if let Some(mut image) = ipsw.stored_image(path)? {
        asr::transfer(stream, &mut image, length)
    } else {
        crate::log!(
            Info,
            "filesystem",
            "Распаковка файловой системы во временный файл ({length} байт)"
        );
        crate::storage::require(&std::env::temp_dir(), length)?;
        let mut image = tempfile::tempfile()?;
        ensure!(
            ipsw.stream(path, &mut image)? == length,
            "truncated filesystem"
        );
        asr::transfer(stream, &mut image, length)
    }
}

impl ContextState {
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
    let path = match name {
        "__RestoreVersion__" => "RestoreVersion.plist".into(),
        "__SystemVersion__" => "SystemVersion.plist".into(),
        "__GlobalManifest__" => {
            let variant = match wire::optional(message, &["Arguments", "Variant"])? {
                Some(value) => value
                    .as_string()
                    .filter(|value| !value.is_empty())
                    .context("invalid Arguments.Variant")?,
                None => wire::string(&id.value, &["Info", "MacOSVariant"])?,
            };
            let class = wire::string(&id.value, &["Info", "DeviceClass"])?;
            // These optional fields select an AP ticket without a suffix when
            // omitted. A present value with the wrong type is still an error.
            let prefix = wire::optional(message, &["Arguments", "GlobalManifestPrefix"])?
                .map(|value| {
                    value
                        .as_string()
                        .context("invalid Arguments.GlobalManifestPrefix")
                })
                .transpose()?
                .unwrap_or("apticket");
            let suffix = wire::optional(message, &["Arguments", "GlobalManifestSuffix"])?
                .map(|value| {
                    value
                        .as_string()
                        .context("invalid Arguments.GlobalManifestSuffix")
                })
                .transpose()?
                .unwrap_or("");
            format!("Firmware/Manifests/restore/{variant}/{prefix}.{class}{suffix}.im4m")
        }
        component => id.path(component)?.into(),
    };
    crate::ipsw::validate_path(&path)?;
    Ok(path)
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
    let want_list = wire::optional_boolean(message, &["Arguments", list])?.unwrap_or(false);
    let image_name = wire::optional(message, &["Arguments", "ImageName"])?
        .map(|value| {
            value
                .as_string()
                .filter(|value| !value.is_empty())
                .context("invalid Arguments.ImageName")
        })
        .transpose()?;
    let mut names = Vec::new();
    for (name, entry) in id.manifest()? {
        if wire::optional_boolean(entry, &["Info", image_type])?.unwrap_or(false) {
            names.push(name.as_str());
        }
    }
    if want_list {
        return Ok(wire::dict([(
            list,
            Value::Array(names.into_iter().map(Value::from).collect()),
        )]));
    }
    if let Some(name) = image_name {
        ensure!(
            names.contains(&name),
            "requested image does not match {image_type}"
        );
        return Ok(wire::dict([
            (key, Value::Data(ipsw.personalized(id, name, ticket)?)),
            ("ImageName", name.into()),
        ]));
    }
    Ok(wire::dict([(
        key,
        Value::Dictionary(personalized_images(ipsw, id, ticket, names.into_iter())?),
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
    let llb = id.require_component_type(b"illb")?;
    let restore_sep = id.component_by_type(b"rsep")?;
    let iboot = id.component_by_type(b"ibot")?;
    let mut names = Vec::new();
    for (name, entry) in id.manifest()? {
        let primary =
            wire::optional_boolean(entry, &["Info", "IsFirmwarePayload"])?.unwrap_or(false);
        let secondary = wire::optional_boolean(entry, &["Info", "IsSecondaryFirmwarePayload"])?
            .unwrap_or(false);
        let loaded = wire::optional_boolean(entry, &["Info", "IsLoadedByiBoot"])?.unwrap_or(false);
        if (primary || (secondary && loaded)) && name != llb && Some(name.as_str()) != restore_sep {
            names.push(name.as_str());
        }
    }
    names.sort_by_key(|n| Some(*n) != iboot);
    let flash_v1 = wire::optional(message, &["Arguments", "FlashVersion1"])?.is_some();
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
        Value::Data(ipsw.personalized(id, llb, ticket)?),
    );
    d.insert("NorImageData".into(), images);
    for (tag, key) in [(b"rsep", "RestoreSEPImageData"), (b"sepi", "SEPImageData")] {
        if let Some(name) = id.component_by_type(tag)? {
            d.insert(
                key.into(),
                Value::Data(ipsw.personalized(id, name, ticket)?),
            );
        }
    }
    Ok(Value::Dictionary(d))
}
