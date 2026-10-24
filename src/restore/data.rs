//! Responses to restored data requests and recovery assets.
use super::ContextState;
use super::file_data::{FileDataWriter, send_file_data};
use crate::{
    asr, img4,
    ipsw::{Identity, Ipsw},
    mux::{MuxStream, Session},
    tss, wire,
};
use anyhow::{Context, Result, bail, ensure};
use plist::{Dictionary, Value};
use std::{io::Write, time::Duration};

impl ContextState {
    pub fn serve(
        &mut self,
        session: &Session,
        main: &mut MuxStream,
        message: &Value,
    ) -> Result<()> {
        let kind = wire::string(message, &["DataType"])?;
        eprintln!("restored requests {kind}");
        for key in [
            "ImageName",
            "ImageType",
            "UpdaterName",
            "MessageArgUpdaterName",
        ] {
            if let Ok(value) = wire::string(message, &["Arguments", key]) {
                eprintln!("  {key}: {value}");
            }
        }
        let default_port = if matches!(kind, "SystemImageData" | "RecoveryOSASRImage") {
            12345
        } else {
            0
        };
        let port = asr::data_port(message, default_port)?;
        if port != 0 {
            let mut service = session.connect_retry(port, Duration::from_secs(60))?;
            self.serve_on(session, &mut service, message)
        } else {
            self.serve_on(session, main, message)
        }
    }

    fn serve_asr(&mut self, stream: &mut MuxStream, message: &Value) -> Result<()> {
        let id = if wire::string(message, &["DataType"])? == "RecoveryOSASRImage"
            || wire::boolean(message, &["Arguments", "IsRecoveryOS"])
        {
            self.recovery
                .as_ref()
                .context("device requested a recoveryOS identity absent from this IPSW")?
        } else {
            &self.identity
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

    pub(super) fn serve_on(
        &mut self,
        session: &Session,
        out: &mut MuxStream,
        message: &Value,
    ) -> Result<()> {
        let kind = wire::string(message, &["DataType"])?;
        if matches!(kind, "SystemImageData" | "RecoveryOSASRImage") {
            return self.serve_asr(out, message);
        }
        // Optional asset probes can be answered even when the IPSW has no
        // recovery identity. Other requests must resolve their identity.
        let id = if wire::boolean(message, &["Arguments", "IsRecoveryOS"])
            && !matches!(
                kind,
                "RecoveryOSFileAssetImage" | "RecoveryOSIBootFWFilesImages"
            ) {
            self.recovery
                .as_ref()
                .context("device requested a recoveryOS identity absent from this IPSW")?
        } else {
            &self.identity
        };
        // Generic boot objects use the restore ticket even for MacOSVariant
        // paths. Dedicated RecoveryOS* requests use recovery_ticket instead.
        let response = match kind {
            "BuildIdentityDict" | "BuildIdentityDictV2" => wire::dict([
                ("BuildIdentityDict", id.value.clone()),
                (
                    "Variant",
                    wire::get(message, &["Arguments", "Variant"])
                        .cloned()
                        .unwrap_or("Erase".into()),
                ),
            ]),
            "ReceiptManifest" => {
                wire::dict([("ReceiptManifest", Value::Dictionary(id.manifest()?.clone()))])
            }
            "RootTicket" => wire::dict([(
                "RootTicketData",
                Value::Data(tss::ticket(&self.ticket)?.to_vec()),
            )]),
            "RecoveryOSRootTicketData" => {
                let ticket = self
                    .recovery_ticket
                    .as_ref()
                    .context("missing recoveryOS ticket")?;
                wire::dict([("RootTicketData", Value::Data(tss::ticket(ticket)?.to_vec()))])
            }
            "FDRTrustData" | "FirmwareUpdaterPreflight" | "DeviceRestoreInfoPreflight" => {
                Value::Dictionary(Dictionary::new())
            }
            "KernelCache"
            | "DeviceTree"
            | "SystemVolumeData"
            | "SystemVolumeCanonicalMetadata"
            | "SystemImageRootHash"
            | "SystemImageCanonicalMetadata" => {
                let component = match kind {
                    "SystemVolumeData" | "SystemImageRootHash" => "SystemVolume",
                    "SystemVolumeCanonicalMetadata" | "SystemImageCanonicalMetadata" => {
                        "Ap,SystemVolumeCanonicalMetadata"
                    }
                    _ => kind,
                };
                let bytes = self.ipsw.personalized(id, component, &self.ticket)?;
                wire::dict([(format!("{kind}File"), Value::Data(bytes))])
            }
            "PersonalizedBootObjectV3"
            | "SourceBootObjectV4"
            | "SourceBootObjectV3"
            | "SourceBootObjectV5" => {
                let name = wire::string(message, &["Arguments", "ImageName"])?;
                let path = boot_object_path(id, name, message)?;
                crate::ipsw::validate_path(&path)?;
                if kind != "PersonalizedBootObjectV3"
                    && name == "__GlobalManifest__"
                    && !self.ipsw.contains(&path)
                {
                    ensure!(
                        id.info("VariantSupportsGlobalSigning").is_err()
                            || wire::boolean(message, &["Arguments", "GlobalManifestOptional"]),
                        "IPSW is missing required global manifest {path}"
                    );
                    wire::send(out, &wire::dict([("FileDataDone", true.into())]))?;
                    return Ok(());
                }
                if kind == "PersonalizedBootObjectV3" && !name.starts_with("__") {
                    let bytes = self.ipsw.personalized(id, name, &self.ticket)?;
                    send_file_data(out, session, &self.assets, name, &bytes)?;
                } else {
                    self.stream_file(out, session, name, &path)?;
                }
                return Ok(());
            }
            "RecoveryOSImage" => {
                let path = self
                    .recovery
                    .as_ref()
                    .context("missing recovery identity")?
                    .path("OS")?
                    .to_owned();
                return self.stream_file(out, session, "RecoveryOS", &path);
            }
            "RecoveryOSVersionData" => {
                let id = self
                    .recovery
                    .as_ref()
                    .context("missing recovery identity")?;
                let mut version = Dictionary::new();
                for k in ["BuildNumber", "Variant", "BuildTrain"] {
                    if let Ok(v) = id.info(k) {
                        version.insert(k.into(), v.clone());
                    }
                }
                if let Ok(v) = id.info("ProductMarketingVersion") {
                    version.insert("ProductVersion".into(), v.clone());
                }
                wire::dict([(
                    "RecoveryOSVersionData",
                    Value::Data(wire::xml(&Value::Dictionary(version))?),
                )])
            }
            "RecoveryOSFileAssetImage" => {
                let key = wire::string(message, &["Arguments", "FWOverrideKey"])?;
                if let Some(name) = key.strip_prefix("RecoveryOS") {
                    self.recovery_assets(Some(name))?
                } else {
                    wire::dict([("RecoveryOSNoAssetFound", true.into())])
                }
            }
            "RecoveryOSIBootFWFilesImages" => self.recovery_assets(None)?,
            "RecoveryOSLocalPolicy" => {
                self.recovery
                    .as_ref()
                    .context("missing recoveryOS local-policy identity")?;
                let args = wire::get(message, &["Arguments"])?;
                let local = tss::send(&tss::local_policy_request(
                    &self.device,
                    tss::ticket(&self.ticket)?,
                    Some(args),
                )?)
                .context("personalizing RecoveryOS Ap,LocalPolicy")?;
                let bytes = img4::personalize(
                    "Ap,LocalPolicy",
                    &img4::empty_local_policy(),
                    tss::ticket(&local)?,
                )?;
                wire::dict([("Ap,LocalPolicy", Value::Data(bytes))])
            }
            "FUDData" | "PersonalizedData" | "ImageData" | "EANData" => {
                image_data(&mut self.ipsw, id, &self.ticket, kind, message)?
            }
            "NORData" => nor_data(&mut self.ipsw, id, &self.ticket, message)?,
            "BootabilityBundle" | "BootabilityBundleV2" => {
                self.bootability(out)?;
                return Ok(());
            }
            "URLAsset" | "StreamedImageDecryptionKey" => {
                wire::send_binary(out, &self.assets.response(message)?)?;
                return Ok(());
            }
            // Apple's MobileDevice64.dll dispatches both names to the same
            // request/response handler (MobileDevice 1860.2.5.100.2).
            "FirmwareUpdaterData" | "FirmwareUpdaterDataV2" => {
                let args = wire::get(message, &["Arguments"])?;
                let response = if let Some(response) = crate::firmware::canary_response(args)? {
                    response
                } else {
                    let update = crate::firmware::prepare(&mut self.ipsw, id, args)?;
                    let response = tss::send_raw(&update.request)?;
                    update.finish(response)?
                };
                return crate::firmware::send_response(out, response, args);
            }
            other => bail!("unsupported restored DataType {other}; the restore did not complete"),
        };
        wire::send(out, &response).with_context(|| format!("sending restored response {kind}"))?;
        eprintln!("restored response sent: {kind}");
        Ok(())
    }

    fn stream_file(
        &mut self,
        out: &mut MuxStream,
        session: &Session,
        name: &str,
        path: &str,
    ) -> Result<()> {
        let size = self.ipsw.size(path)?;
        let mut writer = FileDataWriter::new(out, session, &self.assets, name, Some(size));
        self.ipsw.stream(path, &mut writer)?;
        writer.finish()
    }

    fn recovery_assets(&mut self, component: Option<&str>) -> Result<Value> {
        let no_asset = || wire::dict([("RecoveryOSNoAssetFound", true.into())]);
        let Some(id) = self.recovery.as_ref() else {
            return Ok(no_asset());
        };
        let images = if let Some(name) = component {
            if !id.has(name) {
                return Ok(no_asset());
            }
            let ticket = self
                .recovery_ticket
                .as_ref()
                .context("missing recovery ticket")?;
            Value::Data(self.ipsw.personalized(id, name, ticket)?)
        } else {
            let mut names = id
                .manifest()?
                .iter()
                .filter(|(_, entry)| {
                    wire::boolean(entry, &["Info", "IsLoadedByiBoot"])
                        || wire::boolean(entry, &["Info", "IsLoadedByiBootStage1"])
                })
                .map(|(name, _)| name.as_str())
                .peekable();
            if names.peek().is_none() {
                return Ok(no_asset());
            }
            let ticket = self
                .recovery_ticket
                .as_ref()
                .context("missing recovery ticket")?;
            Value::Dictionary(personalized_images(&mut self.ipsw, id, ticket, names)?)
        };
        Ok(wire::dict([("AdditionalBootImages", images)]))
    }

    fn bootability(&mut self, out: &mut impl Write) -> Result<()> {
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

fn boot_object_path(id: &Identity, name: &str, message: &Value) -> Result<String> {
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

fn image_data(
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

fn personalized_images<'a>(
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

fn nor_data(ipsw: &mut Ipsw, id: &Identity, ticket: &Value, message: &Value) -> Result<Value> {
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
