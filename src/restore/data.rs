//! Responses to restored data requests and recovery assets.
use super::ContextState;
use super::file_data::{FileDataWriter, send_file_data};
use super::images::{boot_object_path, image_data, nor_data};
use crate::{
    asr,
    ipsw::Identity,
    mux::{MuxStream, Session},
    tss, wire,
};
use anyhow::{Context, Result, bail, ensure};
use plist::{Dictionary, Value};
use std::time::Duration;

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
        // Resolve firmware identity only for handlers that consume it. Network,
        // preflight and optional RecoveryOS probes do not depend on an identity.
        let restore = &self.restore.identity;
        let recovery = self.recovery.as_ref();
        let identity = || -> Result<&Identity> {
            if wire::boolean(message, &["Arguments", "IsRecoveryOS"]) {
                Ok(&recovery
                    .context("device requested a recoveryOS identity absent from this IPSW")?
                    .identity)
            } else {
                Ok(restore)
            }
        };
        // Generic boot objects use the restore ticket even for MacOSVariant
        // paths. Dedicated RecoveryOS* requests use the recovery signature instead.
        let response = match kind {
            "BuildIdentityDict" | "BuildIdentityDictV2" => wire::dict([
                ("BuildIdentityDict", identity()?.value.clone()),
                (
                    "Variant",
                    wire::get(message, &["Arguments", "Variant"])
                        .cloned()
                        .unwrap_or("Erase".into()),
                ),
            ]),
            "ReceiptManifest" => wire::dict([(
                "ReceiptManifest",
                Value::Dictionary(identity()?.manifest()?.clone()),
            )]),
            "RootTicket" => wire::dict([(
                "RootTicketData",
                Value::Data(tss::ticket(&self.restore.ticket)?.to_vec()),
            )]),
            "RecoveryOSRootTicketData" => {
                let recovery = self
                    .recovery
                    .as_ref()
                    .context("missing recoveryOS identity")?;
                wire::dict([(
                    "RootTicketData",
                    Value::Data(tss::ticket(&recovery.ticket)?.to_vec()),
                )])
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
                let bytes = self
                    .ipsw
                    .personalized(identity()?, component, &self.restore.ticket)?;
                wire::dict([(format!("{kind}File"), Value::Data(bytes))])
            }
            "PersonalizedBootObjectV3"
            | "SourceBootObjectV4"
            | "SourceBootObjectV3"
            | "SourceBootObjectV5" => {
                let id = identity()?;
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
                    let bytes = self.ipsw.personalized(id, name, &self.restore.ticket)?;
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
                    .identity
                    .path("OS")?
                    .to_owned();
                return self.stream_file(out, session, "RecoveryOS", &path);
            }
            "RecoveryOSVersionData" => self.recovery_version()?,
            "RecoveryOSFileAssetImage" => {
                let key = wire::string(message, &["Arguments", "FWOverrideKey"])?;
                if let Some(name) = key.strip_prefix("RecoveryOS") {
                    self.recovery_assets(Some(name))?
                } else {
                    wire::dict([("RecoveryOSNoAssetFound", true.into())])
                }
            }
            "RecoveryOSIBootFWFilesImages" => self.recovery_assets(None)?,
            "RecoveryOSLocalPolicy" => self.recovery_local_policy(message)?,
            "FUDData" | "PersonalizedData" | "ImageData" | "EANData" => image_data(
                &mut self.ipsw,
                identity()?,
                &self.restore.ticket,
                kind,
                message,
            )?,
            "NORData" => nor_data(&mut self.ipsw, identity()?, &self.restore.ticket, message)?,
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
                    let update = crate::firmware::prepare(&mut self.ipsw, identity()?, args)?;
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
}
