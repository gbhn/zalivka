//! Responses to restored data requests and recovery assets.
use super::ContextState;
use super::data_type::DataType;
use super::file_data::{FileDataWriter, send_file_data};
use super::images::{boot_object_path, image_data, nor_data, serve_asr};
use crate::{
    ipsw::Identity,
    mux::{MuxStream, Session},
    net, tss, wire,
};
use anyhow::{Context, Result, ensure};
use plist::{Dictionary, Value};
use std::time::Duration;

impl ContextState {
    pub fn serve(
        &mut self,
        session: &Session,
        main: &mut MuxStream,
        message: &Value,
    ) -> Result<()> {
        let kind = wire::data_type(message)?;
        let data_type = DataType::parse(kind)?;
        let arguments = [
            "ImageName",
            "ImageType",
            "UpdaterName",
            "MessageArgUpdaterName",
        ]
        .into_iter()
        .filter_map(|key| {
            wire::string(message, &["Arguments", key])
                .ok()
                .map(|value| format!("{key}={value}"))
        })
        .collect::<Vec<_>>()
        .join(", ");
        crate::log!(Debug, "restored", "Запрос {kind}: {arguments}");
        let port = data_type.data_port(message, false)?;
        if port != 0 {
            let mut service = session.connect_retry(port, Duration::from_secs(60))?;
            self.serve_on(session, &mut service, message, data_type)
        } else {
            self.serve_on(session, main, message, data_type)
        }
    }

    pub(super) fn serve_on(
        &mut self,
        session: &Session,
        out: &mut MuxStream,
        message: &Value,
        data_type: DataType,
    ) -> Result<()> {
        let kind = wire::data_type(message)?;
        // Resolve firmware identity only for handlers that consume it. Network,
        // preflight and optional RecoveryOS probes do not depend on an identity.
        let restore = &self.restore.identity;
        let recovery = self.recovery.as_ref();
        let identity = || -> Result<&Identity> {
            if data_type == DataType::RecoveryAsr
                || wire::boolean(message, &["Arguments", "IsRecoveryOS"])
            {
                Ok(&recovery
                    .context("device requested a recoveryOS identity absent from this IPSW")?
                    .identity)
            } else {
                Ok(restore)
            }
        };
        // Generic boot objects use the restore ticket even for MacOSVariant
        // paths. Dedicated RecoveryOS* requests use the recovery signature instead.
        let response = match data_type {
            DataType::Asr | DataType::RecoveryAsr => {
                return serve_asr(&mut self.ipsw, identity()?, out);
            }
            DataType::BuildIdentity => wire::dict([
                ("BuildIdentityDict", identity()?.value.clone()),
                (
                    "Variant",
                    wire::get(message, &["Arguments", "Variant"])
                        .cloned()
                        .unwrap_or("Erase".into()),
                ),
            ]),
            DataType::ReceiptManifest => wire::dict([(
                "ReceiptManifest",
                Value::Dictionary(identity()?.manifest()?.clone()),
            )]),
            DataType::RootTicket => wire::dict([(
                "RootTicketData",
                Value::Data(tss::ticket(&self.restore.ticket)?.to_vec()),
            )]),
            DataType::RecoveryRootTicket => {
                let recovery = self
                    .recovery
                    .as_ref()
                    .context("missing recoveryOS identity")?;
                wire::dict([(
                    "RootTicketData",
                    Value::Data(tss::ticket(&recovery.ticket)?.to_vec()),
                )])
            }
            DataType::Empty => Value::Dictionary(Dictionary::new()),
            DataType::Component(component) => {
                let bytes = self
                    .ipsw
                    .personalized(identity()?, component, &self.restore.ticket)?;
                wire::dict([(format!("{kind}File"), Value::Data(bytes))])
            }
            DataType::PersonalizedBootObject | DataType::SourceBootObject => {
                let id = identity()?;
                let name = wire::string(message, &["Arguments", "ImageName"])?;
                let path = boot_object_path(id, name, message)?;
                crate::ipsw::validate_path(&path)?;
                if data_type == DataType::SourceBootObject
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
                if data_type == DataType::PersonalizedBootObject && !name.starts_with("__") {
                    let bytes = self.ipsw.personalized(id, name, &self.restore.ticket)?;
                    send_file_data(out, session, &self.assets, name, &bytes)?;
                } else {
                    self.stream_file(out, session, name, &path)?;
                }
                return Ok(());
            }
            DataType::RecoveryImage => {
                let path = self
                    .recovery
                    .as_ref()
                    .context("missing recovery identity")?
                    .identity
                    .path("OS")?
                    .to_owned();
                return self.stream_file(out, session, "RecoveryOS", &path);
            }
            DataType::RecoveryVersion => self.recovery_version()?,
            DataType::RecoveryAsset => {
                let key = wire::string(message, &["Arguments", "FWOverrideKey"])?;
                if let Some(name) = key.strip_prefix("RecoveryOS") {
                    self.recovery_assets(Some(name))?
                } else {
                    wire::dict([("RecoveryOSNoAssetFound", true.into())])
                }
            }
            DataType::RecoveryFirmware => self.recovery_assets(None)?,
            DataType::RecoveryLocalPolicy => self.recovery_local_policy(message)?,
            DataType::Images => image_data(
                &mut self.ipsw,
                identity()?,
                &self.restore.ticket,
                kind,
                message,
            )?,
            DataType::Nor => nor_data(&mut self.ipsw, identity()?, &self.restore.ticket, message)?,
            DataType::Bootability => {
                self.bootability(out)?;
                return Ok(());
            }
            DataType::Asset => return serve_asset(&self.assets, out, message),
            DataType::Firmware => {
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
        };
        wire::send(out, &response).with_context(|| format!("sending restored response {kind}"))?;
        crate::log!(Debug, "restored", "Ответ на запрос {kind} отправлен");
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

pub(super) fn serve_asset(
    assets: &net::AssetClient,
    out: &mut impl std::io::Write,
    message: &Value,
) -> Result<()> {
    wire::send_binary(out, &assets.response(message)?)
}
