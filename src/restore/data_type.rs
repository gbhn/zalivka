//! Implemented restored requests. Dispatch and async capabilities share this table.
use super::RESTORED_PORT;
use crate::wire;
use anyhow::{Context, Result, ensure};
use plist::{Dictionary, Value};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum DataType {
    BuildIdentity,
    ReceiptManifest,
    RootTicket,
    RecoveryRootTicket,
    Empty,
    Component(&'static str),
    PersonalizedBootObject,
    SourceBootObject,
    Asr,
    RecoveryAsr,
    RecoveryImage,
    RecoveryVersion,
    RecoveryAsset,
    RecoveryFirmware,
    RecoveryLocalPolicy,
    Images,
    Nor,
    Bootability,
    Asset,
    Firmware,
}

impl DataType {
    const TYPES: &[(&str, Self)] = &[
        ("BuildIdentityDict", Self::BuildIdentity),
        ("BuildIdentityDictV2", Self::BuildIdentity),
        ("ReceiptManifest", Self::ReceiptManifest),
        ("RootTicket", Self::RootTicket),
        ("RecoveryOSRootTicketData", Self::RecoveryRootTicket),
        ("FDRTrustData", Self::Empty),
        ("FirmwareUpdaterPreflight", Self::Empty),
        ("DeviceRestoreInfoPreflight", Self::Empty),
        ("KernelCache", Self::Component("KernelCache")),
        ("DeviceTree", Self::Component("DeviceTree")),
        ("SystemVolumeData", Self::Component("SystemVolume")),
        ("SystemImageRootHash", Self::Component("SystemVolume")),
        (
            "SystemVolumeCanonicalMetadata",
            Self::Component("Ap,SystemVolumeCanonicalMetadata"),
        ),
        (
            "SystemImageCanonicalMetadata",
            Self::Component("Ap,SystemVolumeCanonicalMetadata"),
        ),
        ("PersonalizedBootObjectV3", Self::PersonalizedBootObject),
        ("SourceBootObjectV3", Self::SourceBootObject),
        ("SourceBootObjectV4", Self::SourceBootObject),
        ("SourceBootObjectV5", Self::SourceBootObject),
        ("SystemImageData", Self::Asr),
        ("RecoveryOSASRImage", Self::RecoveryAsr),
        ("RecoveryOSImage", Self::RecoveryImage),
        ("RecoveryOSVersionData", Self::RecoveryVersion),
        ("RecoveryOSFileAssetImage", Self::RecoveryAsset),
        ("RecoveryOSIBootFWFilesImages", Self::RecoveryFirmware),
        ("RecoveryOSLocalPolicy", Self::RecoveryLocalPolicy),
        ("FUDData", Self::Images),
        // Presence enables early iBoot firmware, including J313 DCP.
        ("PersonalizedData", Self::Images),
        ("ImageData", Self::Images),
        ("EANData", Self::Images),
        ("NORData", Self::Nor),
        ("BootabilityBundle", Self::Bootability),
        ("BootabilityBundleV2", Self::Bootability),
        ("URLAsset", Self::Asset),
        ("StreamedImageDecryptionKey", Self::Asset),
        // MobileDevice dispatches both names to the same firmware handler.
        ("FirmwareUpdaterData", Self::Firmware),
        ("FirmwareUpdaterDataV2", Self::Firmware),
    ];

    pub(super) fn parse(name: &str) -> Result<Self> {
        Self::TYPES
            .iter()
            .find_map(|(candidate, kind)| (*candidate == name).then_some(*kind))
            .with_context(|| {
                format!("unsupported restored DataType {name}; the restore did not complete")
            })
    }

    pub(super) fn async_types() -> Dictionary {
        Self::TYPES
            .iter()
            .map(|(name, _)| (*name, plist::Value::Boolean(true)))
            .collect()
    }

    pub(super) fn data_port(self, message: &Value, asynchronous: bool) -> Result<u16> {
        let default = if !asynchronous && matches!(self, Self::Asr | Self::RecoveryAsr) {
            12345
        } else {
            0
        };
        let port = wire::data_port(message, default).context("invalid DataPort")?;
        ensure!(
            !asynchronous || (port != 0 && port != RESTORED_PORT),
            "async request requires a separate DataPort"
        );
        Ok(port)
    }
}
