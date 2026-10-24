use crate::{
    ipsw::{Behavior, Identity},
    wire,
};
use anyhow::Result;
use plist::{Dictionary, Value};

// Compatibility value used by idevicerestore's macOS path. Its formula is
// unknown upstream too; preserve it until a Mac-specific calculation is verified.
// https://cgit.libimobiledevice.org/idevicerestore.git/tree/src/restore.c?id=45145e9fdc8458022c61a4b87bd029b866d5bcdc
const MACOS_RECOVERY_PARTITION_MIB: u64 = 58201;

pub fn supported_data_types() -> Value {
    let mut types = async_data_types();
    // This is the protocol vocabulary, including field names and legacy types.
    // false marks a required entry; it does not disable the entry.
    for name in [
        "DataType",
        "SystemImageData",
        "SystemImageRootHash",
        "SystemImageCanonicalMetadata",
        "ProvisioningData",
        "FDRTrustData",
        "FDRMemoryCommit",
        "NORData",
        "FUDData",
        "EANData",
        "RootData",
        "OverlayRootDataCount",
        "KernelCache",
        "RootTicket",
        "BuildIdentityDict",
        "BuildIdentityDictV2",
        "BasebandBootData",
        "BasebandStackData",
        "BasebandData",
        "DiagData",
        "BasebandUpdaterOutputData",
        "GrapeFWData",
        "HPMFWData",
        "SsoServiceTicket",
        "S3EOverride",
        "USBCOverride",
        "USBCFWData",
        "OpalFWData",
        "StockholmPostflight",
        "FirmwareUpdaterData",
        "FirmwareUpdaterDataV2",
        "FileData",
        "FileDataDone",
        "RecoveryOSOverlayRootDataCount",
        "SourceBootObjectV3",
        "SourceBootObjectV4",
        "RecoveryOSLocalPolicy",
        "PersonalizedBootObjectV3",
        "BootabilityBundle",
        "BootabilityBundleV2",
        "MessageUseStreamedImageFile",
    ] {
        types.insert(name.into(), false.into());
    }
    // A capability marker enabling Canary's self-test, not a V3 data envelope.
    types.insert("FirmwareUpdaterDataV3".into(), true.into());
    Value::Dictionary(types)
}

pub(super) const ASYNC_DATA_TYPES: &[&str] = &[
    "BuildIdentityDict",
    "BuildIdentityDictV2",
    "ReceiptManifest",
    "PersonalizedBootObjectV3",
    "SourceBootObjectV4",
    "SourceBootObjectV3",
    "SourceBootObjectV5",
    "SystemImageData",
    "RecoveryOSASRImage",
    "RootTicket",
    "RecoveryOSRootTicketData",
    "KernelCache",
    "DeviceTree",
    "SystemVolumeData",
    "SystemVolumeCanonicalMetadata",
    "SystemImageRootHash",
    "SystemImageCanonicalMetadata",
    "NORData",
    "FDRTrustData",
    "FUDData",
    // copy_ibfw_ean skips early firmware (including J313 DCP) if absent.
    "PersonalizedData",
    "ImageData",
    "EANData",
    "FirmwareUpdaterPreflight",
    "DeviceRestoreInfoPreflight",
    "FirmwareUpdaterData",
    "FirmwareUpdaterDataV2",
    "BootabilityBundle",
    "BootabilityBundleV2",
    "URLAsset",
    "StreamedImageDecryptionKey",
    "RecoveryOSLocalPolicy",
    "RecoveryOSFileAssetImage",
    "RecoveryOSIBootFWFilesImages",
    "RecoveryOSImage",
    "RecoveryOSVersionData",
];

pub(super) fn async_data_types() -> Dictionary {
    ASYNC_DATA_TYPES
        .iter()
        .map(|&name| (name, Value::Boolean(true)))
        .collect()
}

pub fn options(id: &Identity) -> Result<Value> {
    let update = id.behavior()? == Behavior::Update;
    // The booleans mark optionality, not an on/off switch. Legacy required
    // message names must also be present.
    let mut d = Dictionary::from_iter([
        ("SupportedDataTypes", supported_data_types()),
        (
            "SupportedMessageTypes",
            wire::dict(
                [
                    ("MsgType", false),
                    ("DataRequestMsg", false),
                    ("AsyncDataRequestMsg", true),
                    ("ProgressMsg", false),
                    ("StatusMsg", false),
                    ("CheckpointMsg", true),
                    ("PreviousRestoreLogMsg", false),
                    ("BBUpdateStatusMsg", false),
                    ("ProvisioningInfo", false),
                    ("ProvisioningAck", false),
                    ("ProvisioningStatusMsg", false),
                    ("ReceivedFinalStatusMsg", false),
                    ("AsyncWait", true),
                    ("RestoreProtocol", true),
                    ("RestoreAttestation", true),
                    ("RestoredCrash", true),
                ]
                .into_iter()
                .map(|(name, optional)| (name, optional.into())),
            ),
        ),
        (
            "SupportedAsyncDataTypes",
            Value::Dictionary(async_data_types()),
        ),
        (
            "SupportedHostProtocols",
            Value::Array(vec!["MuxSocket".into()]),
        ),
        (
            "AuthInstallRestoreBehavior",
            if update { "Update" } else { "Erase" }.into(),
        ),
        ("CreateFilesystemPartitions", (!update).into()),
        ("FormatForAPFS", (!update).into()),
        ("AutoBootDelay", 0u64.into()),
        ("BootImageType", "User".into()),
        ("SystemImageType", "User".into()),
        ("DFUFileType", "RELEASE".into()),
        ("RestoreBundlePath", "/tmp/Per2.tmp".into()),
    ]);
    for key in [
        "FlashNOR",
        "SystemImage",
        "ShouldRestoreSystemImage",
        "PersonalizedDuringPreflight",
    ] {
        d.insert(key.into(), true.into());
    }
    for key in [
        "RootToInstall",
        "InstallDiags",
        "UpdateBaseband",
        "SkipPreflightPersonalization",
    ] {
        d.insert(key.into(), false.into());
    }
    if id.is_macos() {
        for key in [
            "AddSystemPartitionPadding",
            "DisableUserAuthentication",
            "FitSystemPartitionToContent",
            "InstallRecoveryOS",
            "MacOSSwapPerformed",
            "MacOSVariantPresent",
            "RecoveryOSUnpack",
        ] {
            d.insert(key.into(), true.into());
        }
        for key in [
            "AllowUntetheredRestore",
            "AuthInstallEnableSso",
            "FormatForLwVM",
        ] {
            d.insert(key.into(), false.into());
        }
        d.insert(
            "AuthInstallRecoveryOSVariant".into(),
            id.info("MacOSVariant")?.clone(),
        );
        d.insert(
            "recoveryOSPartitionSize".into(),
            MACOS_RECOVERY_PARTITION_MIB.into(),
        );
        if let Ok(v) = id.info("MinimumSystemPartition") {
            d.insert("SystemPartitionSize".into(), v.clone());
        }
    }
    if let Ok(v) = id.info("SystemPartitionPadding") {
        d.insert("SystemPartitionPadding".into(), v.clone());
    }
    Ok(Value::Dictionary(d))
}

pub fn boot_arguments(id: &Identity) -> Result<&'static str> {
    Ok(behavior_boot_arguments(id.behavior()?))
}

pub(super) fn behavior_boot_arguments(behavior: Behavior) -> &'static str {
    if behavior == Behavior::Update {
        "setenvnp boot-args rd=md0 -progress -restore"
    } else {
        "setenvnp boot-args rd=md0 nand-enable-reformat=1 -progress -restore"
    }
}
