use super::data_type::DataType;
use crate::{
    ipsw::{Behavior, Identity},
    wire,
};
use anyhow::{Context, Result};
use plist::{Dictionary, Value};

pub fn supported_data_types() -> Value {
    let mut types = DataType::async_types();
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
            Value::Dictionary(DataType::async_types()),
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
    if id.is_macos()? {
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
        if let Some(value) = wire::optional(&id.value, &["Info", "recoveryOSPartitionSize"])? {
            wire::number(value).context("invalid recoveryOSPartitionSize")?;
            d.insert("recoveryOSPartitionSize".into(), value.clone());
        }
        if let Some(value) = wire::optional(&id.value, &["Info", "MinimumSystemPartition"])? {
            wire::number(value).context("invalid MinimumSystemPartition")?;
            d.insert("SystemPartitionSize".into(), value.clone());
        }
    }
    if let Some(value) = wire::optional(&id.value, &["Info", "SystemPartitionPadding"])? {
        for (size, padding) in wire::dictionary(value).context("invalid SystemPartitionPadding")? {
            size.parse::<u64>()
                .with_context(|| format!("invalid SystemPartitionPadding key {size}"))?;
            wire::number(padding)
                .with_context(|| format!("invalid SystemPartitionPadding.{size}"))?;
        }
        d.insert("SystemPartitionPadding".into(), value.clone());
    }
    Ok(Value::Dictionary(d))
}

pub fn boot_arguments(id: &Identity) -> Result<&'static str> {
    Ok(if id.behavior()? == Behavior::Update {
        "setenvnp boot-args rd=md0 -progress -restore"
    } else {
        "setenvnp boot-args rd=md0 nand-enable-reformat=1 -progress -restore"
    })
}
