//! Build device-bound signing requests for restore, recoveryOS and local policy.
use crate::{device::DeviceInfo, img4, ipsw::Identity, wire};
use anyhow::{Context, Result, ensure};
use plist::{Dictionary, Value};
use sha2::{Digest, Sha384};

pub(crate) fn host_fields() -> Dictionary {
    Dictionary::from_iter([
        (
            "@HostPlatformInfo",
            Value::from(if cfg!(windows) { "windows" } else { "mac" }),
        ),
        ("@VersionInfo", "libauthinstall-973.0.1".into()),
    ])
}

fn device_fields(device: &DeviceInfo) -> Result<Dictionary> {
    ensure!(
        !device.ap_nonce.is_empty(),
        "ApNonce is unavailable; cannot request a device-bound Apple ticket"
    );
    let mut d = host_fields();
    d.extend([
        ("@ApImg4Ticket".into(), true.into()),
        ("ApECID".into(), device.ecid.into()),
        ("ApChipID".into(), u64::from(device.chip_id).into()),
        ("ApBoardID".into(), u64::from(device.board_id).into()),
        (
            "ApSecurityDomain".into(),
            u64::from(device.security_domain).into(),
        ),
        ("ApProductionMode".into(), true.into()),
        ("ApSecurityMode".into(), true.into()),
        ("ApNonce".into(), Value::Data(device.ap_nonce.clone())),
    ]);
    Ok(d)
}

fn base(device: &DeviceInfo, id: &Identity) -> Result<Dictionary> {
    let mut d = device_fields(device)?;
    if let Some(fields) = id.value.as_dictionary() {
        wire::copy_keys(
            &mut d,
            fields,
            &[
                "UniqueBuildID",
                "Ap,OSLongVersion",
                "Ap,OSReleaseType",
                "Ap,ProductMarketingVersion",
                "Ap,ProductType",
                "Ap,SDKPlatform",
                "Ap,Target",
                "Ap,TargetType",
                "Ap,Timestamp",
                "PearlCertificationRootPub",
                "NeRDEpoch",
                "AllowNeRDBoot",
                "PermitNeRDPivot",
            ],
        );
    }
    if wire::boolean(&id.value, &["Info", "RequiresUIDMode"]) {
        d.insert("UID_MODE".into(), false.into());
        d.insert("Ap,SikaFuse".into(), 0u64.into());
    }
    if !device.sep_nonce.is_empty() {
        d.insert("SepNonce".into(), Value::Data(device.sep_nonce.clone()));
    }
    Ok(d)
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum BootChain {
    Restore,
    Recovery,
}

const EXCLUDED: &[&str] = &[
    "BasebandFirmware",
    "SE,UpdatePayload",
    "BaseSystem",
    "Diags",
];

const RECOVERY_EXCLUDED: &[&str] = &[
    "ANS",
    "Ap,AudioBootChime",
    "Ap,CIO",
    "Ap,RestoreCIO",
    "Ap,RestoreTMU",
    "Ap,TMU",
    "Ap,rOSLogo1",
    "Ap,rOSLogo2",
    "AppleLogo",
    "DCP",
    "LLB",
    "RecoveryMode",
    "RestoreANS",
    "RestoreDCP",
    "RestoreDeviceTree",
    "RestoreKernelCache",
    "RestoreLogo",
    "RestoreRamDisk",
    "RestoreSEP",
    "SEP",
    "ftap",
    "ftsp",
    "iBEC",
    "iBSS",
    "rfta",
    "rfts",
];

pub fn request(device: &DeviceInfo, id: &Identity) -> Result<Value> {
    firmware_request(device, id, BootChain::Restore)
}

pub fn recovery_request(device: &DeviceInfo, id: &Identity) -> Result<Value> {
    firmware_request(device, id, BootChain::Recovery)
}

fn firmware_request(device: &DeviceInfo, id: &Identity, chain: BootChain) -> Result<Value> {
    let mut parameters = base(device, id)?;
    if chain == BootChain::Recovery {
        // A rule parameter, excluded from the root request sent to Apple.
        parameters.insert("Ap,LocalBoot".into(), false.into());
    }
    let mut components = Dictionary::new();
    for (name, value) in id.manifest()? {
        if EXCLUDED.contains(&name.as_str())
            || match chain {
                BootChain::Restore => name == "Ap,ExclaveOS",
                BootChain::Recovery => RECOVERY_EXCLUDED.contains(&name.as_str()),
            }
        {
            continue;
        }
        let component =
            Component::parse(value).with_context(|| format!("invalid signing component {name}"))?;
        let Some(info) = component.info else {
            continue;
        };
        let rules = info.contains_key("RestoreRequestRules");
        if chain == BootChain::Restore
            && ((!component.trusted && !rules) || wire::boolean(value, &["Info", "IsFTAB"]))
        {
            continue;
        }
        let mut entry = component
            .request(&parameters)
            .with_context(|| format!("preparing signing component {name}"))?;
        if chain == BootChain::Restore && !rules {
            entry.insert("EPRO".into(), true.into());
            entry.insert("ESEC".into(), true.into());
        }
        components.insert(name.clone(), Value::Dictionary(entry));
    }
    // Every component sees the same device parameters. A previously prepared
    // component must never become an input to another component's rules.
    parameters.remove("Ap,LocalBoot");
    parameters.extend(components);
    Ok(Value::Dictionary(parameters))
}

/// Validate optional metadata once, preserving signing-only entries without Info.
struct Component<'a> {
    fields: &'a Dictionary,
    info: Option<&'a Dictionary>,
    trusted: bool,
}

impl<'a> Component<'a> {
    fn parse(value: &'a Value) -> Result<Self> {
        let fields = wire::dictionary(value)?;
        let info = fields.get("Info").map(wire::dictionary).transpose()?;
        let trusted = fields
            .get("Trusted")
            .map(|value| value.as_boolean().context("invalid Trusted flag"))
            .transpose()?
            .unwrap_or(false);
        Ok(Self {
            fields,
            info,
            trusted,
        })
    }

    fn request(&self, parameters: &Dictionary) -> Result<Dictionary> {
        let mut entry = self.fields.clone();
        entry.remove("Info");
        if let Some(rules) = self.info.and_then(|info| info.get("RestoreRequestRules")) {
            apply_rules(&mut entry, rules, parameters)?;
        }
        if self.trusted && !entry.contains_key("Digest") {
            entry.insert("Digest".into(), Value::Data(vec![]));
        }
        Ok(entry)
    }
}

pub fn apply_rules(entry: &mut Dictionary, rules: &Value, parameters: &Dictionary) -> Result<()> {
    for rule in rules
        .as_array()
        .context("RestoreRequestRules must be an array")?
    {
        let conditions = wire::dictionary(wire::get(rule, &["Conditions"])?)?;
        let matches = conditions.iter().all(|(key, expected)| {
            let key = match key.as_str() {
                "ApRawProductionMode" | "ApCurrentProductionMode" => "ApProductionMode",
                "ApRawSecurityMode" => "ApSecurityMode",
                "ApRequiresImage4" => "ApSupportsImg4",
                "ApDemotionPolicyOverride" => "DemotionPolicy",
                key => key,
            };
            match key {
                "ApSupportsImg4" => expected.as_boolean() == Some(true),
                "ApInRomDFU" => expected.as_boolean() == Some(false),
                _ => parameters.get(key) == Some(expected),
            }
        });
        if matches {
            for (key, value) in wire::dictionary(wire::get(rule, &["Actions"])?)? {
                ensure!(
                    value.as_boolean().is_some(),
                    "unsupported non-boolean TSS rule action {key}"
                );
                entry.insert(key.clone(), value.clone());
            }
        }
    }
    Ok(())
}

/// RecoveryOS and auxiliary firmware share the manifest component schema.
pub(crate) fn component_request(value: &Value, parameters: &Dictionary) -> Result<Dictionary> {
    Component::parse(value)?.request(parameters)
}

pub fn local_policy_request(
    device: &DeviceInfo,
    next_ticket: &[u8],
    args: Option<&Value>,
) -> Result<Value> {
    // LocalPolicy uses only device fields; firmware metadata makes Apple reject it.
    let mut d = device_fields(device)?;
    d.insert("Ap,LocalBoot".into(), args.is_some().into());
    d.insert(
        "Ap,LocalPolicy".into(),
        wire::dict([
            (
                "Digest",
                Value::Data(Sha384::digest(img4::empty_local_policy()).to_vec()),
            ),
            ("Trusted", true.into()),
        ]),
    );
    d.insert(
        "Ap,NextStageIM4MHash".into(),
        Value::Data(Sha384::digest(next_ticket).to_vec()),
    );
    if let Some(args) = args {
        d.remove("ApNonce");
        for key in ["Ap,NextStageIM4MHash", "Ap,RecoveryOSPolicyNonceHash"] {
            d.insert(key.into(), wire::get(args, &[key])?.clone());
        }
        let uuid = wire::string(args, &["Ap,VolumeUUID"])?;
        let bytes = crate::device::decode_hex(&uuid.replace('-', ""))?;
        ensure!(bytes.len() == 16, "invalid local policy volume UUID");
        d.insert("Ap,VolumeUUID".into(), Value::Data(bytes));
    }
    Ok(Value::Dictionary(d))
}
