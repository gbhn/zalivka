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
        (
            "@VersionInfo",
            concat!(env!("CARGO_PKG_NAME"), "-", env!("CARGO_PKG_VERSION")).into(),
        ),
    ])
}

/// Coprocessor tickets also carry the AP hardware and actual fuse modes.
pub(crate) fn updater_fields(device: &DeviceInfo) -> Result<Dictionary> {
    let fuse = device
        .chip_fuse_mode
        .context("strict restore requires device CPFM")?;
    let mut d = host_fields();
    d.extend([
        ("ApChipID".into(), u64::from(device.chip_id).into()),
        ("ApBoardID".into(), u64::from(device.board_id).into()),
        ("ApProductionMode".into(), (fuse & 2 != 0).into()),
        ("ApSecurityMode".into(), (fuse & 1 != 0).into()),
    ]);
    Ok(d)
}

fn device_fields(device: &DeviceInfo) -> Result<Dictionary> {
    ensure!(
        !device.ap_nonce.is_empty(),
        "ApNonce is unavailable; cannot request a device-bound Apple ticket"
    );
    let domain = device
        .security_domain
        .context("strict restore requires device SDOM")?;
    let mut d = updater_fields(device)?;
    d.extend([
        ("@ApImg4Ticket".into(), true.into()),
        ("ApECID".into(), device.ecid.into()),
        ("ApSecurityDomain".into(), u64::from(domain).into()),
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
    if wire::optional_boolean(&id.value, &["Info", "RequiresUIDMode"])?.unwrap_or(false) {
        let uid = wire::get(&id.value, &["UID_MODE"])
            .context("strict restore requires explicit UID_MODE")?;
        ensure!(uid.as_boolean().is_some(), "invalid UID_MODE");
        d.insert("UID_MODE".into(), uid.clone());
        d.insert(
            "Ap,SikaFuse".into(),
            wire::number(
                wire::get(&id.value, &["Ap,SikaFuse"])
                    .context("strict restore requires explicit Ap,SikaFuse")?,
            )?
            .into(),
        );
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
        let component =
            Component::parse(value).with_context(|| format!("invalid signing component {name}"))?;
        let selected = component
            .info
            .and_then(|info| info.get("Personalize"))
            .map(|value| {
                value
                    .as_boolean()
                    .with_context(|| format!("invalid {name} Info.Personalize"))
            })
            .transpose()?;
        // Personalize controls file packaging. Trusted measurements and explicit
        // signing rules also belong in the ticket, even with Personalize=false.
        if selected != Some(true)
            && !component.trusted
            && !component
                .info
                .is_some_and(|info| info.contains_key("RestoreRequestRules"))
        {
            continue;
        }
        let entry = component
            .request(&parameters)
            .with_context(|| format!("preparing signing component {name}"))?;
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
    path: Option<&'a str>,
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
            path: crate::ipsw::component_path(value)?,
        })
    }

    fn request(&self, parameters: &Dictionary) -> Result<Dictionary> {
        let mut entry = self.fields.clone();
        entry.remove("Info");
        if let Some(rules) = self.info.and_then(|info| info.get("RestoreRequestRules")) {
            apply_rules(&mut entry, rules, parameters)?;
        }
        let digest = entry
            .get("Digest")
            .map(|value| value.as_data().context("invalid signing Digest"))
            .transpose()?;
        if self.trusted && self.path.is_some() {
            ensure!(
                digest.is_some_and(|digest| !digest.is_empty()),
                "strict restore requires a nonempty Digest for a trusted file"
            );
        } else if self.trusted && digest.is_none() {
            ensure!(
                self.info
                    .is_some_and(|info| info.contains_key("RestoreRequestRules")),
                "strict restore requires a Digest or signing rules for a fileless trusted measurement"
            );
            // TSS's wire marker requests the server's measurement (e.g. a trust
            // object). It is never used as a substitute for a file's hash.
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
                entry.insert(key.clone(), value.clone());
            }
        }
    }
    Ok(())
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
            let hash = wire::get(args, &[key])?
                .as_data()
                .filter(|hash| !hash.is_empty())
                .with_context(|| format!("local policy requires nonempty data {key}"))?;
            d.insert(key.into(), Value::Data(hash.to_vec()));
        }
        let uuid = uuid::Uuid::parse_str(wire::string(args, &["Ap,VolumeUUID"])?)
            .context("invalid local policy volume UUID")?;
        d.insert(
            "Ap,VolumeUUID".into(),
            Value::Data(uuid.as_bytes().to_vec()),
        );
    }
    Ok(Value::Dictionary(d))
}
