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
    let device = id.device_parameters(device)?;
    let mut d = device_fields(&device)?;
    wire::copy_keys(
        &mut d,
        wire::dictionary(&id.value)?,
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
    if wire::optional_boolean(&id.value, &["Info", "RequiresUIDMode"])?.unwrap_or(false) {
        // Use upstream's retail DFU compatibility defaults: UID mode off,
        // Sika fuse zero. These are not measurements from the BuildManifest.
        let uid = wire::optional_boolean(&id.value, &["UID_MODE"])?.unwrap_or(false);
        d.insert("UID_MODE".into(), uid.into());
        d.insert(
            "Ap,SikaFuse".into(),
            wire::optional(&id.value, &["Ap,SikaFuse"])?
                .map(wire::number)
                .transpose()?
                .unwrap_or(0)
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
        let Some(entry) = component_request(value, &parameters)
            .with_context(|| format!("preparing signing component {name}"))?
        else {
            continue;
        };
        ensure!(
            !parameters.contains_key(name) && !name.starts_with('@'),
            "signing component {name} conflicts with request parameters"
        );
        components.insert(name.clone(), Value::Dictionary(entry));
    }
    // Every component sees the same device parameters. A previously prepared
    // component must never become an input to another component's rules.
    parameters.remove("Ap,LocalBoot");
    parameters.extend(components);
    Ok(Value::Dictionary(parameters))
}

/// Select and prepare one signing entry, including fileless measurements.
fn component_request(value: &Value, parameters: &Dictionary) -> Result<Option<Dictionary>> {
    let fields = wire::dictionary(value)?;
    let info = fields.get("Info").map(wire::dictionary).transpose()?;
    let trusted = fields
        .get("Trusted")
        .map(|value| value.as_boolean().context("invalid Trusted flag"))
        .transpose()?
        .unwrap_or(false);
    let path = crate::ipsw::component_path(value)?;
    let selected = info
        .and_then(|info| info.get("Personalize"))
        .map(|value| value.as_boolean().context("invalid Info.Personalize"))
        .transpose()?;
    let rules = info.and_then(|info| info.get("RestoreRequestRules"));
    // Personalize controls file packaging. Trusted measurements and explicit
    // signing rules also belong in the ticket, even with Personalize=false.
    if selected != Some(true) && !trusted && rules.is_none() {
        return Ok(None);
    }
    let mut entry = fields.clone();
    entry.remove("Info");
    if let Some(rules) = rules {
        apply_rules(&mut entry, rules, parameters)?;
    }
    let trusted = entry
        .get("Trusted")
        .map(|value| {
            value
                .as_boolean()
                .context("invalid signing Trusted flag after rules")
        })
        .transpose()?
        .unwrap_or(false);
    let digest = entry
        .get("Digest")
        .map(|value| value.as_data().context("invalid signing Digest"))
        .transpose()?;
    ensure!(
        digest.is_none_or(|digest| digest.is_empty() || [20, 32, 48].contains(&digest.len())),
        "unsupported signing Digest size"
    );
    if trusted && path.is_some() {
        ensure!(
            digest.is_some_and(|digest| !digest.is_empty()),
            "strict restore requires a nonempty Digest for a trusted file"
        );
    } else if trusted && digest.is_none() {
        ensure!(
            rules.is_some(),
            "strict restore requires a Digest or signing rules for a fileless trusted measurement"
        );
        // TSS's wire marker requests the server's measurement (e.g. a trust
        // object). It is never used as a substitute for a file's hash.
        entry.insert("Digest".into(), Value::Data(vec![]));
    }
    Ok(Some(entry))
}

pub fn apply_rules(entry: &mut Dictionary, rules: &Value, parameters: &Dictionary) -> Result<()> {
    for rule in rules
        .as_array()
        .context("RestoreRequestRules must be an array")?
    {
        let conditions = wire::dictionary(wire::get(rule, &["Conditions"])?)?;
        let actions = wire::dictionary(wire::get(rule, &["Actions"])?)?;
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
            for (key, value) in actions {
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
    } else {
        d.insert(
            "Ap,NextStageIM4MHash".into(),
            Value::Data(Sha384::digest(next_ticket).to_vec()),
        );
    }
    Ok(Value::Dictionary(d))
}
