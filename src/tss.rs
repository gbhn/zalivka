use crate::{device::DeviceInfo, img4, ipsw::Identity, net, wire};
use anyhow::{Context, Result, ensure};
use plist::{Dictionary, Value};
use sha2::{Digest, Sha384};

const TSS_URL: &str = "https://gs.apple.com/TSS/controller?action=2";

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

pub fn request(device: &DeviceInfo, id: &Identity) -> Result<Value> {
    let mut d = base(device, id)?;
    for (name, value) in id.manifest()? {
        if [
            "BasebandFirmware",
            "SE,UpdatePayload",
            "BaseSystem",
            "Diags",
            "Ap,ExclaveOS",
        ]
        .contains(&name.as_str())
        {
            continue;
        }
        let Ok(info) = wire::get(value, &["Info"]).and_then(wire::dictionary) else {
            continue;
        };
        let trusted = wire::boolean(value, &["Trusted"]);
        if (!trusted && !info.contains_key("RestoreRequestRules"))
            || wire::boolean(value, &["Info", "IsFTAB"])
        {
            continue;
        }
        let mut entry = wire::dictionary(value)?.clone();
        entry.remove("Info");
        if let Some(rules) = info.get("RestoreRequestRules") {
            apply_rules(&mut entry, rules, &d)?;
        } else {
            entry.insert("EPRO".into(), true.into());
            entry.insert("ESEC".into(), true.into());
        }
        if trusted && !entry.contains_key("Digest") {
            entry.insert("Digest".into(), Value::Data(vec![]));
        }
        d.insert(name.clone(), Value::Dictionary(entry));
    }
    Ok(Value::Dictionary(d))
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
pub(crate) fn component_request(value: &Value, parameters: &Dictionary) -> Result<Value> {
    let mut entry = wire::dictionary(value)?.clone();
    if let Ok(rules) = wire::get(value, &["Info", "RestoreRequestRules"]) {
        apply_rules(&mut entry, rules, parameters)?;
    }
    entry.remove("Info");
    if wire::boolean(value, &["Trusted"]) && !entry.contains_key("Digest") {
        entry.insert("Digest".into(), Value::Data(vec![]));
    }
    Ok(Value::Dictionary(entry))
}

pub fn send(request: &Value) -> Result<Value> {
    let response = send_raw(request)?;
    ticket(&response)?;
    Ok(response)
}

pub fn send_raw(request: &Value) -> Result<Value> {
    let body = wire::xml(request)?;
    let request = ureq::http::Request::post(TSS_URL)
        .header("Content-Type", "text/xml")
        .body(body)?;
    let mut response =
        net::send_http(&net::tss_agent(), &request).context("Apple TSS request failed")?;
    ensure!(
        response.status().is_success(),
        "Apple TSS returned {}",
        response.status()
    );
    let data = crate::storage::read_limited(
        response.body_mut().as_reader(),
        16 * 1024 * 1024,
        "TSS response too large",
    )?;
    parse_response(&data)
}

pub fn parse_response(data: &[u8]) -> Result<Value> {
    let text = std::str::from_utf8(data).context("TSS response is not UTF-8")?;
    let header = text
        .split_once("&REQUEST_STRING=")
        .map_or(text, |(header, _)| header);
    ensure!(
        header.split('&').any(|s| s == "STATUS=0"),
        "Apple refused personalization: {header}"
    );
    let (_, plist) = text
        .split_once("&REQUEST_STRING=")
        .context("TSS response has no REQUEST_STRING")?;
    let value =
        Value::from_reader(std::io::Cursor::new(plist.as_bytes())).context("invalid TSS plist")?;
    Ok(value)
}

pub fn recovery_request(device: &DeviceInfo, id: &Identity) -> Result<Value> {
    let mut d = base(device, id)?;
    d.insert("Ap,LocalBoot".into(), false.into());
    // recoveryOS authenticates its own boot chain rather than the restore boot chain.
    let excluded = [
        "BasebandFirmware",
        "SE,UpdatePayload",
        "BaseSystem",
        "Diags",
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
    for (name, value) in id.manifest()? {
        if excluded.contains(&name.as_str()) {
            continue;
        }
        wire::dictionary(value)?;
        if wire::get(value, &["Info"]).is_err() {
            continue;
        }
        d.insert(name.clone(), component_request(value, &d)?);
    }
    // This is a rule parameter, not a field of the RecoveryOS root request.
    d.remove("Ap,LocalBoot");
    Ok(Value::Dictionary(d))
}

pub fn ticket(response: &Value) -> Result<&[u8]> {
    wire::get(response, &["ApImg4Ticket"])?
        .as_data()
        .filter(|d| !d.is_empty())
        .context("Apple returned no ApImg4Ticket")
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
