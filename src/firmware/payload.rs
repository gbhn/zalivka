//! Device-specific auxiliary-controller payload assembly.
use super::{Ftab, payload_ranges, retimer_info};
use crate::{
    ipsw::{Identity, Ipsw},
    wire,
};
use anyhow::{Context, Result, ensure};
use plist::{Dictionary, Value};
use std::io::Cursor;

fn unique<T>(mut items: impl Iterator<Item = T>) -> Option<T> {
    let item = items.next()?;
    items.next().is_none().then_some(item)
}

pub(super) fn payload(
    ipsw: &mut Ipsw,
    id: &Identity,
    updater: &str,
    info: &Dictionary,
    arguments: &Value,
    tags: &[String],
) -> Result<Option<Value>> {
    if updater == "PS190" {
        let name = if info.contains_key("InfoArray") {
            let tag = wire::number(wire::get(retimer_info(info, tags)?, &["TagNumber"])?)?;
            ensure!(tag <= u32::MAX as u64, "invalid PS190 tag number");
            format!("PCON{tag},Firmware")
        } else {
            let generated = wire::dictionary(wire::get(arguments, &["DeviceGeneratedRequest"])?)?;
            unique(generated.keys().filter(|name| {
                name.starts_with("PCON") && name.ends_with(",Firmware") && id.has(name)
            }))
            .context("PS190 firmware selection is ambiguous")?
            .clone()
        };
        let prefix = name
            .strip_suffix(",Firmware")
            .context("invalid PS190 firmware tag")?;
        let board = wire::number(wire::get(&id.value, &[&format!("{prefix},BoardID")])?)?;
        let domain = wire::number(wire::get(
            &id.value,
            &[&format!("{prefix},SecurityDomain")],
        )?)?;
        ensure!(
            board <= u32::MAX as u64 && domain <= u32::MAX as u64,
            "PS190 identifiers exceed 32 bits"
        );
        // _PS190RestoreInfoCopyFirmware returns a dictionary, not raw bytes.
        return Ok(Some(wire::dict([
            ("FirmwareData", Value::Data(ipsw.component(id, &name)?)),
            ("BoardID", board.into()),
            ("SecurityDomain", domain.into()),
        ])));
    }
    let data = match updater {
        "Ace3" if info.contains_key("ManifestPrefix") => {
            let prefix = info["ManifestPrefix"]
                .as_string()
                .filter(|s| !s.is_empty())
                .context("invalid Ace3 ManifestPrefix")?;
            let manifest = id.manifest()?;
            let name = unique(manifest.keys().filter(|name| name.starts_with(prefix)))
                .context("Ace3 ManifestPrefix does not select one component")?;
            ipsw.component(id, name)?
        }
        "SE" => {
            let chip = info
                .get("SE,ChipID")
                .or_else(|| id.value.as_dictionary()?.get("SE,ChipID"))
                .map(wire::number)
                .transpose()?;
            let name = if chip == Some(0x20211) || !id.has("SE,UpdatePayload") {
                "SE,Firmware"
            } else {
                "SE,UpdatePayload"
            };
            ipsw.component(id, name)?
        }
        "AppleTCON" => ipsw.component(id, "Baobab,TCON")?,
        "Rose" => rtkit_payload(ipsw, id, "Rap,RTKitOS", "Rap,RestoreRTKitOS")?,
        "AppleTypeCRetimer" => {
            let tag = wire::number(wire::get(retimer_info(info, tags)?, &["TagNumber"])?)?;
            ensure!(tag <= 255, "invalid retimer tag");
            rtkit_payload(
                ipsw,
                id,
                &format!("Timer,RTKitOS,{tag}"),
                &format!("Timer,RestoreRTKitOS,{tag}"),
            )?
        }
        "T200" => {
            let mut map = Value::from_reader(Cursor::new(ipsw.component(id, "BMU,FirmwareMap")?))?;
            let digest = wire::get(&id.value, &["Manifest", "BMU,FirmwareMap", "Digest"])?;
            ensure!(
                digest.as_data().is_some_and(|d| !d.is_empty()),
                "missing BMU firmware map digest"
            );
            map.as_dictionary_mut()
                .context("BMU firmware map is not a dictionary")?
                .insert("fw_map_digest".into(), digest.clone());
            let mut bytes = Vec::new();
            map.to_writer_binary(&mut bytes)?;
            bytes
        }
        "Centauri" => centauri_payload(ipsw.component(id, "Wireless1,RTKitOS")?, info)?,
        _ => {
            let generated = wire::dictionary(wire::get(arguments, &["DeviceGeneratedRequest"])?)?;
            let Some(name) = unique(generated.keys().filter(|name| id.has(name))) else {
                // The signing service may itself supply FirmwareData. Never
                // guess a multi-component payload if it does not.
                return Ok(None);
            };
            ipsw.component(id, name)?
        }
    };
    Ok(Some(Value::Data(data)))
}

// 26A434 CentauriRestoreHost::copyFirmwareUpdater and ACFUFTABFile::create.
// Keep the original bytes/offsets/padding: optimization is disabled by Apple
// for this restore path. Only the selected table's validity and nonce change.
fn centauri_payload(mut bytes: Vec<u8>, info: &Dictionary) -> Result<Vec<u8>> {
    let revision = info
        .get("Wireless1,ChipRev")
        .and_then(Value::as_data)
        .filter(|data| data.len() == 2)
        .context("Centauri Wireless1,ChipRev must contain two bytes")?;
    let mut table = Ftab::parse(&bytes).context("invalid Centauri FTAB")?;
    if u16::from_le_bytes(revision.try_into()?) != u16::MAX {
        let revision = revision[0];
        // ACFU accepts major A..D and minor 0..5. Unsupported revisions or
        // absent embedded tables leave the outer FTAB selected.
        if revision < 0x40 && revision & 0xf <= 5 {
            let major = b'a' + (revision >> 4);
            for tag in [
                [b'_', major, b'0' + (revision & 0xf), b'f'],
                [b'_', major, b'x', b'f'],
            ] {
                if let Some(entry) = table.entries.iter().find(|e| e.0 == tag) {
                    bytes = entry.1.clone();
                    table = Ftab::parse(&bytes).context("invalid embedded Centauri FTAB")?;
                    break;
                }
            }
        }
    }
    // CentauriRestoreHost::init marks only Wireless1,RTKitOS/rkos required;
    // the remaining wireless components are optional in isFirmwareValid.
    ensure!(
        table.entries.iter().any(|entry| entry.0 == *b"rkos"),
        "Centauri FTAB has no required rkos entry"
    );
    if let Some(nonce) = info.get("Wireless1,RestoreBootNonce") {
        let nonce = nonce
            .as_data()
            .filter(|data| data.len() == 8)
            .context("Centauri Wireless1,RestoreBootNonce must contain eight bytes")?;
        if nonce != [0; 8] {
            bytes[8..16].copy_from_slice(nonce);
        }
    }
    ensure!(
        bytes[8..16] != [0; 8],
        "Centauri FTAB requires a nonzero restore boot nonce"
    );
    bytes[4..8].copy_from_slice(&1u32.to_le_bytes());
    Ok(bytes)
}

fn rtkit_payload(ipsw: &mut Ipsw, id: &Identity, base: &str, restore: &str) -> Result<Vec<u8>> {
    let mut table = rtkit_table(&ipsw.component(id, base)?)?;
    if id.has(restore) {
        let bytes = ipsw.component(id, restore)?;
        let entry = if bytes.get(36..40) == Some(b"ftab") {
            let restore = Ftab::parse(&bytes)?;
            restore
                .entries
                .into_iter()
                .find(|e| e.0 == *b"rrko")
                .context("restore RTKit FTAB has no rrko entry")?
        } else {
            let digest = wire::get(&id.value, &["Manifest", restore, "Digest"])?
                .as_data()
                .context("missing restore RTKit digest")?;
            let range = payload_ranges(&bytes, bytes.len() as u64)?
                .into_iter()
                .find(|range| {
                    crate::ipsw::verify_digest(
                        &bytes[range.start as usize..range.end as usize],
                        digest,
                    )
                    .is_ok()
                })
                .context("UARP has no restore RTKit payload matching the manifest")?;
            (
                *b"rrko",
                bytes[range.start as usize..range.end as usize].to_vec(),
                0,
            )
        };
        table.entries.retain(|e| e.0 != *b"rrko");
        table.entries.push(entry);
    }
    table.encode()
}

fn rtkit_table(bytes: &[u8]) -> Result<Ftab> {
    if bytes.get(36..40) == Some(b"ftab") {
        return Ftab::parse(bytes);
    }
    let mut selected = None;
    for range in payload_ranges(bytes, bytes.len() as u64)? {
        let payload = &bytes[range.start as usize..range.end as usize];
        if payload.get(36..40) == Some(b"ftab") {
            ensure!(selected.is_none(), "multiple RTKit tables in UARP");
            selected = Some(payload);
        }
    }
    Ftab::parse(selected.context("RTKit firmware contains no FTAB")?)
}
