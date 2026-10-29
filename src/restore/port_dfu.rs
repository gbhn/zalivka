//! Port DFU boots a signed Ace3 controller image before the SoC exposes DFU.
//! Protocol reference: libimobiledevice/idevicerestore src/ace3.c and src/dfu.c.
use crate::{device::Mode, dfu, ipsw::Identity, tss, usb::RecoveryUsb, wire};
use anyhow::{Context, Result, ensure};
use plist::Value;
use std::collections::HashSet;

const FIRMWARE: &str = "USBPortController1,USBFirmware";

pub(super) fn boot(
    ipsw: &mut crate::ipsw::Ipsw,
    mut usb: RecoveryUsb,
    identity: &Identity,
) -> Result<RecoveryUsb> {
    ensure!(
        !usb.topology().bus_id().is_empty() && !usb.topology().port_chain().is_empty(),
        "Port DFU requires a physical USB port identity to follow the ECID change"
    );
    let request = request(&usb.info, identity)?;
    let revision = usb.info.serial_hex("PREV")?;
    // Validate the archive and matching metadata before signing
    // or touching the controller. component() also checks its manifest digest.
    let firmware = ipsw.component(identity, FIRMWARE)?;
    let payloads = payloads(&firmware, u64::from(usb.info.board_id), revision)?;
    crate::ipsw::verify_digest(
        payloads.digest_list,
        wire::get(&identity.value, &["Manifest", FIRMWARE, "Digest"])?
            .as_data()
            .context("invalid Ace3 Digest")?,
    )
    .context("selected Ace3 digest list differs from the signing manifest")?;
    let response = tss::send_raw(&request).context("signing Port DFU firmware")?;
    let ticket = wire::get(&response, &["USBPortController1,Ticket"])?
        .as_data()
        .filter(|data| !data.is_empty())
        .context("Apple returned no USBPortController1,Ticket")?;
    let image = binary(payloads, ticket)?;
    let topology = usb.topology().clone();
    let hardware = usb.info.hardware_ids();
    crate::log!(Info, "boot", "Restoring USB port controller before SoC DFU");
    let upload = dfu::upload(&mut usb, Mode::PortDfu, &image, true);
    drop(usb);
    // The reset can invalidate its own handle; only actual SoC DFU on the
    // same physical port, with matching hardware, confirms success.
    if let Err(error) = upload {
        if !error.is::<dfu::ResetFailure>() {
            return Err(error).context("uploading Port DFU firmware");
        }
        crate::log!(Debug, "boot", "Port DFU reset: {error:#}");
    }
    let usb = RecoveryUsb::wait_at_port(&topology, hardware)
        .context("Port DFU did not reconnect as SoC DFU; check the model's DFU port: https://support.apple.com/120694")?;
    crate::log!(
        Info,
        "boot",
        "SoC DFU connected, ECID {:016x}",
        usb.info.ecid
    );
    Ok(usb)
}

fn request(device: &crate::device::DeviceInfo, identity: &Identity) -> Result<Value> {
    ensure!(device.mode == Mode::PortDfu, "expected Port DFU");
    ensure!(!device.ap_nonce.is_empty(), "Port DFU nonce is unavailable");
    let mut fields = tss::host_fields();
    for (suffix, actual) in [
        ("ChipID", u64::from(device.chip_id)),
        ("BoardID", u64::from(device.board_id)),
    ] {
        let key = format!("USBPortController1,{suffix}");
        ensure!(
            wire::number(wire::get(&identity.value, &[&key])?)? == actual,
            "Port DFU {suffix} differs from the firmware; check the DFU USB port"
        );
        fields.insert(key, actual.into());
    }
    let domain = wire::number(wire::get(
        &identity.value,
        &["USBPortController1,SecurityDomain"],
    )?)?;
    ensure!(
        device
            .security_domain
            .is_none_or(|actual| u64::from(actual) == domain),
        "Port DFU security domain differs from firmware"
    );
    fields.insert("USBPortController1,SecurityDomain".into(), domain.into());
    let fuse = device.chip_fuse_mode.context("Port DFU has no CPFM")?;
    fields.extend([
        ("@USBPortController1,Ticket".into(), true.into()),
        ("USBPortController1,ECID".into(), device.ecid.into()),
        (
            "USBPortController1,SecurityMode".into(),
            (fuse & 1 != 0).into(),
        ),
        (
            "USBPortController1,ProductionMode".into(),
            (fuse & 2 != 0).into(),
        ),
        // Port DFU exposes the controller nonce in reverse byte order.
        (
            "USBPortController1,Nonce".into(),
            Value::Data(device.ap_nonce.iter().rev().copied().collect()),
        ),
    ]);
    let mut component =
        wire::dictionary(wire::get(&identity.value, &["Manifest", FIRMWARE])?)?.clone();
    component.remove("Info");
    ensure!(
        component
            .get("Digest")
            .and_then(Value::as_data)
            .is_some_and(|d| !d.is_empty()),
        "Port DFU firmware has no Digest"
    );
    fields.insert(FIRMWARE.into(), Value::Dictionary(component));
    Ok(Value::Dictionary(fields))
}

fn be32(bytes: &[u8], offset: usize) -> Result<usize> {
    Ok(u32::from_be_bytes(
        bytes
            .get(offset..offset + 4)
            .context("truncated UARP field")?
            .try_into()?,
    ) as usize)
}

/// Decode only Foundation value containers; no Objective-C classes are loaded.
fn unarchive(archive: &Value) -> Result<Value> {
    ensure!(
        wire::string(archive, &["$archiver"])? == "NSKeyedArchiver",
        "unsupported UARP metadata archive"
    );
    let objects = wire::get(archive, &["$objects"])?
        .as_array()
        .context("invalid archive objects")?;
    ensure!(objects.len() <= 65536, "too many UARP archive objects");
    fn resolve(
        value: &Value,
        objects: &[Value],
        active: &mut HashSet<usize>,
        remaining: &mut usize,
        depth: usize,
    ) -> Result<Value> {
        ensure!(depth <= 32, "UARP archive nested too deeply");
        let size = 64
            + match value {
                Value::String(s) => s.len(),
                Value::Data(data) => data.len(),
                _ => 0,
            };
        *remaining = remaining
            .checked_sub(size)
            .context("UARP archive expansion exceeds limit")?;
        if let Some(uid) = value.as_uid() {
            let index = usize::try_from(uid.get())?;
            ensure!(active.insert(index), "cyclic UARP archive reference");
            let value = resolve(
                objects
                    .get(index)
                    .context("UARP archive reference outside object table")?,
                objects,
                active,
                remaining,
                depth + 1,
            )?;
            active.remove(&index);
            return Ok(value);
        }
        if let Some(fields) = value.as_dictionary() {
            let values = fields
                .get("NS.objects")
                .and_then(Value::as_array)
                .context("unsupported UARP archive object")?;
            if let Some(keys) = fields.get("NS.keys") {
                let keys = keys
                    .as_array()
                    .context("invalid archived dictionary keys")?;
                ensure!(
                    keys.len() == values.len(),
                    "UARP archived dictionary size mismatch"
                );
                let mut out = plist::Dictionary::new();
                for (key, value) in keys.iter().zip(values) {
                    let key = resolve(key, objects, active, remaining, depth + 1)?
                        .into_string()
                        .context("non-string UARP dictionary key")?;
                    ensure!(
                        !out.contains_key(&key),
                        "duplicate UARP dictionary key {key}"
                    );
                    out.insert(key, resolve(value, objects, active, remaining, depth + 1)?);
                }
                return Ok(Value::Dictionary(out));
            }
            return values
                .iter()
                .map(|v| resolve(v, objects, active, remaining, depth + 1))
                .collect::<Result<Vec<_>>>()
                .map(Value::Array);
        }
        ensure!(
            !matches!(value, Value::Array(_)),
            "unsupported raw UARP archive array"
        );
        Ok(value.clone())
    }
    resolve(
        wire::get(archive, &["$top", "root"])?,
        objects,
        &mut HashSet::new(),
        &mut (8 * 1024 * 1024),
        0,
    )
}

struct Payloads<'a> {
    patch: &'a [u8],
    config: &'a [u8],
    digest_list: &'a [u8],
    version: u32,
}

fn payloads(bytes: &[u8], board: u64, revision: u64) -> Result<Payloads<'_>> {
    ensure!(
        bytes.len() <= 32 * 1024 * 1024,
        "Ace3 UARP exceeds size limit"
    );
    ensure!(
        be32(bytes, 0)? == 2 && be32(bytes, 4)? == 44,
        "unsupported Ace3 UARP format"
    );
    let start = be32(bytes, 36)?;
    let end = start
        .checked_add(be32(bytes, 40)?)
        .context("UARP index overflow")?;
    let metadata_offset = be32(bytes, 8)?;
    ensure!(
        start >= 44 && end <= metadata_offset && metadata_offset <= bytes.len(),
        "invalid UARP index or metadata range"
    );
    // Reuse the container validator for row sizes, payload bounds and overlap.
    crate::firmware::payload_ranges(bytes, bytes.len() as u64)?;
    let archive = wire::decode_plist(&bytes[metadata_offset..])?;
    let metadata = unarchive(&archive)?;
    let mut selection = None;
    for payload in wire::get(&metadata, &["SuperBinary Payloads"])?
        .as_array()
        .context("invalid SuperBinary Payloads")?
    {
        let Some(meta) = wire::optional(payload, &["Payload MetaData"])? else {
            continue;
        };
        if wire::optional(meta, &["Personalization Manifest Prefix"])?.and_then(Value::as_string)
            != Some("USBPortController")
        {
            continue;
        }
        if wire::number(wire::get(meta, &["Personalization Board ID (64 bits)"])?)? != board {
            continue;
        }
        for matching in wire::get(meta, &["Personalization Matching Data"])?
            .as_array()
            .context("invalid UARP matching data")?
        {
            let min = wire::number(wire::get(
                matching,
                &["Personalization Matching Data Product Revision Minimum"],
            )?)?;
            let max = wire::number(wire::get(
                matching,
                &["Personalization Matching Data Product Revision Maximum"],
            )?)?;
            ensure!(min <= max, "invalid UARP product revision range");
            if !(min..=max).contains(&revision) {
                continue;
            }
            ensure!(selection.is_none(), "ambiguous UARP board/revision match");
            let tags = wire::string(matching, &["Personalization Matching Data Payload Tags"])?;
            let (patch, config) = tags
                .split_once(',')
                .context("unsupported Ace3 payload composition")?;
            let dl = wire::string(payload, &["Payload 4CC"])?;
            ensure!(
                [patch, config, dl]
                    .iter()
                    .all(|s| s.len() == 4 && s.is_ascii()),
                "invalid Ace3 payload tags"
            );
            ensure!(
                patch != config && patch != dl && config != dl,
                "duplicate Ace3 payload roles"
            );
            selection = Some((patch, config, dl));
        }
    }
    let (patch, config, dl) =
        selection.context("Ace3 UARP has no matching board and product revision")?;
    let mut selected = [None; 3];
    let mut version = None;
    let mut position = start;
    while position < end {
        let row = &bytes[position..end];
        let size = be32(row, 0)?;
        ensure!(size >= 40 && size <= row.len(), "invalid Ace3 UARP row");
        let offset = be32(row, 32)?;
        let length = be32(row, 36)?;
        for (i, tag) in [patch, config, dl].iter().enumerate() {
            if row.get(4..8) == Some(tag.as_bytes()) {
                ensure!(selected[i].is_none(), "duplicate Ace3 payload {tag}");
                let last = offset
                    .checked_add(length)
                    .context("Ace3 payload range overflow")?;
                ensure!(
                    offset >= end && last <= metadata_offset && length > 0,
                    "invalid Ace3 payload range"
                );
                selected[i] = Some(&bytes[offset..last]);
                if i == 0 {
                    let major = be32(row, 8)?;
                    let minor = be32(row, 12)?;
                    let patch = be32(row, 16)?;
                    let release = if major >= 0xe00 { 0xe00 } else { 0 };
                    let major = major - release;
                    ensure!(
                        major <= 99 && minor <= 999 && patch <= 99,
                        "unsupported Ace3 firmware version"
                    );
                    let bcd = |n: usize| (n / 100) * 256 + ((n / 10) % 10) * 16 + n % 10;
                    version = Some(
                        (((bcd(major) | release) << 20) | (bcd(minor) << 8) | bcd(patch)) as u32,
                    );
                }
            }
        }
        position += size;
    }
    let [patch, config, digest_list] = selected.map(|v| v.context("missing Ace3 payload"));
    Ok(Payloads {
        patch: patch?,
        config: config?,
        digest_list: digest_list?,
        version: version.context("missing Ace3 version")?,
    })
}

fn binary(payloads: Payloads<'_>, ticket: &[u8]) -> Result<Vec<u8>> {
    let parts = [
        payloads.patch,
        payloads.config,
        ticket,
        payloads.digest_list,
    ];
    let size = parts.iter().try_fold(64usize, |n, p| {
        n.checked_add(p.len()).context("Ace3 size overflow")
    })?;
    ensure!(
        !ticket.is_empty() && size.div_ceil(64) <= usize::from(u16::MAX),
        "Ace3 image is empty or exceeds Port DFU transfer limit"
    );
    let mut image = Vec::with_capacity(size);
    for field in [
        0xace00003,
        payloads.version,
        0x2800,
        64,
        u32::try_from(payloads.patch.len())?,
        u32::try_from(payloads.config.len())?,
        u32::try_from(64 + payloads.patch.len() + payloads.config.len())?,
        u32::try_from(ticket.len() + payloads.digest_list.len())?,
        u32::try_from(size - 64)?,
        0,
    ] {
        image.extend(field.to_le_bytes());
    }
    image.extend([0xff; 24]);
    for part in parts {
        image.extend(part);
    }
    // Ace3 uses the MSB-first representation of the uncomplemented CRC32.
    let crc = (!crc32fast::hash(&image[64..])).reverse_bits();
    image[36..40].copy_from_slice(&crc.to_le_bytes());
    Ok(image)
}

#[cfg(test)]
#[path = "../../tests/unit/restore/port_dfu.rs"]
mod tests;
