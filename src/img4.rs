//! Small, bounded DER codec for Apple's IM4P / IMG4 containers.
use anyhow::{Result, ensure};

pub fn element(tag: u8, data: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    if data.len() < 128 {
        out.push(data.len() as u8);
    } else {
        let bytes = data.len().to_be_bytes();
        let first = bytes
            .iter()
            .position(|b| *b != 0)
            .unwrap_or(bytes.len() - 1);
        out.push(0x80 | (bytes.len() - first) as u8);
        out.extend_from_slice(&bytes[first..]);
    }
    out.extend_from_slice(data);
    out
}

#[derive(Debug)]
pub struct Der<'a> {
    pub tag: u8,
    pub content: &'a [u8],
    pub encoded: &'a [u8],
}

pub fn parse(data: &[u8]) -> Result<(Der<'_>, &[u8])> {
    ensure!(data.len() >= 2, "truncated DER header");
    let mut tag_end = 1;
    if data[0] & 31 == 31 {
        ensure!(data[1] & 0x7f != 0, "noncanonical high DER tag");
        loop {
            ensure!(tag_end < data.len() && tag_end <= 5, "invalid high DER tag");
            let b = data[tag_end];
            tag_end += 1;
            if b & 0x80 == 0 {
                break;
            }
        }
    }
    ensure!(tag_end < data.len(), "missing DER length");
    let mut start = tag_end + 1;
    let length = if data[tag_end] < 128 {
        data[tag_end] as usize
    } else {
        let n = usize::from(data[tag_end] & 0x7f);
        ensure!(
            n != 0 && n <= size_of::<usize>() && data.len() >= start + n,
            "invalid DER length"
        );
        ensure!(data[start] != 0, "noncanonical DER length");
        let length_start = start;
        start += n;
        let mut value = 0usize;
        for b in &data[length_start..start] {
            value = value
                .checked_mul(256)
                .and_then(|v| v.checked_add(*b as usize))
                .ok_or_else(|| anyhow::anyhow!("DER length overflow"))?;
        }
        ensure!(value >= 128, "noncanonical DER long length");
        value
    };
    let end = start
        .checked_add(length)
        .filter(|n| *n <= data.len())
        .ok_or_else(|| anyhow::anyhow!("truncated DER value"))?;
    Ok((
        Der {
            tag: data[0],
            content: &data[start..end],
            encoded: &data[..end],
        },
        &data[end..],
    ))
}

pub fn empty_local_policy() -> Vec<u8> {
    let mut fields = element(0x16, b"IM4P");
    fields.extend(element(0x16, b"lpol"));
    fields.extend(element(0x16, b"1.0"));
    fields.extend(element(0x04, &[0]));
    element(0x30, &fields)
}

pub fn personalize(component: &str, payload: &[u8], ticket: &[u8]) -> Result<Vec<u8>> {
    Ok(element(
        0x30,
        &personalized_body(component, payload, ticket)?,
    ))
}

fn personalized_body(component: &str, payload: &[u8], ticket: &[u8]) -> Result<Vec<u8>> {
    let (outer, rest) = parse(payload)?;
    ensure!(
        outer.tag == 0x30 && rest.is_empty(),
        "component is not a DER sequence"
    );
    let (magic, fields) = parse(outer.content)?;
    ensure!(
        magic.tag == 0x16 && magic.content == b"IM4P",
        "component is not an IM4P payload"
    );
    let (kind, trailing) = parse(fields)?;
    ensure!(
        kind.tag == 0x16 && kind.content.len() == 4,
        "invalid IM4P type"
    );
    let (manifest, rest) = parse(ticket)?;
    ensure!(
        manifest.tag == 0x30 && rest.is_empty(),
        "invalid IM4M ticket sequence"
    );
    let (magic_ticket, _) = parse(manifest.content)?;
    ensure!(
        magic_ticket.tag == 0x16 && magic_ticket.content == b"IM4M",
        "TSS ticket is not IM4M"
    );
    let tag = restore_tag(component).unwrap_or(
        kind.content
            .try_into()
            .map_err(|_| anyhow::anyhow!("invalid component tag"))?,
    );
    let mut fields = magic.encoded.to_vec();
    fields.extend(element(0x16, &tag));
    fields.extend_from_slice(trailing);
    let mut body = element(0x16, b"IMG4");
    body.extend(element(0x30, &fields));
    body.extend(element(0xa0, ticket));
    Ok(body)
}

fn private_property(name: &[u8; 4], value: &[u8]) -> Vec<u8> {
    let mut fields = element(0x16, name);
    fields.extend_from_slice(value);
    let sequence = element(0x30, &fields);
    let mut tag = u32::from_be_bytes(*name);
    let mut digits = vec![(tag & 0x7f) as u8];
    tag >>= 7;
    while tag != 0 {
        digits.push((tag & 0x7f) as u8 | 0x80);
        tag >>= 7;
    }
    let mut encoded = vec![0xff];
    encoded.extend(digits.into_iter().rev());
    encoded.extend_from_slice(&element(0, &sequence)[1..]);
    encoded
}

pub fn restore_info(
    tss: &plist::Value,
    component: &str,
    identity: &plist::Value,
) -> Result<Option<Vec<u8>>> {
    use crate::wire;
    let mut properties = Vec::new();
    if wire::boolean(identity, &["Info", "RequiresNonceSlot"])
        && ["SEP", "SepStage1", "LLB"].contains(&component)
    {
        let (tag, key, default) = if component == "LLB" {
            (b"anid", "ApNonceSlotID", 0u64)
        } else {
            (b"snid", "SepNonceSlotID", 2u64)
        };
        let slot = wire::get(identity, &["Info", key])
            .ok()
            .map(wire::number)
            .transpose()?
            .unwrap_or(default);
        let bytes = slot.to_be_bytes();
        let start = bytes
            .iter()
            .position(|b| *b != 0)
            .unwrap_or(bytes.len() - 1);
        let mut integer = bytes[start..].to_vec();
        if integer[0] & 0x80 != 0 {
            integer.insert(0, 0);
        }
        properties.extend(private_property(tag, &element(2, &integer)));
    }
    if let Ok(tbm) = wire::get(tss, &[&format!("{component}-TBM")]) {
        for name in [b"ucon", b"ucer"] {
            let key = std::str::from_utf8(name)?;
            let data = wire::get(tbm, &[key])?
                .as_data()
                .ok_or_else(|| anyhow::anyhow!("invalid TBM {key}"))?;
            properties.extend(private_property(name, &element(4, data)));
        }
    }
    if properties.is_empty() {
        return Ok(None);
    }
    let mut body = element(0x16, b"IM4R");
    body.extend(element(0x31, &properties));
    Ok(Some(element(0xa1, &element(0x30, &body))))
}

pub fn personalize_with_metadata(
    component: &str,
    payload: &[u8],
    tss: &plist::Value,
    identity: &plist::Value,
) -> Result<Vec<u8>> {
    let mut body = personalized_body(component, payload, crate::tss::ticket(tss)?)?;
    if let Some(info) = restore_info(tss, component, identity)? {
        body.extend(info);
    }
    Ok(element(0x30, &body))
}

/// IM4P restore variants share a file with normal components and change its tag.
pub fn restore_tag(component: &str) -> Option<[u8; 4]> {
    match component {
        "RestoreKernelCache" => Some(*b"rkrn"),
        "RestoreDeviceTree" => Some(*b"rdtr"),
        "RestoreSEP" => Some(*b"rsep"),
        "RestoreLogo" => Some(*b"rlgo"),
        "RestoreTrustCache" => Some(*b"rtsc"),
        "RestoreDCP" => Some(*b"rdcp"),
        "Ap,RestoreDCP2" => Some(*b"rdc2"),
        "Ap,DCP2" => Some(*b"dcp2"),
        "Ap,RestoreCIO" => Some(*b"rcio"),
        "Ap,RestoreTMU" => Some(*b"rtmu"),
        "Ap,RestoreSecureM3Firmware" => Some(*b"rsm3"),
        "Ap,RestoreSecurePageTableMonitor" => Some(*b"rspt"),
        "Ap,RestoreTrustedExecutionMonitor" => Some(*b"rtrx"),
        "Ap,RestorecL4" => Some(*b"rxcl"),
        "Ap,RestoreANE1" => Some(*b"ran1"),
        "Ap,RestoreANE2" => Some(*b"ran2"),
        "Ap,RestoreANE3" => Some(*b"ran3"),
        _ => None,
    }
}

/// Locate the four tag bytes from a prefix; the image body may be gigabytes long.
pub fn type_offset(prefix: &[u8]) -> Option<usize> {
    if *prefix.first()? != 0x30 {
        return None;
    }
    let length = *prefix.get(1)?;
    let start = if length < 128 {
        2
    } else {
        let count = usize::from(length & 0x7f);
        if count == 0 || count > size_of::<usize>() {
            return None;
        }
        2 + count
    };
    let (magic, fields) = parse(prefix.get(start..)?).ok()?;
    if magic.tag != 0x16 || magic.content != b"IM4P" {
        return None;
    }
    let (kind, trailing) = parse(fields).ok()?;
    if kind.tag != 0x16 || kind.content.len() != 4 {
        return None;
    }
    Some(prefix.len() - trailing.len() - 4)
}
