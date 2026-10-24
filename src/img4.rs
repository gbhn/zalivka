//! Apple's IM4P / IMG4 envelopes, using ASN.1 headers without copying image bodies.
use anyhow::{Context, Result, ensure};
use asn1_rs::{Class, FromDer, Header, Length, Tag, ToDer};
use std::ops::Range;

pub fn element(tag: u8, data: &[u8]) -> Vec<u8> {
    let mut out = encoded_header(header(tag, data.len()));
    out.reserve(data.len());
    out.extend_from_slice(data);
    out
}

fn header(tag: u8, length: usize) -> Header<'static> {
    Header::new(
        Class::try_from(tag >> 6).expect("two-bit ASN.1 class"),
        tag & 0x20 != 0,
        Tag(u32::from(tag & 0x1f)),
        Length::Definite(length),
    )
}

fn encoded_header(header: Header<'_>) -> Vec<u8> {
    let mut out = Vec::with_capacity(16);
    header
        .write_der_header(&mut out)
        .expect("encoding an ASN.1 header into memory");
    out
}

#[derive(Debug)]
pub struct Der<'a> {
    pub tag: u8,
    pub content: &'a [u8],
    pub encoded: &'a [u8],
}

pub fn parse(data: &[u8]) -> Result<(Der<'_>, &[u8])> {
    let range = content_range(data)?;
    let content = data.get(range.clone()).context("truncated DER value")?;
    Ok((
        Der {
            tag: data[0],
            content,
            encoded: &data[..range.end],
        },
        &data[range.end..],
    ))
}

/// Parse the complete header even when only a prefix of the body is available.
fn content_range(data: &[u8]) -> Result<Range<usize>> {
    let (rest, header) =
        Header::from_der(data).map_err(|error| anyhow::anyhow!("invalid DER header: {error}"))?;
    let start = data.len() - rest.len();
    let length = header.length().definite()?;
    // Header parsing also accepts some BER spellings. Re-encoding enforces
    // minimal tag and length encodings without a second handwritten parser.
    let mut encoded = [0; 16]; // u32 tag + usize length, including their prefixes.
    let size = header.write_der_header(&mut encoded.as_mut_slice())?;
    ensure!(data[..start] == encoded[..size], "noncanonical DER header");
    let end = start.checked_add(length).context("DER length overflow")?;
    Ok(start..end)
}

pub fn empty_local_policy() -> Vec<u8> {
    let mut fields = element(0x16, b"IM4P");
    fields.extend(element(0x16, b"lpol"));
    fields.extend(element(0x16, b"1.0"));
    fields.extend(element(0x04, &[0]));
    element(0x30, &fields)
}

pub fn personalize(component: &str, payload: &[u8], ticket: &[u8]) -> Result<Vec<u8>> {
    personalized_image(component, payload, ticket, &[])
}

fn personalized_image(
    component: &str,
    payload: &[u8],
    ticket: &[u8],
    metadata: &[u8],
) -> Result<Vec<u8>> {
    let (outer, rest) = parse(payload)?;
    ensure!(
        outer.tag == 0x30 && rest.is_empty(),
        "component is not a DER sequence"
    );
    let kind = im4p_type_range(payload)?;
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
    let tag = restore_tag(component).unwrap_or(payload[kind.clone()].try_into()?);
    let manifest_header = encoded_header(header(0xa0, ticket.len()));
    let length = [
        6,
        payload.len(),
        manifest_header.len(),
        ticket.len(),
        metadata.len(),
    ]
    .into_iter()
    .try_fold(0usize, usize::checked_add)
    .context("IMG4 length overflow")?;
    // Allocate the final envelope once. The firmware body is copied directly
    // from the input, with only its four type bytes replaced.
    let image_header = encoded_header(header(0x30, length));
    let mut image = Vec::with_capacity(image_header.len() + length);
    image.extend_from_slice(&image_header);
    image.extend_from_slice(b"\x16\x04IMG4");
    image.extend_from_slice(&payload[..kind.start]);
    image.extend_from_slice(&tag);
    image.extend_from_slice(&payload[kind.end..]);
    image.extend_from_slice(&manifest_header);
    image.extend_from_slice(ticket);
    image.extend_from_slice(metadata);
    Ok(image)
}

fn private_property(name: &[u8; 4], value: &[u8]) -> Vec<u8> {
    let mut fields = element(0x16, name);
    fields.extend_from_slice(value);
    let sequence = element(0x30, &fields);
    let mut encoded = encoded_header(Header::new(
        Class::Private,
        true,
        Tag(u32::from_be_bytes(*name)),
        Length::Definite(sequence.len()),
    ));
    encoded.extend_from_slice(&sequence);
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
        properties.extend(private_property(tag, &slot.to_der_vec()?));
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
    let info = restore_info(tss, component, identity)?;
    personalized_image(
        component,
        payload,
        crate::tss::ticket(tss)?,
        info.as_deref().unwrap_or_default(),
    )
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
    im4p_type_range(prefix).ok().map(|range| range.start)
}

fn im4p_type_range(prefix: &[u8]) -> Result<Range<usize>> {
    let range = content_range(prefix)?;
    ensure!(prefix[0] == 0x30, "component is not a DER sequence");
    let content = &prefix[range.start..range.end.min(prefix.len())];
    let (magic, fields) = parse(content)?;
    ensure!(
        magic.tag == 0x16 && magic.content == b"IM4P",
        "component is not an IM4P payload"
    );
    let (kind, _) = parse(fields)?;
    ensure!(
        kind.tag == 0x16 && kind.content.len() == 4,
        "invalid IM4P type"
    );
    let end = range.start + magic.encoded.len() + kind.encoded.len();
    Ok(end - 4..end)
}
