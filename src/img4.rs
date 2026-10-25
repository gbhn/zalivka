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

pub fn personalize(payload: &[u8], ticket: &[u8]) -> Result<Vec<u8>> {
    personalized_image(None, payload, ticket, &[])
}

fn personalized_image(
    tag: Option<[u8; 4]>,
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
    let tag = tag.unwrap_or(payload[kind.clone()].try_into()?);
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

fn manifest_property<'a>(mut fields: &'a [u8], name: &[u8; 4]) -> Result<Option<Der<'a>>> {
    let mut found = None;
    while !fields.is_empty() {
        let (rest, property) = asn1_rs::Any::from_der(fields)
            .map_err(|error| anyhow::anyhow!("invalid IMG4 manifest property: {error}"))?;
        if property.class() == Class::Private && property.tag().0 == u32::from_be_bytes(*name) {
            ensure!(found.is_none(), "duplicate IMG4 manifest property {name:?}");
            ensure!(
                property.header.constructed(),
                "invalid IMG4 manifest property tag"
            );
            let mut header = Vec::new();
            property.header.write_der_header(&mut header)?;
            ensure!(
                fields.starts_with(&header),
                "noncanonical IMG4 manifest property"
            );
            let (sequence, trailing) = parse(property.data)?;
            ensure!(
                sequence.tag == 0x30 && trailing.is_empty(),
                "invalid IMG4 manifest property sequence"
            );
            let (key, value) = parse(sequence.content)?;
            ensure!(
                key.tag == 0x16 && key.content == name,
                "IMG4 manifest property name mismatch"
            );
            let (value, trailing) = parse(value)?;
            ensure!(trailing.is_empty(), "trailing IMG4 manifest property data");
            found = Some(value);
        }
        fields = rest;
    }
    Ok(found)
}

/// Inspect an IM4M data property. Signature authentication remains with the device.
pub(crate) fn manifest_data<'a>(
    ticket: &'a [u8],
    object: &[u8; 4],
    key: &[u8; 4],
) -> Result<Option<&'a [u8]>> {
    let (sequence, trailing) = parse(ticket)?;
    ensure!(
        sequence.tag == 0x30 && trailing.is_empty(),
        "invalid IM4M sequence"
    );
    let (magic, rest) = parse(sequence.content)?;
    ensure!(
        magic.tag == 0x16 && magic.content == b"IM4M",
        "ticket is not IM4M"
    );
    let (version, rest) = parse(rest)?;
    ensure!(version.tag == 0x02, "invalid IM4M version");
    let (body, _) = parse(rest)?;
    ensure!(body.tag == 0x31, "invalid IM4M body");
    let Some(body) = manifest_property(body.content, b"MANB")? else {
        return Ok(None);
    };
    ensure!(body.tag == 0x31, "invalid IM4M MANB");
    let Some(object) = manifest_property(body.content, object)? else {
        return Ok(None);
    };
    ensure!(object.tag == 0x31, "invalid IM4M object");
    let Some(value) = manifest_property(object.content, key)? else {
        return Ok(None);
    };
    ensure!(value.tag == 0x04, "IMG4 manifest property is not data");
    Ok(Some(value.content))
}

pub(crate) fn nonce_slot(
    identity: &plist::Value,
    payload_type: Option<[u8; 4]>,
) -> Result<Option<([u8; 4], u64)>> {
    use crate::wire;
    if wire::optional_boolean(identity, &["Info", "RequiresNonceSlot"])?.unwrap_or(false)
        && matches!(payload_type, Some(tag) if tag == *b"illb" || tag == *b"sepi")
    {
        let (tag, key) = if payload_type == Some(*b"illb") {
            (b"anid", "ApNonceSlotID")
        } else {
            (b"snid", "SepNonceSlotID")
        };
        let slot = wire::number(
            wire::get(identity, &["Info", key])
                .with_context(|| format!("strict restore requires explicit {key}"))?,
        )?;
        return Ok(Some((*tag, slot)));
    }
    Ok(None)
}

pub fn restore_info(
    tss: &plist::Value,
    component: &str,
    identity: &plist::Value,
    payload_type: Option<[u8; 4]>,
) -> Result<Option<Vec<u8>>> {
    use crate::wire;
    let mut properties = Vec::new();
    if let Some((tag, slot)) = nonce_slot(identity, payload_type)? {
        properties.extend(private_property(&tag, &slot.to_der_vec()?));
    }
    if let Some(tbm) = wire::optional(tss, &[&format!("{component}-TBM")])? {
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
    let manifest = crate::wire::dictionary(identity)?
        .get("Manifest")
        .map(crate::wire::dictionary)
        .transpose()?;
    let tag = component_tag(
        component,
        manifest.and_then(|manifest| manifest.get(component)),
    )?
    .or_else(|| payload_type(payload))
    .with_context(|| format!("cannot resolve IMG4 payload type for {component}: no manifest override or valid IM4P header"))?;
    let info = restore_info(tss, component, identity, Some(tag))?;
    personalized_image(
        Some(tag),
        payload,
        crate::tss::ticket(tss)?,
        info.as_deref().unwrap_or_default(),
    )
}

/// An optional manifest override; missing types can be read from the IM4P file.
pub(crate) fn component_tag(
    component: &str,
    entry: Option<&plist::Value>,
) -> Result<Option<[u8; 4]>> {
    let info = entry
        .map(crate::wire::dictionary)
        .transpose()?
        .and_then(|entry| entry.get("Info"))
        .map(crate::wire::dictionary)
        .transpose()?;
    let Some(tag) = info.and_then(|info| info.get("Img4PayloadType")) else {
        return Ok(None);
    };
    let tag = tag
        .as_string()
        .filter(|tag| tag.len() == 4 && tag.is_ascii())
        .with_context(|| {
            format!("invalid {component} Info.Img4PayloadType: expected four ASCII bytes")
        })?;
    Ok(Some(tag.as_bytes().try_into()?))
}

/// Read the encoded IM4P type without requiring the payload body in memory.
pub fn payload_type(prefix: &[u8]) -> Option<[u8; 4]> {
    let offset = type_offset(prefix)?;
    prefix.get(offset..offset + 4)?.try_into().ok()
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
        kind.tag == 0x16 && kind.content.len() == 4 && kind.content.is_ascii(),
        "invalid IM4P type"
    );
    let end = range.start + magic.encoded.len() + kind.encoded.len();
    Ok(end - 4..end)
}
