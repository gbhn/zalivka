//! Property-list framing used by restored (big-endian length, then XML/binary plist).
use anyhow::{Context, Result, bail, ensure};
use plist::{Dictionary, Value};
use quick_xml::{Reader, Writer, events::Event};
use std::io::{BufRead, Read, Write};

pub const MAX_PLIST: usize = 64 * 1024 * 1024;

pub fn dict(items: impl IntoIterator<Item = (impl Into<String>, Value)>) -> Value {
    Value::Dictionary(items.into_iter().map(|(k, v)| (k.into(), v)).collect())
}

pub(crate) fn copy_keys(target: &mut Dictionary, source: &Dictionary, keys: &[&str]) {
    target.extend(keys.iter().filter_map(|key| {
        source
            .get(key)
            .map(|value| ((*key).to_owned(), value.clone()))
    }));
}

pub fn get<'a>(v: &'a Value, path: &[&str]) -> Result<&'a Value> {
    path.iter().try_fold(v, |v, key| {
        v.as_dictionary()
            .and_then(|d| d.get(key))
            .with_context(|| format!("missing plist key {}", path.join(".")))
    })
}

pub fn string<'a>(v: &'a Value, path: &[&str]) -> Result<&'a str> {
    get(v, path)?.as_string().context("expected plist string")
}

/// Data requests use DataType; image key channels also accept a direct MsgType.
/// A present but malformed DataType must not fall back to another interpretation.
pub(crate) fn data_type(message: &Value) -> Result<&str> {
    let fields = dictionary(message)?;
    let name = fields
        .get("DataType")
        .map(|value| value.as_string().context("invalid DataType"))
        .transpose()?;
    let envelope = fields
        .get("MsgType")
        .map(|value| value.as_string().context("invalid MsgType"))
        .transpose()?;
    match (name, envelope) {
        (Some(name), Some("DataRequestMsg" | "AsyncDataRequestMsg") | None) => Ok(name),
        (Some(name), Some(kind)) => {
            ensure!(
                name == kind,
                "conflicting DataType {name} and MsgType {kind}"
            );
            Ok(name)
        }
        (None, Some("DataRequestMsg" | "AsyncDataRequestMsg")) => {
            bail!("data request has no DataType")
        }
        (None, Some(kind)) => Ok(kind),
        (None, None) => bail!("data request has no DataType or MsgType"),
    }
}

/// A missing or zero service port uses the caller's protocol-specific default.
pub fn data_port(message: &Value, default: u16) -> Result<u16> {
    let port = dictionary(message)?
        .get("DataPort")
        .map(|value| -> Result<u16> { Ok(u16::try_from(number(value)?)?) })
        .transpose()?;
    Ok(port.filter(|port| *port != 0).unwrap_or(default))
}

pub fn number(v: &Value) -> Result<u64> {
    if let Some(n) = v.as_unsigned_integer() {
        return Ok(n);
    }
    if let Some(s) = v.as_string() {
        return if let Some(s) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
            u64::from_str_radix(s, 16).context("invalid hexadecimal integer")
        } else {
            s.parse().context("invalid decimal integer")
        };
    }
    bail!("expected plist integer")
}

pub fn boolean(v: &Value, path: &[&str]) -> bool {
    get(v, path)
        .ok()
        .and_then(Value::as_boolean)
        .unwrap_or(false)
}

pub fn xml(v: &Value) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    v.to_writer_xml(&mut out)?;
    Ok(out)
}

pub fn send(w: &mut impl Write, v: &Value) -> Result<()> {
    let mut bytes = Vec::new();
    append_frame(&mut bytes, |out| v.to_writer_xml(out), u32::to_be_bytes)?;
    send_frame(w, &bytes)
}

pub fn send_binary(w: &mut impl Write, v: &Value) -> Result<()> {
    let mut bytes = Vec::new();
    append_binary(&mut bytes, v)?;
    send_frame(w, &bytes)
}

/// FDR uses the same binary plist body with a little-endian frame length.
pub(crate) fn send_binary_le(w: &mut impl Write, v: &Value) -> Result<()> {
    let mut bytes = Vec::new();
    append_frame(&mut bytes, |out| v.to_writer_binary(out), u32::to_le_bytes)?;
    send_frame(w, &bytes)
}

/// Append a complete frame directly to an existing batch. Offsets inside a
/// binary plist stay relative to its own writer, not the enclosing batch.
pub(crate) fn append_binary(bytes: &mut Vec<u8>, v: &impl serde::Serialize) -> Result<()> {
    append_frame(
        bytes,
        |out| plist::to_writer_binary(out, v),
        u32::to_be_bytes,
    )
}

fn append_frame(
    bytes: &mut Vec<u8>,
    encode: impl FnOnce(&mut Vec<u8>) -> std::result::Result<(), plist::Error>,
    length_prefix: fn(u32) -> [u8; 4],
) -> Result<()> {
    let start = bytes.len();
    bytes.extend_from_slice(&[0; 4]);
    let result = (|| {
        encode(bytes)?;
        let length = bytes.len() - start - 4;
        ensure!(length <= MAX_PLIST, "outgoing plist too large");
        bytes[start..start + 4].copy_from_slice(&length_prefix(length as u32));
        Ok(())
    })();
    if result.is_err() {
        bytes.truncate(start);
    }
    result
}

fn send_frame(w: &mut impl Write, bytes: &[u8]) -> Result<()> {
    // A separate four-byte write becomes a separate USB transfer on MuxStream.
    w.write_all(bytes)?;
    w.flush()?;
    Ok(())
}

/// A timeout is optional only when no byte of the next frame has arrived.
pub fn try_receive(r: &mut impl Read) -> Result<Option<Value>> {
    let mut prefix = [0; 4];
    match r.read_exact(&mut prefix[..1]) {
        Err(e) if e.kind() == std::io::ErrorKind::TimedOut => return Ok(None),
        result => result.context("service disconnected during optional message read")?,
    };
    r.read_exact(&mut prefix[1..])?;
    receive_body(r, u32::from_be_bytes(prefix)).map(Some)
}

pub fn receive(r: &mut impl Read) -> Result<Value> {
    let mut len = [0; 4];
    r.read_exact(&mut len).context("reading plist length")?;
    receive_body(r, u32::from_be_bytes(len))
}

pub(crate) fn receive_body(r: &mut impl Read, len: u32) -> Result<Value> {
    let len = len as usize;
    ensure!(
        (1..=MAX_PLIST).contains(&len),
        "invalid plist frame length {len}"
    );
    let mut buf = vec![0; len];
    r.read_exact(&mut buf).context("reading plist body")?;
    Value::from_reader(std::io::Cursor::new(buf)).context("decoding plist")
}

/// ASR uses unframed XML. Keep the caller's buffer across messages so read-ahead
/// remains available for the next plist or raw payload.
pub fn receive_xml(r: &mut impl BufRead) -> Result<Value> {
    let mut reader = Reader::from_reader(r.take(MAX_PLIST as u64));
    let mut writer = Writer::new(Vec::new());
    let mut buffer = Vec::new();
    let mut depth = 0usize;
    loop {
        let event = reader
            .read_event_into(&mut buffer)
            .context("reading ASR XML")?;
        match &event {
            Event::Start(tag) => {
                ensure!(
                    depth != 0 || tag.name().as_ref() == "plist",
                    "ASR XML root is not plist"
                );
                depth += 1;
            }
            Event::End(_) => {
                depth = depth
                    .checked_sub(1)
                    .context("unexpected ASR XML closing tag")?;
            }
            Event::Empty(tag) if depth == 0 => {
                ensure!(tag.name().as_ref() == "plist", "ASR XML root is not plist");
            }
            Event::Eof => bail!("truncated ASR XML or message exceeds {MAX_PLIST} bytes"),
            _ => {}
        }
        let finished = depth == 0 && matches!(event, Event::End(_) | Event::Empty(_));
        writer.write_event(event)?;
        if finished {
            return Value::from_reader_xml(writer.into_inner().as_slice())
                .context("decoding ASR plist");
        }
        buffer.clear();
    }
}

pub fn dictionary(v: &Value) -> Result<&Dictionary> {
    v.as_dictionary().context("expected plist dictionary")
}

#[cfg(test)]
#[path = "../tests/unit/wire.rs"]
mod tests;
