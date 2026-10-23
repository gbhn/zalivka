//! Property-list framing used by restored (big-endian length, then XML/binary plist).
use anyhow::{Context, Result, bail, ensure};
use plist::{Dictionary, Value};
use std::io::{Read, Write};

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
    let mut bytes = vec![0; 4];
    v.to_writer_xml(&mut bytes)?;
    send_frame(w, bytes)
}

pub fn send_binary(w: &mut impl Write, v: &Value) -> Result<()> {
    let mut bytes = Vec::new();
    append_binary(&mut bytes, v)?;
    w.write_all(&bytes)?;
    w.flush()?;
    Ok(())
}

/// Append a complete frame directly to an existing batch. Offsets inside a
/// binary plist stay relative to its own writer, not the enclosing batch.
pub(crate) fn append_binary(bytes: &mut Vec<u8>, v: &Value) -> Result<()> {
    let start = bytes.len();
    bytes.extend_from_slice(&[0; 4]);
    let result = (|| {
        v.to_writer_binary(&mut *bytes)?;
        let length = bytes.len() - start - 4;
        ensure!(length <= MAX_PLIST, "outgoing plist too large");
        bytes[start..start + 4].copy_from_slice(&(length as u32).to_be_bytes());
        Ok(())
    })();
    if result.is_err() {
        bytes.truncate(start);
    }
    result
}

fn send_frame(w: &mut impl Write, mut bytes: Vec<u8>) -> Result<()> {
    let length = bytes.len() - 4;
    ensure!(length <= MAX_PLIST, "outgoing plist too large");
    bytes[..4].copy_from_slice(&(length as u32).to_be_bytes());
    // A separate four-byte write becomes a separate USB transfer on MuxStream.
    w.write_all(&bytes)?;
    w.flush()?;
    Ok(())
}

/// A timeout is optional only when no byte of the next frame has arrived.
pub fn try_receive(r: &mut impl Read) -> Result<Option<Value>> {
    let mut prefix = [0; 4];
    let n = match r.read(&mut prefix) {
        Err(e) if e.kind() == std::io::ErrorKind::TimedOut => return Ok(None),
        result => result?,
    };
    ensure!(n > 0, "service disconnected during optional message read");
    r.read_exact(&mut prefix[n..])?;
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

/// ASR uses unframed XML. Read through the end tag without swallowing raw payload.
pub fn receive_xml(r: &mut impl Read) -> Result<Value> {
    let mut buf = Vec::new();
    let mut byte = [0];
    loop {
        r.read_exact(&mut byte)?;
        buf.push(byte[0]);
        if buf.ends_with(b"</plist>") {
            break;
        }
        ensure!(buf.len() <= MAX_PLIST, "unframed XML too large");
    }
    Value::from_reader(std::io::Cursor::new(buf)).context("decoding ASR plist")
}

pub fn dictionary(v: &Value) -> Result<&Dictionary> {
    v.as_dictionary().context("expected plist dictionary")
}

#[cfg(test)]
#[path = "../tests/unit/wire.rs"]
mod tests;
