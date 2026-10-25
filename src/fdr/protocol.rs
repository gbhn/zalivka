//! FDR v1/v2 framing, handshakes and endpoint validation.
use crate::{
    mux::{MuxStream, Session},
    wire,
};
use anyhow::{Context, Result, ensure};
use plist::Value;
use std::{
    io::{Read, Write},
    sync::atomic::{AtomicBool, Ordering},
    time::Duration,
};

pub(super) fn control_handshake(session: &Session, version: u8) -> Result<(MuxStream, u16)> {
    let mut control = session.connect(1082).context("connecting FDR control")?;
    control.set_read_timeout(Duration::from_secs(20));
    let port = if version == 2 {
        control.write_all(b"BeginCtrl\0")?;
        wire::send_binary_le(
            &mut control,
            &wire::dict([
                ("Command", "BeginCtrl".into()),
                ("CtrlProtoVersion", 2u64.into()),
            ]),
        )?;
        let response = receive(&mut control)?;
        u16::try_from(wire::number(wire::get(&response, &["ConnPort"])?)?)?
    } else {
        control.write_all(b"HelloCtrl\0")?;
        // FDR v1 echoes the NUL-terminated command, then the little-endian port.
        // Do not guess from the low port byte: zero is valid there.
        let mut echo = [0; 10];
        control.read_exact(&mut echo)?;
        ensure!(&echo == b"HelloCtrl\0", "invalid FDR v1 control handshake");
        let mut port = [0; 2];
        control.read_exact(&mut port)?;
        u16::from_le_bytes(port)
    };
    ensure!(port != 0, "FDR returned zero connection port");
    control.set_read_timeout(Duration::from_secs(1));
    Ok((control, port))
}

/// Idle FDR channels are normal during long ASR transfers. Preserve a partial
/// command across timeouts. EOF between commands ends this channel; a truncated
/// command remains an error. A cancelled session must also be able to shut down.
pub(super) fn read_exact_idle(
    input: &mut impl Read,
    buffer: &mut [u8],
    stop: &AtomicBool,
) -> std::io::Result<bool> {
    let mut done = 0;
    while done < buffer.len() {
        if stop.load(Ordering::Relaxed) {
            return Ok(false);
        }
        match input.read(&mut buffer[done..]) {
            Ok(0) if done == 0 => return Ok(false),
            Ok(0) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "FDR channel closed within a command",
                ));
            }
            Ok(n) => done += n,
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::TimedOut | std::io::ErrorKind::Interrupted
                ) => {}
            Err(e) => return Err(e),
        }
    }
    Ok(true)
}

pub(super) fn connection_handshake(connection: &mut MuxStream, version: u8) -> Result<()> {
    if version == 2 {
        let hello = receive(connection)?;
        ensure!(
            wire::string(&hello, &["Command"])? == "HelloConn",
            "invalid FDR connection handshake"
        );
    } else {
        let mut hello = [0; 10];
        connection.read_exact(&mut hello)?;
        ensure!(
            &hello == b"HelloConn\0",
            "invalid FDR v1 connection handshake"
        );
    }
    Ok(())
}
fn receive(input: &mut impl Read) -> Result<Value> {
    let mut length = [0; 4];
    input.read_exact(&mut length)?;
    wire::receive_body(input, u32::from_le_bytes(length))
}
pub(super) fn ping(stream: &mut (impl Read + Write)) -> Result<()> {
    let command = receive(stream)?;
    ensure!(
        wire::string(&command, &["Command"])? == "Ping",
        "unsupported FDR plist command"
    );
    wire::send_binary_le(stream, &wire::dict([("Pong", true.into())]))
}

/// The 05 01 command can begin either a SOCKS greeting (05 01 00) or
/// CONNECT (05 01 00 03 ...). Acknowledge the single zero byte first:
/// the greeting's sender waits for 05 00 before sending CONNECT. Parse
/// bytes rather than relying on USB packet boundaries to tell them apart.
pub(super) fn proxy_handshake(stream: &mut (impl Read + Write)) -> Result<(String, u16)> {
    let mut zero = [0];
    stream
        .read_exact(&mut zero)
        .context("reading FDR proxy method")?;
    ensure!(zero == [0], "unsupported FDR proxy method");
    stream.write_all(&[5, 0])?;

    let mut address_type = [0; 2];
    stream
        .read_exact(&mut address_type)
        .context("reading FDR proxy address type or CONNECT")?;
    if address_type == [5, 1] {
        // The first command was a greeting; this is the actual CONNECT.
        stream
            .read_exact(&mut zero)
            .context("reading FDR proxy CONNECT reserved byte")?;
        ensure!(zero == [0], "unsupported FDR proxy CONNECT reserved byte");
        stream.write_all(&[5, 0])?;
        stream
            .read_exact(&mut address_type)
            .context("reading FDR proxy address type")?;
    }
    ensure!(
        address_type[0] == 3 && address_type[1] > 0,
        "unsupported FDR proxy address format"
    );
    let mut address = vec![0; address_type[1] as usize + 2];
    stream
        .read_exact(&mut address)
        .context("reading FDR proxy address")?;
    let n = address.len();
    let host = std::str::from_utf8(&address[..n - 2])?.trim_end_matches('\0');
    let port = u16::from_be_bytes(address[n - 2..].try_into()?);
    validate_proxy_target(host, port)?;
    stream.write_all(&[0, address_type[0], address_type[1]])?;
    stream.write_all(&address)?;
    crate::log!(Debug, "fdr", "Запрос CONNECT к {host}:{port} принят");
    Ok((host.into(), port))
}

pub fn validate_proxy_target(host: &str, port: u16) -> Result<()> {
    ensure!(
        matches!(port, 80 | 443),
        "unsupported FDR endpoint port {port}"
    );
    let host = host.to_ascii_lowercase();
    ensure!(
        crate::net::is_apple_host(&host),
        "FDR requested a non-Apple endpoint"
    );
    ensure!(
        host.bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'.' || c == b'-'),
        "invalid FDR hostname"
    );
    Ok(())
}

#[cfg(test)]
#[path = "../../tests/unit/fdr/protocol.rs"]
mod tests;
