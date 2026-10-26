use crate::{device::Mode, usb::RecoveryTransport};
use anyhow::{Context, Result, bail, ensure};
use std::{
    borrow::Cow,
    time::{Duration, Instant},
};

pub const BLOCK_SIZE: usize = 0x800;
const SUFFIX: [u8; 12] = [255, 255, 255, 255, 0xac, 5, 0, 1, 0x55, 0x46, 0x44, 0x10];

/// Only the reset failed: the complete image and final DFU requests were sent.
/// A boot-stage caller can check reconnection without replaying the upload.
#[derive(Debug)]
pub struct ResetFailure;

impl std::fmt::Display for ResetFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("DFU image transferred, but USB reset reported an error")
    }
}

/// DFU CRC is the uncomplemented IEEE CRC32 register, including the suffix.
pub fn crc32(data: &[u8]) -> u32 {
    !crc32fast::hash(data)
}

#[derive(Debug, PartialEq, Eq)]
pub struct Status {
    pub status: u8,
    pub poll_ms: u32,
    pub state: u8,
}
impl Status {
    pub fn parse(b: &[u8]) -> Result<Self> {
        ensure!(b.len() == 6, "DFU GETSTATUS returned {} bytes", b.len());
        let status = Self {
            status: b[0],
            poll_ms: u32::from_le_bytes([b[1], b[2], b[3], 0]),
            state: b[4],
        };
        ensure!(
            status.status == 0,
            "DFU error {} in state {}",
            status.status,
            status.state
        );
        Ok(status)
    }
}

fn status(usb: &mut impl RecoveryTransport) -> Result<Status> {
    Status::parse(&usb.control_in(0xa1, 3, 0, 0, 6)?)
}

fn wait_download(usb: &mut impl RecoveryTransport) -> Result<()> {
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let s = status(usb)?;
        if s.state == 5 {
            return Ok(());
        }
        ensure!(
            matches!(s.state, 3 | 4),
            "unexpected DFU download state {}",
            s.state
        );
        ensure!(Instant::now() < deadline, "DFU download status timed out");
        std::thread::sleep(Duration::from_millis(u64::from(s.poll_ms).clamp(1, 1000)));
    }
}

/// Match Apple's last-packet convention: a suffix-only packet can reuse the last block index.
pub fn packets(data: &[u8]) -> Result<Vec<(u16, Vec<u8>)>> {
    Ok(packet_iter(data)?
        .map(|(index, bytes)| (index, bytes.into_owned()))
        .collect())
}

// Full blocks borrow the input. Only the final block and suffix need storage.
fn packet_iter(data: &[u8]) -> Result<impl Iterator<Item = (u16, Cow<'_, [u8]>)>> {
    ensure!(!data.is_empty(), "cannot send an empty DFU image");
    let blocks = data.len().div_ceil(BLOCK_SIZE);
    ensure!(
        blocks <= u16::MAX as usize,
        "DFU image exceeds block index range"
    );
    let mut suffix = [0; 16];
    suffix[..SUFFIX.len()].copy_from_slice(&SUFFIX);
    let mut checksum = crc32fast::Hasher::new();
    checksum.update(data);
    checksum.update(&SUFFIX);
    suffix[SUFFIX.len()..].copy_from_slice(&(!checksum.finalize()).to_le_bytes());
    let index = (blocks - 1) as u16;
    let (prefix, last) = data.split_at(usize::from(index) * BLOCK_SIZE);
    let (last, continuation) = if last.len() + suffix.len() <= BLOCK_SIZE {
        let mut bytes = Vec::with_capacity(last.len() + suffix.len());
        bytes.extend_from_slice(last);
        bytes.extend_from_slice(&suffix);
        (Cow::Owned(bytes), None)
    } else {
        (
            Cow::Borrowed(last),
            Some((index, Cow::Owned(suffix.to_vec()))),
        )
    };
    Ok(prefix
        .chunks(BLOCK_SIZE)
        .enumerate()
        .map(|(i, chunk)| (i as u16, Cow::Borrowed(chunk)))
        .chain(std::iter::once((index, last)))
        .chain(continuation))
}

pub fn upload(
    usb: &mut impl RecoveryTransport,
    mode: Mode,
    data: &[u8],
    finish: bool,
) -> Result<()> {
    ensure!(!data.is_empty(), "cannot send an empty firmware image");
    let mut progress = crate::progress::Progress::new(
        if mode == Mode::Recovery {
            "Передача USB Recovery"
        } else {
            "Передача USB DFU"
        },
        Some(data.len() as u64),
        0,
    );
    if mode == Mode::Recovery {
        usb.control_out(0x41, 0, 0, 0, &[])?;
        for chunk in data.chunks(0x8000) {
            usb.bulk_out(chunk)?;
            progress.advance(chunk.len() as u64);
        }
        if data.len().is_multiple_of(512) {
            usb.bulk_out(&[])?;
        }
        progress.finish();
        return Ok(());
    }
    let state = usb.control_in(0xa1, 5, 0, 0, 1)?;
    ensure!(state.len() == 1, "invalid DFU GETSTATE reply");
    match state[0] {
        2 => {}
        10 => {
            usb.control_out(0x21, 4, 0, 0, &[])?;
            bail!("DFU error cleared; re-enter DFU before retrying");
        }
        state => bail!("expected DFU idle state 2, got {state}; re-enter DFU"),
    }
    let mut packets = packet_iter(data)?.peekable();
    let mut remaining = data.len();
    while let Some((block, bytes)) = packets.next() {
        usb.control_out(0x21, 1, block, 0, &bytes)?;
        let sent = remaining.min(bytes.len());
        progress.advance(sent as u64);
        remaining -= sent;
        // Apple sends a suffix-only continuation with the same block index.
        // GETSTATUS must follow that continuation, not separate it from the payload.
        if packets.peek().is_none_or(|next| next.0 != block) {
            wait_download(usb)?;
        }
    }
    progress.finish();
    if finish {
        usb.control_out(0x21, 1, data.len().div_ceil(BLOCK_SIZE) as u16, 0, &[])?;
        for _ in 0..2 {
            status(usb)?;
        }
        usb.reset().context(ResetFailure)?;
    }
    Ok(())
}

pub fn command(usb: &mut impl RecoveryTransport, command: &str, execute: bool) -> Result<()> {
    ensure!(
        !command.contains('\0') && command.len() < 255,
        "invalid iBoot command"
    );
    let mut bytes = command.as_bytes().to_vec();
    bytes.push(0);
    usb.control_out(0x40, u8::from(execute), 0, 0, &bytes)
        .with_context(|| format!("sending iBoot command {command:?}"))
}

pub fn getenv(usb: &mut impl RecoveryTransport, name: &str) -> Result<String> {
    ensure!(
        !name.is_empty()
            && name
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || b"-_".contains(&c)),
        "invalid iBoot environment variable name"
    );
    command(usb, &format!("getenv {name}"), false)?;
    // iBoot stalls instead of truncating when strlen(cmd-results) + 1 > wLength.
    // Persistent boot breadcrumbs can exceed the usual 255-byte getenv buffer.
    let mut bytes = usb.control_in(0xc0, 0, 0, 0, 0x1000)?;
    let end = bytes.iter().position(|b| *b == 0).unwrap_or(bytes.len());
    bytes.truncate(end);
    String::from_utf8(bytes).context("iBoot environment reply is not UTF-8")
}

/// The legacy transfer notification is best effort; bootx starts the restore kernel.
/// Its USB completion alone cannot confirm that the restore service has booted.
pub fn boot_kernel(usb: &mut impl RecoveryTransport) -> Result<()> {
    if let Err(error) = usb.control_out(0x21, 1, 0, 0, &[]) {
        crate::log!(
            Debug,
            "boot",
            "Ошибка уведомления о передаче ядра: {error:#}; отправка bootx"
        );
    }
    crate::log!(Debug, "boot", "Запуск ядра командой bootx");
    command(usb, "bootx", true)
}
