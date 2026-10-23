//! Apple Software Restore image transfer, including validation reads and SHA-1 chunks.
use crate::wire;
use anyhow::{Context, Result, bail, ensure};
use plist::Value;
use sha1::{Digest, Sha1};
use std::{
    io::{Read, Seek, SeekFrom, Write},
    time::Instant,
};

const CHUNK: usize = 131072;
const BATCH_CHUNKS: usize = 4;

fn info(stream: &mut impl Write, length: u64, checksum: bool) -> Result<()> {
    let mut d = wire::dict([
        ("Version", 1u64.into()),
        ("Stream ID", 1u64.into()),
        ("FEC Slice Stride", 40u64.into()),
        ("Packet Payload Size", 1450u64.into()),
        ("Packets Per FEC", 25u64.into()),
        (
            "Payload",
            wire::dict([("Port", 1u64.into()), ("Size", length.into())]),
        ),
    ]);
    if checksum {
        d.as_dictionary_mut()
            .unwrap()
            .insert("Checksum Chunk Size".into(), (CHUNK as u64).into());
    }
    stream.write_all(&wire::xml(&d)?)?;
    Ok(())
}

pub fn transfer(
    stream: &mut (impl Read + Write),
    image: &mut (impl Read + Seek),
    length: u64,
) -> Result<()> {
    let initiate = wire::receive_xml(stream)?;
    ensure!(
        wire::string(&initiate, &["Command"])? == "Initiate",
        "ASR did not send Initiate"
    );
    let mut checksum = checksum_mode(&initiate, false)?;
    info(stream, length, checksum)?;
    let mut requests = 0u64;
    loop {
        let message = wire::receive_xml(stream)?;
        match wire::string(&message, &["Command"])? {
            "Initiate" => {
                checksum = checksum_mode(&message, checksum)?;
                info(stream, length, checksum)?;
            }
            "OOBData" => {
                requests += 1;
                ensure!(requests <= 100000, "too many ASR validation requests");
                let offset = wire::number(wire::get(&message, &["OOB Offset"])?)?;
                let count = wire::number(wire::get(&message, &["OOB Length"])?)?;
                ensure!(
                    count <= 64 * 1024 * 1024
                        && offset.checked_add(count).is_some_and(|end| end <= length),
                    "ASR OOB read is outside image"
                );
                image.seek(SeekFrom::Start(offset))?;
                let copied = std::io::copy(&mut image.take(count), stream)?;
                ensure!(copied == count, "truncated ASR validation data");
            }
            "Payload" => break,
            command => bail!("unsupported ASR command {command}"),
        }
    }
    image.seek(SeekFrom::Start(0))?;
    // Keep the negotiated checksum boundaries, but fill several blocks before
    // writing so USB packets can span ASR block boundaries.
    let stride = CHUNK + if checksum { 20 } else { 0 };
    let mut buf = vec![0; BATCH_CHUNKS * stride];
    let mut total = 0;
    let mut progress =
        crate::progress::Progress::new("Передача файловой системы ASR", Some(length), 0);
    let mut profile = crate::progress::TransferProfile::new("ASR");
    while total < length {
        let mut payload = 0;
        let mut sent = 0;
        for block in buf.chunks_mut(stride) {
            let n = (length - total - payload).min(CHUNK as u64) as usize;
            if n == 0 {
                break;
            }
            let started = Instant::now();
            let read = image.read_exact(&mut block[..n]);
            profile.read = Some(profile.read.unwrap_or_default() + started.elapsed());
            read.context("reading filesystem image")?;
            if checksum {
                let started = Instant::now();
                let digest = Sha1::digest(&block[..n]);
                block[n..n + 20].copy_from_slice(&digest);
                profile.prepare += started.elapsed();
                sent += n + 20;
            } else {
                sent += n;
            }
            payload += n as u64;
        }
        let started = Instant::now();
        let written = stream.write_all(&buf[..sent]);
        profile.write += started.elapsed();
        written?;
        total += payload;
        profile.bytes = total;
        progress.advance(payload);
    }
    let started = Instant::now();
    let flushed = stream.flush();
    profile.write += started.elapsed();
    flushed?;
    progress.finish();
    profile.finished = true;
    Ok(())
}

fn checksum_mode(message: &Value, previous: bool) -> Result<bool> {
    match wire::dictionary(message)?.get("Checksum Chunks") {
        Some(value) => value.as_boolean().context("invalid ASR checksum mode"),
        None => Ok(previous),
    }
}

pub fn data_port(message: &Value, default: u16) -> Result<u16> {
    let port = message.as_dictionary().and_then(|d| d.get("DataPort"));
    if let Some(v) = port {
        let port = u16::try_from(wire::number(v)?)?;
        Ok(if port == 0 { default } else { port })
    } else {
        Ok(default)
    }
}
