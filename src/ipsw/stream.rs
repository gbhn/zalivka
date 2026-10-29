//! Bounded image cursors and read-ahead for compressed ZIP entries.
use anyhow::{Context, Result, ensure};
use std::{
    fs::File,
    io::{BufReader, Read, Seek, SeekFrom, Write},
    sync::mpsc,
    thread,
};

pub(super) const STREAM_CHUNK: usize = 256 * 1024;

/// Overlap decompression with writes. The queue, reader and writer hold at most
/// three blocks; the output stays on the calling thread for mux/AEA exchanges.
pub(super) fn copy_prefetched(mut input: impl Read + Send, out: &mut impl Write) -> Result<u64> {
    thread::scope(|scope| {
        let (sender, receiver) = mpsc::sync_channel(1);
        let reader = thread::Builder::new()
            .name("ipsw-read-ahead".into())
            .spawn_scoped(
                scope,
                crate::progress::inherit(move || -> std::io::Result<u64> {
                    let mut total = 0;
                    loop {
                        crate::progress::check_cancelled()?;
                        let mut block = vec![0; STREAM_CHUNK];
                        let mut filled = 0;
                        while filled < block.len() {
                            crate::progress::check_cancelled()?;
                            match input.read(&mut block[filled..]) {
                                Ok(0) => break,
                                Ok(n) => filled += n,
                                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {
                                    continue;
                                }
                                Err(error) => return Err(error),
                            }
                        }
                        if filled == 0 {
                            return Ok(total);
                        }
                        block.truncate(filled);
                        total += filled as u64;
                        sender.send(block).map_err(|_| {
                            std::io::Error::new(
                                std::io::ErrorKind::BrokenPipe,
                                "IPSW stream consumer closed",
                            )
                        })?;
                    }
                }),
            )
            .context("starting IPSW reader")?;
        let written: std::io::Result<()> = (|| {
            for block in &receiver {
                out.write_all(&block)?;
            }
            Ok(())
        })();
        // Unblock a reader waiting on a full queue before joining after an
        // output failure. Preserve that original failure over queue closure.
        drop(receiver);
        let read = reader
            .join()
            .map_err(|_| anyhow::anyhow!("IPSW reader panicked"));
        written?;
        // EOF (including ZIP CRC validation) must succeed before the caller
        // can signal FileDataDone, even if every payload block was written.
        Ok(read??)
    })
}

pub struct ImageReader {
    file: File,
    start: u64,
    size: u64,
    position: u64,
    expected_crc: u32,
    crc: Option<crc32fast::Hasher>,
}
impl ImageReader {
    pub(super) fn new(mut file: File, start: u64, size: u64, expected_crc: u32) -> Result<Self> {
        let backing_size = file.metadata()?.len();
        ensure!(
            start
                .checked_add(size)
                .is_some_and(|end| end <= backing_size),
            "filesystem image extends beyond its backing file"
        );
        file.seek(SeekFrom::Start(start))?;
        Ok(Self {
            file,
            start,
            size,
            position: 0,
            expected_crc,
            crc: Some(crc32fast::Hasher::new()),
        })
    }

    pub(super) fn copy_to(self, out: &mut impl Write) -> Result<u64> {
        // FileData consumes 8-KiB frames; keep filesystem reads much larger,
        // especially when the archive lives across the Windows filesystem bridge.
        Ok(std::io::copy(
            &mut BufReader::with_capacity(STREAM_CHUNK, self),
            out,
        )?)
    }

    pub fn size(&self) -> u64 {
        self.size
    }
}
impl Read for ImageReader {
    fn read(&mut self, b: &mut [u8]) -> std::io::Result<usize> {
        let limit = b
            .len()
            .min((self.size - self.position).min(usize::MAX as u64) as usize);
        let n = self.file.read(&mut b[..limit])?;
        if n == 0 && limit != 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "truncated filesystem image",
            ));
        }
        self.position += n as u64;
        if let Some(crc) = &mut self.crc {
            crc.update(&b[..n]);
            if self.position == self.size && crc.clone().finalize() != self.expected_crc {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "filesystem image CRC mismatch",
                ));
            }
        }
        Ok(n)
    }
}
impl Seek for ImageReader {
    fn seek(&mut self, from: SeekFrom) -> std::io::Result<u64> {
        let n = match from {
            SeekFrom::Start(n) => i128::from(n),
            SeekFrom::Current(n) => i128::from(self.position) + i128::from(n),
            SeekFrom::End(n) => i128::from(self.size) + i128::from(n),
        };
        if n < 0 || n > i128::from(self.size) {
            return Err(std::io::Error::other("image seek out of bounds"));
        }
        self.file.seek(SeekFrom::Start(self.start + n as u64))?;
        if n == 0 {
            self.crc = Some(crc32fast::Hasher::new());
        } else if n as u64 != self.position {
            self.crc = None;
        }
        self.position = n as u64;
        Ok(self.position)
    }
}
