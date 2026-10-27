use super::{agent_with_body_timeout, fetch, public_roots, validate_apple_url};
use anyhow::{Context, Result, ensure};
use sha2::digest::DynDigest;
use std::{
    fs::{File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    path::Path,
    time::Duration,
};
use ureq::http::{Request, Response, StatusCode};

pub fn download(url: &str, destination: &Path, expected_sha256: &str) -> Result<()> {
    let expected = crate::device::decode_hex(expected_sha256)?;
    ensure!(
        expected.len() == 32,
        "SHA-256 must contain 64 hexadecimal digits"
    );
    download_verified(url, destination, &expected)
}

fn download_hasher(expected: &[u8]) -> Result<Box<dyn DynDigest>> {
    ensure!(
        [20, 32].contains(&expected.len()),
        "unsupported firmware checksum length"
    );
    crate::checksum::hasher(expected.len()).context("unsupported firmware checksum length")
}

pub fn verify_file(path: &Path, expected: &[u8]) -> Result<()> {
    let mut hash = download_hasher(expected)?;
    hash_file(&mut File::open(path)?, hash.as_mut())?;
    ensure!(
        hash.finalize().as_ref() == expected,
        "firmware checksum mismatch: {}",
        path.display()
    );
    Ok(())
}

fn hash_file(file: &mut File, hash: &mut dyn DynDigest) -> Result<u64> {
    let mut buffer = vec![0; 1024 * 1024];
    let mut total = 0u64;
    let mut progress =
        crate::progress::Progress::new("Проверка IPSW", Some(file.metadata()?.len()), 0);
    loop {
        let n = file.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        hash.update(&buffer[..n]);
        total += n as u64;
        progress.advance(n as u64);
    }
    progress.finish();
    Ok(total)
}

/// Apple publishes SHA-1 for catalog IPSWs; explicit downloads use SHA-256.
pub fn download_verified(url: &str, destination: &Path, expected: &[u8]) -> Result<()> {
    validate_apple_url(url)?;
    // RecvBody is a total body deadline, not an inactivity timer. A full IPSW
    // can take hours; retain connect/header deadlines without a body limit.
    let agent = agent_with_body_timeout(None, public_roots());
    download_from(destination, expected, 5, |offset| {
        fetch(firmware_request(url, offset)?, &agent)
    })
}

fn retry_download(error: &anyhow::Error, attempts: &mut u8, maximum: u8) -> bool {
    if *attempts >= maximum || !retryable_download(error) {
        return false;
    }
    let delay = 1u64 << *attempts;
    *attempts += 1;
    crate::log!(
        Warning,
        "download",
        "Загрузка прервана: {error:#}. Повтор через {delay} с; загруженные данные сохранены"
    );
    std::thread::sleep(Duration::from_secs(delay));
    true
}

pub(super) fn retryable_download(error: &anyhow::Error) -> bool {
    error.chain().any(|e| {
        e.downcast_ref::<ureq::Error>().is_some_and(|e| {
            matches!(
                e,
                ureq::Error::Io(_)
                    | ureq::Error::Timeout(_)
                    | ureq::Error::ConnectionFailed
                    | ureq::Error::HostNotFound
                    | ureq::Error::Protocol(_)
                    | ureq::Error::StatusCode(408 | 429 | 500 | 502 | 503 | 504)
            )
        }) || e.downcast_ref::<std::io::Error>().is_some_and(|e| {
            matches!(
                e.kind(),
                std::io::ErrorKind::ConnectionAborted
                    | std::io::ErrorKind::ConnectionReset
                    | std::io::ErrorKind::BrokenPipe
                    | std::io::ErrorKind::UnexpectedEof
                    | std::io::ErrorKind::TimedOut
            )
        })
    })
}

pub(super) fn firmware_request(url: &str, offset: u64) -> Result<Request<Vec<u8>>> {
    let mut request = Request::get(url).header("Accept-Encoding", "identity");
    if offset > 0 {
        request = request.header("Range", format!("bytes={offset}-"));
    }
    Ok(request.body(Vec::new())?)
}

pub(super) fn download_from(
    destination: &Path,
    expected: &[u8],
    maximum_retries: u8,
    mut request: impl FnMut(u64) -> Result<Response<ureq::Body>>,
) -> Result<()> {
    ensure!(!destination.exists(), "destination already exists");
    let mut part_name = destination.as_os_str().to_os_string();
    part_name.push(".part");
    let part = std::path::PathBuf::from(part_name);
    let directory = destination
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let mut download = PartialDownload::open(&part, expected)?;
    // A crash can leave the whole verified file under its temporary name.
    if !download.verified() {
        if download.total > 0 {
            crate::log!(
                Info,
                "download",
                "Продолжение загрузки с {} МиБ",
                download.total / 1048576
            );
        }
        let mut attempts = 0;
        let mut restarts = 0;
        loop {
            let step = match request(download.total) {
                Ok(response) => download.receive(response, directory)?,
                Err(error) => DownloadStep::Interrupted(error),
            };
            match step {
                DownloadStep::Complete => break,
                DownloadStep::More => {}
                DownloadStep::Restart => {
                    restarts += 1;
                    ensure!(
                        restarts <= 1,
                        "firmware server repeatedly rejected resume; retry the download later"
                    );
                }
                DownloadStep::Interrupted(error) => {
                    if !retry_download(&error, &mut attempts, maximum_retries) {
                        return Err(error);
                    }
                }
            }
        }
    }
    download.file.sync_all()?;
    // Hard-link publication fails if another process created the destination in the meantime.
    std::fs::hard_link(&part, destination).context("publishing verified download")?;
    std::fs::remove_file(part)?;
    Ok(())
}

enum DownloadStep {
    More,
    Restart,
    Complete,
    Interrupted(anyhow::Error),
}

/// The locked partial, byte offset and rolling checksum advance together.
struct PartialDownload<'a> {
    file: File,
    hash: Box<dyn DynDigest>,
    total: u64,
    expected: &'a [u8],
    length: Option<u64>,
}

impl<'a> PartialDownload<'a> {
    fn open(path: &Path, expected: &'a [u8]) -> Result<Self> {
        let mut hash = download_hasher(expected)?;
        match std::fs::symlink_metadata(path) {
            Ok(metadata) => ensure!(
                metadata.file_type().is_file(),
                "partial download is not a regular file"
            ),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error).context("checking .part file"),
        }
        let mut file = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(path)
            .context("opening .part file")?;
        file.try_lock()
            .map_err(|error| anyhow::anyhow!("firmware download is locked: {error}"))?;
        ensure!(
            file.metadata()?.is_file(),
            "partial download is not a regular file"
        );
        let total = hash_file(&mut file, hash.as_mut())?;
        Ok(Self {
            file,
            hash,
            total,
            expected,
            length: None,
        })
    }

    fn verified(&self) -> bool {
        self.hash.box_clone().finalize().as_ref() == self.expected
    }

    fn reset(&mut self) -> Result<()> {
        self.file.set_len(0)?;
        self.file.seek(SeekFrom::Start(0))?;
        self.hash.reset();
        self.total = 0;
        self.length = None;
        Ok(())
    }

    // Only request/body interruptions can be retried. Metadata, disk and
    // checksum errors abort without reusing an uncertain file/hash position.
    fn receive(
        &mut self,
        mut response: Response<ureq::Body>,
        directory: &Path,
    ) -> Result<DownloadStep> {
        let status = response.status();
        match status {
            StatusCode::OK | StatusCode::PARTIAL_CONTENT => {}
            StatusCode::RANGE_NOT_SATISFIABLE if self.total > 0 => {
                self.reset()?;
                return Ok(DownloadStep::Restart);
            }
            _ => {
                return Ok(DownloadStep::Interrupted(
                    ureq::Error::StatusCode(status.as_u16()).into(),
                ));
            }
        }
        ensure!(
            response
                .headers()
                .get_all("content-encoding")
                .iter()
                .all(|value| value.as_bytes().eq_ignore_ascii_case(b"identity")),
            "firmware response uses unsupported Content-Encoding"
        );
        let content_length = response
            .headers()
            .get("content-length")
            .map(|v| decimal(v.to_str()?, "Content-Length"))
            .transpose()?;
        ensure!(
            status != StatusCode::OK || !response.headers().contains_key("content-range"),
            "full firmware response contains Content-Range"
        );
        if self.total > 0 && status == StatusCode::OK {
            // Some Apple servers return 200 with the original length but only
            // the requested suffix. Restart without Range rather than consume it.
            // Validate full-response metadata before discarding a usable partial.
            self.reset()?;
            return Ok(DownloadStep::Restart);
        }
        let (expected_end, expected_length) = if status == StatusCode::PARTIAL_CONTENT {
            let range = response
                .headers()
                .get("content-range")
                .context("partial firmware response has no Content-Range")?
                .to_str()?;
            let (start, end, length) = content_range(range)?;
            ensure!(start == self.total, "firmware resume offset mismatch");
            ensure!(
                content_length.is_none_or(|n| n == end - start + 1),
                "firmware Content-Length disagrees with Content-Range"
            );
            (Some(end + 1), Some(length))
        } else {
            (content_length, content_length)
        };
        if let Some(length) = expected_length {
            ensure!(
                self.length.is_none_or(|previous| previous == length),
                "firmware total length changed during download"
            );
            self.length = Some(length);
            crate::storage::require(directory, length.saturating_sub(self.total))?;
        }
        let mut reader = response.body_mut().as_reader();
        // Coalesce TLS records into disk writes across Windows filesystem bridges.
        let mut output = std::io::BufWriter::with_capacity(4 * 1024 * 1024, &mut self.file);
        let mut buffer = vec![0; 1024 * 1024];
        let mut progress =
            crate::progress::Progress::new("Загрузка IPSW", expected_length, self.total);
        let read_error = loop {
            let n = match reader.read(&mut buffer) {
                Ok(n) => n,
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(error) => break Some(error),
            };
            if n == 0 {
                break expected_end.filter(|&end| end != self.total).map(|_| {
                    std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        "truncated firmware download",
                    )
                });
            }
            let next = self
                .total
                .checked_add(n as u64)
                .context("firmware size overflow")?;
            ensure!(
                expected_end.is_none_or(|end| next <= end),
                "firmware response exceeds its declared range"
            );
            output.write_all(&buffer[..n])?;
            self.hash.update(&buffer[..n]);
            self.total = next;
            progress.advance(n as u64);
        };
        // Persist the bytes already hashed before the outer loop retries a read.
        output.flush()?;
        drop(output);
        if let Some(error) = read_error {
            return Ok(DownloadStep::Interrupted(error.into()));
        }
        if expected_length.is_some_and(|length| self.total < length) {
            // Some distribution servers limit the size of a single range.
            return Ok(DownloadStep::More);
        }
        if !self.verified() {
            // Retain the lock while discarding corrupt bytes.
            self.reset()?;
            anyhow::bail!("firmware checksum mismatch; partial download reset");
        }
        progress.finish();
        Ok(DownloadStep::Complete)
    }
}

fn content_range(value: &str) -> Result<(u64, u64, u64)> {
    let (range, length) = value
        .strip_prefix("bytes ")
        .context("invalid Content-Range unit")?
        .split_once('/')
        .context("invalid Content-Range")?;
    let (start, end) = range
        .split_once('-')
        .context("invalid Content-Range interval")?;
    let (start, end, length) = (
        decimal(start, "Content-Range start")?,
        decimal(end, "Content-Range end")?,
        decimal(length, "Content-Range length")?,
    );
    ensure!(start <= end && end < length, "invalid Content-Range bounds");
    Ok((start, end, length))
}

fn decimal(value: &str, field: &str) -> Result<u64> {
    ensure!(
        !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()),
        "invalid firmware {field}"
    );
    value
        .parse()
        .with_context(|| format!("invalid firmware {field}"))
}
