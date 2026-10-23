use super::{agent_with_body_timeout, fetch, validate_apple_url};
use anyhow::{Context, Result, ensure};
use sha2::digest::DynDigest;
use std::{
    fs::OpenOptions,
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
    let mut file = std::fs::File::open(path)?;
    hash_partial(&mut file, hash.as_mut())?;
    ensure!(
        hash.finalize().as_ref() == expected,
        "firmware checksum mismatch: {}",
        path.display()
    );
    Ok(())
}

fn hash_partial(file: &mut std::fs::File, hash: &mut dyn DynDigest) -> Result<u64> {
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
    let agent = agent_with_body_timeout(None, ureq::tls::RootCerts::WebPki);
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
    eprintln!(
        "Download interrupted: {error:#}. Retrying in {delay}s; partial file and rolling checksum retained."
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
    let mut hash = download_hasher(expected)?;
    ensure!(!destination.exists(), "destination already exists");
    let mut part_name = destination.as_os_str().to_os_string();
    part_name.push(".part");
    let part = std::path::PathBuf::from(part_name);
    let mut file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(&part)
        .context("opening .part file")?;
    file.try_lock()
        .map_err(|error| anyhow::anyhow!("firmware download is locked: {error}"))?;
    let mut total = hash_partial(&mut file, hash.as_mut())?;
    // A crash can leave the whole verified file under its temporary name.
    let complete = hash.box_clone().finalize().as_ref() == expected;
    if total > 0 && !complete {
        eprintln!("Resuming firmware from {} MiB", total / 1048576);
    }
    if !complete {
        let mut attempts = 0;
        loop {
            let response = request(total).and_then(|response| match response.status().as_u16() {
                code @ (408 | 429 | 500 | 502 | 503 | 504) => {
                    Err(ureq::Error::StatusCode(code).into())
                }
                _ => Ok(response),
            });
            let mut response = match response {
                Ok(response) => response,
                Err(error) => {
                    if retry_download(&error, &mut attempts, maximum_retries) {
                        continue;
                    }
                    return Err(error);
                }
            };
            let content_length = response
                .headers()
                .get("content-length")
                .map(|v| -> Result<u64> { Ok(v.to_str()?.parse()?) })
                .transpose();
            if total > 0
                && matches!(
                    response.status(),
                    StatusCode::OK | StatusCode::RANGE_NOT_SATISFIABLE
                )
            {
                // Validate a full response before discarding a usable partial.
                // A 416 response is allowed to omit or invalidate this header.
                if response.status() == StatusCode::OK {
                    content_length?;
                }
                // Discard a stale partial or restart without Range when ignored.
                // The originally selected digest still applies to the entire file.
                file.set_len(0)?;
                file.seek(SeekFrom::Start(0))?;
                hash.reset();
                total = 0;
                continue;
            }
            let content_length = content_length?;
            let (expected_end, expected_length) = match response.status() {
                StatusCode::OK => (content_length, content_length),
                StatusCode::PARTIAL_CONTENT => {
                    let range = response
                        .headers()
                        .get("content-range")
                        .context("partial firmware response has no Content-Range")?
                        .to_str()?;
                    let (start, end, length) = content_range(range)?;
                    ensure!(start == total, "firmware resume offset mismatch");
                    ensure!(
                        content_length.is_none_or(|n| n == end - start + 1),
                        "firmware Content-Length disagrees with Content-Range"
                    );
                    (Some(end + 1), Some(length))
                }
                status => return Err(ureq::Error::StatusCode(status.as_u16()).into()),
            };
            if let Some(length) = expected_length {
                crate::storage::require(
                    destination
                        .parent()
                        .filter(|p| !p.as_os_str().is_empty())
                        .unwrap_or(Path::new(".")),
                    length.saturating_sub(total),
                )?;
            }
            let mut reader = response.body_mut().as_reader();
            // TLS often yields 16 KiB records. Coalesce disk writes, especially
            // on Windows-mounted filesystems where each write crosses a bridge.
            let mut output = std::io::BufWriter::with_capacity(4 * 1024 * 1024, &mut file);
            let mut buffer = vec![0; 1024 * 1024];
            let mut progress =
                crate::progress::Progress::new("Загрузка IPSW", expected_length, total);
            let read_error = loop {
                let n = match reader.read(&mut buffer) {
                    Ok(n) => n,
                    Err(error) => break Some(error),
                };
                if n == 0 {
                    break None;
                }
                let next = total
                    .checked_add(n as u64)
                    .context("firmware size overflow")?;
                ensure!(
                    expected_end.is_none_or(|end| next <= end),
                    "firmware response exceeds its declared range"
                );
                output.write_all(&buffer[..n])?;
                hash.update(&buffer[..n]);
                total = next;
                progress.advance(n as u64);
            };
            output.flush()?;
            drop(output);
            let read_error = read_error.or_else(|| {
                expected_end.filter(|&end| end != total).map(|_| {
                    std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        "truncated firmware download",
                    )
                })
            });
            if let Some(error) = read_error {
                let error = error.into();
                if retry_download(&error, &mut attempts, maximum_retries) {
                    continue;
                }
                return Err(error);
            }
            if expected_length.is_some_and(|length| total < length) {
                // Some distribution servers limit the size of a single range.
                continue;
            }
            if hash.finalize_reset().as_ref() != expected {
                // Keep the lock while discarding corrupt bytes so another process
                // cannot begin resuming a file which is about to be removed.
                file.set_len(0)?;
                anyhow::bail!("firmware checksum mismatch; partial download reset");
            }
            progress.finish();
            break;
        }
    }
    file.sync_all()?;
    // Hard-link publication fails if another process created the destination in the meantime.
    std::fs::hard_link(&part, destination).context("publishing verified download")?;
    std::fs::remove_file(part)?;
    Ok(())
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
        start.parse::<u64>()?,
        end.parse::<u64>()?,
        length.parse::<u64>()?,
    );
    ensure!(start <= end && end < length, "invalid Content-Range bounds");
    Ok((start, end, length))
}
