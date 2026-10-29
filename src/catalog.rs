//! Apple's IPSW catalogs contain the model lookup and latest restore URL/hash.
use crate::{
    device::{DeviceInfo, Mode, decode_hex},
    ipsw::{Behavior, Ipsw},
    net, wire,
};
use anyhow::{Context, Result, ensure};
use plist::Value;
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};

pub const MACOS_CATALOG: &str =
    "https://mesu.apple.com/assets/macos/com_apple_macOSIPSW/com_apple_macOSIPSW.xml";
pub const BRIDGEOS_CATALOG: &str =
    "https://mesu.apple.com/assets/bridgeos/com_apple_bridgeOSIPSW/com_apple_bridgeOSIPSW.xml";
const MAX_CATALOG: u64 = 8 * 1024 * 1024;

fn valid_build_identifier(build: &str) -> bool {
    !build.is_empty() && build.len() <= 64 && build.bytes().all(|c| c.is_ascii_alphanumeric())
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Release {
    pub product_type: String,
    pub version: String,
    pub build: String,
    pub url: String,
    pub sha1: [u8; 20],
}

fn model_key(device: &DeviceInfo) -> Result<String> {
    ensure!(
        device.chip_id <= 0xffff && device.board_id <= 0xff,
        "hardware identifiers exceed the Apple catalog lookup format"
    );
    Ok(((u64::from(device.board_id) << 24) | u64::from(device.chip_id)).to_string())
}

fn product_type<'a>(catalog: &'a Value, device: &DeviceInfo) -> Result<Option<&'a str>> {
    let key = model_key(device)?;
    let mode = match device.mode {
        Mode::Dfu => "DFU",
        Mode::Recovery => "Recovery",
    };
    let types = wire::dictionary(wire::get(catalog, &["MobileDeviceProductTypes"])?)?;
    let Some(types) = types.get(mode) else {
        return Ok(None);
    };
    wire::dictionary(types)?
        .get(&key)
        .map(|value| {
            value
                .as_string()
                .filter(|value| !value.is_empty())
                .context("invalid catalog product type")
        })
        .transpose()
}

pub fn resolve(catalog: &Value, device: &DeviceInfo) -> Result<Release> {
    let product_type = product_type(catalog, device)?
        .context("Apple catalog has no model for the supplied hardware and mode")?;
    resolve_product(catalog, product_type)
}

fn resolve_product(catalog: &Value, product_type: &str) -> Result<Release> {
    let versions = wire::dictionary(wire::get(
        catalog,
        &["MobileDeviceSoftwareVersionsByVersion"],
    )?)?;
    let mut schemas = BTreeMap::new();
    for (version, value) in versions {
        let version = version
            .parse::<u64>()
            .context("invalid Apple catalog schema version")?;
        if let Some(previous) = schemas.insert(version, value) {
            ensure!(
                previous == value,
                "conflicting Apple catalog schema version {version}"
            );
        }
    }
    let mut selected = None;
    for value in schemas.values() {
        if let Some(release) =
            wire::optional(value, &["MobileDeviceSoftwareVersions", product_type])?
        {
            selected = Some(release);
        }
    }
    let release = selected.context("Apple catalog has no firmware releases for this model")?;
    let restore = wire::get(release, &["Unknown", "Universal", "Restore"])
        .context("Apple catalog has no current universal restore for this model")?;
    let url = wire::string(restore, &["FirmwareURL"])?;
    let uri = net::apple_url(url)?;
    ensure!(
        uri.path().ends_with(".ipsw"),
        "catalog restore URL is not an IPSW"
    );
    let sha1 = decode_hex(wire::string(restore, &["FirmwareSHA1"])?)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("Apple catalog SHA-1 must contain 40 hexadecimal digits"))?;
    let build = wire::string(restore, &["BuildVersion"])?;
    ensure!(
        valid_build_identifier(build),
        "invalid Apple catalog build identifier"
    );
    let version = wire::string(restore, &["ProductVersion"])?;
    ensure!(
        !version.is_empty(),
        "Apple catalog has an empty product version"
    );
    Ok(Release {
        product_type: product_type.into(),
        version: version.into(),
        build: build.into(),
        url: url.into(),
        sha1,
    })
}

pub fn latest(device: &DeviceInfo) -> Result<Release> {
    latest_with(device, |url| {
        let mut response = net::get(url).context("downloading Apple IPSW catalog")?;
        let bytes = crate::storage::read_limited(
            response.body_mut().as_reader(),
            MAX_CATALOG,
            "Apple IPSW catalog exceeds size limit",
        )?;
        wire::decode_plist(&bytes).context("decoding Apple IPSW catalog")
    })
}

fn latest_with(
    device: &DeviceInfo,
    mut load: impl FnMut(&str) -> Result<Value>,
) -> Result<Release> {
    let mut selected = None;
    let mut errors = Vec::new();
    for url in [MACOS_CATALOG, BRIDGEOS_CATALOG] {
        let loaded = load(url).and_then(|catalog| {
            product_type(&catalog, device)?
                .map(|product| resolve_product(&catalog, product))
                .transpose()
        });
        match loaded {
            Ok(Some(release)) => {
                ensure!(
                    selected
                        .as_ref()
                        .is_none_or(|previous| previous == &release),
                    "Apple catalogs contain conflicting firmware releases for this hardware; select an IPSW explicitly"
                );
                selected = Some(release);
            }
            Ok(None) => {}
            Err(error) => {
                crate::log!(Warning, "firmware", "Catalog {url}: {error:#}");
                errors.push(format!("{url}: {error:#}"));
            }
        }
    }
    let result = selected.context("Apple catalogs have no firmware for this hardware");
    if errors.is_empty() {
        result
    } else {
        result.with_context(|| format!("unavailable Apple catalogs: {}", errors.join("; ")))
    }
}

pub fn cache_directory() -> Result<PathBuf> {
    Ok(crate::storage::app_directory()?.join("firmware"))
}

pub fn obtain(
    device: &DeviceInfo,
    directory: &Path,
    identity: Option<usize>,
    behavior: Behavior,
    release: Option<&Release>,
) -> Result<Ipsw> {
    crate::log!(
        Info,
        "firmware",
        "Searching: CPID={:04x}, BDID={:02x}",
        device.chip_id,
        device.board_id
    );
    let release = release.cloned().map_or_else(|| latest(device), Ok)?;
    crate::log!(
        Info,
        "firmware",
        "Selected {}: {} ({})",
        release.product_type,
        release.version,
        release.build
    );
    ensure_cached(&release, device, directory, identity, behavior)
}

pub fn ensure_cached(
    release: &Release,
    device: &DeviceInfo,
    directory: &Path,
    identity: Option<usize>,
    behavior: Behavior,
) -> Result<Ipsw> {
    net::validate_apple_url(&release.url)?;
    ensure!(
        valid_build_identifier(&release.build),
        "invalid firmware build identifier"
    );
    std::fs::create_dir_all(directory).context("creating firmware cache")?;
    // Universal images are shared across models. The checksum also keeps a
    // changed catalog entry from replacing another cached image.
    let path = directory.join(format!(
        "{}-{}.ipsw",
        release.build,
        hex::encode(release.sha1)
    ));
    if path.exists() {
        crate::log!(Info, "firmware", "Checking cache: {}", path.display());
        net::verify_file(&path, &release.sha1).with_context(|| {
            format!(
                "cached IPSW is corrupt; remove {} to download it again",
                path.display()
            )
        })?;
    } else {
        crate::log!(Info, "firmware", "Downloading firmware: {}", path.display());
        net::download_verified(&release.url, &path, &release.sha1)?;
    }
    let ipsw = Ipsw::open(&path)?;
    ipsw.select_behavior(device, identity, behavior)?;
    ensure!(
        wire::get(&ipsw.manifest, &["SupportedProductTypes"])?
            .as_array()
            .is_some_and(|types| types
                .iter()
                .any(|value| value.as_string() == Some(release.product_type.as_str()))),
        "downloaded IPSW does not support the catalog's selected model"
    );
    ensure!(
        wire::string(&ipsw.manifest, &["ProductVersion"])? == release.version
            && wire::string(&ipsw.manifest, &["ProductBuildVersion"])? == release.build,
        "downloaded IPSW version/build differs from Apple's catalog"
    );
    Ok(ipsw)
}

#[cfg(test)]
#[path = "../tests/unit/catalog.rs"]
mod tests;
