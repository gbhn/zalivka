//! Native operations shared by the terminal and desktop interface.
use crate::{
    catalog, drivers,
    ipsw::{Behavior, Ipsw, Verification},
    net, progress, restore, usb,
};
use anyhow::{Result, ensure};
use std::path::{Path, PathBuf};

#[derive(Clone, Debug, clap::Args)]
#[group(skip)]
pub struct Restore {
    /// Local IPSW; omitted to automatically download the current compatible image.
    pub ipsw: Option<PathBuf>,
    /// Firmware cache for automatic downloads.
    #[arg(long, conflicts_with = "ipsw")]
    pub firmware_dir: Option<PathBuf>,
    #[arg(skip)]
    pub release: Option<catalog::Release>,
    #[arg(long, value_parser = crate::device::parse_ecid)]
    pub ecid: u64,
    #[arg(long)]
    pub identity: Option<usize>,
    /// Record restored's plist messages as JSON lines (new file only).
    #[arg(long)]
    pub transcript: Option<PathBuf>,
    /// Apple host-to-bearer-token plist for WKMS authorization.
    #[arg(long)]
    pub authorization_tokens: Option<PathBuf>,
    /// Raw DAWTKN data obtained from an authorized AppleConnect session.
    #[arg(long)]
    pub apple_connect_data: Option<PathBuf>,
}

impl Restore {
    pub fn run(self, behavior: Behavior) -> Result<()> {
        drivers::check_host()?;
        let assets = net::AssetClient::from_files(
            self.authorization_tokens.as_deref(),
            self.apple_connect_data.as_deref(),
        )?;
        let ipsw = if let Some(path) = self.ipsw {
            Ipsw::open(&path)?
        } else {
            let device = usb::RecoveryUsb::open(self.ecid)?.info;
            ensure!(device.mode.can_restore(), "enter DFU before restoring");
            let directory = self
                .firmware_dir
                .map_or_else(catalog::cache_directory, Ok)?;
            catalog::obtain(
                &device,
                &directory,
                self.identity,
                behavior,
                self.release.as_ref(),
            )?
        };
        restore::run(
            ipsw,
            self.ecid,
            self.identity,
            self.transcript.as_deref(),
            behavior,
            assets,
        )?;
        crate::log!(Info, "restore", "Restore complete");
        progress::Event::RestoreCompleted.emit();
        Ok(())
    }
}

pub fn verify(path: &Path, checksum: Option<&str>) -> Result<Verification> {
    crate::log!(Info, "ipsw", "Verifying archive: {}", path.display());
    if let Some(checksum) = checksum {
        net::verify_file(path, &crate::device::decode_hex(checksum)?)?;
    }
    let mut report = Ipsw::open(path)?.verify_all()?;
    report.archive_checksum_verified = checksum.is_some();
    crate::log!(
        Info,
        "ipsw",
        "Verified files: {}; manifest digests: {}",
        report.entries,
        report.manifest_digests
    );
    if !report.aea_content_digests_not_checked.is_empty() {
        crate::log!(
            Warning,
            "ipsw",
            "AEA content digests not checked: {}",
            report.aea_content_digests_not_checked.len()
        );
    }
    Ok(report)
}

pub fn fetch(
    ecid: u64,
    directory: Option<&Path>,
    release: Option<&catalog::Release>,
) -> Result<PathBuf> {
    let device = usb::RecoveryUsb::open(ecid)?.info;
    let directory = directory
        .map(Path::to_path_buf)
        .map_or_else(catalog::cache_directory, Ok)?;
    let ipsw = catalog::obtain(&device, &directory, None, Behavior::Erase, release)?;
    let path = ipsw.path().to_path_buf();
    crate::log!(Info, "firmware", "Saved: {}", path.display());
    Ok(path)
}

pub fn doctor() -> Result<Vec<drivers::UsbDiagnostic>> {
    if let Some(host) = drivers::host_status()? {
        crate::log!(Debug, "drivers:status", "{}", serde_json::to_string(&host)?);
        crate::log!(
            Info,
            "drivers",
            "Apple USB driver: {}; Apple KIS/RSM drivers: {}; Apple service running: {}",
            host.apple_driver_installed,
            host.apple_kis_driver_installed,
            host.apple_service_running
        );
        if let Some(reason) = host.blocking_reason() {
            crate::log!(Warning, "drivers", "{reason}");
        }
    }
    let devices = drivers::doctor()?;
    if devices.is_empty() {
        crate::log!(Info, "usb", "No Apple DFU or Recovery devices found");
    }
    for device in &devices {
        if device.accessible {
            crate::log!(Info, "usb", "{}: accessible", device.product_id);
        } else {
            crate::log!(
                Warning,
                "usb",
                "{}: {}",
                device.product_id,
                device.error.as_deref().unwrap_or("unavailable")
            );
        }
    }
    Ok(devices)
}
