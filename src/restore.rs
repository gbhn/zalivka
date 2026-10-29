//! Firmware preparation and shared context for the restore service.
mod attestation;
mod boot;
mod connection;
mod data;
mod data_type;
mod events;
mod file_data;
mod images;
mod keys;
mod options;
mod recovery;
mod requests;
mod session;

pub use boot::{IBootStep, probe_boot_state};
pub use connection::query_value;
pub use images::cpio_header;
pub use options::{boot_arguments, options, supported_data_types};
pub use requests::AsyncRequests;
pub use session::validate_final_status;

use crate::{
    device::{DeviceInfo, Mode},
    img4,
    ipsw::{Behavior, Identity, Ipsw},
    net, tss,
    usb::RecoveryUsb,
    wire,
};
use anyhow::{Context, Result, ensure};
use plist::Value;
use std::{fs::File, path::Path, sync::Arc};

pub const RESTORED_PORT: u16 = 62078;

/// An identity and the signing response used to personalize its components.
pub struct SignedIdentity {
    pub identity: Identity,
    pub ticket: Value,
}

/// Final signing responses and device metadata. Created after iBoot has
/// refreshed its nonces, then shared without cloning identities per request.
pub struct RestoreContext {
    pub restore: SignedIdentity,
    pub recovery: Option<SignedIdentity>,
    pub device: DeviceInfo,
    pub assets: net::AssetClient,
}

/// The main restored channel owns a ZIP cursor. Concurrent requests open
/// independent readers and share the same immutable restore context.
pub struct RestoreSession {
    pub ipsw: Ipsw,
    pub context: Arc<RestoreContext>,
}

/// Validate the available IPSW metadata and build the exact iBoot firmware stages.
/// This is shared by the offline plan and the restore path, before any upload.
pub fn preflight(ipsw: &mut Ipsw, identity: &mut Identity) -> Result<[Vec<IBootStep>; 2]> {
    ipsw.validate_identity(identity)?;
    let mut components = std::collections::BTreeSet::new();
    for tag in [b"ibss", b"ibec", b"rdsk", b"rdtr", b"rkrn"] {
        components.insert(identity.require_component_type(tag)?);
    }
    options(identity)?;
    let stage1 = if identity.is_macos()? {
        boot::iboot_stage(identity, true)?
    } else {
        Vec::new()
    };
    let stage2 = boot::iboot_stage(identity, false)?;
    let stages = [stage1, stage2];
    for step in stages.iter().flatten() {
        if let IBootStep::Component(name) = step {
            components.insert(name.as_str());
        }
    }
    if let Some(name) = identity.component_by_type(b"rsep")? {
        components.insert(name);
    }
    for name in components {
        ipsw.verify_boot_component(identity, name)?;
    }
    Ok(stages)
}

pub(crate) fn run(
    mut ipsw: Ipsw,
    ecid: u64,
    identity_index: Option<usize>,
    transcript: Option<&Path>,
    behavior: Behavior,
    assets: net::AssetClient,
) -> Result<()> {
    // The catalog/download phase can outlive a change in host driver/service state.
    crate::drivers::check_host()?;
    let usb = RecoveryUsb::open(ecid)?;
    ensure!(usb.info.mode == Mode::Dfu, "enter DFU before restoring");
    usb.check_reset_access()?;
    crate::log!(
        Info,
        "ipsw",
        "Preparing firmware: {}",
        ipsw.path().display()
    );
    let mut identity = ipsw.select_behavior(&usb.info, identity_index, behavior)?;
    let stages = preflight(&mut ipsw, &mut identity)?;
    let mut recovery = ipsw.recovery_identity(&usb.info, &identity)?;
    ipsw.prepare_filesystem(&identity)?;
    if let Some(id) = &mut recovery {
        ipsw.validate_identity(id)?;
        if id.path("OS")? != identity.path("OS")? {
            ipsw.prepare_filesystem(id)?;
        }
        // Validate fields known now before iBSS; signing still uses fresh nonces
        // after boot, when the device may have replaced them.
        if identity.is_macos()? {
            tss::recovery_request(&usb.info, id)?;
        } else {
            tss::request(&usb.info, id)?;
        }
    }
    crate::log!(
        Info,
        "restore",
        "Requesting Apple signatures for {}, ECID {ecid:016x}",
        wire::string(&identity.value, &["Info", "DeviceClass"])?
    );
    let ticket = tss::send(&tss::request(&usb.info, &identity)?)
        .context("personalizing restore firmware")?;
    // BAA measures the manifest used to boot iBSS. A later nonce change can
    // replace the restore ticket, so retain the bootstrap measurement now.
    let attestation = attestation::Attestation::new(&identity, &usb.info, &ticket)?;
    // Validate personalization metadata before sending the first byte of firmware.
    for name in identity.manifest()?.keys() {
        img4::restore_info(&ticket, name, &identity.value, identity.payload_type(name)?)?;
    }
    let log = transcript
        .map(|p| File::options().write(true).create_new(true).open(p))
        .transpose()?;
    let mut restore = SignedIdentity { identity, ticket };
    let (device, bootx_error) = restore.boot(&mut ipsw, usb, &stages)?;
    let recovery = recovery
        .map(|identity| -> Result<SignedIdentity> {
            let request = if restore.identity.is_macos()? {
                tss::recovery_request(&device, &identity)?
            } else {
                tss::request(&device, &identity)?
            };
            let ticket = tss::send(&request).context("personalizing RecoveryOS root ticket")?;
            Ok(SignedIdentity { identity, ticket })
        })
        .transpose()?;
    let mut state = RestoreSession {
        ipsw,
        context: Arc::new(RestoreContext {
            restore,
            recovery,
            device,
            assets,
        }),
    };
    session::run(
        &mut state,
        bootx_error,
        log,
        attestation,
        connection::wait_restored,
    )
}

#[cfg(test)]
#[path = "../tests/unit/restore.rs"]
mod tests;
