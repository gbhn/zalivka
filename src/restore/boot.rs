//! iBoot preparation and the explicitly requested RAM-only boot-state probe.
use super::{SignedIdentity, options::boot_arguments};
use crate::{
    device::{DeviceInfo, Mode},
    dfu, img4,
    ipsw::{Behavior, Identity, Ipsw},
    tss,
    usb::RecoveryUsb,
    wire,
};
use anyhow::{Context, Result, ensure};
use plist::Value;
use std::{
    path::Path,
    time::{Duration, Instant},
};

#[derive(Debug, PartialEq, Eq, serde::Serialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum IBootStep {
    Component(String),
    Command(&'static str),
}

/// MobileDevice's stage preparation: ANS, parameters, iBootData, DCP, remainder.
/// These are full restore stages, not the separate ApBootstrapOnly operation.
pub(super) fn iboot_stage(id: &Identity, stage1: bool) -> Result<Vec<IBootStep>> {
    let mut firmware = Vec::new();
    for (name, entry) in id.manifest()? {
        let first =
            wire::optional_boolean(entry, &["Info", "IsLoadedByiBootStage1"])?.unwrap_or(false);
        let loaded = wire::optional_boolean(entry, &["Info", "IsLoadedByiBoot"])?.unwrap_or(false);
        if first == stage1 && (stage1 || loaded) {
            ensure!(
                id.payload_type(name)?.is_some(),
                "cannot resolve iBoot firmware payload type for {name}: no manifest override or valid IM4P header"
            );
            firmware.push(name.clone());
        }
    }
    let dcp = id.component_by_type(b"rdcp")?;
    let has_dcp = dcp.is_some_and(|dcp| firmware.iter().any(|name| name == dcp));
    let restore_logo = id.component_by_type(b"rlgo")?;
    let mut steps = Vec::new();
    let logo = |steps: &mut Vec<IBootStep>| {
        if let Some(name) = restore_logo {
            steps.push(IBootStep::Component(name.into()));
            steps.push(IBootStep::Command("setpicture 4"));
            steps.push(IBootStep::Command("bgcolor 0 0 0"));
        }
    };
    // The caller displays the logo before stage 2 when DCP is not in this stage.
    // With DCP, the firmware helper displays it after DCP has initialized graphics.
    if !stage1 && !has_dcp {
        logo(&mut steps);
    }
    if let Some(ans) = id.component_by_type(b"rans")?
        && let Some(index) = firmware.iter().position(|name| name == ans)
    {
        steps.push(IBootStep::Component(firmware.remove(index)));
        steps.push(IBootStep::Command("firmware"));
    }
    steps.extend([
        IBootStep::Command("setenv auto-boot false"),
        IBootStep::Command("saveenv"),
        IBootStep::Command(boot_arguments(id)?),
    ]);
    for tag in [b"ibdt", b"rdcp"] {
        if let Some(priority) = id.component_by_type(tag)?
            && let Some(index) = firmware.iter().position(|name| name == priority)
        {
            steps.push(IBootStep::Component(firmware.remove(index)));
            steps.push(IBootStep::Command("firmware"));
        }
    }
    if has_dcp {
        logo(&mut steps);
    }
    for name in firmware {
        steps.push(IBootStep::Component(name));
        steps.push(IBootStep::Command("firmware"));
    }
    Ok(steps)
}

/// Query iBoot's environment, optionally loading only a signed iBSS into RAM.
/// No local policy, firmware, setenv/saveenv, kernel or StartRestore is sent.
pub fn probe_boot_state(path: &Path, ecid: u64, load_ibss: bool) -> Result<serde_json::Value> {
    let mut usb = RecoveryUsb::open(ecid)?;
    let original_mode = usb.info.mode;
    ensure!(
        original_mode != Mode::PortDfu,
        "Port DFU requires controller recovery before an iBoot RAM probe; use restore or revive to prepare the controller"
    );
    if original_mode == Mode::Dfu {
        ensure!(
            load_ibss,
            "reading boot state from DFU requires --load-ibss (loads a signed bootloader into RAM)"
        );
        usb.check_reset_access()?;
        let mut ipsw = Ipsw::open(path)?;
        let mut identity = ipsw.select_behavior(&usb.info, None, Behavior::Update)?;
        usb.info = identity.device_parameters(&usb.info)?;
        ensure!(
            identity.is_macos()?,
            "RAM boot-state probe supports Apple silicon Macs only"
        );
        ipsw.resolve_types(&mut identity)?;
        let name = identity.require_component_type(b"ibss")?;
        let component = ipsw.verify_boot_component(&identity, name)?;
        let ticket = tss::send(&tss::request(&usb.info, &identity)?)
            .context("personalizing diagnostic iBSS")?;
        let bytes = img4::personalize_with_metadata(name, &component, &ticket, &identity.value)?;
        crate::log!(Debug, "boot", "iBSS in RAM: {} B", bytes.len());
        usb = boot_ibss(usb, &bytes, Some(Mode::Recovery))?;
    }
    let mut variables = serde_json::Map::new();
    for name in [
        "auto-boot",
        "auto-boot-once",
        "bootdelay",
        "boot-image",
        "iboot1-precommitted",
        "anid",
        "is-tethered",
        "darkboot",
        "idle-off",
        "BootPreference",
        "disable-boot-breadcrumbs",
        "recovery-reason",
        "preserve-debuggability",
        "upgrade-retry",
        "boot-command",
        "one-time-boot-command",
        "recovery-boot-mode",
        "iboot-failure-reason",
        "iboot-failure-reason-str",
        "iboot-failure-volume",
        "boot-fail-count",
        "boot-breadcrumbs",
        "failboot-breadcrumbs",
        "recovery-breadcrumbs",
        "boot-picker-bringup-reason",
        "boot-volume",
        "alt-boot-volume",
        "upgrade-boot-volume",
        "update-volume",
        "upgrade-fallback-boot-command",
        "apfs-preboot-uuid",
        "panicmedic-timestamps",
        "usbcfwflasherResult",
        "boot-stage",
        "build-version",
        "build-style",
        "boot-args",
    ] {
        crate::log!(Debug, "boot:env", "getenv {name}");
        let value = match dfu::getenv(&mut usb, name) {
            Ok(value) => serde_json::json!({"value": value}),
            Err(error) => serde_json::json!({"error": format!("{error:#}")}),
        };
        variables.insert(name.into(), value);
    }
    Ok(serde_json::json!({
        "ecid": format!("{ecid:016x}"), "initial_mode": original_mode,
        "mode": usb.info.mode, "chip_id": usb.info.chip_id, "board_id": usb.info.board_id,
        "ibss_loaded_into_ram": original_mode == Mode::Dfu,
        "variables": variables,
        "note": "Values are reported by the current in-memory iBoot stage. Empty replies may mean unset or unavailable; they do not confirm a healthy boot configuration. No firmware-install, setenv/saveenv, kernel boot or StartRestore commands were sent."
    }))
}

impl SignedIdentity {
    pub(super) fn send_component(
        &self,
        ipsw: &mut Ipsw,
        usb: &mut RecoveryUsb,
        name: &str,
        ticket: Option<&Value>,
    ) -> Result<()> {
        let bytes = ipsw.personalized(&self.identity, name, ticket.unwrap_or(&self.ticket))?;
        crate::log!(Debug, "boot", "Sending {name}: {} B", bytes.len());
        dfu::upload(usb, usb.info.mode, &bytes, true).with_context(|| format!("uploading {name}"))
    }

    fn send_boot_object(
        &self,
        ipsw: &mut Ipsw,
        usb: &mut RecoveryUsb,
        tag: &[u8; 4],
    ) -> Result<()> {
        let name = self.identity.require_component_type(tag)?;
        self.send_component(ipsw, usb, name, None)
    }

    // Errors before bootx stop immediately. A bootx USB error must be resolved
    // by checking the restore service's identity after closing iBoot USB.
    pub(super) fn boot(
        &mut self,
        ipsw: &mut Ipsw,
        usb: RecoveryUsb,
        stages: &[Vec<IBootStep>; 2],
    ) -> Result<(DeviceInfo, Option<anyhow::Error>)> {
        let mut device = usb.info.clone();
        ensure!(
            usb.info.mode == Mode::Dfu,
            "restore must start in ROM DFU mode"
        );
        let mut usb = {
            let name = self.identity.require_component_type(b"ibss")?;
            let bytes = ipsw.personalized(&self.identity, name, &self.ticket)?;
            crate::log!(Debug, "boot", "Sending {name}: {} B", bytes.len());
            boot_ibss(
                usb,
                &bytes,
                self.identity.is_macos()?.then_some(Mode::Recovery),
            )?
        };
        if usb.info.ap_nonce != device.ap_nonce || usb.info.sep_nonce != device.sep_nonce {
            crate::log!(Info, "boot", "Refreshing signatures after iBSS");
            device = usb.info.clone();
            self.ticket = tss::send(&tss::request(&device, &self.identity)?)
                .context("personalizing restore firmware after iBSS nonce change")?;
        }
        if self.identity.is_macos()? {
            ensure!(
                usb.info.mode == Mode::Recovery,
                "Apple Silicon iBSS did not expose the iBoot recovery transport"
            );
            let local = tss::send(&tss::local_policy_request(
                &device,
                tss::ticket(&self.ticket)?,
                None,
            )?)
            .context("personalizing initial Ap,LocalPolicy for iBoot")?;
            self.send_component(ipsw, &mut usb, "Ap,LocalPolicy", Some(&local))?;
            dfu::command(&mut usb, "lpolrestore", false)?;
            self.send_iboot_firmware(ipsw, &mut usb, true, &stages[0])?;
        }
        self.send_boot_object(ipsw, &mut usb, b"ibec")?;
        if usb.info.mode == Mode::Recovery {
            dfu::command(&mut usb, "go", true)?;
        }
        drop(usb);
        let mut usb = wait_recovery(device.ecid, Some(Mode::Recovery))?;
        usb.info = self.identity.device_parameters(&usb.info)?;
        validate_reconnected_device(&device, &usb.info)
            .context("hardware identity changed after iBEC")?;
        self.send_iboot_firmware(ipsw, &mut usb, false, &stages[1])?;
        self.send_boot_object(ipsw, &mut usb, b"rdsk")?;
        dfu::command(&mut usb, "ramdisk", false)?;
        std::thread::sleep(Duration::from_secs(2));
        self.send_boot_object(ipsw, &mut usb, b"rdtr")?;
        dfu::command(&mut usb, "devicetree", false)?;
        if self.identity.component_by_type(b"rsep")?.is_some() {
            self.send_boot_object(ipsw, &mut usb, b"rsep")?;
            dfu::command(&mut usb, "rsepfirmware", false)?;
        }
        self.send_boot_object(ipsw, &mut usb, b"rkrn")?;
        Ok((device, dfu::boot_kernel(&mut usb).err()))
    }

    pub(super) fn send_iboot_firmware(
        &self,
        ipsw: &mut Ipsw,
        usb: &mut RecoveryUsb,
        stage1: bool,
        steps: &[IBootStep],
    ) -> Result<()> {
        crate::log!(
            Info,
            "boot",
            "Preparing bootloader: stage {}",
            if stage1 { 1 } else { 2 }
        );
        for step in steps {
            match step {
                IBootStep::Component(name) => {
                    self.send_component(ipsw, usb, name, None)?;
                }
                IBootStep::Command(command) => {
                    crate::log!(Debug, "boot:cmd", "{command}");
                    dfu::command(usb, command, false)?;
                }
            }
        }
        Ok(())
    }
}

/// Both diagnostic and restore boots retire the DFU handle before reconnecting.
/// A reset error alone never proves that the expected device reached iBSS.
fn boot_ibss(mut usb: RecoveryUsb, bytes: &[u8], mode: Option<Mode>) -> Result<RecoveryUsb> {
    let expected = usb.info.clone();
    let upload = dfu::upload(&mut usb, Mode::Dfu, bytes, true).context("uploading iBSS");
    drop(usb);
    let mut usb = reconnect_after_ibss(upload, mode, |mode| wait_recovery(expected.ecid, mode))?;
    validate_reconnected_device(&expected, &usb.info)
        .context("hardware identity changed after iBSS")?;
    usb.info.security_domain = usb.info.security_domain.or(expected.security_domain);
    Ok(usb)
}

pub(super) fn validate_reconnected_device(
    expected: &DeviceInfo,
    actual: &DeviceInfo,
) -> Result<()> {
    ensure!(
        expected.ecid == actual.ecid
            && expected.chip_id == actual.chip_id
            && expected.board_id == actual.board_id,
        "USB hardware identifiers do not match"
    );
    ensure!(
        expected
            .security_domain
            .zip(actual.security_domain)
            .is_none_or(|(expected, actual)| expected == actual)
            && expected.chip_fuse_mode == actual.chip_fuse_mode,
        "USB security domain or fuse mode changed"
    );
    Ok(())
}

pub(super) fn reconnect_after_ibss<T>(
    upload: Result<()>,
    mode: Option<Mode>,
    reconnect: impl FnOnce(Option<Mode>) -> Result<T>,
) -> Result<T> {
    match upload {
        Ok(()) => reconnect(mode),
        Err(reset_error) if reset_error.is::<dfu::ResetFailure>() => {
            crate::log!(Debug, "boot", "USB reset: {reset_error:#}");
            // A reset can remove its own USB handle before Windows reports its
            // completion. Only a working Recovery connection proves the transition;
            // absence or the old DFU device must not count as success.
            match reconnect(Some(Mode::Recovery)) {
                Ok(usb) => {
                    crate::log!(Debug, "boot", "Recovery connected");
                    Ok(usb)
                }
                Err(error) => Err(reset_error.context(format!(
                    "Recovery not confirmed after iBSS ({error:#}); re-enter DFU before retrying"
                ))),
            }
        }
        Err(error) => Err(error),
    }
}

pub(super) fn wait_recovery(ecid: u64, mode: Option<Mode>) -> Result<RecoveryUsb> {
    std::thread::sleep(Duration::from_secs(1));
    let deadline = Instant::now() + Duration::from_secs(60);
    let mut error;
    loop {
        error = match RecoveryUsb::open(ecid) {
            Ok(usb) if mode.is_none_or(|m| usb.info.mode == m) => return Ok(usb),
            Ok(_) => anyhow::anyhow!("device is in an unexpected mode"),
            Err(e) => e,
        };
        if Instant::now() >= deadline {
            return Err(error.context("device did not reconnect after boot stage"));
        }
        std::thread::sleep(Duration::from_millis(500));
    }
}
