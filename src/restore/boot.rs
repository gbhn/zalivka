//! iBoot preparation and explicitly requested diagnostic boots.
use super::{
    ContextState, confirm_restore_service, options::behavior_boot_arguments, query_value,
    wait_restored,
};
use crate::{
    device::Mode,
    dfu, img4,
    ipsw::{Behavior, Identity, Ipsw},
    net, tss,
    usb::RecoveryUsb,
    wire,
};
use anyhow::{Context, Result, ensure};
use plist::Value;
use std::{
    path::Path,
    time::{Duration, Instant},
};

#[derive(Debug, PartialEq, Eq)]
pub(super) enum IBootStep {
    Component(String),
    Command(&'static str),
}

/// MobileDevice's stage preparation: ANS, parameters, iBootData, DCP, remainder.
/// These are full restore stages, not the separate ApBootstrapOnly operation.
pub(super) fn iboot_stage(id: &Identity, stage1: bool, diagnostic: bool) -> Result<Vec<IBootStep>> {
    let mut firmware: Vec<_> = id
        .manifest()?
        .iter()
        .filter(|(_, v)| {
            wire::boolean(v, &["Info", "IsLoadedByiBootStage1"]) == stage1
                && (stage1 || wire::boolean(v, &["Info", "IsLoadedByiBoot"]))
        })
        .map(|(name, _)| name.clone())
        .collect();
    let has_dcp = firmware.iter().any(|name| name == "RestoreDCP");
    let mut steps = Vec::new();
    let logo = |steps: &mut Vec<IBootStep>| {
        if id.has("RestoreLogo") {
            steps.push(IBootStep::Component("RestoreLogo".into()));
            steps.push(IBootStep::Command("setpicture 4"));
            steps.push(IBootStep::Command("bgcolor 0 0 0"));
        }
    };
    // The caller displays the logo before stage 2 when DCP is not in this stage.
    // With DCP, the firmware helper displays it after DCP has initialized graphics.
    if !stage1 && !has_dcp {
        logo(&mut steps);
    }
    if let Some(index) = firmware.iter().position(|name| name == "RestoreANS") {
        steps.push(IBootStep::Component(firmware.remove(index)));
        steps.push(IBootStep::Command("firmware"));
    }
    // Diagnostic boots never generate persistent settings or reformat arguments.
    let behavior = if diagnostic {
        steps.push(IBootStep::Command("setenvnp auto-boot false"));
        Behavior::Update
    } else {
        steps.extend([
            IBootStep::Command("setenv auto-boot false"),
            IBootStep::Command("saveenv"),
        ]);
        id.behavior()?
    };
    steps.push(IBootStep::Command(behavior_boot_arguments(behavior)));
    for priority in ["iBootData", "RestoreDCP"] {
        if let Some(index) = firmware.iter().position(|name| name == priority) {
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
    if original_mode == Mode::Dfu {
        ensure!(
            load_ibss,
            "reading boot state from DFU requires --load-ibss (loads a signed bootloader into RAM)"
        );
        usb.check_reset_access()?;
        let mut ipsw = Ipsw::open(path)?;
        let identity = ipsw.select_behavior(&usb.info, None, Behavior::Update)?;
        ensure!(
            identity.is_macos(),
            "RAM boot-state probe supports Apple silicon Macs only"
        );
        let component = ipsw.component(&identity, "iBSS")?;
        let ticket = tss::send(&tss::request(&usb.info, &identity)?)
            .context("personalizing diagnostic iBSS")?;
        let bytes = img4::personalize_with_metadata("iBSS", &component, &ticket, &identity.value)?;
        let chip_id = usb.info.chip_id;
        let board_id = usb.info.board_id;
        eprintln!("Loading diagnostic iBSS into RAM: {} bytes", bytes.len());
        let upload = dfu::upload(&mut usb, Mode::Dfu, &bytes, true);
        drop(usb);
        usb = reconnect_after_ibss(upload, Some(Mode::Recovery), |mode| {
            wait_recovery(ecid, mode)
        })?;
        ensure!(
            usb.info.chip_id == chip_id && usb.info.board_id == board_id,
            "hardware identity changed after diagnostic iBSS"
        );
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
        eprintln!("Reading iBoot variable: {name}");
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

/// Load an Update restore environment into RAM, then query saved diagnostics.
/// This performs DFU reset/boot, but sends no StartRestore or persistent setenv.
/// No reboot is requested; the device's state after disconnect is not guaranteed.
pub fn probe_saved_debug(path: &Path, ecid: u64) -> Result<serde_json::Value> {
    let usb = RecoveryUsb::open(ecid)?;
    ensure!(
        usb.info.mode == Mode::Dfu,
        "enter DFU before the RAM diagnostic boot"
    );
    usb.check_reset_access()?;
    let mut ipsw = Ipsw::open(path)?;
    let identity = ipsw.select_behavior(&usb.info, None, Behavior::Update)?;
    ensure!(
        identity.is_macos(),
        "RAM diagnostic boot supports Apple silicon Macs only"
    );
    ipsw.preflight(&identity)?;
    let ticket = tss::send(&tss::request(&usb.info, &identity)?)
        .context("personalizing RAM diagnostic firmware")?;
    for name in identity.manifest()?.keys() {
        img4::restore_info(&ticket, name, &identity.value)?;
    }
    let mut state = ContextState {
        ipsw,
        identity,
        recovery: None,
        device: usb.info.clone(),
        ticket,
        recovery_ticket: None,
        assets: net::AssetClient::default(),
    };
    eprintln!("RAM diagnostic boot only: no StartRestore, saveenv or NAND reformat argument");
    let bootx_error = state.boot(usb, true)?;
    let (session, mut main, version) =
        confirm_restore_service(bootx_error, || wait_restored(&state.device))?;
    main.set_read_timeout(Duration::from_secs(15));
    eprintln!("Reading restored QueryValue: SavedDebugInfo");
    let reply = query_value(&mut main, "SavedDebugInfo")?;
    eprintln!("Reading restored QueryValue: Logs");
    // Preserve SavedDebugInfo even if the optional log query fails. Some restore
    // environments disappear after the host disconnects, so use this session.
    let service_log = match query_value(&mut main, "Logs") {
        Ok(reply) => serde_json::json!({"reply": reply}),
        Err(error) => serde_json::json!({"error": format!("{error:#}")}),
    };
    drop(main);
    drop(session);
    Ok(serde_json::json!({
        "ecid": format!("{ecid:016x}"),
        "restore_protocol_version": version,
        "saved_debug_info": reply,
        "service_log": service_log,
        "start_restore_sent": false,
        "note": "Diagnostic firmware/kernel loaded into RAM; DFU reset performed. No StartRestore, saveenv, disk-install requests, reboot command or NAND reformat boot argument were sent. The device's state after host disconnect is not guaranteed. These logs may be empty or refer to an earlier event; they do not themselves confirm the cause or a successful disk boot."
    }))
}

impl ContextState {
    pub(super) fn send_component(
        &mut self,
        usb: &mut RecoveryUsb,
        name: &str,
        ticket: Option<&Value>,
    ) -> Result<()> {
        let bytes = self
            .ipsw
            .personalized(&self.identity, name, ticket.unwrap_or(&self.ticket))?;
        eprintln!("Sending {name}: {} bytes", bytes.len());
        dfu::upload(usb, usb.info.mode, &bytes, true).with_context(|| format!("uploading {name}"))
    }

    // Errors before bootx stop immediately. A bootx USB error must be resolved
    // by checking the restore service's identity after closing iBoot USB.
    pub(super) fn boot(
        &mut self,
        mut usb: RecoveryUsb,
        diagnostic: bool,
    ) -> Result<Option<anyhow::Error>> {
        ensure!(
            usb.info.mode == Mode::Dfu,
            "restore must start in ROM DFU mode"
        );
        let upload = self.send_component(&mut usb, "iBSS", None);
        drop(usb);
        let mode = self.identity.is_macos().then_some(Mode::Recovery);
        let mut usb =
            reconnect_after_ibss(upload, mode, |mode| wait_recovery(self.device.ecid, mode))?;
        ensure!(
            usb.info.chip_id == self.device.chip_id && usb.info.board_id == self.device.board_id,
            "hardware identity changed after iBSS"
        );
        if usb.info.ap_nonce != self.device.ap_nonce || usb.info.sep_nonce != self.device.sep_nonce
        {
            eprintln!("Device nonce changed after iBSS; obtaining new Apple signatures");
            self.device = usb.info.clone();
            self.ticket = tss::send(&tss::request(&self.device, &self.identity)?)
                .context("personalizing restore firmware after iBSS nonce change")?;
        }
        if self.identity.is_macos() {
            ensure!(
                usb.info.mode == Mode::Recovery,
                "Apple Silicon iBSS did not expose the iBoot recovery transport"
            );
            let local = tss::send(&tss::local_policy_request(
                &self.device,
                tss::ticket(&self.ticket)?,
                None,
            )?)
            .context("personalizing initial Ap,LocalPolicy for iBoot")?;
            self.send_component(&mut usb, "Ap,LocalPolicy", Some(&local))?;
            dfu::command(&mut usb, "lpolrestore", false)?;
            self.send_iboot_firmware(&mut usb, true, diagnostic)?;
        }
        self.send_component(&mut usb, "iBEC", None)?;
        if usb.info.mode == Mode::Recovery {
            dfu::command(&mut usb, "go", true)?;
        }
        drop(usb);
        let mut usb = wait_recovery(self.device.ecid, Some(Mode::Recovery))?;
        self.send_iboot_firmware(&mut usb, false, diagnostic)?;
        self.send_component(&mut usb, "RestoreRamDisk", None)?;
        dfu::command(&mut usb, "ramdisk", false)?;
        std::thread::sleep(Duration::from_secs(2));
        self.send_component(&mut usb, "RestoreDeviceTree", None)?;
        dfu::command(&mut usb, "devicetree", false)?;
        if self.identity.has("RestoreSEP") {
            self.send_component(&mut usb, "RestoreSEP", None)?;
            dfu::command(&mut usb, "rsepfirmware", false)?;
        }
        self.send_component(&mut usb, "RestoreKernelCache", None)?;
        Ok(dfu::boot_kernel(&mut usb).err())
    }

    pub(super) fn send_iboot_firmware(
        &mut self,
        usb: &mut RecoveryUsb,
        stage1: bool,
        diagnostic: bool,
    ) -> Result<()> {
        eprintln!("Preparing iBoot stage {}", if stage1 { 1 } else { 2 });
        for step in iboot_stage(&self.identity, stage1, diagnostic)? {
            match step {
                IBootStep::Component(name) => {
                    self.send_component(usb, &name, None)?;
                }
                IBootStep::Command(command) => {
                    eprintln!("iBoot: {command}");
                    dfu::command(usb, command, false)?;
                }
            }
        }
        Ok(())
    }
}

pub(super) fn reconnect_after_ibss<T>(
    upload: Result<()>,
    mode: Option<Mode>,
    reconnect: impl FnOnce(Option<Mode>) -> Result<T>,
) -> Result<T> {
    match upload {
        Ok(()) => reconnect(mode),
        Err(reset_error) if reset_error.is::<dfu::ResetFailure>() => {
            eprintln!("{reset_error:#}; waiting for the same device in Recovery");
            // A reset can remove its own USB handle before Windows reports its
            // completion. Only a working Recovery connection proves the transition;
            // absence or the old DFU device must not count as success.
            match reconnect(Some(Mode::Recovery)) {
                Ok(usb) => {
                    eprintln!("Recovery connection confirmed after USB reset error; continuing");
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
