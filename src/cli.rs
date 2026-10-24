use anyhow::{Context, Result, ensure};
use clap::{Args, Parser, Subcommand};
use serde_json::json;
use std::path::PathBuf;
use zalivka::{
    catalog,
    device::{Mode, parse_ecid},
    drivers,
    ipsw::{Behavior, Ipsw},
    net, progress, restore, tss, usb, usb_internet, wire,
};

#[derive(Parser)]
#[command(
    version,
    about = "Native Rust Mac DFU tools (experimental restore engine)"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Temporary internet access for a connected Mac through USB Ethernet.
    UsbInternet {
        #[command(subcommand)]
        command: InternetCommand,
    },
    #[cfg(feature = "gui")]
    /// Open the native desktop interface.
    Gui,
    /// Diagnose USB access, installed drivers and interface claim errors.
    Doctor,
    /// Export or install host USB driver configuration.
    Drivers {
        #[command(subcommand)]
        command: DriverCommand,
    },
    /// List Apple devices currently in DFU or recovery mode.
    Detect {
        #[arg(long)]
        json: bool,
    },
    /// Read iBoot variables; DFU optionally loads a signed iBSS into RAM, without starting restore.
    BootState {
        ipsw: PathBuf,
        #[arg(long, value_parser = parse_ecid)]
        ecid: u64,
        /// Allow loading iBSS into RAM and its USB reset when starting in DFU.
        #[arg(long)]
        load_ibss: bool,
    },
    /// Inspect a local Mac IPSW without opening a USB device.
    Inspect {
        ipsw: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// Check all ZIP streams and supported manifest digests; report encrypted AEA separately.
    Verify {
        ipsw: PathBuf,
        /// Trusted complete archive SHA-1 (Apple catalog) or SHA-256, in hex.
        #[arg(long)]
        checksum: Option<String>,
    },
    /// Validate restore components without writing to USB or contacting Apple.
    Plan {
        ipsw: PathBuf,
        /// Hexadecimal ECID of a connected DFU device.
        #[arg(long, value_parser = parse_ecid, conflicts_with = "identity", required_unless_present = "identity")]
        ecid: Option<u64>,
        /// Offline plan for an explicit identity. Does not check hardware compatibility.
        #[arg(long, conflicts_with = "ecid", required_unless_present = "ecid")]
        identity: Option<usize>,
        /// Validate an Upgrade identity for the Revive path.
        #[arg(long)]
        revive: bool,
    },
    /// Write an Apple TSS request plist for the connected DFU device; no USB writes.
    TssRequest {
        ipsw: PathBuf,
        #[arg(long, value_parser = parse_ecid)]
        ecid: u64,
        #[arg(long)]
        identity: Option<usize>,
        #[arg(long)]
        output: PathBuf,
    },
    /// Download an IPSW from an Apple HTTPS URL and verify its SHA-256.
    Download {
        url: String,
        #[arg(long)]
        output: PathBuf,
        #[arg(long)]
        sha256: String,
    },
    /// Automatically select and download Apple's current IPSW for a connected Mac.
    Fetch {
        #[arg(long, value_parser = parse_ecid)]
        ecid: u64,
        /// Directory for verified firmware; defaults to the user's cache directory.
        #[arg(long)]
        firmware_dir: Option<PathBuf>,
    },
    /// Experimental erase restore. Requires device testing; see README limitations.
    Restore {
        #[command(flatten)]
        args: RestoreArgs,
        /// Acknowledge that restore erases the target Mac.
        #[arg(long, required = true)]
        erase: bool,
    },
    /// Experimental firmware/recovery update using an Upgrade identity; never falls back to erase.
    Revive(RestoreArgs),
}

#[derive(Subcommand)]
enum InternetCommand {
    /// Inspect Mac USB network interfaces without changing drivers.
    Status,
    /// Prepare only the connected Mac's USB network interfaces (Windows UAC).
    Prepare {
        #[arg(long)]
        serial: Option<String>,
        /// Restore the driver settings saved before preparation.
        #[arg(long)]
        restore: bool,
    },
    #[cfg(windows)]
    #[command(hide = true)]
    PrepareElevated {
        #[arg(long)]
        serial: String,
        #[arg(long)]
        restore: bool,
    },
    /// Share this computer's internet with the connected Mac.
    Share {
        #[arg(long)]
        serial: Option<String>,
        /// Stop sharing after this many seconds; omitted means no time limit.
        #[arg(long, value_parser = clap::value_parser!(u64).range(1..=86400))]
        seconds: Option<u64>,
    },
}

#[derive(Args)]
struct RestoreArgs {
    /// After successful erase restore, share internet with the same USB port for 15 minutes.
    #[arg(long)]
    share_internet: bool,
    /// Local IPSW; omitted to automatically download the current compatible image.
    ipsw: Option<PathBuf>,
    /// Firmware cache for automatic downloads.
    #[arg(long, conflicts_with = "ipsw")]
    firmware_dir: Option<PathBuf>,
    #[arg(long, value_parser = parse_ecid)]
    ecid: u64,
    #[arg(long)]
    identity: Option<usize>,
    /// Acknowledge the experimental status of the restore engine.
    #[arg(long, required = true)]
    experimental: bool,
    /// Record restored's plist messages as JSON lines (new file only).
    #[arg(long)]
    transcript: Option<PathBuf>,
    /// Apple host-to-bearer-token plist for WKMS authorization.
    #[arg(long)]
    authorization_tokens: Option<PathBuf>,
    /// Raw DAWTKN data obtained from an authorized AppleConnect session.
    #[arg(long)]
    apple_connect_data: Option<PathBuf>,
}

impl RestoreArgs {
    fn run(self, behavior: Behavior) -> Result<()> {
        ensure!(self.experimental, "--experimental is required");
        ensure!(
            !self.share_internet || behavior == Behavior::Erase,
            "--share-internet is available for erase restore only"
        );
        let internet_target = self
            .share_internet
            .then(|| usb_internet::Target::for_ecid(self.ecid))
            .transpose()?;
        drivers::check_host()?;
        let assets = net::AssetClient::from_files(
            self.authorization_tokens.as_deref(),
            self.apple_connect_data.as_deref(),
        )?;
        let ipsw = if let Some(path) = self.ipsw {
            path
        } else {
            let action = match behavior {
                Behavior::Erase => "restoring",
                Behavior::Update => "reviving",
            };
            let device = usb::RecoveryUsb::open(self.ecid)?.info;
            ensure!(device.mode == Mode::Dfu, "enter DFU before {action}");
            let directory = self
                .firmware_dir
                .map_or_else(catalog::cache_directory, Ok)?;
            catalog::obtain(&device, &directory, self.identity, behavior)?
        };
        restore::run(
            &ipsw,
            self.ecid,
            self.identity,
            self.transcript.as_deref(),
            behavior,
            assets,
        )?;
        progress::Event::RestoreCompleted.emit();
        if let Some(target) = internet_target {
            eprintln!("Restore completed; waiting for the Mac's USB network");
            if let Err(error) = usb_internet::share(
                None,
                Some(&target),
                Some(std::time::Duration::from_secs(900)),
            ) {
                progress::Event::InternetUnavailable {
                    error: format!("{error:#}"),
                }
                .emit();
                eprintln!("USB internet unavailable: {error:#}");
            }
        }
        Ok(())
    }
}

#[derive(Subcommand)]
enum DriverCommand {
    /// Check Apple USB, USB network interface drivers and the Apple service.
    Status,
    /// Install missing Apple USB / USB network drivers and stop AMDS (Windows UAC).
    Prepare,
    #[cfg(windows)]
    #[command(hide = true)]
    PrepareElevated,
    /// Export a targeted WinUSB INF source and Linux udev rule; does not install.
    Export {
        directory: PathBuf,
        #[arg(long, value_parser = parse_pid)]
        pid: u16,
        #[arg(long)]
        interface: Option<u8>,
    },
    /// Install a signed WinUSB INF/CAT package using Windows' driver installer.
    Install { inf: PathBuf },
    /// Install the bundled udev rule and reload rules (Linux, requires root).
    InstallUdev,
}

fn parse_pid(value: &str) -> std::result::Result<u16, String> {
    u16::from_str_radix(value.trim_start_matches("0x"), 16).map_err(|e| e.to_string())
}

fn print_json(value: &impl serde::Serialize) -> Result<()> {
    println!("{}", serde_json::to_string_pretty(value)?);
    Ok(())
}

pub(super) fn run() -> Result<()> {
    #[cfg(feature = "gui")]
    if std::env::args_os().len() == 1 {
        return crate::gui::run();
    }
    match Cli::parse().command {
        Command::UsbInternet { command } => match command {
            InternetCommand::Status => print_json(&usb_internet::status()?)?,
            InternetCommand::Prepare { serial, restore } => {
                usb_internet::prepare(serial.as_deref(), restore)?
            }
            #[cfg(windows)]
            InternetCommand::PrepareElevated { serial, restore } => {
                usb_internet::prepare_elevated(&serial, restore)?
            }
            InternetCommand::Share { serial, seconds } => usb_internet::share(
                serial.as_deref(),
                None,
                seconds.map(std::time::Duration::from_secs),
            )?,
        },
        #[cfg(feature = "gui")]
        Command::Gui => crate::gui::run()?,
        Command::Doctor => {
            if let Some(host) = drivers::host_status()? {
                eprintln!("Windows: {}", serde_json::to_string(&host)?);
                if let Some(reason) = host.blocking_reason() {
                    eprintln!("{reason}; zalivka drivers prepare");
                }
            }
            let diagnostics = drivers::doctor()?;
            print_json(&diagnostics)?;
            ensure!(
                diagnostics.iter().all(|d| d.accessible),
                "USB diagnostics found inaccessible devices; see the errors above"
            );
        }
        Command::Drivers { command } => match command {
            DriverCommand::Status => {
                print_json(&drivers::host_status()?)?;
            }
            DriverCommand::Prepare => {
                let reboot = drivers::prepare_windows()?;
                println!("Подготовка Windows завершена. Перезагрузка требуется: {reboot}");
                if reboot {
                    progress::Event::RebootRequired.emit();
                    println!("Перезагрузите Windows перед восстановлением Mac.");
                }
            }
            #[cfg(windows)]
            DriverCommand::PrepareElevated => {
                let reboot = drivers::prepare_windows_elevated()?;
                std::process::exit(if reboot { 3010 } else { 0 });
            }
            DriverCommand::Export {
                directory,
                pid,
                interface,
            } => {
                drivers::export(&directory, pid, interface)?;
                println!(
                    "Driver sources saved to {}. Windows INF requires a signed CAT before installation.",
                    directory.display()
                );
            }
            DriverCommand::Install { inf } => {
                println!(
                    "Driver package installed. Reboot required: {}",
                    drivers::install(&inf)?
                );
            }
            DriverCommand::InstallUdev => {
                drivers::install_udev()?;
                println!("udev rules installed. Reconnect the USB cable.");
            }
        },
        Command::BootState {
            ipsw,
            ecid,
            load_ibss,
        } => {
            print_json(&restore::probe_boot_state(&ipsw, ecid, load_ibss)?)?;
        }
        Command::Verify { ipsw, checksum } => {
            if let Some(checksum) = &checksum {
                net::verify_file(&ipsw, &zalivka::device::decode_hex(checksum)?)?;
            }
            let mut ipsw = Ipsw::open(&ipsw)?;
            let mut report = ipsw.verify_all()?;
            report.archive_checksum_verified = checksum.is_some();
            print_json(&report)?;
        }
        Command::Detect { json } => {
            let devices = usb::detect()?;
            if json {
                print_json(&devices)?;
            } else if devices.is_empty() {
                println!("No Apple DFU/recovery devices found.");
            } else {
                for d in devices {
                    println!(
                        "ECID {:016x}  CPID {:04x}  BDID {:02x}  {:?}",
                        d.ecid, d.chip_id, d.board_id, d.mode
                    );
                }
            }
        }
        Command::Inspect {
            ipsw,
            json: as_json,
        } => {
            let ipsw = Ipsw::open(&ipsw)?;
            let identities = ipsw.identity_summaries().collect::<Result<Vec<_>>>()?;
            let version = wire::get(&ipsw.manifest, &["ProductVersion"])
                .cloned()
                .unwrap_or("?".into());
            let build = wire::get(&ipsw.manifest, &["ProductBuildVersion"])
                .cloned()
                .unwrap_or("?".into());
            if as_json {
                print_json(&json!({"version": version, "build": build, "identities": identities}))?;
            } else {
                println!(
                    "Version: {}  Build: {}",
                    version.as_string().unwrap_or("?"),
                    build.as_string().unwrap_or("?")
                );
                for i in identities {
                    println!(
                        "[{}] {}  CPID {:04x}  BDID {:02x}  {}  {} ({} components)",
                        i.index,
                        i.device_class,
                        i.chip_id,
                        i.board_id,
                        i.restore_behavior,
                        i.variant,
                        i.components
                    );
                }
            }
        }
        Command::Plan {
            ipsw,
            ecid,
            identity,
            revive,
        } => {
            let behavior = if revive {
                Behavior::Update
            } else {
                Behavior::Erase
            };
            let mut ipsw = Ipsw::open(&ipsw)?;
            let identity = if let Some(index) = identity {
                ipsw.identity(index)?
            } else {
                let device = usb::detect()?
                    .into_iter()
                    .find(|d| Some(d.ecid) == ecid)
                    .context("DFU device with this ECID not found")?;
                ipsw.select_behavior(&device, None, behavior)?
            };
            let summary = identity.summary()?;
            identity.validate_behavior(behavior)?;
            ipsw.preflight(&identity)?;
            print_json(&json!({
                    "ecid": ecid.map(|n| format!("{n:016x}")), "hardware_checked": ecid.is_some(),
                    "identity": summary, "filesystem_bytes": ipsw.size(identity.path("OS")?)?,
                    "boot_components_verified": true, "hardware_restore_validated": false,
                    "limitations": ["no physical Mac restore has been validated", "unknown firmware updaters may require additional payload assembly", "reconnection requires restored to continue and issue fresh data requests; no byte-offset replay"],
                    "stages": ["Apple TSS", "iBSS", "local policy and stage 1 firmware", "iBEC", "restore ramdisk and kernel", "restored", "ASR filesystem transfer", "final status"]
            }))?;
        }
        Command::TssRequest {
            ipsw,
            ecid,
            identity,
            output,
        } => {
            let usb = usb::RecoveryUsb::open(ecid)?;
            let ipsw = Ipsw::open(&ipsw)?;
            let identity = ipsw.select_behavior(&usb.info, identity, Behavior::Erase)?;
            let request = tss::request(&usb.info, &identity)?;
            let mut file = std::fs::File::options()
                .create_new(true)
                .write(true)
                .open(&output)?;
            request.to_writer_xml(&mut file)?;
            println!("TSS request saved to {}", output.display());
        }
        Command::Download {
            url,
            output,
            sha256,
        } => {
            net::download(&url, &output, &sha256)?;
            println!("Verified firmware saved to {}", output.display());
        }
        Command::Fetch { ecid, firmware_dir } => {
            let device = usb::RecoveryUsb::open(ecid)?.info;
            let directory = firmware_dir.map_or_else(catalog::cache_directory, Ok)?;
            let path = catalog::obtain(&device, &directory, None, Behavior::Erase)?;
            println!("Verified firmware saved to {}", path.display());
        }
        Command::Restore { args, erase } => {
            ensure!(
                erase && args.experimental,
                "--erase and --experimental are required"
            );
            args.run(Behavior::Erase)?;
        }
        Command::Revive(args) => args.run(Behavior::Update)?,
    }
    Ok(())
}

#[cfg(test)]
#[path = "../tests/unit/cli.rs"]
mod tests;
