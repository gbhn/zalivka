use anyhow::{Context, Result, ensure};
use clap::{Args, Parser, Subcommand};
use serde_json::json;
use std::path::PathBuf;
use zalivka::{
    device::parse_ecid,
    drivers,
    ipsw::{Behavior, Ipsw},
    net, operations, restore, tss, usb, wire,
};

#[derive(Parser)]
#[command(
    version = zalivka::VERSION,
    about = "Native Rust Mac DFU tools (experimental restore engine)"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
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
    /// Experimental erase restore. See README.md and docs/validation.md for tested scenarios.
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

#[derive(Args)]
struct RestoreArgs {
    /// Local IPSW; omitted to automatically download the current compatible image.
    ipsw: Option<PathBuf>,
    /// Firmware cache for automatic downloads.
    #[arg(long, conflicts_with = "ipsw")]
    firmware_dir: Option<PathBuf>,
    #[arg(long, value_parser = parse_ecid)]
    ecid: u64,
    #[arg(long)]
    identity: Option<usize>,
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

impl From<RestoreArgs> for operations::Restore {
    fn from(args: RestoreArgs) -> Self {
        Self {
            ipsw: args.ipsw,
            firmware_dir: args.firmware_dir,
            release: None,
            ecid: args.ecid,
            identity: args.identity,
            transcript: args.transcript,
            authorization_tokens: args.authorization_tokens,
            apple_connect_data: args.apple_connect_data,
        }
    }
}

#[derive(Subcommand)]
enum DriverCommand {
    /// Check Apple USB drivers and the Apple service.
    Status,
    /// Install missing Apple USB drivers and stop AMDS (Windows UAC).
    Prepare,
    /// Reset Apple DFU / Recovery / Restore device records and reinstall the USB driver (Windows UAC).
    Reset,
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
    let digits = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
        .unwrap_or(value);
    if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("PID must contain hexadecimal digits".into());
    }
    let pid = u16::from_str_radix(digits, 16).map_err(|e| e.to_string())?;
    if pid == 0 {
        return Err("USB PID cannot be zero".into());
    }
    Ok(pid)
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
    #[cfg(all(windows, feature = "gui"))]
    #[allow(unsafe_code)]
    {
        // GUI builds never allocate a console. CLI calls can reuse their parent's
        // terminal; redirected standard handles remain inherited from the caller.
        unsafe {
            windows_sys::Win32::System::Console::AttachConsole(
                windows_sys::Win32::System::Console::ATTACH_PARENT_PROCESS,
            );
        }
    }
    let cli = Cli::parse();
    match cli.command {
        #[cfg(feature = "gui")]
        Command::Gui => crate::gui::run()?,
        Command::Doctor => {
            let diagnostics = operations::doctor()?;
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
            DriverCommand::Prepare => operations::prepare_windows()?,
            DriverCommand::Reset => operations::reset_drivers()?,
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
            print_json(&operations::verify(&ipsw, checksum.as_deref())?)?;
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
            let mut identity = if let Some(index) = identity {
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
            let stages = restore::preflight(&mut ipsw, &mut identity)?;
            print_json(&json!({
                    "ecid": ecid.map(|n| format!("{n:016x}")), "hardware_checked": ecid.is_some(),
                    "identity": summary, "filesystem_bytes": ipsw.size(identity.path("OS")?)?,
                    "boot_components_verified": true, "hardware_restore_validated": false,
                    "validation_scope": "this plan checks boot components; it does not perform a hardware restore",
                    "hardware_validation_report": "docs/validation.md",
                    "limitations": ["firmware updaters require explicit device requests or an unambiguous namespace with a verified plist payload bundle", "reconnection requires restored to continue and issue fresh data requests; no byte-offset replay"],
                    "iboot_firmware_stages": stages,
                    "runtime_operations_known": false
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
            operations::fetch(ecid, firmware_dir.as_deref(), None)?;
        }
        Command::Restore { args, erase } => {
            ensure!(erase, "--erase is required");
            operations::Restore::from(args).run(Behavior::Erase)?;
        }
        Command::Revive(args) => operations::Restore::from(args).run(Behavior::Update)?,
    }
    Ok(())
}

#[cfg(test)]
#[path = "../tests/unit/cli.rs"]
mod tests;
