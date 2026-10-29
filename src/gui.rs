mod cards;
mod dialogs;
mod events;
mod setup;
mod widgets;
use setup::{Action, Setup};
mod theme;
mod view;
mod worker;
use worker::{Job, Output};

use theme::{Tone, configure};

use anyhow::{Context, Result};
use eframe::egui;
use std::{
    collections::VecDeque,
    path::PathBuf,
    process::{Command, Stdio},
    sync::mpsc::{self, Receiver, Sender},
    time::{Duration, Instant},
};
use zalivka::{
    catalog,
    device::{DeviceInfo, Mode, parse_ecid},
    drivers,
    logging::{Level, Record},
    progress, usb,
};

const SCAN_INTERVAL: Duration = Duration::from_secs(2);
// Progress arrives twice per second. Background work must not drive the GPU
// at the display's refresh rate; egui still repaints immediately for user input.
const UI_REFRESH_INTERVAL: Duration = Duration::from_millis(500);
const NOTICE_LIFETIME: Duration = Duration::from_secs(5);

fn trim_logs(records: &mut VecDeque<Record>) {
    if records.len() > 4000 {
        // Byte dumps must not evict the visible operation history.
        let index = records
            .iter()
            .position(|record| record.level < Level::Info)
            .unwrap_or(0);
        records.remove(index);
    }
}

fn logo_icon() -> egui::IconData {
    eframe::icon_data::from_png_bytes(include_bytes!("../assets/logo.png"))
        .expect("embedded logo must be a valid PNG")
}

pub fn run() -> Result<()> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_icon(eframe::icon_data::from_png_bytes(include_bytes!(
                "../assets/window-icon.png"
            ))?)
            .with_inner_size([1280.0, 900.0])
            .with_min_inner_size([480.0, 360.0]),
        ..Default::default()
    };
    eframe::run_native(
        "Zalivka",
        options,
        Box::new(|cc| {
            configure(&cc.egui_ctx);
            Ok(Box::new(App::new()))
        }),
    )
    .map_err(|error| anyhow::anyhow!("opening desktop interface: {error}"))
}

#[derive(Clone, Copy)]
enum Picker {
    Firmware,
    Cache,
    Tokens,
    Connect,
    Log,
}
enum Event {
    Scan {
        devices: std::result::Result<Vec<DeviceInfo>, String>,
        host: std::result::Result<Option<drivers::HostStatus>, String>,
    },
    Worker(u64, Output),
    Firmware(u64, std::result::Result<catalog::Release, String>),
    Picked(Picker, Option<PathBuf>),
    Saved(std::result::Result<PathBuf, String>),
}

struct Notice {
    title: String,
    detail: String,
    journal_error: Option<String>,
    tone: Tone,
    expires_at: Option<Instant>,
}
struct Confirmation {
    action: Action,
    ecid: u64,
    accepted: bool,
}

struct FirmwareSelection {
    device: DeviceInfo,
    request: u64,
    release: Option<std::result::Result<catalog::Release, String>>,
}

impl FirmwareSelection {
    fn matches(&self, device: &DeviceInfo) -> bool {
        self.device.ecid == device.ecid
            && self.device.chip_id == device.chip_id
            && self.device.board_id == device.board_id
            && self.device.mode == device.mode
    }
}

struct App {
    localization: zalivka::localization::Localizer,
    logo: Option<egui::TextureHandle>,
    setup: Setup,
    devices: Vec<DeviceInfo>,
    firmware: Option<FirmwareSelection>,
    next_firmware_request: u64,
    scanning: bool,
    scan_error: Option<String>,
    host: std::result::Result<Option<drivers::HostStatus>, String>,
    windows_reboot_required: bool,
    last_scan: Instant,
    tx: Sender<Event>,
    rx: Receiver<Event>,
    next_job: u64,
    job: Option<Job>,
    logs: VecDeque<Record>,
    log_details: bool,
    log_path: Option<PathBuf>,
    notice: Option<Notice>,
    journal_open: bool,
    settings_open: bool,
    picking: bool,
    confirmation: Option<Confirmation>,
}

impl App {
    fn new() -> Self {
        let (tx, rx) = mpsc::channel();
        Self {
            localization: zalivka::localization::Localizer::load(),
            logo: None,
            setup: Setup::default(),
            devices: vec![],
            firmware: None,
            next_firmware_request: 0,
            scanning: false,
            scan_error: None,
            host: Ok(None),
            windows_reboot_required: false,
            last_scan: Instant::now() - SCAN_INTERVAL,
            tx,
            rx,
            next_job: 0,
            job: None,
            logs: VecDeque::new(),
            log_details: false,
            log_path: None,
            notice: None,
            journal_open: false,
            settings_open: false,
            picking: false,
            confirmation: None,
        }
    }
    fn target(&self) -> Option<&DeviceInfo> {
        let ecid = parse_ecid(self.setup.ecid.trim()).ok()?;
        self.devices.iter().find(|d| d.ecid == ecid)
    }
    fn blocked_reason(&self) -> Option<&'static str> {
        if self.windows_reboot_required {
            return Some("Restart Windows after installing the driver");
        }
        match &self.host {
            Err(_) => return Some("Could not check Windows readiness"),
            Ok(Some(host)) => {
                if let Some(reason) = host.blocking_reason() {
                    return Some(reason);
                }
            }
            Ok(None) if cfg!(windows) => return Some("Checking Windows readiness"),
            _ => {}
        }
        match self.target() {
            None => {
                return Some(if self.devices.is_empty() {
                    "Connect a Mac in DFU mode"
                } else {
                    "Select a Mac"
                });
            }
            Some(d) if d.mode != Mode::Dfu => return Some("Put the Mac in DFU mode"),
            _ => {}
        }
        if !self.setup.automatic && self.setup.local_file().is_err() {
            return Some("Select an IPSW file");
        }
        None
    }
    fn error(&mut self, title: impl Into<String>, error: impl std::fmt::Display) {
        self.notice = Some(Notice {
            title: title.into(),
            detail: error.to_string(),
            journal_error: None,
            tone: Tone::Error,
            expires_at: None,
        });
    }
    fn journal_text(&self, details: bool) -> String {
        self.logs
            .iter()
            .filter(|record| details || record.level >= Level::Info)
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join("\n")
    }
    fn journal_error(&mut self, error: Option<&str>) {
        if self.log_path.is_some()
            && let Some(error) = error
        {
            self.log_path = None;
            self.error(
                "The disk journal is incomplete",
                format!("{error}. You can save the recent journal history from memory."),
            );
            self.journal_open = true;
        }
    }
    fn journal_line(&mut self, line: Record) {
        self.logs.push_back(line);
        trim_logs(&mut self.logs);
    }
    fn background(
        &self,
        ctx: &egui::Context,
        name: &str,
        task: impl FnOnce() -> Event + Send + 'static,
    ) -> std::io::Result<()> {
        let tx = self.tx.clone();
        let ctx = ctx.clone();
        std::thread::Builder::new()
            .name(format!("zalivka-{name}"))
            .spawn(move || {
                let _ = tx.send(task());
                ctx.request_repaint();
            })
            .map(|_| ())
    }
    fn detect(&mut self, ctx: &egui::Context) {
        if self.scanning || self.job.is_some() {
            return;
        }
        self.scanning = true;
        self.last_scan = Instant::now();
        if let Err(e) = self.background(ctx, "detect", || Event::Scan {
            host: drivers::host_status().map_err(|e| format!("{e:#}")),
            devices: usb::detect().map_err(|e| format!("{e:#}")),
        }) {
            self.scanning = false;
            self.scan_error = Some(e.to_string());
        }
    }
    fn refresh_firmware(&mut self, ctx: &egui::Context, retry: bool) {
        let Some(device) = self.target().cloned() else {
            self.firmware = None;
            return;
        };
        if !retry
            && self
                .firmware
                .as_ref()
                .is_some_and(|firmware| firmware.matches(&device))
        {
            return;
        }
        self.next_firmware_request += 1;
        let request = self.next_firmware_request;
        self.firmware = Some(FirmwareSelection {
            device: device.clone(),
            request,
            release: None,
        });
        if let Err(error) = self.background(ctx, "firmware", move || {
            Event::Firmware(
                request,
                catalog::latest(&device).map_err(|e| format!("{e:#}")),
            )
        }) {
            self.firmware.as_mut().unwrap().release = Some(Err(error.to_string()));
        }
    }
    fn pick(&mut self, picker: Picker, ctx: &egui::Context) {
        if self.picking {
            return;
        }
        self.picking = true;
        let title = zalivka::localization::text(match picker {
            Picker::Firmware => "Select firmware",
            Picker::Cache => "Firmware folder",
            Picker::Tokens => "Token file",
            Picker::Connect => "DAWTKN file",
            Picker::Log => "Save journal",
        });
        if let Err(e) = self.background(ctx, "file", move || {
            let dialog = rfd::FileDialog::new();
            let path = match picker {
                Picker::Firmware => dialog
                    .set_title(&title)
                    .add_filter("Apple IPSW", &["ipsw"])
                    .pick_file(),
                Picker::Cache => dialog.set_title(&title).pick_folder(),
                Picker::Tokens => dialog
                    .set_title(&title)
                    .add_filter("Property list", &["plist"])
                    .pick_file(),
                Picker::Connect => dialog.set_title(&title).pick_file(),
                Picker::Log => dialog
                    .set_title(&title)
                    .set_file_name("zalivka.log")
                    .save_file(),
            };
            Event::Picked(picker, path)
        }) {
            self.picking = false;
            self.error("Could not open the file picker", e);
        }
    }
    fn open_firmware_folder(&self) -> Result<()> {
        let directory = if self.setup.cache.trim().is_empty() {
            catalog::cache_directory()?
        } else {
            PathBuf::from(self.setup.cache.trim())
        };
        std::fs::create_dir_all(&directory).context("creating firmware directory")?;
        let directory = std::path::absolute(directory).context("locating firmware directory")?;
        #[cfg(windows)]
        let opener = "explorer.exe";
        #[cfg(target_os = "macos")]
        let opener = "open";
        #[cfg(not(any(windows, target_os = "macos")))]
        let opener = "xdg-open";
        let mut child = Command::new(opener)
            .arg(directory)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .context("opening firmware directory")?;
        std::thread::spawn(move || {
            let _ = child.wait();
        });
        Ok(())
    }
    fn start(&mut self, action: Action, ctx: &egui::Context) {
        if self.job.is_some() {
            return;
        }
        if action.writes_device()
            && let Some(reason) = self.blocked_reason()
        {
            self.error("Operation unavailable", reason);
            return;
        }
        if matches!(
            action,
            Action::Doctor | Action::PrepareWindows | Action::ResetDrivers
        ) {
            self.journal_open = true;
        }
        self.next_job += 1;
        let id = self.next_job;
        let mut setup = self.setup.clone();
        setup.release = self.firmware.as_ref().and_then(|selection| {
            self.target()
                .filter(|device| selection.matches(device))
                .and(selection.release.as_ref())
                .and_then(|release| release.as_ref().ok())
                .cloned()
        });
        let result = Job::spawn(
            id,
            action,
            &setup,
            &self.tx,
            ctx,
            self.windows_reboot_required,
        );
        match result {
            Ok((job, path)) => {
                self.logs.clear();
                self.log_path = Some(path);
                self.notice = None;
                self.job = Some(job);
                self.collect_job_logs();
            }
            Err(e) => self.error("Could not start the operation", format!("{e:#}")),
        }
    }
}

#[cfg(test)]
#[path = "../tests/unit/gui.rs"]
mod tests;
