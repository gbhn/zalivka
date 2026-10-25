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

use anyhow::Result;
use eframe::egui;
use std::{
    collections::VecDeque,
    path::PathBuf,
    sync::mpsc::{self, Receiver, Sender},
    time::{Duration, Instant},
};
use zalivka::{
    device::{DeviceInfo, Mode, parse_ecid},
    drivers,
    logging::{Level, Record},
    progress, usb,
};

const SCAN_INTERVAL: Duration = Duration::from_secs(2);

pub fn run() -> Result<()> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1020.0, 800.0])
            .with_min_inner_size([700.0, 640.0]),
        ..Default::default()
    };
    eframe::run_native(
        "Zalivka",
        options,
        Box::new(|cc| {
            #[cfg(windows)]
            #[allow(unsafe_code)]
            {
                // Detach this GUI process after window creation. CLI workers retain their pipes.
                unsafe { windows_sys::Win32::System::Console::FreeConsole() };
            }
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
    Picked(Picker, Option<PathBuf>),
    Saved(std::result::Result<PathBuf, String>),
}

struct Notice {
    title: String,
    detail: String,
    tone: Tone,
}
struct Confirmation {
    action: Action,
    ecid: u64,
    accepted: bool,
}

struct App {
    setup: Setup,
    devices: Vec<DeviceInfo>,
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
            setup: Setup::default(),
            devices: vec![],
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
            return Some("Перезагрузите Windows после установки драйвера");
        }
        match &self.host {
            Err(_) => return Some("Не удалось проверить подготовку Windows"),
            Ok(Some(host)) => {
                if let Some(reason) = host.blocking_reason() {
                    return Some(reason);
                }
            }
            Ok(None) if cfg!(windows) => return Some("Проверяем подготовку Windows"),
            _ => {}
        }
        match self.target() {
            None => {
                return Some(if self.devices.is_empty() {
                    "Подключите Mac в режиме DFU"
                } else {
                    "Выберите Mac"
                });
            }
            Some(d) if d.mode != Mode::Dfu => return Some("Переведите Mac в режим DFU"),
            _ => {}
        }
        if !self.setup.automatic && self.setup.local_file().is_err() {
            return Some("Выберите файл IPSW");
        }
        None
    }
    fn error(&mut self, title: impl Into<String>, error: impl std::fmt::Display) {
        self.notice = Some(Notice {
            title: title.into(),
            detail: error.to_string(),
            tone: Tone::Error,
        });
    }
    fn journal_text(&self) -> String {
        self.logs
            .iter()
            .filter(|record| self.log_details || record.level != Level::Debug)
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join("\n")
    }
    fn journal_line(&mut self, line: Record) {
        self.logs.push_back(line);
        while self.logs.len() > 4000 {
            self.logs.pop_front();
        }
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
    fn pick(&mut self, picker: Picker, ctx: &egui::Context) {
        if self.picking {
            return;
        }
        self.picking = true;
        if let Err(e) = self.background(ctx, "file", move || {
            let dialog = rfd::FileDialog::new();
            let path = match picker {
                Picker::Firmware => dialog
                    .set_title("Выберите прошивку")
                    .add_filter("Apple IPSW", &["ipsw"])
                    .pick_file(),
                Picker::Cache => dialog.set_title("Папка прошивок").pick_folder(),
                Picker::Tokens => dialog
                    .set_title("Файл токенов")
                    .add_filter("Property list", &["plist"])
                    .pick_file(),
                Picker::Connect => dialog.set_title("Файл DAWTKN").pick_file(),
                Picker::Log => dialog
                    .set_title("Сохранить журнал")
                    .set_file_name("zalivka.log")
                    .save_file(),
            };
            Event::Picked(picker, path)
        }) {
            self.picking = false;
            self.error("Не удалось открыть окно выбора", e);
        }
    }
    fn start(&mut self, action: Action, ctx: &egui::Context) {
        if self.job.is_some() {
            return;
        }
        if action.writes_device()
            && let Some(reason) = self.blocked_reason()
        {
            self.error("Операция недоступна", reason);
            return;
        }
        if matches!(action, Action::Doctor | Action::PrepareWindows) {
            self.journal_open = true;
        }
        self.next_job += 1;
        let id = self.next_job;
        let result = Job::spawn(id, action, &self.setup, &self.tx, ctx);
        match result {
            Ok((mut job, path)) => {
                self.logs.clear();
                let record = job.record(Record::new(
                    Level::Info,
                    "session",
                    format!(
                        "Начало: {}; Zalivka {}{}",
                        action.title(),
                        zalivka::VERSION,
                        if self.setup.ecid.is_empty() {
                            String::new()
                        } else {
                            format!("; ECID: {}", self.setup.ecid)
                        }
                    ),
                ));
                self.journal_line(record);
                self.log_path = Some(path);
                self.notice = None;
                self.job = Some(job);
            }
            Err(e) => self.error("Не удалось начать операцию", format!("{e:#}")),
        }
    }
}

#[cfg(test)]
#[path = "../tests/unit/gui.rs"]
mod tests;
