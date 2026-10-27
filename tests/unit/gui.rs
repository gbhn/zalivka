use super::*;
use std::{ffi::OsString, fs::File, path::Path};

fn job(action: Action) -> Job {
    let mut child = std::process::Command::new(std::env::current_exe().unwrap())
        .arg("--help")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();
    assert!(child.wait().unwrap().success());
    Job::new(7, action, child, tempfile::tempfile().unwrap())
}

fn render_app(app: &mut App, ctx: &egui::Context, frame: u32) -> egui::FullOutput {
    ctx.run(
        egui::RawInput {
            screen_rect: Some(egui::Rect::from_min_size(
                egui::Pos2::ZERO,
                egui::vec2(1020.0, 800.0),
            )),
            time: Some(f64::from(frame) / 60.0),
            ..Default::default()
        },
        |ctx| eframe::App::update(app, ctx, &mut eframe::Frame::_new_kittest()),
    )
}

#[test]
fn active_operations_wait_for_updates_instead_of_redrawing_at_monitor_refresh_rate() {
    for action in [
        Action::Restore,
        Action::Download,
        Action::Verify,
        Action::UsbInternet,
    ] {
        for fraction in [None, Some(0.5)] {
            let mut app = App::new();
            let mut job = job(action);
            job.overall_fraction = fraction;
            let mut update = transfer(1, "Файловая система");
            update.total = fraction.map(|_| 100);
            job.output(Output::State(progress::Event::Transfer(update)));
            app.job = Some(job);
            app.journal_open = true;
            app.journal_line(Record::new(Level::Info, "test", "Передача идёт"));
            let ctx = egui::Context::default();
            configure(&ctx);
            for frame in 0..12 {
                let output = render_app(&mut app, &ctx, frame);
                if frame == 11 {
                    let delay = output.viewport_output[&egui::ViewportId::ROOT].repaint_delay;
                    assert!(
                        delay >= Duration::from_millis(400),
                        "{action:?}, fraction={fraction:?}: redraw in {delay:?}"
                    );
                    assert!(
                        delay <= Duration::from_millis(500),
                        "active progress must still refresh: {delay:?}"
                    );
                }
            }
        }
    }
}

#[test]
fn scanning_devices_does_not_start_a_continuous_animation() {
    let mut app = App::new();
    app.scanning = true;
    let ctx = egui::Context::default();
    configure(&ctx);
    for frame in 0..12 {
        let output = render_app(&mut app, &ctx, frame);
        if frame == 11 {
            assert!(
                output.viewport_output[&egui::ViewportId::ROOT].repaint_delay
                    >= Duration::from_millis(400)
            );
        }
    }
}

#[test]
fn throttled_background_paints_do_not_delay_input_or_drop_worker_updates() {
    let mut app = App::new();
    app.job = Some(job(Action::Restore));
    let ctx = egui::Context::default();
    configure(&ctx);
    let mut journal_button = None;
    for frame in 0..12 {
        let output = render_app(&mut app, &ctx, frame);
        journal_button = output.shapes.iter().find_map(|shape| match &shape.shape {
            egui::Shape::Text(text) if text.galley.text() == "Журнал" => {
                Some(text.pos + egui::vec2(4.0, 4.0))
            }
            _ => None,
        });
    }
    let pos = journal_button.expect("journal button");
    app.tx
        .send(Event::Worker(
            7,
            Output::State(progress::Event::Checkpoint {
                name: "writing_filesystem".into(),
                complete: false,
            }),
        ))
        .unwrap();
    let _ = ctx.run(
        egui::RawInput {
            screen_rect: Some(egui::Rect::from_min_size(
                egui::Pos2::ZERO,
                egui::vec2(1020.0, 800.0),
            )),
            time: Some(12.0 / 60.0),
            events: vec![
                egui::Event::PointerMoved(pos),
                egui::Event::PointerButton {
                    pos,
                    button: egui::PointerButton::Primary,
                    pressed: true,
                    modifiers: egui::Modifiers::NONE,
                },
                egui::Event::PointerButton {
                    pos,
                    button: egui::PointerButton::Primary,
                    pressed: false,
                    modifiers: egui::Modifiers::NONE,
                },
            ],
            ..Default::default()
        },
        |ctx| eframe::App::update(&mut app, ctx, &mut eframe::Frame::_new_kittest()),
    );
    assert!(
        app.journal_open,
        "clicks must be applied in the input frame"
    );
    assert_eq!(app.job.as_ref().unwrap().phase, "Этап: writing filesystem");
}

fn worker_line(event: progress::Event) -> String {
    let mut line = Vec::new();
    event.write_to(&mut line).unwrap();
    String::from_utf8(line).unwrap().trim_end().to_owned()
}

fn send_worker(app: &mut App, event: progress::Event) {
    app.tx
        .send(Event::Worker(7, Output::parse(worker_line(event), true)))
        .unwrap();
    app.poll(&egui::Context::default());
}

#[test]
fn a_log_burst_leaves_time_for_rendering_without_losing_records() {
    let mut app = App::new();
    app.job = Some(job(Action::Doctor));
    for index in 0..600 {
        app.tx
            .send(Event::Worker(7, Output::Line(format!("line {index}"))))
            .unwrap();
    }
    let ctx = egui::Context::default();
    app.poll(&ctx);
    assert_eq!(app.logs.len(), 256);
    app.poll(&ctx);
    app.poll(&ctx);
    assert_eq!(app.logs.len(), 600);
    assert_eq!(app.logs.back().unwrap().message, "line 599");
}
fn device(ecid: u64, mode: Mode) -> DeviceInfo {
    DeviceInfo {
        ecid,
        chip_id: 0x8103,
        board_id: 0x26,
        security_domain: Some(1),
        iboot_flags: Some(0),
        chip_fuse_mode: Some(3),
        mode,
        serial: String::new(),
        ap_nonce: vec![],
        sep_nonce: vec![],
    }
}
#[test]
fn erase_confirmation_is_bound_to_target_and_explicit_consent() {
    let mut p = Confirmation {
        action: Action::Restore,
        ecid: 42,
        accepted: false,
    };
    assert!(!p.ready(Some(&device(42, Mode::Dfu))));
    p.accepted = true;
    assert!(p.ready(Some(&device(42, Mode::Dfu))));
    assert!(!p.ready(Some(&device(43, Mode::Dfu))));
    assert!(!p.ready(Some(&device(42, Mode::Recovery))));
    assert!(!p.ready(None));
    p.action = Action::Revive;
    assert!(p.ready(Some(&device(42, Mode::Dfu))));
}
#[test]
fn worker_arguments_preserve_mode_authorization_and_transcript() {
    let s = Setup {
        ecid: "2a".into(),
        cache: "cache".into(),
        tokens: "tokens.plist".into(),
        connect_data: "connect.data".into(),
        ..Setup::default()
    };
    let revive = s
        .arguments(Action::Revive, Some(Path::new("run.jsonl")))
        .unwrap();
    assert!(revive.contains(&"--experimental".into()));
    assert!(!revive.contains(&"--erase".into()));
    assert!(revive.contains(&"--transcript".into()));
    assert!(revive.contains(&"run.jsonl".into()));
    assert!(revive.contains(&"--authorization-tokens".into()));
    assert!(
        s.arguments(Action::Restore, None)
            .unwrap()
            .contains(&"--erase".into())
    );
    let download = s.arguments(Action::Download, None).unwrap();
    assert!(!download.contains(&"--experimental".into()));
    assert!(!download.contains(&"--authorization-tokens".into()));
    assert_eq!(
        Setup::default().arguments(Action::Doctor, None).unwrap(),
        vec![OsString::from("doctor")]
    );
    assert_eq!(
        Setup::default()
            .arguments(Action::PrepareWindows, None)
            .unwrap(),
        vec![OsString::from("drivers"), OsString::from("prepare")]
    );
    assert_eq!(
        Setup::default()
            .arguments(Action::ResetDrivers, None)
            .unwrap(),
        vec![OsString::from("drivers"), OsString::from("reset")]
    );
}
#[test]
fn local_firmware_is_required_and_does_not_pass_a_cache_option() {
    let file = tempfile::Builder::new().suffix(".IPSW").tempfile().unwrap();
    let mut s = Setup {
        automatic: false,
        ecid: "2a".into(),
        ipsw: file.path().display().to_string(),
        cache: "cache".into(),
        ..Setup::default()
    };
    let args = s.arguments(Action::Revive, None).unwrap();
    assert_eq!(args[1], file.path().as_os_str());
    assert!(!args.contains(&"--firmware-dir".into()));
    s.ipsw = "missing.ipsw".into();
    assert!(s.arguments(Action::Revive, None).is_err());
    assert!(s.arguments(Action::Verify, None).is_err());
}
#[test]
fn disconnected_or_recovery_target_blocks_a_write() {
    let mut app = App::new();
    app.host = Ok(Some(drivers::HostStatus {
        apple_service_installed: false,
        apple_service_running: false,
        apple_driver_installed: true,
        compatible_usb_driver: false,
        usb_network_driver_available: true,
        usb_network_interfaces: vec![],
    }));
    app.setup.ecid = "2a".into();
    assert!(app.blocked_reason().is_some());
    app.devices.push(device(42, Mode::Recovery));
    assert!(app.blocked_reason().is_some());
    app.devices[0].mode = Mode::Dfu;
    assert!(app.blocked_reason().is_none());
    if let Ok(Some(host)) = &mut app.host {
        host.usb_network_interfaces
            .push(drivers::UsbNetworkInterfaceStatus {
                serial: "TEST".into(),
                interface: 1,
                instance_id: "TEST_MI_01".into(),
                ready: false,
                error: Some("WinUSB is missing".into()),
            });
        assert!(host.needs_preparation());
    }
    assert!(app.blocked_reason().is_none());
    app.setup.automatic = false;
    assert!(app.blocked_reason().is_some());
}
#[test]
fn windows_conflicts_and_failed_checks_block_restore_before_worker_start() {
    let mut app = App::new();
    app.setup.ecid = "2a".into();
    app.devices.push(device(42, Mode::Dfu));
    let host = drivers::HostStatus {
        apple_service_installed: true,
        apple_service_running: true,
        apple_driver_installed: true,
        compatible_usb_driver: false,
        usb_network_driver_available: true,
        usb_network_interfaces: vec![],
    };
    app.host = Ok(Some(host.clone()));
    app.start(Action::Revive, &egui::Context::default());
    assert!(app.job.is_none());
    assert!(
        app.notice
            .as_ref()
            .unwrap()
            .detail
            .contains("Apple Mobile Device Service")
    );
    app.host = Ok(Some(drivers::HostStatus {
        apple_service_running: false,
        ..host
    }));
    assert!(app.blocked_reason().is_none());
    app.host = Err("service access denied".into());
    assert!(app.blocked_reason().is_some());
    app.windows_reboot_required = true;
    assert!(app.blocked_reason().unwrap().contains("Перезагрузите"));
}
#[test]
fn scan_results_keep_host_and_usb_failures_independent() {
    let mut app = App::new();
    let ctx = egui::Context::default();
    app.scanning = true;
    app.tx
        .send(Event::Scan {
            devices: Ok(vec![device(42, Mode::Dfu)]),
            host: Err("service access denied".into()),
        })
        .unwrap();
    app.poll(&ctx);
    assert!(!app.scanning);
    assert_eq!(app.target().unwrap().ecid, 42);
    assert!(app.scan_error.is_none());
    assert_eq!(app.host.as_ref().unwrap_err(), "service access denied");
    assert!(app.blocked_reason().is_some());

    app.scanning = true;
    app.tx
        .send(Event::Scan {
            devices: Err("USB access denied".into()),
            host: Ok(None),
        })
        .unwrap();
    app.poll(&ctx);
    assert!(!app.scanning);
    assert!(app.devices.is_empty());
    assert_eq!(app.scan_error.as_deref(), Some("USB access denied"));
    assert!(matches!(app.host, Ok(None)));
}

#[test]
fn stale_worker_events_do_not_enter_a_new_journal() {
    for active in [false, true] {
        let mut app = App::new();
        if active {
            app.job = Some(job(Action::Restore));
        }
        for output in [
            Output::Line("stale error".into()),
            Output::State(progress::Event::RestoreCompleted),
            Output::State(progress::Event::RebootRequired),
            Output::Closed,
        ] {
            app.tx.send(Event::Worker(999, output)).unwrap();
        }
        app.poll(&egui::Context::default());
        assert!(app.logs.is_empty());
        assert!(app.notice.is_none());
        assert!(!app.windows_reboot_required);
        if let Some(job) = app.job {
            assert_eq!(job.readers, 2);
            assert!(!job.restore_completed);
        }
    }
}

#[test]
fn structured_journal_filters_details_and_saves_each_record_once() {
    let log = tempfile::NamedTempFile::new().unwrap();
    let mut app = App::new();
    let mut operation = job(Action::Restore);
    operation.log = log.reopen().unwrap();
    app.job = Some(operation);
    for (level, message) in [
        (Level::Debug, "protocol details"),
        (Level::Info, "Error: this text is informational"),
        (Level::Warning, "retry"),
        (Level::Error, "connection failed"),
    ] {
        send_worker(
            &mut app,
            progress::Event::Log(Record::new(level, "test", message)),
        );
    }
    assert_eq!(app.logs.len(), 4);
    assert_eq!(app.logs[1].level, Level::Info);
    assert!(
        !app.journal_text(app.log_details)
            .contains("protocol details")
    );
    assert!(
        app.journal_text(app.log_details)
            .contains("connection failed")
    );
    app.log_details = true;
    assert!(
        app.journal_text(app.log_details)
            .contains("protocol details")
    );
    send_worker(
        &mut app,
        progress::Event::Transfer(progress::Update {
            id: 1,
            stage: "ASR".into(),
            completed: 0,
            total: Some(100),
            bytes_per_second: 0.0,
            elapsed_seconds: 0.0,
            finished: false,
        }),
    );
    assert_eq!(app.logs.len(), 4);
    let saved = std::fs::read_to_string(log.path()).unwrap();
    assert_eq!(saved.lines().count(), 4);
    assert!(saved.contains("protocol details"));
    assert!(!saved.contains(progress::EVENT_PREFIX));
}

#[test]
fn failed_journal_writes_keep_worker_state_and_report_partial_logging() {
    let log = tempfile::NamedTempFile::new().unwrap();
    let mut operation = job(Action::Restore);
    operation.log = File::open(log.path()).unwrap();
    let mut app = App::new();
    app.log_path = Some(log.path().into());
    app.job = Some(operation);
    send_worker(
        &mut app,
        progress::Event::Log(Record::new(Level::Debug, "test", "original record")),
    );
    assert!(app.log_path.is_none());
    assert!(app.journal_open);
    assert!(app.notice.as_ref().unwrap().title.contains("неполный"));
    assert!(app.logs[0].message.contains("original record"));
    assert_eq!(app.logs[0].level, Level::Warning);
    assert!(!app.job.as_ref().unwrap().can_stop());
    send_worker(
        &mut app,
        progress::Event::Log(Record::new(Level::Info, "test", "next record")),
    );
    assert_eq!(app.logs[1].message, "next record");
    send_worker(&mut app, progress::Event::RestoreCompleted);
    assert!(app.job.as_ref().unwrap().can_stop());
    for _ in 0..2 {
        app.tx.send(Event::Worker(7, Output::Closed)).unwrap();
    }
    app.poll(&egui::Context::default());
    let notice = app.notice.as_ref().unwrap();
    assert_eq!(notice.title, Action::Restore.completed_title());
    assert_eq!(notice.tone, Tone::Neutral);
    assert!(notice.detail.contains("Журнал на диске неполный"));
    assert!(std::fs::read(log.path()).unwrap().is_empty());
}

#[test]
fn a_failure_writing_the_final_record_cannot_report_a_complete_journal() {
    let log = tempfile::NamedTempFile::new().unwrap();
    let mut operation = job(Action::Verify);
    operation.log = File::open(log.path()).unwrap();
    let mut app = App::new();
    app.log_path = Some(log.path().into());
    app.job = Some(operation);
    for _ in 0..2 {
        app.tx.send(Event::Worker(7, Output::Closed)).unwrap();
    }
    app.poll(&egui::Context::default());
    assert!(app.job.is_none());
    assert!(app.log_path.is_none());
    assert!(app.journal_open);
    let notice = app.notice.as_ref().unwrap();
    assert_eq!(notice.title, Action::Verify.completed_title());
    assert_eq!(notice.tone, Tone::Neutral);
    assert!(notice.detail.contains("Журнал на диске неполный"));
}

#[test]
fn memory_journal_export_includes_hidden_details_and_marks_the_partial_copy() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("memory.log");
    let mut app = App::new();
    app.journal_line(Record::new(Level::Debug, "test", "protocol details"));
    app.journal_line(Record::new(Level::Info, "test", "visible record"));
    assert!(!app.log_details);
    app.tx
        .send(Event::Picked(Picker::Log, Some(path.clone())))
        .unwrap();
    let ctx = egui::Context::default();
    app.poll(&ctx);
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while !path.exists() && std::time::Instant::now() < deadline {
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    let saved = std::fs::read_to_string(path).unwrap();
    assert!(saved.contains("protocol details"));
    assert!(saved.contains("visible record"));
    assert!(saved.starts_with("Неполный журнал:"));
}

#[cfg(target_os = "linux")]
#[test]
fn stopped_worker_is_reaped_when_the_window_drops_without_another_poll() {
    let child = std::process::Command::new(std::env::current_exe().unwrap())
        .arg("--help")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();
    let pid = child.id();
    let mut job = Job::new(7, Action::Download, child, tempfile::tempfile().unwrap());
    job.stop().unwrap();
    drop(job);
    assert!(!Path::new(&format!("/proc/{pid}")).exists());
}

#[test]
fn exited_worker_keeps_final_lines_until_both_readers_finish() {
    let log = tempfile::NamedTempFile::new().unwrap();
    let mut app = App::new();
    let ctx = egui::Context::default();
    let mut operation = job(Action::Restore);
    operation.log = log.reopen().unwrap();
    app.job = Some(operation);
    app.poll(&ctx);
    assert_eq!(app.job.as_ref().unwrap().success, Some(true));
    assert!(app.notice.is_none());
    app.tx.send(Event::Worker(999, Output::Closed)).unwrap();
    app.tx.send(Event::Worker(7, Output::Closed)).unwrap();
    app.poll(&ctx);
    assert_eq!(app.job.as_ref().unwrap().readers, 1);
    assert!(app.notice.is_none());

    app.tx
        .send(Event::Worker(
            7,
            Output::parse(
                worker_line(progress::Event::InternetUnavailable {
                    error: "disconnected".into(),
                }),
                true,
            ),
        ))
        .unwrap();
    app.tx.send(Event::Worker(7, Output::Closed)).unwrap();
    app.poll(&ctx);
    assert!(app.job.is_none());
    let notice = app.notice.as_ref().unwrap();
    assert_eq!(notice.tone, Tone::Neutral);
    assert_eq!(notice.detail, "disconnected");
    assert!(
        std::fs::read_to_string(log.path())
            .unwrap()
            .contains("disconnected")
    );
}

#[test]
fn completion_notice_preserves_cancel_failure_reboot_and_success_priority() {
    let mut job = job(Action::Restore);
    job.output(Output::State(progress::Event::InternetUnavailable {
        error: "no network".into(),
    }));
    job.cancelled = true;
    for success in [false, true] {
        let notice = job.completion_notice(success, true);
        assert_eq!(notice.title, "Операция остановлена");
        assert_eq!(notice.tone, Tone::Neutral);
    }
    job.restore_completed = true;
    let notice = job.completion_notice(false, true);
    assert_eq!(
        notice.title,
        "Восстановление завершено, раздача остановлена"
    );
    assert_eq!(notice.tone, Tone::Neutral);
    job.action = Action::Revive;
    assert_eq!(
        job.completion_notice(false, true).title,
        "Операция остановлена"
    );
    job.cancelled = false;
    for action in [
        Action::Restore,
        Action::PrepareWindows,
        Action::ResetDrivers,
    ] {
        job.action = action;
        let notice = job.completion_notice(false, true);
        assert_eq!(notice.tone, Tone::Error);
        assert!(notice.title.ends_with(": ошибка"));
    }
    let notice = job.completion_notice(true, true);
    assert_eq!(notice.title, "Перезагрузите Windows");
    assert_eq!(notice.tone, Tone::Neutral);
    job.action = Action::Restore;
    let notice = job.completion_notice(true, true);
    assert_eq!(notice.detail, "no network");
    assert_eq!(notice.tone, Tone::Neutral);
    job.output(Output::State(progress::Event::InternetReady));
    for action in [
        Action::Restore,
        Action::Revive,
        Action::Download,
        Action::UsbInternet,
    ] {
        job.action = action;
        let notice = job.completion_notice(true, true);
        assert_eq!(notice.title, action.completed_title());
        assert_eq!(notice.tone, Tone::Success);
        assert_eq!(
            notice.detail.contains("Проверьте запуск Mac"),
            action.writes_device()
        );
    }
}

#[test]
fn worker_state_survives_journal_eviction_and_allows_stopping_only_after_restore() {
    let mut app = App::new();
    app.job = Some(job(Action::Restore));
    assert!(!app.job.as_ref().unwrap().can_stop());
    app.journal_line(Record::new(Level::Info, "test", "Восстановление завершено"));
    app.journal_line(Record::new(
        Level::Warning,
        "test",
        "Перезагрузите Windows перед восстановлением Mac.",
    ));
    app.tx
        .send(Event::Worker(
            7,
            Output::parse(worker_line(progress::Event::RestoreCompleted), false),
        ))
        .unwrap();
    app.poll(&egui::Context::default());
    assert!(!app.job.as_ref().unwrap().can_stop());
    assert!(!app.windows_reboot_required);

    send_worker(
        &mut app,
        progress::Event::OperationProgress {
            operation: 28,
            progress: 50,
        },
    );
    assert_eq!(app.job.as_ref().unwrap().overall_fraction, None);
    send_worker(
        &mut app,
        progress::Event::OperationProgress {
            operation: 28,
            progress: -1,
        },
    );
    assert_eq!(app.job.as_ref().unwrap().overall_fraction, None);
    send_worker(
        &mut app,
        progress::Event::Checkpoint {
            name: "update_firmware".into(),
            complete: false,
        },
    );
    assert_eq!(app.job.as_ref().unwrap().phase, "Этап: update firmware");
    send_worker(&mut app, progress::Event::RestoreCompleted);
    send_worker(&mut app, progress::Event::InternetWaiting);
    assert!(app.job.as_ref().unwrap().can_stop());
    send_worker(&mut app, progress::Event::InternetPreparing);
    assert!(!app.job.as_ref().unwrap().can_stop());
    send_worker(&mut app, progress::Event::InternetReady);
    assert!(app.job.as_ref().unwrap().can_stop());
    assert_eq!(
        app.job.as_ref().unwrap().phase,
        "Интернет по USB, оставьте Zalivka открытой"
    );
    send_worker(
        &mut app,
        progress::Event::InternetUnavailable {
            error: "no network".into(),
        },
    );
    for index in 0..4001 {
        app.journal_line(Record::new(Level::Info, "test", format!("message {index}")));
    }
    assert_eq!(app.logs.len(), 4000);
    let job = app.job.as_mut().unwrap();
    assert_eq!(job.completion_notice(true, false).detail, "no network");
    job.cancelled = true;
    assert_eq!(
        job.completion_notice(false, false).title,
        "Восстановление завершено, раздача остановлена"
    );
    job.action = Action::PrepareWindows;
    job.cancelled = false;
    assert!(!job.can_stop());
    job.action = Action::ResetDrivers;
    assert!(!job.can_stop());
    assert_eq!(
        job.completion_notice(true, true).title,
        "Перезагрузите Windows"
    );
    send_worker(&mut app, progress::Event::RebootRequired);
    assert!(app.windows_reboot_required);
}

#[test]
fn driver_reset_waits_for_completion_and_prompts_to_reconnect_or_reboot() {
    let job = job(Action::ResetDrivers);
    assert!(!job.can_stop());
    let notice = job.completion_notice(true, false);
    assert_eq!(notice.title, Action::ResetDrivers.completed_title());
    assert!(notice.detail.contains("введите его в DFU"));
    assert_eq!(
        job.completion_notice(true, true).title,
        "Перезагрузите Windows"
    );
    assert_eq!(job.completion_notice(false, true).tone, Tone::Error);
}

#[test]
fn transfer_events_preserve_phase_order_and_stderr_never_changes_progress() {
    let mut app = App::new();
    app.job = Some(job(Action::Restore));
    let update = progress::Update {
        id: 1,
        stage: "ASR".into(),
        completed: 100,
        total: Some(100),
        bytes_per_second: 10.0,
        elapsed_seconds: 10.0,
        finished: true,
    };
    send_worker(&mut app, progress::Event::Transfer(update.clone()));
    assert!(app.job.as_ref().unwrap().transfers.is_empty());
    send_worker(
        &mut app,
        progress::Event::OperationProgress {
            operation: 28,
            progress: 50,
        },
    );
    assert!(!app.job.as_ref().unwrap().transfers.contains_key(&1));
    assert_eq!(app.job.as_ref().unwrap().overall_fraction, None);
    send_worker(&mut app, progress::Event::RestoreCompleted);
    send_worker(&mut app, progress::Event::InternetWaiting);
    send_worker(&mut app, progress::Event::InternetReady);
    let line = worker_line(progress::Event::Transfer(update));
    app.tx
        .send(Event::Worker(7, Output::parse(line.clone(), false)))
        .unwrap();
    app.poll(&egui::Context::default());
    assert!(app.job.as_ref().unwrap().transfers.is_empty());
    assert!(app.job.as_ref().unwrap().can_stop());
    assert_eq!(
        app.job.as_ref().unwrap().phase,
        "Интернет по USB, оставьте Zalivka открытой"
    );
    assert_eq!(app.logs.back().unwrap().message, line);
}

fn active_job_labels(app: &mut App, theme: egui::Theme) -> (Vec<String>, usize) {
    let ctx = egui::Context::default();
    configure(&ctx);
    ctx.set_theme(theme);
    let output = ctx.run(
        egui::RawInput {
            screen_rect: Some(egui::Rect::from_min_size(
                egui::Pos2::ZERO,
                egui::vec2(1000.0, 2000.0),
            )),
            ..Default::default()
        },
        |ctx| {
            egui::CentralPanel::default().show(ctx, |ui| app.active_job(ui));
        },
    );
    let labels = output
        .shapes
        .iter()
        .filter_map(|shape| match &shape.shape {
            egui::Shape::Text(text) => Some(text.galley.text().to_owned()),
            _ => None,
        })
        .collect();
    let cards = output
        .shapes
        .iter()
        .filter(|shape| {
            matches!(&shape.shape,
                egui::Shape::Rect(rect) if rect.rect.width() > 500.0 && rect.rect.height() > 50.0
                    && rect.fill == ctx.style().visuals.window_fill
            )
        })
        .count();
    (labels, cards)
}

fn transfer(id: u64, stage: &str) -> progress::Update {
    progress::Update {
        id,
        stage: stage.into(),
        completed: 60,
        total: Some(100),
        bytes_per_second: 10.0,
        elapsed_seconds: 6.0,
        finished: false,
    }
}

#[test]
fn only_current_transfers_render_cards_regardless_of_device_progress_order() {
    for transfer_first in [false, true] {
        let mut app = App::new();
        app.job = Some(job(Action::Restore));
        let mut update = transfer(1, "Передача файловой системы ASR");
        let mut events = vec![
            progress::Event::Transfer(update.clone()),
            progress::Event::OperationProgress {
                operation: 13,
                progress: 9,
            },
        ];
        if !transfer_first {
            events.reverse();
        }
        for event in events {
            send_worker(&mut app, event);
        }
        assert_eq!(app.job.as_ref().unwrap().transfers.len(), 1);
        for theme in [egui::Theme::Dark, egui::Theme::Light] {
            let (labels, cards) = active_job_labels(&mut app, theme);
            assert_eq!(cards, 2, "summary plus one transfer: {theme:?}");
            assert!(
                !labels
                    .iter()
                    .any(|label| label == "Общий прогресс восстановления (оценка)")
            );
            assert!(
                labels
                    .iter()
                    .any(|label| label == "Передача файловой системы ASR")
            );
            assert!(labels.iter().any(|label| label == "60%"));
            assert!(
                labels
                    .iter()
                    .any(|label| label == "Передано: 60 Б из 100 Б")
            );
            assert!(labels.iter().any(|label| label == "Скорость"));
            assert!(labels.iter().any(|label| label == "До конца передачи"));
            assert!(
                !labels
                    .iter()
                    .any(|label| label == "9%" || label == "Операция 13")
            );
        }
        // The transfer ends independently of the device's current percentage.
        update.finished = true;
        send_worker(&mut app, progress::Event::Transfer(update));
        assert!(app.job.as_ref().unwrap().transfers.is_empty());
        for theme in [egui::Theme::Dark, egui::Theme::Light] {
            assert_eq!(active_job_labels(&mut app, theme).1, 1);
        }
    }
}

#[test]
fn identical_names_never_merge_transfers_or_hide_retries() {
    let mut app = App::new();
    app.job = Some(job(Action::Restore));
    let mut first = transfer(1, "Одинаковое имя");
    let mut second = first.clone();
    second.id = 2;
    let third = transfer(3, "Одинаковое имя");
    for update in [&first, &second, &third] {
        send_worker(&mut app, progress::Event::Transfer(update.clone()));
    }
    assert_eq!(app.job.as_ref().unwrap().transfers.len(), 3);
    for theme in [egui::Theme::Dark, egui::Theme::Light] {
        assert_eq!(active_job_labels(&mut app, theme).1, 4);
    }
    first.finished = true;
    send_worker(&mut app, progress::Event::Transfer(first.clone()));
    let retry = transfer(4, "Одинаковое имя");
    send_worker(&mut app, progress::Event::Transfer(retry.clone()));
    send_worker(&mut app, progress::Event::Transfer(first));
    let transfers = &app.job.as_ref().unwrap().transfers;
    assert_eq!(transfers.len(), 3);
    assert_eq!(transfers[&2].update, second);
    assert_eq!(transfers[&4].update, retry);
    send_worker(&mut app, progress::Event::RestoreCompleted);
    assert!(app.job.as_ref().unwrap().transfers.is_empty());
}

#[test]
fn overall_progress_uses_device_weights_and_waits_for_confirmed_completion() {
    let mut app = App::new();
    app.job = Some(job(Action::Restore));
    assert_eq!(app.job.as_ref().unwrap().overall_fraction, None);
    send_worker(
        &mut app,
        progress::Event::OperationWeights {
            weights: vec![(12, 1), (13, 8), (55, 1)],
            progresses: vec![],
        },
    );
    assert_eq!(app.job.as_ref().unwrap().overall_fraction, Some(0.0));
    send_worker(
        &mut app,
        progress::Event::OperationProgress {
            operation: 13,
            progress: 25,
        },
    );
    assert_eq!(app.job.as_ref().unwrap().overall_fraction, Some(0.2));
    send_worker(
        &mut app,
        progress::Event::OperationProgress {
            operation: 55,
            progress: 100,
        },
    );
    assert_eq!(app.job.as_ref().unwrap().overall_fraction, Some(0.3));
    assert!(app.job.as_ref().unwrap().transfers.is_empty());
    // New, invalid and restarted subtasks cannot make the total regress.
    for (operation, progress) in [(79, 0), (13, -2), (13, 5), (55, 0)] {
        send_worker(
            &mut app,
            progress::Event::OperationProgress {
                operation,
                progress,
            },
        );
        assert_eq!(app.job.as_ref().unwrap().overall_fraction, Some(0.3));
    }
    send_worker(
        &mut app,
        progress::Event::Checkpoint {
            name: "format_media".into(),
            complete: true,
        },
    );
    assert_eq!(app.job.as_ref().unwrap().overall_fraction, Some(0.3));
    send_worker(
        &mut app,
        progress::Event::OperationProgress {
            operation: 12,
            progress: 100,
        },
    );
    assert_eq!(app.job.as_ref().unwrap().overall_fraction, Some(0.4));
    send_worker(
        &mut app,
        progress::Event::OperationProgress {
            operation: 13,
            progress: 100,
        },
    );
    assert_eq!(app.job.as_ref().unwrap().overall_fraction, Some(0.99));
    // A finished checkpoint or a human-readable line is not final confirmation.
    send_worker(
        &mut app,
        progress::Event::Checkpoint {
            name: "cleanup_send_final_status".into(),
            complete: true,
        },
    );
    send_worker(
        &mut app,
        progress::Event::Log(Record::new(
            Level::Info,
            "restore",
            "Восстановление завершено",
        )),
    );
    assert_eq!(app.job.as_ref().unwrap().overall_fraction, Some(0.99));
    send_worker(&mut app, progress::Event::RestoreCompleted);
    assert_eq!(app.job.as_ref().unwrap().overall_fraction, Some(1.0));
    for event in [
        progress::Event::InternetWaiting,
        progress::Event::InternetPreparing,
        progress::Event::InternetReady,
    ] {
        send_worker(&mut app, event);
        assert_eq!(app.job.as_ref().unwrap().overall_fraction, Some(1.0));
    }
}

#[test]
fn overall_progress_keeps_updates_received_before_their_weights() {
    let mut app = App::new();
    app.job = Some(job(Action::Restore));
    send_worker(
        &mut app,
        progress::Event::OperationProgress {
            operation: 28,
            progress: 80,
        },
    );
    assert_eq!(app.job.as_ref().unwrap().overall_fraction, None);
    send_worker(
        &mut app,
        progress::Event::OperationWeights {
            weights: vec![(28, 100), (99, 100)],
            progresses: vec![],
        },
    );
    assert_eq!(app.job.as_ref().unwrap().overall_fraction, Some(0.4));
    send_worker(
        &mut app,
        progress::Event::OperationWeights {
            weights: vec![(99, 100)],
            progresses: vec![],
        },
    );
    send_worker(
        &mut app,
        progress::Event::OperationWeights {
            weights: vec![(28, 100)],
            progresses: vec![],
        },
    );
    assert_eq!(app.job.as_ref().unwrap().overall_fraction, Some(0.8));
    send_worker(&mut app, progress::Event::RestoreCompleted);
    assert_eq!(app.job.as_ref().unwrap().overall_fraction, Some(1.0));
}

#[test]
fn overall_progress_uses_completed_weight_units_and_apples_integer_rounding() {
    let mut app = App::new();
    app.job = Some(job(Action::Restore));
    send_worker(
        &mut app,
        progress::Event::OperationWeights {
            weights: vec![(13, 1800), (18, 200)],
            progresses: vec![(13, 450)],
        },
    );
    // 450 / 2000 is 22.5%; Apple truncates the overall percentage to 22.
    assert_eq!(app.job.as_ref().unwrap().overall_fraction, Some(0.22));
    for progress in [0, 10, -2, 101] {
        send_worker(
            &mut app,
            progress::Event::OperationProgress {
                operation: 13,
                progress,
            },
        );
        assert_eq!(app.job.as_ref().unwrap().overall_fraction, Some(0.22));
    }
    send_worker(
        &mut app,
        progress::Event::OperationProgress {
            operation: 18,
            progress: -1,
        },
    );
    assert_eq!(app.job.as_ref().unwrap().overall_fraction, Some(0.32));
    assert!(!app.job.as_ref().unwrap().restore_completed);
    send_worker(
        &mut app,
        progress::Event::OperationProgress {
            operation: 13,
            progress: 26,
        },
    );
    assert_eq!(app.job.as_ref().unwrap().overall_fraction, Some(0.33));

    // Each contribution is truncated before the sum, not after it.
    let mut app = App::new();
    app.job = Some(job(Action::Restore));
    send_worker(
        &mut app,
        progress::Event::OperationWeights {
            weights: vec![(1, 3), (2, 7)],
            progresses: vec![],
        },
    );
    for operation in [1, 2] {
        send_worker(
            &mut app,
            progress::Event::OperationProgress {
                operation,
                progress: 50,
            },
        );
    }
    assert_eq!(app.job.as_ref().unwrap().overall_fraction, Some(0.4));
}

#[test]
fn overall_progress_replays_real_mac_messages_without_inventing_missing_operations() {
    let traces: std::collections::BTreeMap<String, Vec<progress::Event>> =
        serde_json::from_str(include_str!("../fixtures/restored-progress-26A434.json")).unwrap();
    for (name, action, expected) in [
        ("erase", Action::Restore, 0.99),
        // The device advertises operations 13 and 14 during this Revive, but
        // never reports their progress. They must not be guessed complete.
        ("update", Action::Revive, 0.41),
    ] {
        let mut app = App::new();
        app.job = Some(job(action));
        for event in &traces[name] {
            send_worker(&mut app, event.clone());
        }
        let job = app.job.as_ref().unwrap();
        assert_eq!(job.overall_fraction, Some(expected), "{name}");
        assert!(!job.restore_completed);
        assert!(!job.can_stop());
        send_worker(&mut app, progress::Event::RestoreCompleted);
        assert_eq!(app.job.as_ref().unwrap().overall_fraction, Some(1.0));
    }
}

#[test]
fn atomic_progress_received_before_weights_is_retained_without_confirming_success() {
    let mut app = App::new();
    app.job = Some(job(Action::Restore));
    send_worker(
        &mut app,
        progress::Event::OperationProgress {
            operation: 12,
            progress: -1,
        },
    );
    assert_eq!(app.job.as_ref().unwrap().overall_fraction, None);
    send_worker(
        &mut app,
        progress::Event::OperationWeights {
            weights: vec![(12, 300), (18, 200)],
            progresses: vec![],
        },
    );
    assert_eq!(app.job.as_ref().unwrap().overall_fraction, Some(0.6));
    assert!(!app.job.as_ref().unwrap().restore_completed);
}

#[test]
fn checkpoints_and_operation_completion_preserve_an_active_transfer() {
    let mut app = App::new();
    app.job = Some(job(Action::Restore));
    send_worker(
        &mut app,
        progress::Event::OperationWeights {
            weights: vec![(999, 1)],
            progresses: vec![],
        },
    );
    send_worker(
        &mut app,
        progress::Event::Transfer(transfer(1, "Current transfer")),
    );
    for complete in [false, true] {
        send_worker(
            &mut app,
            progress::Event::Checkpoint {
                name: "unlisted_step".into(),
                complete,
            },
        );
        assert_eq!(app.job.as_ref().unwrap().transfers.len(), 1);
        assert_eq!(app.job.as_ref().unwrap().overall_fraction, Some(0.0));
    }
    send_worker(
        &mut app,
        progress::Event::OperationProgress {
            operation: 999,
            progress: 100,
        },
    );
    assert_eq!(app.job.as_ref().unwrap().overall_fraction, Some(0.99));
    assert_eq!(app.job.as_ref().unwrap().transfers.len(), 1);
}

#[test]
fn saving_a_journal_preserves_full_log_and_does_not_overwrite_its_source() {
    let directory = tempfile::tempdir().unwrap();
    let source = directory.path().join("full.log");
    let target = directory.path().join("saved.log");
    let full = "complete log\n".repeat(5000);
    std::fs::write(&source, &full).unwrap();
    assert_eq!(
        worker::save_log(source.clone(), Some(&source), "visible tail").unwrap(),
        source
    );
    assert_eq!(std::fs::read_to_string(&source).unwrap(), full);
    worker::save_log(target.clone(), Some(&source), "visible tail").unwrap();
    assert_eq!(std::fs::read_to_string(&target).unwrap(), full);
    worker::save_log(target.clone(), None, "visible tail").unwrap();
    assert_eq!(std::fs::read_to_string(&target).unwrap(), "visible tail");
    assert!(
        worker::save_log(
            target.clone(),
            Some(&directory.path().join("missing")),
            "tail"
        )
        .is_err()
    );
    assert_eq!(std::fs::read_to_string(target).unwrap(), "visible tail");
}

#[test]
fn saving_a_journal_through_a_hard_link_preserves_the_active_source() {
    use std::io::{Read, Seek, SeekFrom, Write};

    let directory = tempfile::tempdir().unwrap();
    let source = directory.path().join("active.log");
    let destination = directory.path().join("export.log");
    let mut active = File::options()
        .create_new(true)
        .read(true)
        .write(true)
        .open(&source)
        .unwrap();
    active.write_all(b"complete log\n").unwrap();
    std::fs::hard_link(&source, &destination).unwrap();

    worker::save_log(destination.clone(), Some(&source), "tail").unwrap();
    assert_eq!(
        std::fs::read_to_string(&destination).unwrap(),
        "complete log\n"
    );
    active.write_all(b"next event\n").unwrap();
    active.seek(SeekFrom::Start(0)).unwrap();
    let mut full = String::new();
    active.read_to_string(&mut full).unwrap();
    assert_eq!(full, "complete log\nnext event\n");
    assert_eq!(std::fs::read_to_string(source).unwrap(), full);
    assert_eq!(
        std::fs::read_to_string(destination).unwrap(),
        "complete log\n"
    );
}

#[test]
fn failed_network_preparation_releases_stop_and_clears_stale_progress() {
    let mut app = App::new();
    app.job = Some(job(Action::Restore));
    assert!(app.job.as_mut().unwrap().stop().is_err());
    assert!(!app.job.as_ref().unwrap().cancelled);
    send_worker(&mut app, progress::Event::RestoreCompleted);
    send_worker(&mut app, progress::Event::InternetPreparing);
    assert!(!app.job.as_ref().unwrap().can_stop());
    send_worker(
        &mut app,
        progress::Event::InternetUnavailable {
            error: "UAC cancelled".into(),
        },
    );
    let operation = app.job.as_ref().unwrap();
    assert!(operation.can_stop());
    assert_eq!(operation.phase, "Интернет по USB недоступен");
    assert!(operation.transfers.is_empty());
    assert_eq!(
        operation.completion_notice(true, false).detail,
        "UAC cancelled"
    );

    send_worker(&mut app, progress::Event::InternetWaiting);
    send_worker(&mut app, progress::Event::InternetReady);
    let operation = app.job.as_ref().unwrap();
    assert_eq!(operation.completion_notice(true, false).tone, Tone::Success);
}

#[test]
fn dialogs_stay_open_and_escape_cancels_without_starting_a_job() {
    for (theme, action) in [egui::Theme::Dark, egui::Theme::Light]
        .into_iter()
        .flat_map(|theme| {
            [None, Some(Action::Revive), Some(Action::Restore)].map(|action| (theme, action))
        })
    {
        let ctx = egui::Context::default();
        configure(&ctx);
        ctx.set_theme(egui::ThemePreference::System);
        let mut app = App::new();
        app.setup.ecid = "2a".into();
        app.devices.push(device(42, Mode::Dfu));
        app.settings_open = action.is_none();
        app.confirmation = action.map(|action| Confirmation {
            action,
            ecid: 42,
            accepted: false,
        });
        for _ in 0..3 {
            let _ = ctx.run(
                egui::RawInput {
                    system_theme: Some(theme),
                    ..Default::default()
                },
                |ctx| {
                    app.settings(ctx);
                    app.confirmation(ctx);
                },
            );
            assert_eq!(ctx.theme(), theme);
            assert_eq!(app.settings_open, action.is_none());
            assert_eq!(app.confirmation.is_some(), action.is_some());
        }
        let input = egui::RawInput {
            system_theme: Some(theme),
            events: vec![egui::Event::Key {
                key: egui::Key::Escape,
                physical_key: None,
                pressed: true,
                repeat: false,
                modifiers: egui::Modifiers::NONE,
            }],
            ..Default::default()
        };
        let _ = ctx.run(input, |ctx| {
            app.settings(ctx);
            app.confirmation(ctx);
        });
        assert!(!app.settings_open);
        assert!(app.confirmation.is_none());
        assert!(app.job.is_none());
    }
}
#[test]
fn stalled_transfer_hides_speed_and_eta() {
    let now = Instant::now();
    let mut t = worker::Transfer {
        update: progress::Update {
            id: 1,
            stage: "BaseSystem".into(),
            completed: 1048576,
            total: Some(3145728),
            bytes_per_second: 1048576.0,
            elapsed_seconds: 1.0,
            finished: false,
        },
        received: now,
    };
    assert_eq!(t.remaining(now), Some(2));
    assert_eq!(t.speed(now + Duration::from_secs(3)), 0.0);
    assert_eq!(t.remaining(now + Duration::from_secs(3)), None);
    t.update.finished = true;
    assert_eq!(t.remaining(now), None);
}

#[test]
fn main_panels_render_in_both_themes_without_light_surfaces_in_dark_mode() {
    let ctx = egui::Context::default();
    configure(&ctx);
    let mut app = App::new();
    app.journal_open = true;
    app.logs
        .push_back(Record::new(Level::Error, "test", "example"));
    for theme in [egui::Theme::Dark, egui::Theme::Light] {
        ctx.set_theme(theme);
        let output = ctx.run(
            egui::RawInput {
                screen_rect: Some(egui::Rect::from_min_size(
                    egui::Pos2::ZERO,
                    egui::vec2(1020.0, 1100.0),
                )),
                ..Default::default()
            },
            |ctx| {
                app.header(ctx);
                app.journal(ctx);
                egui::CentralPanel::default().show(ctx, |ui| {
                    app.prepare_device_card(ui, ctx).end(ui);
                    app.prepare_firmware_card(ui, ctx).end(ui);
                    app.actions(ui);
                });
            },
        );
        let surfaces: Vec<_> = output
            .shapes
            .iter()
            .filter_map(|shape| {
                if let egui::Shape::Rect(rect) = &shape.shape
                    && rect.rect.width() > 500.0
                    && rect.rect.height() > 50.0
                {
                    Some(rect.fill)
                } else {
                    None
                }
            })
            .collect();
        assert!(surfaces.len() >= 3, "main panels were not painted");
        assert!(
            surfaces
                .iter()
                .all(|color| color.r() < 64 && color.g() < 64 && color.b() < 64)
                == (theme == egui::Theme::Dark)
        );
        assert!(app.job.is_none());
    }
}

fn visible_text_rect(output: &egui::FullOutput, value: &str) -> Option<egui::Rect> {
    output.shapes.iter().find_map(|shape| {
        if let egui::Shape::Text(text) = &shape.shape
            && text.galley.text() == value
        {
            let rect = text.galley.rect.translate(text.pos.to_vec2());
            if shape.clip_rect.expand(1.0).contains_rect(rect) {
                return Some(rect);
            }
        }
        None
    })
}

#[test]
fn small_windows_keep_content_visible_and_all_steps_reachable_with_the_journal_open() {
    for size in [
        egui::vec2(1020.0, 630.0),
        egui::vec2(700.0, 480.0),
        egui::vec2(480.0, 360.0),
    ] {
        let ctx = egui::Context::default();
        configure(&ctx);
        let mut app = App::new();
        app.journal_open = true;
        app.host = Ok(Some(drivers::HostStatus {
            apple_service_installed: false,
            apple_service_running: false,
            apple_driver_installed: false,
            compatible_usb_driver: false,
            usb_network_driver_available: true,
            usb_network_interfaces: vec![],
        }));
        for _ in 0..20 {
            app.journal_line(Record::new(Level::Error, "test", "Проверка журнала"));
        }
        let screen = egui::Rect::from_min_size(egui::Pos2::ZERO, size);
        let mut output = egui::FullOutput::default();
        // Also exercise shrinking a window after egui has saved a taller journal.
        for frame_size in [egui::vec2(1280.0, 1000.0), size, size, size] {
            output = ctx.run(
                egui::RawInput {
                    screen_rect: Some(egui::Rect::from_min_size(egui::Pos2::ZERO, frame_size)),
                    ..Default::default()
                },
                |ctx| app.view(ctx),
            );
        }
        let heading = visible_text_rect(&output, "Восстановление Mac")
            .unwrap_or_else(|| panic!("main content hidden at {size:?}"));
        assert!(screen.contains_rect(heading));
        for label in ["Копировать", "Сохранить журнал", "Скрыть"] {
            assert!(
                visible_text_rect(&output, label).is_some(),
                "journal control {label} clipped at {size:?}"
            );
        }
        assert!(
            output.shapes.iter().any(|shape| {
                if let egui::Shape::Text(text) = &shape.shape
                    && text.galley.text().contains("Проверка журнала")
                {
                    let rect = text.galley.rect.translate(text.pos.to_vec2());
                    return rect.top() >= shape.clip_rect.top()
                        && rect.bottom() <= shape.clip_rect.bottom();
                }
                false
            }),
            "journal rows hidden at {size:?}"
        );
        let mut reached = [false; 4];
        let labels = [
            "Устройство",
            "Прошивка",
            "Запустить Revive",
            "Стереть и восстановить",
        ];
        for _ in 0..50 {
            for (reached, label) in reached.iter_mut().zip(labels) {
                *reached |= visible_text_rect(&output, label).is_some();
            }
            output = ctx.run(
                egui::RawInput {
                    screen_rect: Some(screen),
                    events: vec![
                        egui::Event::PointerMoved(heading.center()),
                        egui::Event::MouseWheel {
                            unit: egui::MouseWheelUnit::Point,
                            delta: egui::vec2(0.0, -35.0),
                            modifiers: egui::Modifiers::NONE,
                        },
                    ],
                    ..Default::default()
                },
                |ctx| app.view(ctx),
            );
        }
        for (reached, label) in reached.into_iter().zip(labels) {
            assert!(reached, "cannot scroll to {label} at {size:?}");
        }
        assert!(app.job.is_none());
    }
}

#[test]
fn narrow_cards_keep_text_and_controls_inside_their_bounds() {
    for width in [480.0, 700.0, 840.0, 1020.0, 1280.0] {
        for automatic in [false, true] {
            let ctx = egui::Context::default();
            configure(&ctx);
            let mut app = App::new();
            app.setup.automatic = automatic;
            app.setup.ecid = "2a".into();
            app.devices.push(device(42, Mode::Recovery));
            app.scanning = true;
            app.firmware = Some(FirmwareSelection {
                device: app.devices[0].clone(),
                request: 0,
                release: Some(Err("offline".into())),
            });
            for scanning in [false, true, false] {
                app.scanning = scanning;
                let output = ctx.run(
                    egui::RawInput {
                        screen_rect: Some(egui::Rect::from_min_size(
                            egui::Pos2::ZERO,
                            egui::vec2(width, 1600.0),
                        )),
                        ..Default::default()
                    },
                    |ctx| app.view(ctx),
                );
                for shape in &output.shapes {
                    if let egui::Shape::Text(text) = &shape.shape {
                        assert_ne!(text.galley.text(), "Поиск…");
                        let rect = text.galley.rect.translate(text.pos.to_vec2());
                        assert!(
                            shape.clip_rect.expand(1.0).contains_rect(rect),
                            "clipped {} at width {width}, automatic={automatic}: {rect:?} outside {:?}",
                            text.galley.text(),
                            shape.clip_rect,
                        );
                    }
                }
                let card_rect = |title| {
                    let heading = visible_text_rect(&output, title).unwrap();
                    output
                        .shapes
                        .iter()
                        .find_map(|shape| match &shape.shape {
                            egui::Shape::Rect(rect)
                                if rect.rect.height() > 60.0
                                    && rect.fill == ctx.style().visuals.window_fill
                                    && rect.rect.contains(heading.center()) =>
                            {
                                Some(rect.rect)
                            }
                            _ => None,
                        })
                        .unwrap()
                };
                let device = card_rect("Устройство");
                let firmware = card_rect("Прошивка");
                let actions = card_rect("Действие");
                assert!((device.width() - firmware.width()).abs() < 1.0);
                assert!((device.left() - actions.left()).abs() < 1.0);
                assert!((firmware.right() - actions.right()).abs() < 1.0);
                if width >= 840.0 {
                    assert!((device.top() - firmware.top()).abs() < 1.0);
                    assert!(
                        (device.bottom() - firmware.bottom()).abs() < 1.0,
                        "unequal card heights at width {width}, automatic={automatic}: {device:?}, {firmware:?}"
                    );
                    assert!(device.right() < firmware.left());
                } else {
                    assert!((device.width() - actions.width()).abs() < 1.0);
                    assert!(device.bottom() < firmware.top());
                }
                let revive = visible_text_rect(&output, "Запустить Revive").unwrap();
                let restore = visible_text_rect(&output, "Стереть и восстановить").unwrap();
                assert!(!revive.intersects(restore));
                if width <= 700.0 {
                    assert!(revive.bottom() < restore.top());
                } else {
                    assert!((revive.top() - restore.top()).abs() < 1.0);
                }
            }
        }
    }
}

#[test]
fn small_dialogs_scroll_to_their_controls() {
    for action in [None, Some(Action::Revive), Some(Action::Restore)] {
        let ctx = egui::Context::default();
        configure(&ctx);
        let mut app = App::new();
        app.setup.ecid = "2a".into();
        app.devices.push(device(42, Mode::Dfu));
        app.settings_open = action.is_none();
        app.confirmation = action.map(|action| Confirmation {
            action,
            ecid: 42,
            accepted: false,
        });
        let screen = egui::Rect::from_min_size(egui::Pos2::ZERO, egui::vec2(480.0, 360.0));
        let label = match action {
            None => "Диагностика USB",
            Some(Action::Revive) => "Начать Revive",
            _ => "Стереть Mac",
        };
        let mut reached = false;
        let mut compact_folder_row = false;
        for frame in 0..30 {
            let output = ctx.run(
                egui::RawInput {
                    screen_rect: Some(screen),
                    events: vec![
                        egui::Event::PointerMoved(screen.center()),
                        egui::Event::MouseWheel {
                            unit: egui::MouseWheelUnit::Point,
                            delta: egui::vec2(0.0, -20.0),
                            modifiers: egui::Modifiers::NONE,
                        },
                    ],
                    ..Default::default()
                },
                |ctx| {
                    app.settings(ctx);
                    app.confirmation(ctx);
                },
            );
            if let Some(rect) = visible_text_rect(&output, label) {
                reached |= screen.contains_rect(rect);
            }
            if action.is_none() {
                if frame >= 3 {
                    for label in ["Настройки", "Готово"] {
                        let rect = visible_text_rect(&output, label)
                            .unwrap_or_else(|| panic!("settings header {label} scrolled away"));
                        assert!(screen.contains_rect(rect));
                    }
                }
                if let (Some(title), Some(field), Some(button)) = (
                    visible_text_rect(&output, "Папка прошивок"),
                    visible_text_rect(&output, "По умолчанию"),
                    visible_text_rect(&output, "Выбрать"),
                ) {
                    assert!(field.top() - title.bottom() < 34.0);
                    assert!(button.top() - title.bottom() < 34.0);
                    assert!((field.center().y - button.center().y).abs() < 10.0);
                    compact_folder_row = true;
                }
            }
        }
        assert!(reached, "dialog control {label} is unreachable");
        assert!(action.is_some() || compact_folder_row);
        assert!(app.job.is_none());
    }
}

#[test]
fn usb_internet_can_start_without_dfu_or_firmware_and_only_follows_erase_restore() {
    let mut setup = Setup::default();
    assert_eq!(
        setup.arguments(Action::UsbInternet, None).unwrap(),
        vec![OsString::from("usb-internet"), OsString::from("share")]
    );
    setup.ecid = "2a".into();
    setup.share_internet = true;
    assert!(
        setup
            .arguments(Action::Restore, None)
            .unwrap()
            .contains(&OsString::from("--share-internet"))
    );
    assert!(
        !setup
            .arguments(Action::Revive, None)
            .unwrap()
            .contains(&OsString::from("--share-internet"))
    );
    assert!(
        !setup
            .arguments(Action::Download, None)
            .unwrap()
            .contains(&OsString::from("--share-internet"))
    );
}

fn firmware_card_text(app: &mut App, ctx: &egui::Context) -> String {
    let output = ctx.run(
        egui::RawInput {
            screen_rect: Some(egui::Rect::from_min_size(
                egui::Pos2::ZERO,
                egui::vec2(700.0, 640.0),
            )),
            ..Default::default()
        },
        |ctx| {
            egui::CentralPanel::default()
                .show(ctx, |ui| app.prepare_firmware_card(ui, ctx).end(ui));
        },
    );
    output
        .shapes
        .iter()
        .filter_map(|shape| match &shape.shape {
            egui::Shape::Text(text) => Some(text.galley.text()),
            _ => None,
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn selected_release() -> catalog::Release {
    catalog::Release {
        product_type: "MacBookAir10,1".into(),
        version: "26.0.1".into(),
        build: "25A362".into(),
        url: "https://updates.cdn-apple.com/restore.ipsw".into(),
        sha1: [0xab; 20],
    }
}

#[test]
fn automatic_firmware_shows_selection_and_clears_it_after_disconnect() {
    let ctx = egui::Context::default();
    configure(&ctx);
    let mut app = App::new();
    assert!(firmware_card_text(&mut app, &ctx).contains("Подключите Mac"));
    assert!(app.firmware.is_none());
    assert_eq!(app.next_firmware_request, 0);

    app.setup.ecid = "2a".into();
    app.devices.push(device(42, Mode::Dfu));
    app.next_firmware_request = 1;
    app.firmware = Some(FirmwareSelection {
        device: app.devices[0].clone(),
        request: 1,
        release: None,
    });
    assert!(firmware_card_text(&mut app, &ctx).contains("Подбираем прошивку"));
    app.tx
        .send(Event::Firmware(1, Ok(selected_release())))
        .unwrap();
    app.poll(&ctx);
    let text = firmware_card_text(&mut app, &ctx);
    for value in ["26.0.1", "25A362", "MacBookAir10,1"] {
        assert!(text.contains(value), "missing {value}: {text}");
    }
    // USB scanning can refresh nonces without changing the firmware model.
    app.devices[0].ap_nonce = vec![1; 32];
    app.tx
        .send(Event::Scan {
            devices: Ok(app.devices.clone()),
            host: Ok(None),
        })
        .unwrap();
    app.poll(&ctx);
    assert!(firmware_card_text(&mut app, &ctx).contains("26.0.1"));
    assert_eq!(app.next_firmware_request, 1);

    app.tx
        .send(Event::Scan {
            devices: Ok(vec![]),
            host: Ok(None),
        })
        .unwrap();
    app.poll(&ctx);
    assert!(app.firmware.is_none());
    let text = firmware_card_text(&mut app, &ctx);
    assert!(text.contains("Подключите Mac"));
    assert!(!text.contains("26.0.1"));
    app.tx
        .send(Event::Firmware(1, Ok(selected_release())))
        .unwrap();
    app.poll(&ctx);
    assert!(app.firmware.is_none());
}

#[test]
fn firmware_lookup_ignores_superseded_requests_and_surfaces_network_failure() {
    let ctx = egui::Context::default();
    configure(&ctx);
    let mut app = App::new();
    app.setup.ecid = "2a".into();
    app.devices.push(device(42, Mode::Dfu));
    app.next_firmware_request = 2;
    app.firmware = Some(FirmwareSelection {
        device: app.devices[0].clone(),
        request: 2,
        release: None,
    });
    app.tx
        .send(Event::Firmware(1, Ok(selected_release())))
        .unwrap();
    app.poll(&ctx);
    assert!(app.firmware.as_ref().unwrap().release.is_none());
    app.tx
        .send(Event::Firmware(2, Err("offline".into())))
        .unwrap();
    app.poll(&ctx);
    let text = firmware_card_text(&mut app, &ctx);
    assert!(text.contains("Не удалось подобрать прошивку"));
    assert!(text.contains("Повторить"));
    assert!(!text.contains("26.0.1"));
    assert_eq!(app.next_firmware_request, 2);

    // A result for the previous hardware must not be applied after a mode change,
    // even if no new lookup has started yet (for example, while using local IPSW).
    app.devices[0].mode = Mode::Recovery;
    app.tx
        .send(Event::Firmware(2, Ok(selected_release())))
        .unwrap();
    app.poll(&ctx);
    assert!(app.firmware.is_none());
}
