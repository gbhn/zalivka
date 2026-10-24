use super::*;
use std::ffi::OsString;

fn job(action: Action) -> Job {
    let mut child = std::process::Command::new(std::env::current_exe().unwrap())
        .arg("--help")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();
    assert!(child.wait().unwrap().success());
    Job {
        id: 7,
        action,
        started: Instant::now(),
        child,
        log: tempfile::tempfile().unwrap(),
        success: None,
        readers: 2,
        cancelled: false,
        restore_completed: false,
        internet_error: None,
        preparing_internet: false,
    }
}

fn worker_line(event: progress::Event) -> String {
    let mut line = Vec::new();
    event.write_to(&mut line).unwrap();
    String::from_utf8(line).unwrap().trim_end().to_owned()
}

fn send_worker(app: &mut App, event: progress::Event) {
    app.tx
        .send(Event::worker_output(7, worker_line(event), true))
        .unwrap();
    app.poll(&egui::Context::default());
}
fn device(ecid: u64, mode: Mode) -> DeviceInfo {
    DeviceInfo {
        ecid,
        chip_id: 0x8103,
        board_id: 0x26,
        security_domain: 1,
        iboot_flags: 0,
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
        erase: "ERASE".into(),
    };
    assert!(!p.ready(Some(&device(42, Mode::Dfu))));
    p.accepted = true;
    assert!(p.ready(Some(&device(42, Mode::Dfu))));
    assert!(!p.ready(Some(&device(43, Mode::Dfu))));
    assert!(!p.ready(Some(&device(42, Mode::Recovery))));
    assert!(!p.ready(None));
    p.erase = "erase".into();
    assert!(!p.ready(Some(&device(42, Mode::Dfu))));
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
    let mut app = App::new();
    let ctx = egui::Context::default();
    app.tx.send(Event::Line(999, "stale error".into())).unwrap();
    app.tx
        .send(Event::Worker(999, progress::Event::RestoreCompleted))
        .unwrap();
    app.tx.send(Event::ReaderDone(999)).unwrap();
    app.poll(&ctx);
    assert!(app.logs.is_empty());
    assert!(app.notice.is_none());
}

#[test]
fn exited_worker_keeps_final_lines_until_both_readers_finish() {
    let log = tempfile::NamedTempFile::new().unwrap();
    let mut app = App::new();
    let ctx = egui::Context::default();
    app.job = Some(Job {
        id: 7,
        log: log.reopen().unwrap(),
        ..job(Action::Restore)
    });
    app.poll(&ctx);
    assert_eq!(app.job.as_ref().unwrap().success, Some(true));
    assert!(app.notice.is_none());
    app.tx.send(Event::ReaderDone(999)).unwrap();
    app.tx.send(Event::ReaderDone(7)).unwrap();
    app.poll(&ctx);
    assert_eq!(app.job.as_ref().unwrap().readers, 1);
    assert!(app.notice.is_none());

    app.tx
        .send(Event::worker_output(
            7,
            worker_line(progress::Event::InternetUnavailable {
                error: "disconnected".into(),
            }),
            true,
        ))
        .unwrap();
    app.tx.send(Event::ReaderDone(7)).unwrap();
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
    job.internet_error = Some("no network".into());
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
        "Восстановление завершено · раздача остановлена"
    );
    assert_eq!(notice.tone, Tone::Neutral);
    job.action = Action::Revive;
    assert_eq!(
        job.completion_notice(false, true).title,
        "Операция остановлена"
    );
    job.cancelled = false;
    for action in [Action::Restore, Action::PrepareWindows] {
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
    job.internet_error = None;
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
    app.log("Restore completed; waiting for the Mac's USB network".into());
    app.log("Перезагрузите Windows перед восстановлением Mac.".into());
    app.tx
        .send(Event::worker_output(
            7,
            worker_line(progress::Event::RestoreCompleted),
            false,
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
    assert_eq!(app.fraction, Some(0.5));
    send_worker(
        &mut app,
        progress::Event::OperationProgress {
            operation: 28,
            progress: -1,
        },
    );
    assert_eq!(app.fraction, None);
    send_worker(
        &mut app,
        progress::Event::Checkpoint {
            name: "update_firmware".into(),
        },
    );
    assert_eq!(app.phase, "Обновление прошивки");
    send_worker(&mut app, progress::Event::RestoreCompleted);
    send_worker(&mut app, progress::Event::InternetWaiting);
    assert!(app.job.as_ref().unwrap().can_stop());
    send_worker(&mut app, progress::Event::InternetPreparing);
    assert!(!app.job.as_ref().unwrap().can_stop());
    send_worker(&mut app, progress::Event::InternetReady);
    assert!(app.job.as_ref().unwrap().can_stop());
    assert_eq!(app.phase, "Интернет по USB · оставьте Zalivka открытой");
    send_worker(
        &mut app,
        progress::Event::InternetUnavailable {
            error: "no network".into(),
        },
    );
    for index in 0..4001 {
        app.log(format!("message {index}"));
    }
    assert_eq!(app.logs.len(), 4000);
    let job = app.job.as_mut().unwrap();
    assert_eq!(job.completion_notice(true, false).detail, "no network");
    job.cancelled = true;
    assert_eq!(
        job.completion_notice(false, false).title,
        "Восстановление завершено · раздача остановлена"
    );
    job.action = Action::PrepareWindows;
    job.cancelled = false;
    assert!(!job.can_stop());
    send_worker(&mut app, progress::Event::RebootRequired);
    assert!(app.windows_reboot_required);
}

#[test]
fn transfer_events_preserve_phase_order_and_stderr_never_changes_progress() {
    let mut app = App::new();
    app.job = Some(job(Action::Restore));
    let update = progress::Update {
        stage: "ASR".into(),
        completed: 100,
        total: Some(100),
        bytes_per_second: 10.0,
        elapsed_seconds: 10.0,
        finished: true,
    };
    send_worker(&mut app, progress::Event::Transfer(update.clone()));
    assert_eq!(app.transfer.as_ref().unwrap().update.fraction(), Some(1.0));
    send_worker(
        &mut app,
        progress::Event::OperationProgress {
            operation: 28,
            progress: 50,
        },
    );
    assert!(app.transfer.is_none());
    assert_eq!(app.fraction, Some(0.5));
    send_worker(&mut app, progress::Event::RestoreCompleted);
    send_worker(&mut app, progress::Event::InternetWaiting);
    send_worker(&mut app, progress::Event::InternetReady);
    let line = worker_line(progress::Event::Transfer(update));
    app.tx
        .send(Event::worker_output(7, line.clone(), false))
        .unwrap();
    app.poll(&egui::Context::default());
    assert!(app.transfer.is_none());
    assert!(app.fraction.is_none());
    assert!(app.job.as_ref().unwrap().can_stop());
    assert_eq!(app.phase, "Интернет по USB · оставьте Zalivka открытой");
    assert_eq!(app.logs.back(), Some(&line));
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
            erase: String::new(),
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
    let mut t = Transfer {
        update: progress::Update {
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
    app.logs.push_back("Error: example".into());
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
                    app.device_card(ui, ctx);
                    app.firmware_card(ui, ctx);
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
