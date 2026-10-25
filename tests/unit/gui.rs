use super::worker::ActivityId;
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
    assert!(!app.journal_text().contains("protocol details"));
    assert!(app.journal_text().contains("connection failed"));
    app.log_details = true;
    assert!(app.journal_text().contains("protocol details"));
    send_worker(
        &mut app,
        progress::Event::Transfer(progress::Update {
            id: 1,
            operation: None,
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
    assert_eq!(
        app.job.as_ref().unwrap().activities[&ActivityId::Operation(28)].fraction(),
        Some(0.5)
    );
    send_worker(
        &mut app,
        progress::Event::OperationProgress {
            operation: 28,
            progress: -1,
        },
    );
    assert_eq!(
        app.job.as_ref().unwrap().activities[&ActivityId::Operation(28)].fraction(),
        None
    );
    send_worker(
        &mut app,
        progress::Event::Checkpoint {
            name: "update_firmware".into(),
            complete: false,
        },
    );
    assert_eq!(app.job.as_ref().unwrap().phase, "Обновление прошивки");
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
    send_worker(&mut app, progress::Event::RebootRequired);
    assert!(app.windows_reboot_required);
}

#[test]
fn transfer_events_preserve_phase_order_and_stderr_never_changes_progress() {
    let mut app = App::new();
    app.job = Some(job(Action::Restore));
    let update = progress::Update {
        id: 1,
        operation: None,
        stage: "ASR".into(),
        completed: 100,
        total: Some(100),
        bytes_per_second: 10.0,
        elapsed_seconds: 10.0,
        finished: true,
    };
    send_worker(&mut app, progress::Event::Transfer(update.clone()));
    assert!(app.job.as_ref().unwrap().activities.is_empty());
    send_worker(
        &mut app,
        progress::Event::OperationProgress {
            operation: 28,
            progress: 50,
        },
    );
    assert!(
        !app.job
            .as_ref()
            .unwrap()
            .activities
            .contains_key(&ActivityId::Transfer(1))
    );
    assert_eq!(
        app.job.as_ref().unwrap().activities[&ActivityId::Operation(28)].fraction(),
        Some(0.5)
    );
    send_worker(&mut app, progress::Event::RestoreCompleted);
    send_worker(&mut app, progress::Event::InternetWaiting);
    send_worker(&mut app, progress::Event::InternetReady);
    let line = worker_line(progress::Event::Transfer(update));
    app.tx
        .send(Event::Worker(7, Output::parse(line.clone(), false)))
        .unwrap();
    app.poll(&egui::Context::default());
    assert!(app.job.as_ref().unwrap().activities.is_empty());
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

fn transfer(id: u64, operation: Option<u64>, stage: &str) -> progress::Update {
    progress::Update {
        id,
        operation,
        stage: stage.into(),
        completed: 60,
        total: Some(100),
        bytes_per_second: 10.0,
        elapsed_seconds: 6.0,
        finished: false,
    }
}

#[test]
fn transfers_and_device_progress_share_one_card_for_every_operation_and_event_order() {
    // Names deliberately do not identify the operation; the worker's metadata does.
    for operation in [13, 36, 59, 71, 80, 999] {
        for transfer_first in [false, true] {
            let mut app = App::new();
            app.job = Some(job(Action::Restore));
            let mut update = transfer(1, Some(operation), "Компонент прошивки");
            let mut events = vec![
                progress::Event::Transfer(update.clone()),
                progress::Event::OperationProgress {
                    operation,
                    progress: 40,
                },
            ];
            if !transfer_first {
                events.reverse();
            }
            for event in events {
                send_worker(&mut app, event);
            }
            let activity = &app.job.as_ref().unwrap().activities[&ActivityId::Operation(operation)];
            assert_eq!(activity.fraction(), Some(0.4));
            assert_eq!(activity.transfers.len(), 1);
            for theme in [egui::Theme::Dark, egui::Theme::Light] {
                let (labels, cards) = active_job_labels(&mut app, theme);
                assert_eq!(
                    cards, 2,
                    "summary plus one operation: {operation}, {theme:?}"
                );
                assert_eq!(
                    labels
                        .iter()
                        .filter(|label| **label == widgets::operation_title(operation))
                        .count(),
                    1
                );
                assert_eq!(labels.iter().filter(|label| *label == "40%").count(), 1);
                assert!(labels.iter().any(|label| label == "Компонент прошивки"));
                assert!(labels.iter().any(|label| label == "Скорость"));
            }
            send_worker(
                &mut app,
                progress::Event::OperationProgress {
                    operation,
                    progress: -1,
                },
            );
            assert_eq!(
                app.job.as_ref().unwrap().activities[&ActivityId::Operation(operation)].fraction(),
                Some(0.6)
            );
            send_worker(
                &mut app,
                progress::Event::OperationProgress {
                    operation,
                    progress: 40,
                },
            );
            // Either the Mac or the transfer can finish first. The other stays visible.
            update.completed = 100;
            update.finished = true;
            if transfer_first {
                send_worker(&mut app, progress::Event::Transfer(update.clone()));
            } else {
                send_worker(
                    &mut app,
                    progress::Event::OperationProgress {
                        operation,
                        progress: 100,
                    },
                );
            }
            assert_eq!(app.job.as_ref().unwrap().activities.len(), 1);
            for theme in [egui::Theme::Dark, egui::Theme::Light] {
                assert_eq!(active_job_labels(&mut app, theme).1, 2);
            }
            if transfer_first {
                send_worker(
                    &mut app,
                    progress::Event::OperationProgress {
                        operation,
                        progress: 100,
                    },
                );
            } else {
                send_worker(&mut app, progress::Event::Transfer(update));
            }
            assert!(app.job.as_ref().unwrap().activities.is_empty());
        }
    }
}

#[test]
fn identical_names_do_not_merge_independent_transfers_or_lose_parallel_files() {
    let mut app = App::new();
    app.job = Some(job(Action::Restore));
    let mut updates = vec![
        transfer(1, Some(13), "Одинаковое имя"),
        transfer(2, Some(59), "Одинаковое имя"),
        transfer(13, None, "Одинаковое имя"),
        transfer(59, None, "Одинаковое имя"),
    ];
    for update in &updates {
        send_worker(&mut app, progress::Event::Transfer(update.clone()));
    }
    assert_eq!(app.job.as_ref().unwrap().activities.len(), 4);
    for theme in [egui::Theme::Dark, egui::Theme::Light] {
        assert_eq!(active_job_labels(&mut app, theme).1, 5);
    }
    updates[0].finished = true;
    send_worker(&mut app, progress::Event::Transfer(updates[0].clone()));
    let activities = &app.job.as_ref().unwrap().activities;
    assert_eq!(activities.len(), 3);
    assert!(!activities.contains_key(&ActivityId::Operation(13)));
    assert_eq!(
        activities[&ActivityId::Operation(59)].transfers[&2].update,
        updates[1]
    );
    assert!(activities.contains_key(&ActivityId::Transfer(13)));
    assert!(activities.contains_key(&ActivityId::Transfer(59)));
    let retry = transfer(6, Some(13), "Одинаковое имя");
    send_worker(&mut app, progress::Event::Transfer(retry.clone()));
    send_worker(&mut app, progress::Event::Transfer(updates[0].clone()));
    assert_eq!(
        app.job.as_ref().unwrap().activities[&ActivityId::Operation(13)].transfers[&6].update,
        retry
    );

    let mut second_file = transfer(5, Some(59), "Одинаковое имя");
    send_worker(&mut app, progress::Event::Transfer(second_file.clone()));
    assert_eq!(app.job.as_ref().unwrap().activities.len(), 4);
    assert_eq!(
        app.job.as_ref().unwrap().activities[&ActivityId::Operation(59)]
            .transfers
            .len(),
        2
    );
    second_file.finished = true;
    send_worker(&mut app, progress::Event::Transfer(second_file));
    assert_eq!(
        app.job.as_ref().unwrap().activities[&ActivityId::Operation(59)]
            .transfers
            .len(),
        1
    );
    send_worker(&mut app, progress::Event::RestoreCompleted);
    assert!(app.job.as_ref().unwrap().activities.is_empty());
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
    assert!(
        !app.job
            .as_ref()
            .unwrap()
            .activities
            .contains_key(&ActivityId::Operation(55))
    );
    // New, indeterminate and restarted subtasks cannot make the total regress.
    for (operation, progress) in [(79, 0), (13, -1), (13, 5), (55, 0)] {
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
fn completed_checkpoints_remove_only_their_operation_when_no_final_percentage_arrives() {
    let mut app = App::new();
    app.job = Some(job(Action::Restore));
    for (operation, progress) in [(13, 5), (28, -1), (36, 50), (59, 0)] {
        send_worker(
            &mut app,
            progress::Event::OperationProgress {
                operation,
                progress,
            },
        );
    }
    for (name, operation) in [
        ("wait_for_storage", 28),
        ("update_aht", 36),
        ("await_update_se", 59),
    ] {
        send_worker(
            &mut app,
            progress::Event::Checkpoint {
                name: name.into(),
                complete: false,
            },
        );
        assert!(
            app.job
                .as_ref()
                .unwrap()
                .activities
                .contains_key(&ActivityId::Operation(operation))
        );
        send_worker(
            &mut app,
            progress::Event::Checkpoint {
                name: name.into(),
                complete: true,
            },
        );
        let job = app.job.as_ref().unwrap();
        assert!(
            !job.activities
                .contains_key(&ActivityId::Operation(operation))
        );
        assert_eq!(
            job.activities[&ActivityId::Operation(13)].fraction(),
            Some(0.05)
        );
    }
    assert_eq!(app.job.as_ref().unwrap().activities.len(), 1);
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
    assert!(operation.activities.is_empty());
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
            operation: None,
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
