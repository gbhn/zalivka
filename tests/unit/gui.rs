use super::*;
use std::{fs::File, path::Path};
use zalivka::device::Mode;

fn english_app() -> App {
    let mut app = App::new();
    app.localization.select("en");
    app
}

fn job(action: Action) -> Job {
    Job::new(
        7,
        action,
        progress::Context::new(|_| {}),
        std::sync::Arc::new(std::sync::Mutex::new(journal::Journal::new(
            tempfile::tempfile().unwrap(),
        ))),
    )
}

// These layout tests have no renderer to apply GPU texture updates.
fn render_pass(
    ctx: &egui::Context,
    input: egui::RawInput,
    contents: impl FnMut(&egui::Context),
) -> egui::FullOutput {
    let mut output = ctx.run_pass(input, contents);
    output.textures_delta.clear();
    output
}

fn render_app(app: &mut App, ctx: &egui::Context, frame: u32) -> egui::FullOutput {
    render_pass(
        ctx,
        egui::RawInput {
            screen_rect: Some(egui::Rect::from_min_size(
                egui::Pos2::ZERO,
                egui::vec2(1020.0, 800.0),
            )),
            time: Some(f64::from(frame) / 60.0),
            ..Default::default()
        },
        |ctx| {
            let mut frame = eframe::Frame::_new_kittest();
            eframe::App::logic(app, ctx, &mut frame);
            ctx.root_ui(|ui| eframe::App::ui(app, ui, &mut frame));
        },
    )
}

#[test]
fn startup_keeps_a_normal_window_and_clears_with_the_selected_background() {
    for preference in [egui::ThemePreference::Light, egui::ThemePreference::Dark] {
        let ctx = egui::Context::default();
        configure(&ctx);
        theme::apply_preference(&ctx, preference);
        let mut app = english_app();
        app.scanning = true;
        for frame in 0..3 {
            let output = render_app(&mut app, &ctx, frame);
            let maximizes = output.viewport_output[&egui::ViewportId::ROOT]
                .commands
                .iter()
                .any(|command| matches!(command, egui::ViewportCommand::Maximized(_)));
            assert!(!maximizes, "{preference:?}, frame {frame}");
            let visuals = ctx.global_style().visuals.clone();
            let clear = eframe::App::clear_color(&app, &visuals);
            assert_eq!(clear, visuals.panel_fill.to_normalized_gamma_f32());
            assert_eq!(clear[3], 1.0);
        }
    }
}

#[test]
fn interface_languages_change_labels_while_diagnostics_remain_english() {
    for (language, settings, journal, language_label) in [
        ("en", "Settings", "Journal", "Language"),
        ("ru", "Настройки", "Журнал", "Язык"),
    ] {
        let ctx = egui::Context::default();
        configure(&ctx);
        let mut app = english_app();
        app.localization.select(language);
        app.scanning = true;
        app.journal_open = true;
        app.journal_line(Record::new(
            Level::Info,
            "proxy:auth",
            "Authentication complete",
        ));
        let mut output = render_app(&mut app, &ctx, 0);
        for frame in 1..4 {
            output = render_app(&mut app, &ctx, frame);
        }
        let labels: Vec<_> = output
            .shapes
            .iter()
            .filter_map(|shape| match &shape.shape {
                egui::Shape::Text(text) => Some(text.galley.text()),
                _ => None,
            })
            .collect();
        assert!(labels.contains(&settings), "{language}: {labels:?}");
        assert!(labels.contains(&journal), "{language}: {labels:?}");
        assert!(
            labels
                .iter()
                .any(|text| text.contains("Authentication complete"))
        );
        assert_eq!(app.logs[0].message, "Authentication complete");
        app.settings_open = true;
        for frame in 4..7 {
            output = render_app(&mut app, &ctx, frame);
        }
        assert!(output.shapes.iter().any(|shape| matches!(&shape.shape,
            egui::Shape::Text(text) if text.galley.text() == language_label)));
    }
}

#[test]
fn active_operations_wait_for_updates_instead_of_redrawing_at_monitor_refresh_rate() {
    for action in [Action::Restore, Action::Download, Action::Verify] {
        for fraction in [None, Some(0.5)] {
            let mut app = english_app();
            let mut job = job(action);
            job.overall_fraction = fraction;
            let mut update = transfer(1, "Filesystem");
            update.total = fraction.map(|_| 100);
            job.output(Output::State(progress::Event::Transfer(update)));
            app.job = Some(job);
            app.journal_open = true;
            app.journal_line(Record::new(Level::Info, "test", "Transfer in progress"));
            let ctx = egui::Context::default();
            configure(&ctx);
            // Let egui's initial scrollbar animations finish before checking idle paints.
            for frame in 0..30 {
                let output = render_app(&mut app, &ctx, frame);
                if frame == 29 {
                    let delay = output.viewport_output[&egui::ViewportId::ROOT].repaint_delay;
                    assert!(
                        delay >= Duration::from_millis(400),
                        "{action:?}, fraction={fraction:?}: redraw in {delay:?}; causes={:?}",
                        ctx.repaint_causes()
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
    let mut app = english_app();
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
    let mut app = english_app();
    app.job = Some(job(Action::Restore));
    let ctx = egui::Context::default();
    configure(&ctx);
    let mut journal_button = None;
    for frame in 0..12 {
        let output = render_app(&mut app, &ctx, frame);
        journal_button = output.shapes.iter().find_map(|shape| match &shape.shape {
            egui::Shape::Text(text) if text.galley.text() == "Journal" => {
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
    let _ = render_pass(
        &ctx,
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
        |ctx| {
            let mut frame = eframe::Frame::_new_kittest();
            eframe::App::logic(&mut app, ctx, &mut frame);
            ctx.root_ui(|ui| eframe::App::ui(&mut app, ui, &mut frame));
        },
    );
    assert!(
        app.journal_open,
        "clicks must be applied in the input frame"
    );
    assert_eq!(
        app.job.as_ref().unwrap().phase(),
        "Stage: writing filesystem"
    );
}

fn worker_line(event: progress::Event) -> String {
    format!("{event:?}")
}

fn send_worker(app: &mut App, event: progress::Event) {
    if let progress::Event::Log(record) = event {
        let job = app.job.as_ref().unwrap();
        let mut journal = job.journal.lock().unwrap();
        journal.record(record);
        journal.flush();
    } else {
        app.tx.send(Event::Worker(7, Output::State(event))).unwrap();
    }
    app.poll(&egui::Context::default());
}

fn finished(success: bool) -> Output {
    Output::Finished(worker::Completion {
        success,
        ..worker::Completion::default()
    })
}

fn connect_worker(app: &mut App) -> std::sync::Arc<std::sync::Mutex<worker::Completion>> {
    let job = app.job.as_mut().unwrap();
    let (context, completion) = Job::worker_context(
        job.id,
        &job.journal,
        &app.tx,
        &egui::Context::default(),
        app.windows_reboot_required,
    )
    .unwrap();
    if job.context.cancelled() {
        context.cancel();
    }
    job.context = context;
    completion
}

fn finish_worker(app: &mut App, completion: worker::Completion) {
    let job = app.job.as_ref().unwrap();
    let completion = completion.finish(job.action, job.started, &job.context, &job.journal);
    app.tx
        .send(Event::Worker(job.id, Output::Finished(completion)))
        .unwrap();
}

fn record_completion(app: &mut App, success: bool) {
    let state = connect_worker(app);
    let mut completion = std::mem::take(&mut *state.lock().unwrap());
    completion.success = success;
    finish_worker(app, completion);
}

#[test]
fn a_state_burst_leaves_time_for_rendering_without_losing_events() {
    let mut app = english_app();
    app.job = Some(job(Action::Doctor));
    for index in 0..600 {
        app.tx
            .send(Event::Worker(
                7,
                Output::State(progress::Event::Checkpoint {
                    name: format!("stage_{index}"),
                    complete: false,
                }),
            ))
            .unwrap();
    }
    let ctx = egui::Context::default();
    app.poll(&ctx);
    assert_eq!(app.job.as_ref().unwrap().phase(), "Stage: stage 255");
    app.poll(&ctx);
    app.poll(&ctx);
    assert_eq!(app.job.as_ref().unwrap().phase(), "Stage: stage 599");
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
    assert!(p.ready(Some(&device(42, Mode::PortDfu))));
    assert!(p.ready(Some(&device(42, Mode::Dfu))));
    assert!(!p.ready(Some(&device(43, Mode::Dfu))));
    assert!(!p.ready(Some(&device(42, Mode::Recovery))));
    assert!(!p.ready(None));
    p.action = Action::Revive;
    assert!(p.ready(Some(&device(42, Mode::Dfu))));
}
#[test]
fn native_restore_options_preserve_authorization_and_transcript() {
    let setup = Setup {
        ecid: "2a".into(),
        cache: "cache".into(),
        tokens: "tokens.plist".into(),
        connect_data: "connect.data".into(),
        ..Setup::default()
    };
    let options = setup.restore_options(Path::new("run.jsonl")).unwrap();
    assert!(options.ipsw.is_none());
    assert_eq!(options.ecid, 42);
    assert_eq!(options.firmware_dir.as_deref(), Some(Path::new("cache")));
    assert_eq!(options.transcript.as_deref(), Some(Path::new("run.jsonl")));
    assert_eq!(
        options.authorization_tokens.as_deref(),
        Some(Path::new("tokens.plist"))
    );
    assert_eq!(
        options.apple_connect_data.as_deref(),
        Some(Path::new("connect.data"))
    );
    for action in [
        Action::Doctor,
        Action::PrepareWindows,
        Action::ResetDrivers,
        Action::InstallUdev,
    ] {
        Setup::default().validate(action).unwrap();
    }
    assert!(Setup::default().validate(Action::Download).is_err());
}

#[test]
fn selected_release_is_carried_into_automatic_restore_but_not_local_restore() {
    let file = tempfile::Builder::new().suffix(".ipsw").tempfile().unwrap();
    let release = selected_release();
    let mut setup = Setup {
        ecid: "2a".into(),
        release: Some(release.clone()),
        ipsw: file.path().display().to_string(),
        ..Setup::default()
    };
    assert_eq!(
        setup
            .restore_options(Path::new("run.jsonl"))
            .unwrap()
            .release,
        Some(release)
    );
    setup.automatic = false;
    assert!(
        setup
            .restore_options(Path::new("run.jsonl"))
            .unwrap()
            .release
            .is_none()
    );
}

#[test]
fn udev_setup_needs_no_mac_and_keeps_the_administrator_prompt_until_completion() {
    let operation = job(Action::InstallUdev);
    assert!(operation.action.requires_admin());
    assert!(!operation.action.writes_device());
    assert!(!operation.can_stop());
    assert_eq!(operation.phase(), "Approve the Linux administrator prompt");
    let completion = worker::Completion {
        success: true,
        ..Default::default()
    };
    let notice = completion.notice(Action::InstallUdev);
    assert_eq!(notice.title, "USB access configured");
    assert_eq!(
        notice.detail,
        "Reconnect the USB cable to apply the new access rules."
    );
    assert_eq!(notice.tone, Tone::Success);
    assert!(notice.expires_at.is_some());
}

#[test]
fn linux_settings_offer_usb_access_rules_without_a_connected_device() {
    let ctx = egui::Context::default();
    configure(&ctx);
    let mut app = english_app();
    app.settings_open = true;
    let screen = egui::Rect::from_min_size(egui::Pos2::ZERO, egui::vec2(900.0, 1000.0));
    let mut reached = false;
    for _ in 0..20 {
        let output = render_pass(
            &ctx,
            egui::RawInput {
                screen_rect: Some(screen),
                events: vec![
                    egui::Event::PointerMoved(screen.center()),
                    egui::Event::MouseWheel {
                        phase: egui::TouchPhase::Move,
                        source: egui::MouseWheelSource::Unknown,
                        unit: egui::MouseWheelUnit::Point,
                        delta: egui::vec2(0.0, -60.0),
                        modifiers: egui::Modifiers::NONE,
                    },
                ],
                ..Default::default()
            },
            |ctx| app.settings(ctx),
        );
        if let Some(rect) = visible_text_rect(&output, "Install USB access rules") {
            reached |= screen.contains_rect(rect);
        }
    }
    assert_eq!(reached, cfg!(target_os = "linux"));
    assert!(app.devices.is_empty());
    assert!(app.job.is_none());
}

#[test]
fn completion_waits_for_pending_logs_without_blocking_the_gui() {
    let mut app = english_app();
    let operation = job(Action::Doctor);
    let journal = operation.journal.clone();
    app.job = Some(operation);
    {
        let mut journal = journal.lock().unwrap();
        journal.record(Record::new(Level::Error, "test", "last operation error"));
    }
    record_completion(&mut app, false);
    let (ready, locked) = mpsc::channel();
    let (release, released) = mpsc::channel();
    let holder = std::thread::spawn(move || {
        let _locked = journal.lock().unwrap();
        ready.send(()).unwrap();
        let _ = released.recv_timeout(Duration::from_secs(2));
    });
    locked.recv().unwrap();
    app.poll(&egui::Context::default());
    let still_running = app.job.is_some();
    let completed = app.job.as_mut().unwrap();
    assert!(completed.completion.is_some());
    assert!(completed.stop().is_err());
    assert!(!completed.context.cancelled());
    let _ = release.send(());
    holder.join().unwrap();
    assert!(
        still_running,
        "completion must wait until the journal has been drained"
    );
    app.poll(&egui::Context::default());
    assert!(app.job.is_none());
    assert!(app.journal_text(true).contains("last operation error"));
}

#[test]
fn local_firmware_is_required_and_has_no_cache_option() {
    let file = tempfile::Builder::new().suffix(".IPSW").tempfile().unwrap();
    let mut setup = Setup {
        automatic: false,
        ecid: "2a".into(),
        ipsw: file.path().display().to_string(),
        cache: "cache".into(),
        ..Setup::default()
    };
    let options = setup.restore_options(Path::new("run.jsonl")).unwrap();
    assert_eq!(options.ipsw.as_deref(), Some(file.path()));
    assert!(options.firmware_dir.is_none());
    setup.ipsw = "missing.ipsw".into();
    assert!(setup.validate(Action::Revive).is_err());
    assert!(setup.validate(Action::Verify).is_err());
}
#[test]
fn disconnected_or_recovery_target_blocks_a_write() {
    let mut app = english_app();
    app.host = Ok(Some(drivers::HostStatus {
        apple_service_installed: false,
        apple_service_running: false,
        apple_driver_installed: true,
        compatible_usb_driver: false,
    }));
    app.setup.ecid = "2a".into();
    assert!(app.blocked_reason().is_some());
    app.devices.push(device(42, Mode::Recovery));
    assert!(app.blocked_reason().is_some());
    app.devices[0].mode = Mode::Dfu;
    assert!(app.blocked_reason().is_none());
    app.setup.automatic = false;
    assert!(app.blocked_reason().is_some());
}
#[test]
fn windows_conflicts_and_failed_checks_block_restore_before_worker_start() {
    let mut app = english_app();
    app.setup.ecid = "2a".into();
    app.devices.push(device(42, Mode::Dfu));
    let host = drivers::HostStatus {
        apple_service_installed: true,
        apple_service_running: true,
        apple_driver_installed: true,
        compatible_usb_driver: false,
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
    assert!(app.blocked_reason().unwrap().contains("Restart"));
}
#[test]
fn scan_results_keep_host_and_usb_failures_independent() {
    let mut app = english_app();
    let ctx = egui::Context::default();
    app.scanning = true;
    app.checking_host = true;
    app.tx
        .send(Event::Scan {
            devices: Ok(vec![device(42, Mode::Dfu)]),
        })
        .unwrap();
    app.poll(&ctx);
    assert!(!app.scanning);
    assert_eq!(app.target().unwrap().ecid, 42);
    assert!(app.scan_error.is_none());
    assert!(
        app.checking_host,
        "USB discovery must not wait for DriverStore"
    );
    app.tx
        .send(Event::Host(Err("service access denied".into())))
        .unwrap();
    app.poll(&ctx);
    assert!(!app.checking_host);
    assert_eq!(app.target().unwrap().ecid, 42);
    assert_eq!(app.host.as_ref().unwrap_err(), "service access denied");
    assert!(app.blocked_reason().is_some());

    app.scanning = true;
    app.checking_host = true;
    app.tx.send(Event::Host(Ok(None))).unwrap();
    app.poll(&ctx);
    assert!(app.scanning, "readiness must not finish the USB scan");
    assert!(!app.checking_host);
    app.tx
        .send(Event::Scan {
            devices: Err("USB access denied".into()),
        })
        .unwrap();
    app.poll(&ctx);
    assert!(!app.scanning);
    assert!(app.devices.is_empty());
    assert_eq!(app.scan_error.as_deref(), Some("USB access denied"));
    assert!(matches!(app.host, Ok(None)));
}

#[test]
fn unsupported_dfu_modes_show_the_actual_reason_in_the_device_card() {
    for (mode, pid) in [("Port DFU", "05ac:f014"), ("KIS", "05ac:1881")] {
        let ctx = egui::Context::default();
        configure(&ctx);
        let mut app = english_app();
        app.scanning = true;
        app.tx
            .send(Event::Scan {
                devices: Err(format!("{mode} ({pid}) detected; transport not supported")),
            })
            .unwrap();
        app.poll(&ctx);
        let output = render_pass(&ctx, egui::RawInput::default(), |ctx| {
            ctx.root_ui(|ui| {
                app.prepare_device_card(ui, ctx).end(ui);
            });
        });
        assert!(output.shapes.iter().any(|shape| {
            matches!(&shape.shape, egui::Shape::Text(text) if text.galley.text().contains(pid))
        }));
        assert!(!output.shapes.iter().any(|shape| {
            matches!(&shape.shape, egui::Shape::Text(text) if text.galley.text() == "No Mac connected")
        }));
        assert!(app.blocked_reason().is_some());
        assert!(app.devices.is_empty());
    }
}

#[test]
fn stale_worker_events_do_not_enter_a_new_journal() {
    for active in [false, true] {
        let mut app = english_app();
        if active {
            app.job = Some(job(Action::Restore));
        }
        for output in [
            Output::State(progress::Event::Log(Record::new(
                Level::Error,
                "test",
                "stale error",
            ))),
            Output::State(progress::Event::RestoreCompleted),
            Output::State(progress::Event::RebootRequired),
            Output::State(progress::Event::ProvisioningWarning {
                message: "stale activation warning".into(),
            }),
            finished(true),
        ] {
            app.tx.send(Event::Worker(999, output)).unwrap();
        }
        app.poll(&egui::Context::default());
        assert!(app.logs.is_empty());
        assert!(app.notice.is_none());
        assert!(!app.windows_reboot_required);
        if let Some(job) = app.job {
            assert!(job.completion.is_none());
            assert!(!job.restore_completed);
        }
    }
}

#[test]
fn structured_journal_filters_details_and_saves_each_record_once() {
    let log = tempfile::NamedTempFile::new().unwrap();
    let mut app = english_app();
    let operation = job(Action::Restore);
    operation.journal.lock().unwrap().log = std::io::BufWriter::new(log.reopen().unwrap());
    app.job = Some(operation);
    for (level, message) in [
        (Level::Trace, "binary dump"),
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
    assert_eq!(app.logs.len(), 5);
    assert_eq!(app.logs[2].level, Level::Info);
    assert!(!app.journal_text(app.log_details).contains("binary dump"));
    assert!(
        !app.journal_text(app.log_details)
            .contains("protocol details")
    );
    assert!(
        app.journal_text(app.log_details)
            .contains("connection failed")
    );
    app.log_details = true;
    assert!(app.journal_text(app.log_details).contains("binary dump"));
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
    assert_eq!(app.logs.len(), 5);
    let saved = std::fs::read_to_string(log.path()).unwrap();
    assert_eq!(saved.lines().count(), 5);
    assert!(saved.contains("TRACE"));
    assert!(saved.contains("protocol details"));
    assert!(!saved.contains("ZALIVKA_EVENT "));
}

#[test]
fn failed_journal_writes_keep_worker_state_and_report_partial_logging() {
    let log = tempfile::NamedTempFile::new().unwrap();
    let operation = job(Action::Restore);
    operation.journal.lock().unwrap().log =
        std::io::BufWriter::new(File::open(log.path()).unwrap());
    let mut app = english_app();
    app.log_path = Some(log.path().into());
    app.job = Some(operation);
    send_worker(
        &mut app,
        progress::Event::Log(Record::new(Level::Debug, "test", "original record")),
    );
    assert!(app.log_path.is_none());
    assert!(app.journal_open);
    assert!(app.notice.as_ref().unwrap().title.contains("incomplete"));
    assert!(app.logs[0].message.contains("original record"));
    assert!(app.logs.iter().any(|record| record.level == Level::Warning
        && record.message.contains("Disk journal incomplete")));
    assert!(!app.job.as_ref().unwrap().can_stop());
    send_worker(
        &mut app,
        progress::Event::Log(Record::new(Level::Info, "test", "next record")),
    );
    assert_eq!(app.logs.back().unwrap().message, "next record");
    send_worker(&mut app, progress::Event::RestoreCompleted);
    assert!(!app.job.as_ref().unwrap().can_stop());
    record_completion(&mut app, true);
    for _ in 0..2 {
        app.tx.send(Event::Worker(7, finished(true))).unwrap();
    }
    app.poll(&egui::Context::default());
    let notice = app.notice.as_ref().unwrap();
    assert_eq!(notice.title, Action::Restore.completed_title());
    assert_eq!(notice.tone, Tone::Neutral);
    assert!(notice.journal_error.is_some());
    assert!(notice.expires_at.is_none());
    assert!(std::fs::read(log.path()).unwrap().is_empty());
}

#[test]
fn a_failure_writing_the_final_record_cannot_report_a_complete_journal() {
    let log = tempfile::NamedTempFile::new().unwrap();
    let operation = job(Action::Verify);
    operation.journal.lock().unwrap().log =
        std::io::BufWriter::new(File::open(log.path()).unwrap());
    let mut app = english_app();
    app.log_path = Some(log.path().into());
    app.job = Some(operation);
    record_completion(&mut app, true);
    for _ in 0..2 {
        app.tx.send(Event::Worker(7, finished(true))).unwrap();
    }
    app.poll(&egui::Context::default());
    assert!(app.job.is_none());
    assert!(app.log_path.is_none());
    assert!(app.journal_open);
    let notice = app.notice.as_ref().unwrap();
    assert_eq!(notice.title, Action::Verify.completed_title());
    assert_eq!(notice.tone, Tone::Neutral);
    assert!(notice.journal_error.is_some());
    assert!(notice.expires_at.is_none());
}

#[test]
fn memory_journal_export_includes_hidden_details_and_marks_the_partial_copy() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("memory.log");
    let mut app = english_app();
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
    assert!(saved.starts_with("Incomplete journal:"));
}

#[test]
fn native_completion_follows_final_events_and_journal_writes() {
    let log = tempfile::NamedTempFile::new().unwrap();
    let mut app = english_app();
    let ctx = egui::Context::default();
    let operation = job(Action::Restore);
    operation.journal.lock().unwrap().log = std::io::BufWriter::new(log.reopen().unwrap());
    app.job = Some(operation);
    app.poll(&ctx);
    assert!(app.notice.is_none());
    assert!(app.job.as_ref().unwrap().completion.is_none());
    app.tx.send(Event::Worker(999, finished(true))).unwrap();
    send_worker(
        &mut app,
        progress::Event::Log(Record::new(Level::Warning, "test", "final worker message")),
    );
    assert!(app.notice.is_none());
    record_completion(&mut app, true);
    app.poll(&ctx);
    assert!(app.job.is_none());
    let notice = app.notice.as_ref().unwrap();
    assert_eq!(notice.tone, Tone::Success);
    assert_eq!(notice.title, Action::Restore.completed_title());
    assert_eq!(notice.detail, progress::MAC_STARTUP_HINT);
    assert!(
        std::fs::read_to_string(log.path())
            .unwrap()
            .contains("final worker message")
    );
}

#[test]
fn completion_carries_reboot_and_journal_errors_without_earlier_gui_updates() {
    for action in [Action::PrepareWindows, Action::ResetDrivers] {
        let mut app = english_app();
        app.job = Some(job(action));
        app.tx
            .send(Event::Worker(
                7,
                Output::Finished(worker::Completion {
                    success: true,
                    reboot_required: true,
                    ..worker::Completion::default()
                }),
            ))
            .unwrap();
        // The terminal result cannot be replaced by a conflicting duplicate.
        app.tx.send(Event::Worker(7, finished(false))).unwrap();
        assert!(!app.windows_reboot_required);
        app.poll(&egui::Context::default());
        assert!(app.job.is_none());
        assert!(app.windows_reboot_required);
        assert_eq!(app.notice.as_ref().unwrap().title, "Restart Windows");
    }

    let log = tempfile::NamedTempFile::new().unwrap();
    let mut app = english_app();
    app.job = Some(job(Action::Verify));
    app.log_path = Some(log.path().into());
    app.tx
        .send(Event::Worker(
            7,
            Output::Finished(worker::Completion {
                success: true,
                journal_error: Some("journal thread stopped".into()),
                ..worker::Completion::default()
            }),
        ))
        .unwrap();
    app.poll(&egui::Context::default());
    assert!(app.job.is_none());
    assert!(app.log_path.is_none());
    assert!(app.journal_open);
    let notice = app.notice.as_ref().unwrap();
    assert_eq!(notice.title, Action::Verify.completed_title());
    assert_eq!(notice.tone, Tone::Neutral);
    assert_eq!(
        notice.journal_error.as_deref(),
        Some("journal thread stopped")
    );
    assert!(notice.expires_at.is_none());
}

#[test]
fn completion_uses_context_cancellation_without_a_separate_gui_flag() {
    let mut app = english_app();
    app.job = Some(job(Action::Doctor));
    let state = connect_worker(&mut app);
    let context = app.job.as_ref().unwrap().context.clone();
    std::thread::spawn(move || context.cancel()).join().unwrap();
    let mut completion = std::mem::take(&mut *state.lock().unwrap());
    completion.success = true;
    finish_worker(&mut app, completion);
    app.poll(&egui::Context::default());
    assert!(app.job.is_none());
    let notice = app.notice.as_ref().unwrap();
    assert_eq!(notice.title, "Operation stopped");
    assert_eq!(notice.tone, Tone::Neutral);
    assert_eq!(app.logs.back().unwrap().level, Level::Info);
    assert!(
        app.logs
            .back()
            .unwrap()
            .message
            .starts_with("Operation stopped.")
    );
}

#[test]
fn final_record_failure_is_carried_in_the_result_before_the_gui_polls() {
    let log = tempfile::NamedTempFile::new().unwrap();
    let operation = job(Action::Verify);
    operation.journal.lock().unwrap().log =
        std::io::BufWriter::new(File::open(log.path()).unwrap());
    let mut app = english_app();
    app.log_path = Some(log.path().into());
    app.job = Some(operation);
    record_completion(&mut app, true);
    let event = app.rx.recv_timeout(Duration::from_secs(1)).unwrap();
    let Event::Worker(7, Output::Finished(completion)) = &event else {
        panic!("expected the completed worker result");
    };
    assert!(
        completion.success,
        "a journal failure must preserve the operation result"
    );
    assert!(completion.journal_error.is_some());
    let notice = completion.notice(Action::Verify);
    assert_eq!(notice.title, Action::Verify.completed_title());
    assert_eq!(notice.tone, Tone::Neutral);
    assert!(notice.expires_at.is_none());
    assert!(app.notice.is_none());
    assert!(app.log_path.is_some());
    app.tx.send(event).unwrap();
    app.poll(&egui::Context::default());
    assert!(app.job.is_none());
    assert!(app.log_path.is_none());
    assert!(app.notice.as_ref().unwrap().journal_error.is_some());
}

#[test]
fn gui_verifies_an_ipsw_directly_and_keeps_trace_hidden_by_default() {
    use std::io::Write;
    let file = tempfile::Builder::new().suffix(".ipsw").tempfile().unwrap();
    let mut zip = zip::ZipWriter::new(file.reopen().unwrap());
    zip.start_file(
        "BuildManifest.plist",
        zip::write::SimpleFileOptions::default(),
    )
    .unwrap();
    let manifest = zalivka::wire::dict([
        (
            "SupportedProductTypes",
            plist::Value::Array(vec!["MacBookPro17,1".into()]),
        ),
        (
            "BuildIdentities",
            plist::Value::Array(vec![zalivka::wire::dict([(
                "Manifest",
                zalivka::wire::dict([] as [(&str, plist::Value); 0]),
            )])]),
        ),
    ]);
    manifest.to_writer_xml(&mut zip).unwrap();
    zip.start_file("payload", zip::write::SimpleFileOptions::default())
        .unwrap();
    zip.write_all(&[0, 1, 255]).unwrap();
    zip.finish().unwrap();
    let mut app = english_app();
    app.setup.ipsw = file.path().display().to_string();
    let ctx = egui::Context::default();
    app.start(Action::Verify, &ctx);
    assert!(app.job.is_some());
    let path = app.log_path.clone().unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    while app.job.is_some() && Instant::now() < deadline {
        app.poll(&ctx);
        std::thread::sleep(Duration::from_millis(5));
    }
    assert!(app.job.is_none());
    assert_eq!(app.notice.as_ref().unwrap().tone, Tone::Success);
    assert_eq!(app.logs.front().unwrap().source, "session");
    assert!(!app.log_details);
    assert!(!app.journal_text(false).contains("ipsw:zip"));
    assert!(app.journal_text(true).contains("ipsw:zip"));
    let saved = std::fs::read_to_string(&path).unwrap();
    assert!(saved.contains("TRACE"));
    assert!(saved.contains("IPSW verified"));
    assert!(!saved.contains("ZALIVKA_EVENT "));
    std::fs::remove_file(path).unwrap();
}

#[test]
fn trace_bursts_do_not_evict_the_visible_operation_history() {
    let mut app = english_app();
    app.journal_line(Record::new(Level::Info, "restore", "Restore stage"));
    for index in 0..8000 {
        app.journal_line(Record::new(Level::Trace, "fdr:conn", index));
    }
    assert_eq!(app.logs.len(), 4000);
    assert!(app.journal_text(false).contains("Restore stage"));
    assert!(app.journal_text(true).contains("7999"));
}

#[test]
fn completion_notice_preserves_cancel_failure_reboot_and_success_priority() {
    use worker::Completion;
    for action in [Action::Restore, Action::Revive] {
        for success in [false, true] {
            let notice = Completion {
                success,
                cancelled: true,
                reboot_required: true,
                ..Completion::default()
            }
            .notice(action);
            assert_eq!(notice.title, "Operation stopped");
            assert!(notice.detail.is_empty());
            assert_eq!(notice.tone, Tone::Neutral);
            assert!(notice.expires_at.is_some());
        }
    }
    for action in [
        Action::Restore,
        Action::PrepareWindows,
        Action::ResetDrivers,
    ] {
        let notice = Completion {
            reboot_required: true,
            ..Completion::default()
        }
        .notice(action);
        assert_eq!(notice.tone, Tone::Error);
        assert!(notice.title.ends_with(": error"));
        assert!(notice.expires_at.is_none());
    }
    let notice = Completion {
        success: true,
        reboot_required: true,
        ..Completion::default()
    }
    .notice(Action::ResetDrivers);
    assert_eq!(notice.title, "Restart Windows");
    assert_eq!(notice.tone, Tone::Neutral);
    assert!(notice.expires_at.is_none());
    for action in [
        Action::Restore,
        Action::Revive,
        Action::Download,
        Action::Verify,
        Action::Doctor,
        Action::PrepareWindows,
        Action::ResetDrivers,
    ] {
        let notice = Completion {
            success: true,
            ..Completion::default()
        }
        .notice(action);
        assert_eq!(notice.title, action.completed_title());
        assert_eq!(notice.tone, Tone::Success);
        assert!(notice.expires_at.is_some());
        let expected_detail = match action {
            Action::Restore | Action::Revive => progress::MAC_STARTUP_HINT,
            Action::ResetDrivers => "Reconnect the Mac and enter DFU mode.",
            _ => "",
        };
        assert_eq!(notice.detail, expected_detail);
    }
}

#[test]
fn provisioning_warning_survives_completion_and_journal_eviction() {
    for action in [Action::Restore, Action::Revive] {
        let mut app = english_app();
        app.job = Some(job(action));
        let state = connect_worker(&mut app);
        let message = "Could not obtain Apple certificates. Connect the Mac to Wi-Fi or Ethernet and complete activation.";
        app.job.as_ref().unwrap().context.run(|| {
            progress::Event::ProvisioningWarning {
                message: message.into(),
            }
            .emit();
        });
        send_worker(&mut app, progress::Event::RestoreCompleted);
        for index in 0..4001 {
            app.journal_line(Record::new(Level::Info, "test", format!("message {index}")));
        }
        let mut completion = std::mem::take(&mut *state.lock().unwrap());
        completion.success = true;
        let notice = completion.notice(action);
        assert_eq!(notice.tone, Tone::Neutral);
        assert!(notice.title.contains("check activation"));
        assert_eq!(notice.detail, message);
        assert!(notice.expires_at.is_none());
        assert_eq!(app.job.as_ref().unwrap().overall_fraction, Some(1.0));
        completion.success = false;
        assert_eq!(completion.notice(action).tone, Tone::Error);
        completion.success = true;
        completion.cancelled = true;
        assert_eq!(completion.notice(action).title, "Operation stopped");
        completion.cancelled = false;
        finish_worker(&mut app, completion);
        // A duplicate incomplete result cannot erase the worker's warning.
        app.tx.send(Event::Worker(7, finished(true))).unwrap();
        app.poll(&egui::Context::default());
        assert!(app.job.is_none());
        assert_eq!(app.notice.as_ref().unwrap().detail, message);
        assert_eq!(app.logs.back().unwrap().level, Level::Warning);
    }
}

#[test]
fn completion_records_label_duration_without_adding_it_to_notifications() {
    for (action, expected_detail, expected_record) in [
        (
            Action::ResetDrivers,
            "Reconnect the Mac and enter DFU mode.",
            "USB driver reset complete. Duration: 00:00:01. Reconnect the Mac and enter DFU mode.",
        ),
        (Action::Verify, "", "IPSW verified. Duration: 00:00:01."),
    ] {
        let log = tempfile::NamedTempFile::new().unwrap();
        let mut operation = job(action);
        operation.journal.lock().unwrap().log = std::io::BufWriter::new(log.reopen().unwrap());
        operation.started = Instant::now() - Duration::from_secs(1);
        let mut app = english_app();
        app.job = Some(operation);
        record_completion(&mut app, true);
        for _ in 0..2 {
            app.tx.send(Event::Worker(7, finished(true))).unwrap();
        }
        app.poll(&egui::Context::default());
        assert!(app.job.is_none());
        assert_eq!(app.notice.as_ref().unwrap().detail, expected_detail);
        assert_eq!(app.logs.back().unwrap().message, expected_record);
        let saved = std::fs::read_to_string(log.path()).unwrap();
        assert!(saved.contains(expected_record));
        assert_eq!(saved.lines().count(), 1);
    }
}

#[test]
fn worker_state_survives_journal_eviction_and_protects_restore_from_stopping() {
    let mut app = english_app();
    app.job = Some(job(Action::Restore));
    assert!(!app.job.as_ref().unwrap().can_stop());
    app.journal_line(Record::new(Level::Info, "test", "Restore complete"));
    app.journal_line(Record::new(
        Level::Warning,
        "test",
        "Restart Windows before restoring the Mac.",
    ));
    app.tx
        .send(Event::Worker(
            7,
            Output::State(progress::Event::Log(Record::new(
                Level::Info,
                "test",
                worker_line(progress::Event::RestoreCompleted),
            ))),
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
    assert_eq!(app.job.as_ref().unwrap().phase(), "Stage: update firmware");
    send_worker(&mut app, progress::Event::RestoreCompleted);
    for index in 0..4001 {
        app.journal_line(Record::new(Level::Info, "test", format!("message {index}")));
    }
    assert_eq!(app.logs.len(), 4000);
    let job = app.job.as_mut().unwrap();
    assert_eq!(
        worker::Completion {
            success: true,
            ..worker::Completion::default()
        }
        .notice(job.action)
        .detail,
        progress::MAC_STARTUP_HINT
    );
    assert!(!job.can_stop());
    assert!(job.stop().is_err());
    job.action = Action::PrepareWindows;
    assert!(!job.can_stop());
    job.action = Action::ResetDrivers;
    assert!(!job.can_stop());
    assert_eq!(
        worker::Completion {
            success: true,
            reboot_required: true,
            ..worker::Completion::default()
        }
        .notice(job.action)
        .title,
        "Restart Windows"
    );
    send_worker(&mut app, progress::Event::RebootRequired);
    assert!(app.windows_reboot_required);
}

#[test]
fn driver_reset_waits_for_completion_and_prompts_to_reconnect_or_reboot() {
    let job = job(Action::ResetDrivers);
    assert!(!job.can_stop());
    let notice = worker::Completion {
        success: true,
        ..worker::Completion::default()
    }
    .notice(job.action);
    assert_eq!(notice.title, Action::ResetDrivers.completed_title());
    assert!(notice.detail.contains("enter DFU mode"));
    assert_eq!(
        worker::Completion {
            success: true,
            reboot_required: true,
            ..worker::Completion::default()
        }
        .notice(job.action)
        .title,
        "Restart Windows"
    );
    assert_eq!(
        worker::Completion {
            reboot_required: true,
            ..worker::Completion::default()
        }
        .notice(job.action)
        .tone,
        Tone::Error
    );
}

#[test]
fn transfer_events_preserve_phase_order_and_stderr_never_changes_progress() {
    let mut app = english_app();
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
    let line = worker_line(progress::Event::Transfer(update));
    send_worker(
        &mut app,
        progress::Event::Log(Record::new(Level::Info, "test", line.clone())),
    );
    assert!(app.job.as_ref().unwrap().transfers.is_empty());
    assert!(!app.job.as_ref().unwrap().can_stop());
    assert_eq!(app.job.as_ref().unwrap().phase(), "Restore complete");
    assert_eq!(app.logs.back().unwrap().message, line);
}

fn active_job_labels(app: &mut App, theme: egui::Theme) -> (Vec<String>, usize) {
    let ctx = egui::Context::default();
    configure(&ctx);
    ctx.set_theme(theme);
    let output = render_pass(
        &ctx,
        egui::RawInput {
            screen_rect: Some(egui::Rect::from_min_size(
                egui::Pos2::ZERO,
                egui::vec2(1000.0, 2000.0),
            )),
            ..Default::default()
        },
        |ctx| {
            ctx.root_ui(|ui| {
                egui::CentralPanel::default().show(ui, |ui| app.active_job(ui));
            });
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
                    && rect.fill == ctx.global_style().visuals.window_fill
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
        let mut app = english_app();
        app.job = Some(job(Action::Restore));
        let mut update = transfer(1, "ASR filesystem transfer");
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
                    .any(|label| label == "Overall restore progress (estimate)")
            );
            assert!(
                labels
                    .iter()
                    .any(|label| label == "ASR filesystem transfer")
            );
            assert!(labels.iter().any(|label| label == "60%"));
            assert!(
                labels
                    .iter()
                    .any(|label| label == "Transferred: 60 B of 100 B")
            );
            assert!(labels.iter().any(|label| label == "Speed"));
            assert!(labels.iter().any(|label| label == "Time remaining"));
            assert!(
                !labels
                    .iter()
                    .any(|label| label == "9%" || label == "Operation 13")
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
    let mut app = english_app();
    app.job = Some(job(Action::Restore));
    let mut first = transfer(1, "Same name");
    let mut second = first.clone();
    second.id = 2;
    let third = transfer(3, "Same name");
    for update in [&first, &second, &third] {
        send_worker(&mut app, progress::Event::Transfer(update.clone()));
    }
    assert_eq!(app.job.as_ref().unwrap().transfers.len(), 3);
    for theme in [egui::Theme::Dark, egui::Theme::Light] {
        assert_eq!(active_job_labels(&mut app, theme).1, 4);
    }
    first.finished = true;
    send_worker(&mut app, progress::Event::Transfer(first.clone()));
    let retry = transfer(4, "Same name");
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
    let mut app = english_app();
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
        progress::Event::Log(Record::new(Level::Info, "restore", "Restore complete")),
    );
    assert_eq!(app.job.as_ref().unwrap().overall_fraction, Some(0.99));
    send_worker(&mut app, progress::Event::RestoreCompleted);
    assert_eq!(app.job.as_ref().unwrap().overall_fraction, Some(1.0));
}

#[test]
fn overall_progress_keeps_updates_received_before_their_weights() {
    let mut app = english_app();
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
    let mut app = english_app();
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
    let mut app = english_app();
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
    let traces: std::collections::BTreeMap<String, Vec<serde_json::Value>> =
        serde_json::from_str(include_str!("../fixtures/restored-progress-26A434.json")).unwrap();
    for (name, action, expected) in [
        ("erase", Action::Restore, 0.99),
        // The device advertises operations 13 and 14 during this Revive, but
        // never reports their progress. They must not be guessed complete.
        ("update", Action::Revive, 0.41),
    ] {
        let mut app = english_app();
        app.job = Some(job(action));
        for event in &traces[name] {
            let decoded = match event["event"].as_str().unwrap() {
                "operation_weights" => progress::Event::OperationWeights {
                    weights: serde_json::from_value(event["weights"].clone()).unwrap(),
                    progresses: vec![],
                },
                "operation_progress" => progress::Event::OperationProgress {
                    operation: event["operation"].as_u64().unwrap(),
                    progress: event["progress"].as_i64().unwrap(),
                },
                name => panic!("unexpected fixture event {name}"),
            };
            send_worker(&mut app, decoded);
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
    let mut app = english_app();
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
    let mut app = english_app();
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
        journal::save_log(source.clone(), Some(&source), "visible tail", None).unwrap(),
        source
    );
    assert_eq!(std::fs::read_to_string(&source).unwrap(), full);
    journal::save_log(target.clone(), Some(&source), "visible tail", None).unwrap();
    assert_eq!(std::fs::read_to_string(&target).unwrap(), full);
    journal::save_log(target.clone(), None, "visible tail", None).unwrap();
    assert_eq!(std::fs::read_to_string(&target).unwrap(), "visible tail");
    assert!(
        journal::save_log(
            target.clone(),
            Some(&directory.path().join("missing")),
            "tail",
            None
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

    journal::save_log(destination.clone(), Some(&source), "tail", None).unwrap();
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
        let mut app = english_app();
        app.setup.ecid = "2a".into();
        app.devices.push(device(42, Mode::Dfu));
        app.settings_open = action.is_none();
        app.confirmation = action.map(|action| Confirmation {
            action,
            ecid: 42,
            accepted: false,
        });
        for _ in 0..3 {
            let _ = render_pass(
                &ctx,
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
        let _ = render_pass(&ctx, input, |ctx| {
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
    let mut app = english_app();
    app.journal_open = true;
    app.logs
        .push_back(Record::new(Level::Error, "test", "example"));
    for theme in [egui::Theme::Dark, egui::Theme::Light] {
        ctx.set_theme(theme);
        let output = render_pass(
            &ctx,
            egui::RawInput {
                screen_rect: Some(egui::Rect::from_min_size(
                    egui::Pos2::ZERO,
                    egui::vec2(1020.0, 1100.0),
                )),
                ..Default::default()
            },
            |ctx| {
                ctx.root_ui(|ui| {
                    app.header(ui);
                    app.journal(ui);
                    egui::CentralPanel::default().show(ui, |ui| {
                        app.prepare_device_card(ui, ctx).end(ui);
                        app.prepare_firmware_card(ui, ctx).end(ui);
                        app.actions(ui);
                    });
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
fn ordinary_notifications_expire_after_five_seconds_and_replacements_restart_the_timer() {
    let ctx = egui::Context::default();
    configure(&ctx);
    let mut app = english_app();
    app.scanning = true;
    let before = Instant::now();
    app.tx
        .send(Event::Saved(Ok(PathBuf::from("first.log"))))
        .unwrap();
    let mut output = egui::FullOutput::default();
    for frame in 0..30 {
        output = render_app(&mut app, &ctx, frame);
    }
    let deadline = app.notice.as_ref().unwrap().expires_at.unwrap();
    assert!(deadline >= before + Duration::from_secs(5));
    assert!(deadline <= Instant::now() + Duration::from_secs(5));
    assert!(
        output.viewport_output[&egui::ViewportId::ROOT].repaint_delay >= Duration::from_millis(400),
        "waiting for notification expiry must not cause continuous redraws; causes={:?}",
        ctx.repaint_causes()
    );

    app.notice.as_mut().unwrap().expires_at = Some(Instant::now());
    let _ = render_app(&mut app, &ctx, 30);
    assert!(app.notice.is_none());

    for (frame, path) in [(31, "second.log"), (32, "third.log")] {
        let before = Instant::now();
        app.tx.send(Event::Saved(Ok(PathBuf::from(path)))).unwrap();
        let _ = render_app(&mut app, &ctx, frame);
        let notice = app.notice.as_mut().unwrap();
        assert_eq!(notice.detail, path);
        let deadline = notice.expires_at.unwrap();
        assert!(deadline >= before + Duration::from_secs(5));
        assert!(deadline <= Instant::now() + Duration::from_secs(5));
        notice.expires_at = Some(Instant::now());
    }

    app.error("Error", "Critical message");
    for frame in 33..36 {
        let _ = render_app(&mut app, &ctx, frame);
        let notice = app.notice.as_ref().unwrap();
        assert_eq!(notice.tone, Tone::Error);
        assert!(notice.expires_at.is_none());
    }
}

#[test]
fn notifications_keep_content_in_place_and_their_actions_work_in_small_windows() {
    for theme in [egui::Theme::Light, egui::Theme::Dark] {
        for size in [egui::vec2(1280.0, 900.0), egui::vec2(480.0, 360.0)] {
            let ctx = egui::Context::default();
            configure(&ctx);
            ctx.set_theme(theme);
            let mut app = english_app();
            app.journal_line(Record::new(Level::Error, "test", "Error details"));
            let screen = egui::Rect::from_min_size(egui::Pos2::ZERO, size);
            let input = egui::RawInput {
                screen_rect: Some(screen),
                ..Default::default()
            };
            let baseline = render_pass(&ctx, input.clone(), |ctx| ctx.root_ui(|ui| app.view(ui)));
            let heading = visible_text_rect(&baseline, "Mac restore").unwrap();
            for tone in [Tone::Neutral, Tone::Success, Tone::Error] {
                app.notice = Some(Notice {
                    title: "Notice".into(),
                    detail: "Message details. ".repeat(50),
                    journal_error: None,
                    tone,
                    expires_at: None,
                });
                let mut output = egui::FullOutput::default();
                for _ in 0..3 {
                    output = render_pass(&ctx, input.clone(), |ctx| ctx.root_ui(|ui| app.view(ui)));
                }
                assert_eq!(visible_text_rect(&output, "Mac restore"), Some(heading));
                for label in ["Notice", "×"] {
                    let rect = visible_text_rect(&output, label)
                        .unwrap_or_else(|| panic!("{label} clipped at {size:?}, {theme:?}"));
                    assert!(screen.contains_rect(rect));
                }
                let click = |pos| egui::RawInput {
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
                    ..input.clone()
                };
                if tone == Tone::Error {
                    let pos = visible_text_rect(&output, "Open journal").unwrap().center();
                    output = render_pass(&ctx, click(pos), |ctx| ctx.root_ui(|ui| app.view(ui)));
                    assert!(app.journal_open);
                }
                let pos = visible_text_rect(&output, "×").unwrap().center();
                let _ = render_pass(&ctx, click(pos), |ctx| ctx.root_ui(|ui| app.view(ui)));
                assert!(app.notice.is_none());
            }
        }
    }
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
        let mut app = english_app();
        app.journal_open = true;
        app.host = Ok(Some(drivers::HostStatus {
            apple_service_installed: false,
            apple_service_running: false,
            apple_driver_installed: false,
            compatible_usb_driver: false,
        }));
        for _ in 0..20 {
            app.journal_line(Record::new(Level::Error, "test", "Journal check"));
        }
        let screen = egui::Rect::from_min_size(egui::Pos2::ZERO, size);
        let mut output = egui::FullOutput::default();
        // Also exercise shrinking a window after egui has saved a taller journal.
        for frame_size in [egui::vec2(1280.0, 1000.0), size, size, size] {
            output = render_pass(
                &ctx,
                egui::RawInput {
                    screen_rect: Some(egui::Rect::from_min_size(egui::Pos2::ZERO, frame_size)),
                    ..Default::default()
                },
                |ctx| ctx.root_ui(|ui| app.view(ui)),
            );
        }
        let heading = visible_text_rect(&output, "Mac restore")
            .unwrap_or_else(|| panic!("main content hidden at {size:?}"));
        assert!(screen.contains_rect(heading));
        for label in ["Copy", "Save journal", "Hide"] {
            assert!(
                visible_text_rect(&output, label).is_some(),
                "journal control {label} clipped at {size:?}"
            );
        }
        assert!(
            output.shapes.iter().any(|shape| {
                if let egui::Shape::Text(text) = &shape.shape
                    && text.galley.text().contains("Journal check")
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
        let labels = ["Device", "Firmware", "Start Revive", "Erase and restore"];
        for _ in 0..50 {
            for (reached, label) in reached.iter_mut().zip(labels) {
                *reached |= visible_text_rect(&output, label).is_some();
            }
            output = render_pass(
                &ctx,
                egui::RawInput {
                    screen_rect: Some(screen),
                    events: vec![
                        egui::Event::PointerMoved(heading.center()),
                        egui::Event::MouseWheel {
                            phase: egui::TouchPhase::Move,
                            source: egui::MouseWheelSource::Unknown,
                            unit: egui::MouseWheelUnit::Point,
                            delta: egui::vec2(0.0, -35.0),
                            modifiers: egui::Modifiers::NONE,
                        },
                    ],
                    ..Default::default()
                },
                |ctx| ctx.root_ui(|ui| app.view(ui)),
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
            let mut app = english_app();
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
                let output = render_pass(
                    &ctx,
                    egui::RawInput {
                        screen_rect: Some(egui::Rect::from_min_size(
                            egui::Pos2::ZERO,
                            egui::vec2(width, 1600.0),
                        )),
                        ..Default::default()
                    },
                    |ctx| ctx.root_ui(|ui| app.view(ui)),
                );
                for shape in &output.shapes {
                    if let egui::Shape::Text(text) = &shape.shape {
                        assert_ne!(text.galley.text(), "Searching…");
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
                                    && rect.fill == ctx.global_style().visuals.window_fill
                                    && rect.rect.contains(heading.center()) =>
                            {
                                Some(rect.rect)
                            }
                            _ => None,
                        })
                        .unwrap()
                };
                let device = card_rect("Device");
                let firmware = card_rect("Firmware");
                let actions = card_rect("Action");
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
                let revive = visible_text_rect(&output, "Start Revive").unwrap();
                let restore = visible_text_rect(&output, "Erase and restore").unwrap();
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
        let mut app = english_app();
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
            None => "USB diagnostics",
            Some(Action::Revive) => "Start Revive",
            _ => "Erase Mac",
        };
        let mut reached = false;
        let mut compact_folder_row = false;
        for frame in 0..30 {
            let output = render_pass(
                &ctx,
                egui::RawInput {
                    screen_rect: Some(screen),
                    events: vec![
                        egui::Event::PointerMoved(screen.center()),
                        egui::Event::MouseWheel {
                            phase: egui::TouchPhase::Move,
                            source: egui::MouseWheelSource::Unknown,
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
                    for label in ["Settings", "Done"] {
                        let rect = visible_text_rect(&output, label)
                            .unwrap_or_else(|| panic!("settings header {label} scrolled away"));
                        assert!(screen.contains_rect(rect));
                    }
                }
                if let (Some(title), Some(field), Some(button)) = (
                    visible_text_rect(&output, "Firmware folder"),
                    visible_text_rect(&output, "Default"),
                    visible_text_rect(&output, "Browse"),
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

fn firmware_card_text(app: &mut App, ctx: &egui::Context) -> String {
    let output = render_pass(
        ctx,
        egui::RawInput {
            screen_rect: Some(egui::Rect::from_min_size(
                egui::Pos2::ZERO,
                egui::vec2(700.0, 640.0),
            )),
            ..Default::default()
        },
        |ctx| {
            ctx.root_ui(|ui| {
                egui::CentralPanel::default()
                    .show(ui, |ui| app.prepare_firmware_card(ui, ctx).end(ui));
            });
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
    let mut app = english_app();
    assert!(firmware_card_text(&mut app, &ctx).contains("Connect a Mac"));
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
    assert!(firmware_card_text(&mut app, &ctx).contains("Finding firmware"));
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
        })
        .unwrap();
    app.poll(&ctx);
    assert!(firmware_card_text(&mut app, &ctx).contains("26.0.1"));
    assert_eq!(app.next_firmware_request, 1);

    app.tx
        .send(Event::Scan {
            devices: Ok(vec![]),
        })
        .unwrap();
    app.poll(&ctx);
    assert!(app.firmware.is_none());
    let text = firmware_card_text(&mut app, &ctx);
    assert!(text.contains("Connect a Mac"));
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
    let mut app = english_app();
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
    assert!(text.contains("Could not find compatible firmware"));
    assert!(text.contains("Retry"));
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

#[test]
fn phase_labels_follow_the_current_language_and_completion_is_terminal() {
    let mut operation = job(Action::Restore);
    operation.output(Output::State(progress::Event::Checkpoint {
        name: "writing_filesystem".into(),
        complete: false,
    }));
    assert_eq!(operation.phase(), "Stage: writing filesystem");
    let mut localizer = zalivka::localization::Localizer::load();
    localizer.select("ru");
    {
        let _language = localizer.enter();
        assert_eq!(operation.phase(), "Этап: writing filesystem");
        operation.output(Output::State(progress::Event::RestoreCompleted));
        operation.output(Output::State(progress::Event::Checkpoint {
            name: "late_checkpoint".into(),
            complete: false,
        }));
        assert_eq!(operation.phase(), "Восстановление завершено");
    }
    assert_eq!(operation.phase(), "Restore complete");
}
