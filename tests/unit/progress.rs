use super::*;

#[test]
fn dropped_streams_emit_one_terminal_event_without_claiming_all_bytes_were_sent() {
    const CHILD: &str = "ZALIVKA_TEST_PROGRESS_DROP";
    if std::env::var_os(CHILD).is_some() {
        crate::logging::init(false);
        {
            let mut interrupted = Progress::new("download", Some(100), 0);
            interrupted.advance(40);
        }
        let mut retry = Progress::new("download", Some(100), 40);
        retry.advance(60);
        retry.finish();
        return;
    }
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "progress::tests::dropped_streams_emit_one_terminal_event_without_claiming_all_bytes_were_sent", "--nocapture"])
        .env(CHILD, "1").env(WORKER_EVENTS_ENV, "1").output().unwrap();
    assert!(output.status.success());
    let updates: Vec<_> = String::from_utf8(output.stdout)
        .unwrap()
        .lines()
        .filter_map(|line| Event::parse(&line[line.find(EVENT_PREFIX)?..]))
        .filter_map(|event| match event {
            Event::Transfer(update) => Some(update),
            _ => None,
        })
        .collect();
    let ended: Vec<_> = updates.iter().filter(|update| update.finished).collect();
    assert_eq!(ended.len(), 2);
    assert_ne!(ended[0].id, ended[1].id);
    assert_eq!((ended[0].completed, ended[0].total), (40, Some(100)));
    assert_eq!((ended[1].completed, ended[1].total), (100, Some(100)));
}

#[test]
fn transfer_identity_and_operation_are_stable_and_isolated_between_workers() {
    let (first, second) = with_operation(Some(59), || {
        let progress = Progress::new("same component", Some(100), 0);
        let first = progress.update(progress.started, false);
        let second = std::thread::spawn(|| {
            assert_eq!(current_operation(), None);
            with_operation(Some(80), || {
                let progress = Progress::new("same component", Some(100), 0);
                progress.update(progress.started, false)
            })
        })
        .join()
        .unwrap();
        assert_eq!(current_operation(), Some(59));
        assert_eq!(first.id, progress.update(progress.started, true).id);
        (first, second)
    });
    assert_eq!(current_operation(), None);
    assert_ne!(first.id, second.id);
    assert_eq!(first.operation, Some(59));
    assert_eq!(second.operation, Some(80));
    let mut encoded = Vec::new();
    Event::Transfer(first.clone())
        .write_to(&mut encoded)
        .unwrap();
    assert_eq!(
        Event::parse(std::str::from_utf8(&encoded).unwrap()),
        Some(Event::Transfer(first))
    );
    let result = std::panic::catch_unwind(|| with_operation(Some(13), || panic!("failed request")));
    assert!(result.is_err());
    assert_eq!(current_operation(), None);
}

#[test]
fn samples_measure_new_bytes_and_keep_resumed_offsets_out_of_the_rate() {
    let mut progress = Progress::new("BaseSystem", Some(1000), 400);
    progress.completed = 600;
    let update = progress.update(progress.started + Duration::from_secs(2), false);
    assert_eq!(update.bytes_per_second, 100.0);
    assert_eq!(update.fraction(), Some(0.6));
    let mut line = Vec::new();
    Event::Transfer(update).write_to(&mut line).unwrap();
    let Event::Transfer(parsed) = Event::parse(std::str::from_utf8(&line).unwrap()).unwrap() else {
        panic!("expected a transfer event");
    };
    assert_eq!(parsed.completed, 600);
    assert!(!parsed.finished);
    progress.sampled_at += Duration::from_secs(2);
    progress.sampled_bytes = 600;
    let idle = progress.update(progress.started + Duration::from_secs(4), false);
    assert_eq!(idle.bytes_per_second, 0.0);
    let finished = progress.update(progress.started + Duration::from_secs(4), true);
    assert_eq!(finished.bytes_per_second, 50.0);
    progress.total = None;
    assert_eq!(progress.update(progress.started, true).fraction(), None);
}

#[test]
fn malformed_progress_cannot_supply_a_fake_percentage() {
    for json in [
        r#"{"id":1,"operation":null,"stage":"x","completed":20,"total":10,"bytes_per_second":1,"elapsed_seconds":1,"finished":false}"#,
        r#"{"id":1,"operation":null,"stage":"x","completed":0,"total":10,"bytes_per_second":-1,"elapsed_seconds":1,"finished":false}"#,
    ] {
        let json = json.replacen('{', r#"{"event":"transfer","#, 1);
        assert!(Event::parse(&format!("{EVENT_PREFIX}{json}")).is_none());
    }
    assert!(Event::parse("Operation 13: 100%").is_none());
    for weights in ["[]", "[[13,0]]"] {
        assert!(
            Event::parse(&format!(
                r#"{EVENT_PREFIX}{{"event":"operation_weights","weights":{weights}}}"#
            ))
            .is_none()
        );
    }
}
