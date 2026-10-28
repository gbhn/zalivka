use super::*;

#[test]
fn native_context_is_inherited_by_children_and_restored_after_unwinding() {
    let events = Arc::new(Mutex::new(Vec::new()));
    let output = events.clone();
    let context = Context::new(move |event| output.lock().unwrap().push(event));
    context.run(|| {
        std::thread::spawn(inherit(|| {
            crate::log!(Trace, "child", "native child");
            Event::RestoreCompleted.emit();
        }))
        .join()
        .unwrap();
    });
    assert!(!active());
    let events = events.lock().unwrap();
    assert!(matches!(&events[0], Event::Log(record) if record.source == "child"));
    assert_eq!(events[1], Event::RestoreCompleted);
    drop(events);
    assert!(
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(
            || context.run(|| panic!("test panic"))
        ))
        .is_err()
    );
    assert!(!active());
}

#[test]
fn cancellation_runs_each_registered_action_once_including_late_registration() {
    let count = Arc::new(AtomicU64::new(0));
    let context = Context::new(|_| {});
    context.run(|| {
        let output = count.clone();
        on_cancel(move || {
            output.fetch_add(1, Ordering::Relaxed);
        });
    });
    context.cancel();
    context.cancel();
    context.run(|| {
        assert!(check_cancelled().is_err());
        let output = count.clone();
        on_cancel(move || {
            output.fetch_add(1, Ordering::Relaxed);
        });
    });
    assert_eq!(count.load(Ordering::Relaxed), 2);
    assert!(check_cancelled().is_ok());
}

#[test]
fn dropped_streams_emit_one_terminal_event_without_claiming_all_bytes_were_sent() {
    let events = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let output = events.clone();
    Context::new(move |event| output.lock().unwrap().push(event)).run(|| {
        {
            let mut interrupted = Progress::new("download", Some(100), 0);
            interrupted.advance(40);
        }
        let mut retry = Progress::new("download", Some(100), 40);
        retry.advance(60);
        retry.finish();
        retry.finish();
        retry.advance(10);
        retry.report();
    });
    let updates: Vec<_> = events
        .lock()
        .unwrap()
        .iter()
        .filter_map(|event| match event {
            Event::Transfer(update) => Some(update.clone()),
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
fn transfer_identity_is_stable_and_unique_between_workers() {
    let progress = Progress::new("same component", Some(100), 0);
    let first = progress.update(progress.started, false);
    let second = std::thread::spawn(|| {
        let progress = Progress::new("same component", Some(100), 0);
        progress.update(progress.started, false)
    })
    .join()
    .unwrap();
    assert_ne!(first.id, second.id);
    assert_eq!(first.id, progress.update(progress.started, true).id);
}

#[test]
fn samples_measure_new_bytes_and_keep_resumed_offsets_out_of_the_rate() {
    let mut progress = Progress::new("BaseSystem", Some(1000), 400);
    progress.completed = 600;
    let update = progress.update(progress.started + Duration::from_secs(2), false);
    assert_eq!(update.bytes_per_second, 100.0);
    assert_eq!(update.fraction(), Some(0.6));
    assert_eq!(update.completed, 600);
    assert!(!update.finished);
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
fn completed_progress_is_terminal_and_finish_is_idempotent() {
    let mut progress = Progress::new("x", Some(10), 0);
    progress.advance(10);
    progress.finish();
    progress.advance(5);
    progress.finish();
    assert_eq!(progress.completed, 10);
    assert!(progress.finished);
}

#[test]
fn inaccurate_totals_do_not_hide_measured_progress() {
    let mut progress = Progress::new("x", Some(10), 11);
    assert!(
        progress
            .update(Instant::now(), false)
            .bytes_per_second
            .is_finite()
    );
    assert_eq!(progress.total, None);
    progress.total = Some(12);
    progress.advance(2);
    let update = progress.update(Instant::now(), false);
    assert_eq!((update.completed, update.total), (13, None));
    assert!(update.bytes_per_second.is_finite());
}
