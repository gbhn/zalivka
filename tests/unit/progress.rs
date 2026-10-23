use super::*;

#[test]
fn samples_measure_new_bytes_and_keep_resumed_offsets_out_of_the_rate() {
    let mut progress = Progress::new("BaseSystem", Some(1000), 400);
    progress.completed = 600;
    let update = progress.update(progress.started + Duration::from_secs(2), false);
    assert_eq!(update.bytes_per_second, 100.0);
    assert_eq!(update.fraction(), Some(0.6));
    let line = format!("{PREFIX}{}", serde_json::to_string(&update).unwrap());
    let parsed = Update::parse(&line).unwrap();
    assert_eq!(parsed.completed, 600);
    assert!(!parsed.finished);
    progress.sampled_at += Duration::from_secs(2);
    progress.sampled_bytes = 600;
    let idle = progress.update(progress.started + Duration::from_secs(4), false);
    assert_eq!(idle.bytes_per_second, 0.0);
    progress.total = None;
    assert_eq!(progress.update(progress.started, true).fraction(), None);
}

#[test]
fn malformed_progress_cannot_supply_a_fake_percentage() {
    for json in [
        r#"{"stage":"x","completed":20,"total":10,"bytes_per_second":1,"elapsed_seconds":1,"finished":false}"#,
        r#"{"stage":"x","completed":0,"total":10,"bytes_per_second":-1,"elapsed_seconds":1,"finished":false}"#,
    ] {
        assert!(Update::parse(&format!("{PREFIX}{json}")).is_none());
    }
    assert!(Update::parse("Operation 13: 100%").is_none());
}
