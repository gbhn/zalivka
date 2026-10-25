use super::*;

#[test]
fn repeated_stalls_stop_instead_of_spinning_forever() {
    let mut recovery = StallRecovery::default();
    let now = Instant::now();
    for attempt in 1..=3 {
        assert_eq!(recovery.attempt(now).unwrap(), attempt);
    }
    assert!(recovery.attempt(now).is_err());
}

#[test]
fn idle_time_does_not_use_up_recovery_attempts() {
    let mut recovery = StallRecovery::default();
    let now = Instant::now();
    // No successful reads occur between these independent stalls.
    for hours in 0..100 {
        assert_eq!(
            recovery
                .attempt(now + Duration::from_secs(hours * 3600))
                .unwrap(),
            1
        );
    }
}

#[test]
fn successful_transfer_resets_the_stall_budget() {
    let mut recovery = StallRecovery::default();
    let now = Instant::now();
    for _ in 0..3 {
        recovery.attempt(now).unwrap();
    }
    recovery.succeeded();
    assert_eq!(recovery.attempt(now).unwrap(), 1);
}

#[test]
fn a_short_pause_does_not_hide_a_persistent_failure() {
    let mut recovery = StallRecovery::default();
    let now = Instant::now();
    for attempt in 0..3 {
        recovery
            .attempt(now + Duration::from_secs(attempt))
            .unwrap();
    }
    assert!(recovery.attempt(now + Duration::from_secs(6)).is_err());
    assert_eq!(recovery.attempt(now + Duration::from_secs(7)).unwrap(), 1);
}
