use super::*;

#[test]
fn records_keep_their_level_and_source_through_the_worker_pipe() {
    for level in [Level::Debug, Level::Info, Level::Warning, Level::Error] {
        let mut record = Record::new(level, "restore", "Подготовка macOS");
        record.elapsed_ms = 3_723_004;
        let event = crate::progress::Event::Log(record.clone());
        let mut pipe = Vec::new();
        event.write_to(&mut pipe).unwrap();
        assert_eq!(
            crate::progress::Event::parse(std::str::from_utf8(&pipe).unwrap()),
            Some(event)
        );
        let text = record.to_string();
        assert!(text.starts_with("01:02:03.004 "));
        assert!(text.contains(level.label()));
        assert!(text.contains("restore"));
        assert!(text.ends_with("Подготовка macOS"));
    }
}

#[test]
fn external_diagnostics_cannot_break_rows_or_inject_terminal_controls() {
    let record = Record::new(
        Level::Error,
        "usb",
        "one\r\ntwo\tthree\u{00b7}four\u{1b}[31m",
    );
    assert_eq!(record.message, "one  / two three,four\\u{1b}[31m");
    let mut output = Vec::new();
    record.write_to(&mut output).unwrap();
    let text = String::from_utf8(output).unwrap();
    assert_eq!(text.lines().count(), 1);
    assert!(!text.contains('\u{00b7}'));
    assert!(!text.contains('\u{1b}'));
}
