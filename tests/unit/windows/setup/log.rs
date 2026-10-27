use super::*;
use crate::logging::Level;
use std::io::Write;

fn writer(pipe: &LogPipe) -> File {
    use std::os::windows::fs::OpenOptionsExt;
    use windows_sys::Win32::Storage::FileSystem::SECURITY_IDENTIFICATION;
    std::fs::OpenOptions::new()
        .write(true)
        .security_qos_flags(SECURITY_IDENTIFICATION)
        .open(format!(r"\\.\pipe\zalivka-elevated-{}", pipe.id))
        .unwrap()
}

#[test]
fn pipe_does_not_wait_for_a_helper_that_never_connects() {
    let mut pipe = LogPipe::new().unwrap();
    pipe.drain(|_| panic!("unexpected record")).unwrap();
    assert!(!pipe.received);
    assert!(!pipe.incomplete());
}

#[test]
fn pipe_keeps_utf8_levels_and_order_even_after_helper_exit() {
    let mut pipe = LogPipe::new().unwrap();
    let mut writer = writer(&pipe);
    let expected: Vec<_> = [Level::Debug, Level::Info, Level::Warning, Level::Error]
        .into_iter()
        .map(|level| Record::new(level, "drivers", "Ошибка: нужны права администратора"))
        .collect();
    for record in &expected {
        Event::Log(record.clone()).write_to(&mut writer).unwrap();
    }
    drop(writer);
    let mut actual = Vec::new();
    pipe.drain(|record| actual.push(record)).unwrap();
    assert_eq!(actual, expected);
    assert!(pipe.received);
    assert!(!pipe.incomplete());
}

#[test]
fn fragmented_records_are_forwarded_only_after_the_complete_utf8_line() {
    let mut pipe = LogPipe::new().unwrap();
    let mut writer = writer(&pipe);
    let expected = Record::new(Level::Error, "drivers", "Драйвер не установлен");
    let mut bytes = Vec::new();
    Event::Log(expected.clone()).write_to(&mut bytes).unwrap();
    let split = bytes.iter().position(|b| *b >= 0x80).unwrap() + 1;
    writer.write_all(&bytes[..split]).unwrap();
    pipe.drain(|_| panic!("partial UTF-8 must not be published"))
        .unwrap();
    assert!(pipe.incomplete());
    writer.write_all(&bytes[split..]).unwrap();
    let mut actual = Vec::new();
    pipe.drain(|record| actual.push(record)).unwrap();
    assert_eq!(actual, [expected]);
    assert!(!pipe.incomplete());
}

#[test]
fn pipe_rejects_worker_state_and_invalid_log_data() {
    for bytes in [
        b"ZALIVKA_EVENT {\"event\":\"restore_completed\"}\n".as_slice(),
        b"not JSON\n",
        b"\xff\n",
    ] {
        let mut pipe = LogPipe::new().unwrap();
        let mut writer = writer(&pipe);
        writer.write_all(bytes).unwrap();
        assert!(
            pipe.drain(|_| panic!("invalid record was published"))
                .is_err()
        );
    }
}

#[test]
fn log_writer_subprocess() {
    let Ok(id) = std::env::var("ZALIVKA_TEST_LOG_PIPE") else {
        return;
    };
    crate::logging::connect_elevated(id.parse().unwrap()).unwrap();
    crate::log!(Debug, "drivers", "Отладочные сведения установщика");
    crate::log!(
        Error,
        "app",
        "Для подготовки Windows нужны права администратора"
    );
    super::super::token::log().unwrap();
}

#[test]
fn subprocess_records_and_token_diagnostics_reach_the_original_process() {
    use std::{
        os::windows::process::CommandExt,
        process::{Command, Stdio},
        time::{Duration, Instant},
    };
    let mut pipe = LogPipe::new().unwrap();
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "windows::setup::log::tests::log_writer_subprocess",
        ])
        .env("ZALIVKA_TEST_LOG_PIPE", pipe.id.to_string())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .creation_flags(0x08000000)
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(15);
    let mut records = Vec::new();
    let status = loop {
        pipe.drain(|record| records.push(record)).unwrap();
        if let Some(status) = child.try_wait().unwrap() {
            pipe.drain(|record| records.push(record)).unwrap();
            break status;
        }
        if Instant::now() > deadline {
            child.kill().unwrap();
            child.wait().unwrap();
            panic!("helper did not finish");
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    assert!(status.success(), "{status:?}: {records:?}");
    assert_eq!(records[0].level, Level::Debug);
    assert_eq!(records[1].level, Level::Error);
    for text in ["TokenIsElevated=", "S-1-16-", "Учётная запись процесса:"] {
        assert!(
            records.iter().any(|record| record.message.contains(text)),
            "{records:?}"
        );
    }
}
