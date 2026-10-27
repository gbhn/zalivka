use super::*;

#[test]
fn driver_reset_is_a_separate_command_without_a_device_or_firmware() {
    assert!(matches!(
        Cli::try_parse_from(["zalivka", "drivers", "reset"])
            .unwrap()
            .command,
        Command::Drivers {
            command: DriverCommand::Reset
        }
    ));
    #[cfg(windows)]
    assert!(matches!(
        Cli::try_parse_from(["zalivka", "drivers", "reset-elevated"])
            .unwrap()
            .command,
        Command::Drivers {
            command: DriverCommand::ResetElevated
        }
    ));
}

#[cfg(windows)]
#[test]
fn elevated_logging_accepts_only_pipe_identifiers() {
    let id = uuid::Uuid::new_v4().to_string();
    let cli = Cli::try_parse_from([
        "zalivka",
        "--elevated-log",
        &id,
        "drivers",
        "prepare-elevated",
    ])
    .unwrap();
    assert_eq!(cli.elevated_log.unwrap().to_string(), id);
    for name in ["C:/Windows/System32/file", "../file", r"\\server\pipe\file"] {
        assert!(
            Cli::try_parse_from([
                "zalivka",
                "--elevated-log",
                name,
                "drivers",
                "prepare-elevated"
            ])
            .is_err()
        );
    }
}

#[test]
fn boot_state_requires_an_explicit_flag_to_load_ibss() {
    for load in [false, true] {
        let mut args = vec!["zalivka", "boot-state", "firmware.ipsw", "--ecid", "1234"];
        if load {
            args.push("--load-ibss");
        }
        match Cli::try_parse_from(args).unwrap().command {
            Command::BootState {
                ecid, load_ibss, ..
            } => {
                assert_eq!(ecid, 0x1234);
                assert_eq!(load_ibss, load);
            }
            _ => panic!("unexpected command"),
        }
    }
}

#[test]
fn restore_and_revive_accept_automatic_download_and_shared_options() {
    for command in ["restore", "revive"] {
        let mut argv = vec![
            "zalivka",
            command,
            "--ecid",
            "1234",
            "--experimental",
            "--firmware-dir",
            "cache",
            "--identity",
            "63",
            "--transcript",
            "restore.jsonl",
            "--authorization-tokens",
            "tokens.plist",
            "--apple-connect-data",
            "connect.data",
        ];
        if command == "restore" {
            argv.push("--erase");
        }
        let args = match Cli::try_parse_from(argv).unwrap().command {
            Command::Restore { args, erase } => {
                assert!(erase);
                args
            }
            Command::Revive(args) => args,
            _ => panic!("wrong command"),
        };
        assert!(args.ipsw.is_none());
        assert_eq!(args.firmware_dir, Some(PathBuf::from("cache")));
        assert_eq!(args.ecid, 0x1234);
        assert_eq!(args.identity, Some(63));
        assert_eq!(args.transcript, Some(PathBuf::from("restore.jsonl")));
        assert_eq!(
            args.authorization_tokens,
            Some(PathBuf::from("tokens.plist"))
        );
        assert_eq!(args.apple_connect_data, Some(PathBuf::from("connect.data")));
        assert!(Cli::try_parse_from(["zalivka", command, "--ecid", "1234"]).is_err());
    }
}

#[test]
fn local_restore_and_revive_reject_cache_options() {
    for command in ["restore", "revive"] {
        let mut argv = vec![
            "zalivka",
            command,
            "local.ipsw",
            "--ecid",
            "1234",
            "--experimental",
        ];
        if command == "restore" {
            argv.push("--erase");
        }
        let args = match Cli::try_parse_from(&argv).unwrap().command {
            Command::Restore { args, .. } | Command::Revive(args) => args,
            _ => panic!("wrong command"),
        };
        assert_eq!(args.ipsw, Some(PathBuf::from("local.ipsw")));
        argv.extend(["--firmware-dir", "cache"]);
        assert!(Cli::try_parse_from(argv).is_err());
    }
    assert!(matches!(
        Cli::try_parse_from(["zalivka", "fetch", "--ecid", "1234"])
            .unwrap()
            .command,
        Command::Fetch { .. }
    ));
}

#[test]
fn usb_pid_uses_one_optional_case_insensitive_prefix_and_rejects_zero() {
    for value in ["1227", "0x1227", "0X1227"] {
        assert_eq!(parse_pid(value).unwrap(), 0x1227);
    }
    for value in ["", "0", "0x", "+1227", "0x0x1227", "10000", " 1227"] {
        assert!(parse_pid(value).is_err(), "{value}");
    }
}

#[test]
fn usb_internet_commands_and_post_restore_sharing_are_rejected() {
    for command in ["status", "prepare", "share"] {
        assert!(Cli::try_parse_from(["zalivka", "usb-internet", command]).is_err());
    }
    for command in ["restore", "revive"] {
        let mut args = vec!["zalivka", command, "--ecid", "2a", "--experimental"];
        if command == "restore" {
            args.push("--erase");
        }
        assert!(Cli::try_parse_from(&args).is_ok());
        args.push("--share-internet");
        assert!(Cli::try_parse_from(args).is_err());
    }
}
