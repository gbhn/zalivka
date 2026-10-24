use super::*;

#[test]
fn installs_only_missing_interfaces_in_every_partial_state() {
    for control in [false, true] {
        for data in [false, true] {
            let interfaces = [("control".into(), control), ("data".into(), data)];
            let mut calls = vec![];
            prepare_interfaces(
                &interfaces,
                false,
                |id, restore, changed| {
                    calls.push((id.to_owned(), restore));
                    *changed = true;
                    Ok(())
                },
                |_| Ok(()),
            )
            .unwrap();
            let expected: Vec<_> = interfaces
                .iter()
                .filter(|(_, ready)| !ready)
                .map(|(id, _)| (id.clone(), false))
                .collect();
            assert_eq!(calls, expected);
        }
    }
}

#[test]
fn failure_rolls_back_only_interfaces_changed_by_this_attempt() {
    for control_ready in [false, true] {
        let interfaces = [("control".into(), control_ready), ("data".into(), false)];
        let mut calls = vec![];
        let result = prepare_interfaces(
            &interfaces,
            false,
            |id, restore, changed| {
                calls.push((id.to_owned(), restore));
                ensure!(id != "data" || restore, "test installation failure");
                *changed = true;
                Ok(())
            },
            |_| Ok(()),
        );
        assert!(result.is_err());
        let expected = if control_ready {
            vec![("data".into(), false)]
        } else {
            vec![
                ("control".into(), false),
                ("data".into(), false),
                ("control".into(), true),
            ]
        };
        assert_eq!(calls, expected);
    }
}

#[test]
fn explicit_restore_does_not_skip_ready_interfaces() {
    let interfaces = [("control".into(), true), ("data".into(), true)];
    let mut calls = vec![];
    prepare_interfaces(
        &interfaces,
        true,
        |id, restore, changed| {
            calls.push((id.to_owned(), restore));
            *changed = true;
            Ok(())
        },
        |_| panic!("restoring original drivers must not require WinUSB readiness"),
    )
    .unwrap();
    assert_eq!(calls, vec![("control".into(), true), ("data".into(), true)]);
}

#[test]
fn a_partially_changed_current_interface_is_rolled_back_before_previous_interfaces() {
    let interfaces = [("control".into(), false), ("data".into(), false)];
    let mut calls = vec![];
    let result = prepare_interfaces(
        &interfaces,
        false,
        |id, restore, changed| {
            calls.push((id.to_owned(), restore));
            *changed = true;
            ensure!(id != "data" || restore, "partial installation failure");
            Ok(())
        },
        |_| Ok(()),
    );
    assert!(result.is_err());
    assert_eq!(
        calls,
        vec![
            ("control".into(), false),
            ("data".into(), false),
            ("data".into(), true),
            ("control".into(), true),
        ]
    );
}

#[test]
fn readiness_failure_rolls_back_all_changes_and_preserves_preexisting_bindings() {
    for control_ready in [false, true] {
        let interfaces = [("control".into(), control_ready), ("data".into(), false)];
        let mut calls = vec![];
        let mut checked = vec![];
        let result = prepare_interfaces(
            &interfaces,
            false,
            |id, restore, changed| {
                calls.push((id.to_owned(), restore));
                *changed = true;
                Ok(())
            },
            |id| {
                checked.push(id.to_owned());
                ensure!(id != "data", "driver did not start");
                Ok(())
            },
        );
        assert!(format!("{:#}", result.unwrap_err()).contains("driver did not start"));
        assert_eq!(checked, ["control", "data"]);
        let expected = if control_ready {
            vec![("data".into(), false), ("data".into(), true)]
        } else {
            vec![
                ("control".into(), false),
                ("data".into(), false),
                ("data".into(), true),
                ("control".into(), true),
            ]
        };
        assert_eq!(calls, expected);
    }
}

#[test]
fn every_rollback_is_attempted_and_errors_keep_the_installation_failure() {
    let interfaces = [("control".into(), false), ("data".into(), false)];
    let mut rolled_back = vec![];
    let result = prepare_interfaces(
        &interfaces,
        false,
        |id, restore, changed| {
            *changed = true;
            if restore {
                rolled_back.push(id.to_owned());
                anyhow::bail!("cannot restore {id}");
            }
            ensure!(id != "data", "original installation failure");
            Ok(())
        },
        |_| Ok(()),
    );
    assert_eq!(rolled_back, ["data", "control"]);
    let error = format!("{:#}", result.unwrap_err());
    for message in [
        "original installation failure",
        "cannot restore data",
        "cannot restore control",
    ] {
        assert!(error.contains(message), "{error}");
    }
}

#[test]
fn readiness_requires_running_winusb_without_problem_and_a_registered_interface() {
    assert!(binding_state("WinUSB", DN_STARTED, 0, true).is_ok());
    assert!(binding_state("winusb", DN_STARTED, 0, true).is_ok());
    assert!(binding_state("UsbNcm", DN_STARTED, 0, true).is_err());
    assert!(binding_state("WinUSB", 0, 0, true).is_err());
    assert!(binding_state("WinUSB", DN_STARTED, 0, false).is_err());
    for problem in [10, 28] {
        assert!(binding_state("WinUSB", DN_STARTED | DN_HAS_PROBLEM, problem, true).is_err());
    }
}

#[test]
fn interface_guid_roundtrip_and_invalid_values() {
    assert_eq!(
        install::guid_string(parse_guid(GUID_TEXT).unwrap()),
        GUID_TEXT
    );
    let guid = parse_guid(&GUID_TEXT.to_ascii_lowercase()).unwrap();
    assert_eq!(guid.data1, 0x6e36578f);
    assert_eq!(guid.data2, 0x6547);
    assert_eq!(guid.data3, 0x4ba7);
    assert_eq!(guid.data4, [0x97, 0xde, 0x25, 0xd5, 0x89, 0x2f, 0x14, 0x0e]);
    assert_eq!(install::guid_string(guid), GUID_TEXT);
    for invalid in [
        "",
        "{bad}",
        "6E36578F-6547-4BA7-97DE-25D5892F140E",
        "{6E36578F_6547_4BA7_97DE_25D5892F140E}",
        "{6E36578F-6547-4BA7-97DE-25D5892F140G}",
        "{6E36578F6547-4BA7-97DE-25D5892F140E-}",
        "{6E36578F-6547-4BA7-97DE-25D5892F140E}\0",
    ] {
        assert!(parse_guid(invalid).is_err());
    }
}

#[test]
fn registry_guid_lists_check_every_entry_and_respect_the_value_type() {
    let original = "{88BAE032-5A81-49F0-BC3D-A4FF138216D6}";
    let bytes: Vec<_> = wide(original)
        .into_iter()
        .chain(wide(GUID_TEXT))
        .chain([0])
        .flat_map(u16::to_le_bytes)
        .collect();
    let names = |guids: Vec<GUID>| {
        guids
            .into_iter()
            .map(install::guid_string)
            .collect::<Vec<_>>()
    };
    assert_eq!(
        names(interface_guids(REG_MULTI_SZ, &bytes)),
        [original, GUID_TEXT]
    );
    assert_eq!(names(interface_guids(REG_SZ, &bytes)), [original]);
    assert!(interface_guids(REG_BINARY, &bytes).is_empty());
    assert!(interface_guids(REG_MULTI_SZ, &bytes[..bytes.len() - 1]).is_empty());

    let bytes: Vec<_> = wide("invalid GUID")
        .into_iter()
        .chain([0xd800, 0])
        .chain(wide(GUID_TEXT))
        .chain([0])
        .flat_map(u16::to_le_bytes)
        .collect();
    assert_eq!(names(interface_guids(REG_MULTI_SZ, &bytes)), [GUID_TEXT]);

    let bytes: Vec<_> = [0]
        .into_iter()
        .chain(wide(GUID_TEXT))
        .flat_map(u16::to_le_bytes)
        .collect();
    assert!(interface_guids(REG_MULTI_SZ, &bytes).is_empty());
}
