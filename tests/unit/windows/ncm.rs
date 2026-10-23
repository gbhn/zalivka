use super::*;

#[test]
fn installs_only_missing_interfaces_in_every_partial_state() {
    for control in [false, true] {
        for data in [false, true] {
            let interfaces = [("control".into(), control), ("data".into(), data)];
            let mut calls = vec![];
            prepare_interfaces(&interfaces, false, |id, restore| {
                calls.push((id.to_owned(), restore));
                Ok(())
            })
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
        let result = prepare_interfaces(&interfaces, false, |id, restore| {
            calls.push((id.to_owned(), restore));
            ensure!(id != "data" || restore, "test installation failure");
            Ok(())
        });
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
    prepare_interfaces(&interfaces, true, |id, restore| {
        calls.push((id.to_owned(), restore));
        Ok(())
    })
    .unwrap();
    assert_eq!(calls, vec![("control".into(), true), ("data".into(), true)]);
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
    for invalid in [
        "",
        "{bad}",
        "6E36578F-6547-4BA7-97DE-25D5892F140E",
        "{6E36578F_6547_4BA7_97DE_25D5892F140E}",
    ] {
        assert!(parse_guid(invalid).is_err());
    }
}
