use super::*;

fn arguments(name: &str) -> Value {
    wire::dict([
        ("MessageArgType", "FirmwareResponseData".into()),
        ("MessageArgUpdaterName", name.into()),
        ("MessageArgInfo", wire::dict([] as [(&str, Value); 0])),
    ])
}

#[test]
fn controller_names_never_supply_missing_device_metadata() {
    for name in [
        "SE",
        "AppleTCON",
        "PS190",
        "Rose",
        "T200",
        "Centauri",
        "Cryptex1",
        "FutureController",
    ] {
        let args = arguments(name);
        assert!(
            format!("{:#}", Request::parse(&args).err().unwrap())
                .contains("DeviceGeneratedRequest")
        );
    }
}

#[test]
fn explicit_tag_lists_are_required_and_must_be_unambiguous() {
    for key in ["BuildIdentityTags", "ResponseTags"] {
        for value in [
            None,
            Some(true.into()),
            Some(Value::Array(vec!["".into()])),
            Some(Value::Array(vec!["same".into(), "same".into()])),
        ] {
            let mut args = arguments("UnlistedController");
            args.as_dictionary_mut().unwrap().extend(
                wire::dictionary(&wire::dict([
                    (
                        "DeviceGeneratedRequest",
                        wire::dict([("@NewTicket", true.into())]),
                    ),
                    (
                        "DeviceGeneratedTags",
                        wire::dict([
                            ("BuildIdentityTags", Value::Array(vec![])),
                            ("ResponseTags", Value::Array(vec!["NewTicket".into()])),
                        ]),
                    ),
                ]))
                .unwrap()
                .clone(),
            );
            let fields = args
                .as_dictionary_mut()
                .unwrap()
                .get_mut("DeviceGeneratedTags")
                .unwrap()
                .as_dictionary_mut()
                .unwrap();
            if let Some(value) = value {
                fields.insert(key.into(), value);
            } else {
                fields.remove(key);
            }
            assert!(format!("{:#}", Request::parse(&args).err().unwrap()).contains(key));
        }
    }
}
