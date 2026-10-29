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
    let identity = Identity::new(0, wire::dict([] as [(&str, Value); 0]));
    let device =
        DeviceInfo::parse("CPID:8103 BDID:0A ECID:1 CPFM:03", crate::device::Mode::Dfu).unwrap();
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
            format!(
                "{:#}",
                generated_update(&identity, &device, &args).err().unwrap()
            )
            .contains("DeviceGeneratedRequest")
        );
    }
}

#[test]
fn explicit_tag_lists_are_required_and_must_be_unambiguous() {
    let identity = Identity::new(0, wire::dict([] as [(&str, Value); 0]));
    let device =
        DeviceInfo::parse("CPID:8103 BDID:0A ECID:1 CPFM:03", crate::device::Mode::Dfu).unwrap();
    for key in ["BuildIdentityTags", "ResponseTags"] {
        for value in [
            None,
            Some(true.into()),
            Some(Value::Array(vec!["".into()])),
            Some(Value::Array(vec!["same".into(), "same".into()])),
        ] {
            let mut args = arguments("UnlistedController");
            args.as_dictionary_mut().unwrap().extend([
                (
                    "DeviceGeneratedRequest".into(),
                    wire::dict([("@NewTicket", true.into())]),
                ),
                (
                    "DeviceGeneratedTags".into(),
                    wire::dict([
                        ("BuildIdentityTags", Value::Array(vec![])),
                        ("ResponseTags", Value::Array(vec!["NewTicket".into()])),
                    ]),
                ),
            ]);
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
            assert!(
                format!(
                    "{:#}",
                    generated_update(&identity, &device, &args).err().unwrap()
                )
                .contains(key)
            );
        }
    }
}
