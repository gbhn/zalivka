use super::*;

#[test]
fn xml_depth_is_bounded_before_decoding_nested_values() {
    let xml = format!(
        "<plist>{}{}{}",
        "<array>".repeat(300),
        "</array>".repeat(300),
        "</plist>"
    );
    assert!(
        receive_xml(&mut xml.as_bytes())
            .unwrap_err()
            .to_string()
            .contains("nested too deeply")
    );
}

#[test]
fn plist_writer_refuses_growth_past_its_budget_without_partial_writes() {
    let mut bytes = Vec::new();
    let mut writer = LimitedWriter {
        bytes: &mut bytes,
        remaining: 3,
    };
    writer.write_all(b"ab").unwrap();
    assert!(writer.write_all(b"cd").is_err());
    writer.write_all(b"c").unwrap();
    assert!(writer.write_all(b"d").is_err());
    assert_eq!(bytes, b"abc");
}

#[test]
fn optional_metadata_distinguishes_absence_from_malformed_present_values() {
    let missing = dict([] as [(&str, Value); 0]);
    assert_eq!(optional(&missing, &["Arguments", "Flag"]).unwrap(), None);
    for flag in [false, true] {
        let message = dict([("Arguments", dict([("Flag", flag.into())]))]);
        assert_eq!(
            optional_boolean(&message, &["Arguments", "Flag"]).unwrap(),
            Some(flag)
        );
    }
    for message in [
        false.into(),
        dict([("Arguments", false.into())]),
        dict([("Arguments", dict([("Flag", "false".into())]))]),
        dict([("Arguments", dict([("Flag", 0u64.into())]))]),
    ] {
        let error = optional_boolean(&message, &["Arguments", "Flag"]).unwrap_err();
        assert!(error.to_string().contains("Arguments.Flag"), "{error:#}");
    }
}

#[test]
fn unframed_xml_size_limit_also_bounds_an_unterminated_comment() {
    let prefix = b"<plist><!--";
    let input = prefix
        .as_slice()
        .chain(std::io::repeat(b'x').take(MAX_PLIST as u64));
    let mut input = std::io::BufReader::new(input);
    assert!(receive_xml(&mut input).is_err());
    let mut remaining = Vec::new();
    input.read_to_end(&mut remaining).unwrap();
    assert_eq!(remaining, vec![b'x'; prefix.len()]);
}

#[test]
fn data_request_names_are_consistent_across_envelopes_and_direct_messages() {
    for envelope in [
        None,
        Some("DataRequestMsg"),
        Some("AsyncDataRequestMsg"),
        Some("URLAsset"),
    ] {
        let mut message = dict([("DataType", "URLAsset".into())]);
        if let Some(envelope) = envelope {
            message
                .as_dictionary_mut()
                .unwrap()
                .insert("MsgType".into(), envelope.into());
        }
        assert_eq!(data_type(&message).unwrap(), "URLAsset");
    }
    assert_eq!(
        data_type(&dict([("MsgType", "URLAsset".into())])).unwrap(),
        "URLAsset"
    );
    for message in [
        dict([("MsgType", "DataRequestMsg".into())]),
        dict([("MsgType", "AsyncDataRequestMsg".into())]),
        dict([("MsgType", "URLAsset".into()), ("DataType", false.into())]),
        dict([("MsgType", false.into()), ("DataType", "URLAsset".into())]),
        dict([
            ("MsgType", "StatusMsg".into()),
            ("DataType", "URLAsset".into()),
        ]),
        dict([
            ("MsgType", "URLAsset".into()),
            ("DataType", "StreamedImageDecryptionKey".into()),
        ]),
        dict([] as [(&str, Value); 0]),
        Value::Boolean(false),
    ] {
        assert!(data_type(&message).is_err(), "{message:?}");
    }
}
use serde::{
    Serialize, Serializer,
    ser::{Error, SerializeMap},
};

#[test]
fn failed_serialization_rolls_back_only_its_frame_and_allows_the_next_frame() {
    struct Broken;
    impl Serialize for Broken {
        fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
            let mut map = serializer.serialize_map(Some(2))?;
            map.serialize_entry("partial", &42)?;
            Err(S::Error::custom("simulated encoding failure"))
        }
    }

    let mut bytes = Vec::new();
    let first = dict([("first", true.into())]);
    append_binary(&mut bytes, &first).unwrap();
    let previous = bytes.clone();
    let error = append_binary(&mut bytes, &Broken).unwrap_err();
    assert!(error.to_string().contains("simulated encoding failure"));
    assert_eq!(bytes, previous);

    let last = dict([("last", Value::Data(vec![0, 1, 255]))]);
    append_binary(&mut bytes, &last).unwrap();
    let mut input = std::io::Cursor::new(bytes);
    assert_eq!(receive(&mut input).unwrap(), first);
    assert_eq!(receive(&mut input).unwrap(), last);
    assert_eq!(input.position(), input.get_ref().len() as u64);
}

#[test]
fn unsigned_plist_numbers_reject_signs_and_accept_only_digits_in_the_selected_radix() {
    for (value, expected) in [("0", 0), ("42", 42), ("0xff", 255), ("0XFF", 255)] {
        assert_eq!(number(&value.into()).unwrap(), expected);
    }
    for value in [
        "+1",
        "0x+1",
        "-1",
        " 1",
        "1 ",
        "0x",
        "",
        "0x0x1",
        "18446744073709551616",
    ] {
        assert!(number(&value.into()).is_err(), "{value}");
    }
}
