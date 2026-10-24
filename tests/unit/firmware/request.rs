use super::*;

fn arguments(name: &str, info: Value) -> Value {
    wire::dict([
        ("MessageArgType", "FirmwareResponseData".into()),
        ("MessageArgUpdaterName", name.into()),
        ("MessageArgInfo", info),
    ])
}

fn retimer(tag: u64) -> Value {
    wire::dict([
        ("TagNumber", tag.into()),
        ("TicketName", format!("Timer,Ticket,{tag}").into()),
    ])
}

#[test]
fn legacy_requests_are_created_with_their_complete_response_tags() {
    for (name, ticket, firmware) in [
        ("SE", "SE,Ticket", true),
        ("AppleTCON", "Baobab,Ticket", true),
        ("Rose", "Rap,Ticket", true),
        ("T200", "BMU,Ticket", true),
        ("Cryptex1", "Cryptex1,Ticket", false),
        ("Cryptex1LocalPolicy", "ApImg4Ticket", false),
    ] {
        let args = arguments(name, Value::Dictionary(Dictionary::new()));
        let request = Request::parse(&args).unwrap();
        let mut expected = vec![ticket];
        if firmware {
            expected.push("FirmwareData");
        }
        assert_eq!(request.response_tags, expected);
    }
    let mut args = arguments("SE", Value::Dictionary(Dictionary::new()));
    args.as_dictionary_mut().unwrap().insert(
        "DeviceGeneratedRequest".into(),
        wire::dict([("@SE2,Ticket", true.into())]),
    );
    assert_eq!(
        Request::parse(&args).unwrap().response_tags,
        ["SE2,Ticket", "FirmwareData"]
    );
}

#[test]
fn legacy_retimer_infers_only_a_single_unambiguous_ticket() {
    for items in [vec![], vec![retimer(1), retimer(2)]] {
        let args = arguments(
            "AppleTypeCRetimer",
            wire::dict([("InfoArray", Value::Array(items))]),
        );
        assert!(Request::parse(&args).is_err());
    }
    let args = arguments(
        "AppleTypeCRetimer",
        wire::dict([("InfoArray", Value::Array(vec![retimer(2)]))]),
    );
    let request = Request::parse(&args).unwrap();
    assert_eq!(request.response_tags, ["Timer,Ticket,2", "FirmwareData"]);
    assert_eq!(
        wire::number(wire::get(request.retimer_info().unwrap(), &["TagNumber"]).unwrap()).unwrap(),
        2
    );
}
