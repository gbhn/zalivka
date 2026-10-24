use super::*;
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
