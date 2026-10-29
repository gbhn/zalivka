//! Public metadata projections, not hardware restore or signing-server tests.
use super::*;
use zalivka::ipsw::Behavior;

#[derive(serde::Deserialize)]
struct Snapshot {
    product_version: String,
    product_build_version: String,
    models: Vec<Model>,
}

#[derive(serde::Deserialize)]
struct Model {
    product_type: String,
    catalog_key: String,
    catalog_product_type: String,
    identities: Vec<Value>,
}

fn snapshot() -> Snapshot {
    serde_json::from_str(include_str!("../fixtures/m4-m5-metadata.json")).unwrap()
}

fn synthetic_device(identity: &Value, mode: Mode) -> DeviceInfo {
    let chip = wire::number(wire::get(identity, &["ApChipID"]).unwrap()).unwrap();
    let board = wire::number(wire::get(identity, &["ApBoardID"]).unwrap()).unwrap();
    let mut device = DeviceInfo::parse(
        &format!("ECID:123456789ABCD CPID:{chip:04X} BDID:{board:02X} SDOM:01 CPFM:03"),
        mode,
    )
    .unwrap();
    device.ap_nonce = vec![1; 32];
    device.sep_nonce = vec![2; 20];
    device
}

#[test]
fn m4_m5_catalog_and_identity_selection_follow_the_captured_metadata() {
    let snapshot = snapshot();
    let manifest = wire::dict([
        ("ProductVersion", snapshot.product_version.into()),
        ("ProductBuildVersion", snapshot.product_build_version.into()),
        (
            "SupportedProductTypes",
            Value::Array(
                snapshot
                    .models
                    .iter()
                    .map(|model| model.product_type.clone().into())
                    .collect(),
            ),
        ),
        (
            "BuildIdentities",
            Value::Array(
                snapshot
                    .models
                    .iter()
                    .flat_map(|model| model.identities.clone())
                    .collect(),
            ),
        ),
    ]);
    // Keep every projected identity together to exercise shared CPIDs and
    // companion-variant selection, including M5 Pro/Max with the same CPID.
    let file = test_support::ipsw(&manifest, &[], zip::CompressionMethod::Stored);
    let ipsw = Ipsw::open(file.path()).unwrap();
    for model in snapshot.models {
        let catalog = test_support::catalog_fixture(
            &model.catalog_key,
            &model.catalog_product_type,
            &"ab".repeat(20),
            "https://updates.cdn-apple.com/test.ipsw",
        );
        for mode in [Mode::Dfu, Mode::PortDfu, Mode::Recovery] {
            let mut device = synthetic_device(&model.identities[0], mode);
            if mode == Mode::PortDfu {
                device.board_id = (device.board_id << 24) | (device.chip_id << 8);
                device.chip_id = 0x22;
            }
            let release = catalog::resolve(&catalog, &device).unwrap();
            // This captures Apple's current mapping, including the Mac16,10/
            // Mac16,11 discrepancy documented in the investigation.
            assert_eq!(release.product_type, model.catalog_product_type);
            for behavior in [Behavior::Erase, Behavior::Update] {
                let id = ipsw.select_behavior(&device, None, behavior).unwrap();
                assert_eq!(
                    wire::string(&id.value, &["Ap,ProductType"]).unwrap(),
                    model.product_type
                );
                assert_eq!(id.behavior().unwrap(), behavior);
                let recovery = ipsw.recovery_identity(&device, &id).unwrap().unwrap();
                assert_eq!(
                    wire::string(&recovery.value, &["Ap,ProductType"]).unwrap(),
                    model.product_type
                );
                assert_eq!(
                    wire::string(&recovery.value, &["Info", "Variant"]).unwrap(),
                    "macOS Customer"
                );
            }
        }
    }
}

#[test]
fn m4_m5_signing_uses_dfu_defaults_missing_from_current_manifests() {
    for model in snapshot().models {
        for value in model.identities {
            assert_eq!(
                wire::optional_boolean(&value, &["Info", "RequiresUIDMode"]).unwrap(),
                Some(true)
            );
            for key in ["UID_MODE", "Ap,SikaFuse"] {
                assert!(wire::optional(&value, &[key]).unwrap().is_none());
            }
            let device = synthetic_device(&value, Mode::Dfu);
            let id = Identity::new(0, value);
            for request in [
                tss::request(&device, &id),
                tss::recovery_request(&device, &id),
            ] {
                let request = request.unwrap();
                assert_eq!(
                    wire::get(&request, &["UID_MODE"]).unwrap().as_boolean(),
                    Some(false)
                );
                assert_eq!(
                    wire::number(wire::get(&request, &["Ap,SikaFuse"]).unwrap()).unwrap(),
                    0
                );
                assert_eq!(
                    wire::get(&request, &["ApNonce"])
                        .unwrap()
                        .as_data()
                        .unwrap(),
                    device.ap_nonce
                );
            }
        }
    }
}

#[test]
fn m5_nonce_slots_use_dfu_defaults_without_model_specific_metadata() {
    let ticket = wire::dict([] as [(&str, Value); 0]);
    for model in snapshot().models {
        for value in model.identities {
            let required = wire::optional_boolean(&value, &["Info", "RequiresNonceSlot"])
                .unwrap()
                .unwrap_or(false);
            for (tag, key, slot_tag, default) in [
                (b"illb", "ApNonceSlotID", b"anid", 0),
                (b"sepi", "SepNonceSlotID", b"snid", 2),
                (b"stg1", "SepNonceSlotID", b"snid", 2),
            ] {
                let result = img4::restore_info(&ticket, "component", &value, Some(*tag));
                if required {
                    assert!(wire::optional(&value, &["Info", key]).unwrap().is_none());
                    let info = result.unwrap().unwrap();
                    assert!(info.windows(4).any(|bytes| bytes == slot_tag));
                    assert!(info.ends_with(&[2, 1, default]));
                } else {
                    assert!(result.unwrap().is_none());
                }
            }
        }
    }
}
