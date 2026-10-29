use anyhow::Result;
use plist::Value;
use sha2::{Digest, Sha384};
use std::{
    collections::VecDeque,
    io::{Cursor, Read, Seek, SeekFrom, Write},
    sync::{Arc, Mutex, mpsc},
    time::Duration,
};
use zalivka::{
    asr, catalog,
    device::{self, DeviceInfo, Mode},
    dfu, img4,
    ipsw::{Identity, Ipsw},
    mux::{self, PacketTransport, Session},
    net, restore, tss,
    usb::RecoveryTransport,
    wire,
};

#[path = "support/mux.rs"]
mod test_mux;
#[path = "support/mod.rs"]
mod test_support;
use test_mux::{tcp, version_packet};

#[path = "protocols/asr.rs"]
mod asr_tests;
#[path = "protocols/cli.rs"]
mod cli_tests;
#[path = "protocols/fdr.rs"]
mod fdr_tests;
#[path = "protocols/firmware.rs"]
mod firmware_tests;
#[path = "protocols/img4.rs"]
mod img4_tests;
#[path = "protocols/ipsw.rs"]
mod ipsw_tests;
#[path = "protocols/m_series.rs"]
mod m_series_tests;
#[path = "protocols/mux.rs"]
mod mux_tests;
#[path = "protocols/network.rs"]
mod network_tests;
#[path = "protocols/restore.rs"]
mod restore_tests;
#[path = "protocols/tss.rs"]
mod tss_tests;
#[path = "protocols/usb.rs"]
mod usb_tests;
#[path = "protocols/wire.rs"]
mod wire_tests;

fn manifest_mut(id: &mut Identity) -> &mut plist::Dictionary {
    id.value
        .as_dictionary_mut()
        .unwrap()
        .get_mut("Manifest")
        .unwrap()
        .as_dictionary_mut()
        .unwrap()
}

fn device_info() -> DeviceInfo {
    let mut d = DeviceInfo::parse("CPID:8103 CPRV:11 CPFM:03 SCEP:01 BDID:0A ECID:000123456789ABCD IBFL:3C SDOM:01 SRTG:[iBoot-1234]", Mode::Dfu).unwrap();
    d.set_nonces("NONC:0011223344556677 SNON:8899aabb").unwrap();
    d
}

fn im4p(kind: &[u8]) -> Vec<u8> {
    let mut fields = img4::element(0x16, b"IM4P");
    fields.extend(img4::element(0x16, kind));
    fields.extend(img4::element(0x16, b"test"));
    fields.extend(img4::element(4, b"firmware payload"));
    img4::element(0x30, &fields)
}
fn ticket() -> Vec<u8> {
    img4::element(0x30, &img4::element(0x16, b"IM4M"))
}
fn identity() -> Identity {
    let mut manifest = plist::Dictionary::new();
    for name in [
        "iBSS",
        "iBEC",
        "RestoreRamDisk",
        "RestoreDeviceTree",
        "RestoreKernelCache",
        "OS",
    ] {
        let bytes = im4p(b"test");
        manifest.insert(
            name.into(),
            wire::dict([
                ("Trusted", true.into()),
                ("Digest", Value::Data(Sha384::digest(&bytes).to_vec())),
                (
                    "Info",
                    wire::dict([
                        ("Path", format!("Firmware/{name}").into()),
                        ("Personalize", true.into()),
                        (
                            "Img4PayloadType",
                            match name {
                                "iBSS" => "ibss",
                                "iBEC" => "ibec",
                                "RestoreRamDisk" => "rdsk",
                                "RestoreDeviceTree" => "rdtr",
                                "RestoreKernelCache" => "rkrn",
                                _ => "test",
                            }
                            .into(),
                        ),
                        (
                            "RestoreRequestRules",
                            Value::Array(vec![wire::dict([
                                ("Conditions", wire::dict([] as [(&str, Value); 0])),
                                (
                                    "Actions",
                                    wire::dict([("EPRO", true.into()), ("ESEC", true.into())]),
                                ),
                            ])]),
                        ),
                    ]),
                ),
            ]),
        );
    }
    Identity::new(
        0,
        wire::dict([
            ("ApChipID", "0x8103".into()),
            ("ApBoardID", "0x0a".into()),
            ("ApSecurityDomain", "0x01".into()),
            ("UniqueBuildID", Value::Data(vec![1; 20])),
            ("Manifest", Value::Dictionary(manifest)),
            (
                "Info",
                wire::dict([
                    ("DeviceClass", "j313ap".into()),
                    ("RestoreBehavior", "Erase".into()),
                    ("Variant", "Customer Erase Install (IPSW)".into()),
                    ("MacOSVariant", "macOS Customer".into()),
                ]),
            ),
        ]),
    )
}

struct Duplex {
    input: Cursor<Vec<u8>>,
    output: Vec<u8>,
    fragment: usize,
}
impl Duplex {
    fn new(input: Vec<u8>, fragment: usize) -> Self {
        Self {
            input: Cursor::new(input),
            output: vec![],
            fragment,
        }
    }
}
impl Read for Duplex {
    fn read(&mut self, b: &mut [u8]) -> std::io::Result<usize> {
        let n = b.len().min(self.fragment);
        self.input.read(&mut b[..n])
    }
}
impl Write for Duplex {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        self.output.extend_from_slice(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

use test_support::{Scripted as MockMux, scripted as mock_mux};

fn mux_output(output: &Arc<Mutex<Vec<Vec<u8>>>>, port: u16) -> Cursor<Vec<u8>> {
    Cursor::new(test_support::payloads(output, port))
}
struct LiveMux {
    input: mpsc::Receiver<Vec<u8>>,
    output: mpsc::Sender<Vec<u8>>,
}
impl PacketTransport for LiveMux {
    fn write_packet(&mut self, bytes: &[u8]) -> Result<()> {
        self.output.send(bytes.to_vec())?;
        Ok(())
    }
    fn read_packet(&mut self) -> Result<Vec<u8>> {
        match self.input.recv_timeout(Duration::from_millis(5)) {
            Ok(bytes) => Ok(bytes),
            Err(mpsc::RecvTimeoutError::Timeout) => Ok(vec![]),
            Err(e) => Err(e.into()),
        }
    }
}

fn fixture(extra: Option<Identity>, missing: bool) -> tempfile::NamedTempFile {
    fixture_files(extra, missing, &[])
}

fn fixture_files(
    extra: Option<Identity>,
    missing: bool,
    files: &[(&str, &[u8])],
) -> tempfile::NamedTempFile {
    fixture_compression(extra, missing, files, zip::CompressionMethod::Stored)
}

fn fixture_compression(
    extra: Option<Identity>,
    missing: bool,
    files: &[(&str, &[u8])],
    compression: zip::CompressionMethod,
) -> tempfile::NamedTempFile {
    let mut ids = vec![identity().value];
    if let Some(extra) = extra {
        ids.push(extra.value);
    }
    let manifest = wire::dict([
        ("BuildIdentities", Value::Array(ids)),
        (
            "SupportedProductTypes",
            Value::Array(vec!["MacBookAir10,1".into()]),
        ),
        ("ProductVersion", "11.0".into()),
        ("ProductBuildVersion", "20A2411".into()),
    ]);
    let paths: Vec<_> = [
        "iBSS",
        "iBEC",
        "RestoreRamDisk",
        "RestoreDeviceTree",
        "RestoreKernelCache",
        "OS",
    ]
    .into_iter()
    .filter(|name| !missing || *name != "iBEC")
    .map(|name| format!("Firmware/{name}"))
    .collect();
    let payload = im4p(b"test");
    let mut entries: Vec<_> = paths
        .iter()
        .map(|path| (path.as_str(), payload.as_slice()))
        .collect();
    entries.extend_from_slice(files);
    test_support::ipsw(&manifest, &entries, compression)
}

fn recovery_identity() -> Identity {
    let mut id = identity();
    id.index = 1;
    id.value
        .as_dictionary_mut()
        .unwrap()
        .get_mut("Info")
        .unwrap()
        .as_dictionary_mut()
        .unwrap()
        .insert("Variant".into(), "macOS Customer".into());
    id.value
        .as_dictionary_mut()
        .unwrap()
        .get_mut("Info")
        .unwrap()
        .as_dictionary_mut()
        .unwrap()
        .remove("MacOSVariant");
    let manifest = manifest_mut(&mut id);
    manifest.insert("KernelCache".into(), manifest["RestoreKernelCache"].clone());
    id
}

fn component_entry(path: &str, bytes: &[u8]) -> Value {
    wire::dict([
        ("Trusted", true.into()),
        ("Digest", Value::Data(Sha384::digest(bytes).to_vec())),
        (
            "Info",
            wire::dict([
                ("Path", path.into()),
                (
                    "Img4PayloadType",
                    img4::type_offset(bytes)
                        .map(|offset| {
                            String::from_utf8(bytes[offset..offset + 4].to_vec()).unwrap()
                        })
                        .unwrap_or("test".into())
                        .into(),
                ),
                ("Personalize", true.into()),
            ]),
        ),
    ])
}

fn restore_state(file: &std::path::Path) -> restore::RestoreSession {
    restore::RestoreSession {
        ipsw: Ipsw::open(file).unwrap(),
        context: Arc::new(restore::RestoreContext {
            restore: restore::SignedIdentity {
                identity: identity(),
                ticket: wire::dict([("ApImg4Ticket", Value::Data(ticket()))]),
            },
            recovery: None,
            device: device_info(),
            assets: net::AssetClient::default(),
        }),
    }
}

fn context_mut(state: &mut restore::RestoreSession) -> &mut restore::RestoreContext {
    Arc::get_mut(&mut state.context)
        .expect("restore context must be unique before starting requests")
}

fn declare_type(id: &mut Identity, name: &str, tag: &str) {
    manifest_mut(id)[name]
        .as_dictionary_mut()
        .unwrap()
        .get_mut("Info")
        .unwrap()
        .as_dictionary_mut()
        .unwrap()
        .insert("Img4PayloadType".into(), tag.into());
}
