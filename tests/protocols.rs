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
                    wire::dict([("Path", format!("Firmware/{name}").into())]),
                ),
            ]),
        );
    }
    Identity {
        index: 0,
        value: wire::dict([
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
    }
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

fn tcp(source: u16, destination: u16, seq: u32, ack: u32, flags: u8, data: &[u8]) -> Vec<u8> {
    let mut header = vec![0; 20];
    header[..2].copy_from_slice(&source.to_be_bytes());
    header[2..4].copy_from_slice(&destination.to_be_bytes());
    header[4..8].copy_from_slice(&seq.to_be_bytes());
    header[8..12].copy_from_slice(&ack.to_be_bytes());
    header[12] = 0x50;
    header[13] = flags;
    header[14..16].copy_from_slice(&1024u16.to_be_bytes());
    header.extend_from_slice(data);
    mux::encode_packet(6, 2, 1, 0, &header).unwrap()
}
struct MockMux {
    input: VecDeque<Vec<u8>>,
    output: Arc<Mutex<Vec<Vec<u8>>>>,
}
impl PacketTransport for MockMux {
    fn write_packet(&mut self, b: &[u8]) -> Result<()> {
        self.output.lock().unwrap().push(b.to_vec());
        Ok(())
    }
    fn read_packet(&mut self) -> Result<Vec<u8>> {
        self.input
            .pop_front()
            .ok_or_else(|| anyhow::anyhow!("unexpected mux read"))
    }
}
fn mock_mux(packets: Vec<Vec<u8>>) -> (MockMux, Arc<Mutex<Vec<Vec<u8>>>>) {
    let output = Arc::new(Mutex::new(vec![]));
    (
        MockMux {
            input: packets.into(),
            output: output.clone(),
        },
        output,
    )
}

fn mux_output(output: &Arc<Mutex<Vec<Vec<u8>>>>, port: u16) -> Cursor<Vec<u8>> {
    let mut data = vec![];
    for bytes in output.lock().unwrap().iter().skip(2) {
        let packet = mux::decode_packet(bytes, 2).unwrap();
        if packet.protocol == 6
            && packet.payload.len() >= 20
            && u16::from_be_bytes(packet.payload[2..4].try_into().unwrap()) == port
        {
            data.extend_from_slice(&packet.payload[20..]);
        }
    }
    Cursor::new(data)
}
fn version_packet() -> Vec<u8> {
    mux::encode_packet(0, 0, 0, 0, &[0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0]).unwrap()
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
    let file = tempfile::NamedTempFile::new().unwrap();
    let mut zip = zip::ZipWriter::new(file.reopen().unwrap());
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
    let options = zip::write::SimpleFileOptions::default().compression_method(compression);
    zip.start_file("BuildManifest.plist", options).unwrap();
    zip.write_all(&wire::xml(&manifest).unwrap()).unwrap();
    for name in [
        "iBSS",
        "iBEC",
        "RestoreRamDisk",
        "RestoreDeviceTree",
        "RestoreKernelCache",
        "OS",
    ] {
        if missing && name == "iBEC" {
            continue;
        }
        zip.start_file(format!("Firmware/{name}"), options).unwrap();
        zip.write_all(&im4p(b"test")).unwrap();
    }
    for (path, bytes) in files {
        zip.start_file(*path, options).unwrap();
        zip.write_all(bytes).unwrap();
    }
    zip.finish().unwrap();
    file
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
        ("Info", wire::dict([("Path", path.into())])),
    ])
}

fn restore_state(file: &std::path::Path) -> restore::ContextState {
    restore::ContextState {
        ipsw: Ipsw::open(file).unwrap(),
        identity: identity(),
        recovery: None,
        device: device_info(),
        ticket: wire::dict([("ApImg4Ticket", Value::Data(ticket()))]),
        recovery_ticket: None,
        assets: net::AssetClient::default(),
    }
}
