use anyhow::{Context, Result, ensure};
use serde::Serialize;

pub(crate) fn is_mac_product(product: &str) -> bool {
    ["Mac", "iMac", "iBridge"]
        .iter()
        .any(|prefix| product.starts_with(prefix))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    Dfu,
    Recovery,
}

impl Mode {
    pub fn from_pid(pid: u16) -> Option<Self> {
        match pid {
            0x1227 => Some(Self::Dfu),
            0x1280..=0x1283 => Some(Self::Recovery),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DeviceInfo {
    pub ecid: u64,
    pub chip_id: u32,
    pub board_id: u32,
    pub security_domain: u32,
    pub iboot_flags: u32,
    pub mode: Mode,
    pub serial: String,
    pub ap_nonce: Vec<u8>,
    pub sep_nonce: Vec<u8>,
}

impl DeviceInfo {
    pub fn parse(serial: &str, mode: Mode) -> Result<Self> {
        let hex_field = |name: &str| -> Result<Option<u64>> {
            field(serial, name)
                .map(|raw| {
                    u64::from_str_radix(raw.trim_start_matches("0x"), 16)
                        .with_context(|| format!("invalid {name}: {raw}"))
                })
                .transpose()
        };
        let required =
            |name: &str| hex_field(name)?.with_context(|| format!("USB serial has no {name}"));
        let ecid = required("ECID")?;
        ensure!(ecid != 0, "device returned zero ECID");
        Ok(Self {
            ecid,
            chip_id: u32::try_from(required("CPID")?)?,
            board_id: u32::try_from(required("BDID")?)?,
            security_domain: u32::try_from(hex_field("SDOM")?.unwrap_or(1))?,
            iboot_flags: u32::try_from(hex_field("IBFL")?.unwrap_or(0))?,
            mode,
            serial: serial.into(),
            ap_nonce: vec![],
            sep_nonce: vec![],
        })
    }

    pub fn set_nonces(&mut self, s: &str) -> Result<()> {
        let nonce = |name| {
            field(s, name)
                .map(decode_hex)
                .transpose()
                .map(Option::unwrap_or_default)
        };
        (self.ap_nonce, self.sep_nonce) = (nonce("NONC")?, nonce("SNON")?);
        Ok(())
    }
}

fn field<'a>(s: &'a str, key: &str) -> Option<&'a str> {
    s.split_ascii_whitespace().find_map(|s| {
        let (k, v) = s.split_once(':')?;
        (k == key).then_some(v)
    })
}

pub fn decode_hex(s: &str) -> Result<Vec<u8>> {
    hex::decode(s).context("expected an even number of hexadecimal digits")
}

pub fn encode_hex(data: &[u8]) -> String {
    hex::encode(data)
}

pub fn parse_ecid(s: &str) -> std::result::Result<u64, String> {
    let s = s
        .strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .unwrap_or(s);
    let n = u64::from_str_radix(s, 16).map_err(|e| e.to_string())?;
    if n == 0 {
        return Err("ECID must be nonzero".into());
    }
    Ok(n)
}
