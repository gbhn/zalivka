use anyhow::{Context, Result, ensure};
use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    Dfu,
    PortDfu,
    Recovery,
}

impl Mode {
    pub fn from_pid(pid: u16) -> Option<Self> {
        match pid {
            0x1227 => Some(Self::Dfu),
            0xf014 => Some(Self::PortDfu),
            0x1280..=0x1283 => Some(Self::Recovery),
            _ => None,
        }
    }

    pub fn can_restore(self) -> bool {
        matches!(self, Self::Dfu | Self::PortDfu)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DeviceInfo {
    pub ecid: u64,
    pub chip_id: u32,
    pub board_id: u32,
    pub security_domain: Option<u32>,
    pub iboot_flags: Option<u32>,
    pub chip_fuse_mode: Option<u32>,
    pub mode: Mode,
    pub serial: String,
    pub ap_nonce: Vec<u8>,
    pub sep_nonce: Vec<u8>,
}

impl DeviceInfo {
    /// Port DFU identifies the USB controller. Its board word also encodes
    /// the SoC's CPID and BDID, used only for firmware selection.
    pub fn hardware_ids(&self) -> (u32, u32) {
        if self.mode == Mode::PortDfu {
            ((self.board_id >> 8) & 0xffff, self.board_id >> 24)
        } else {
            (self.chip_id, self.board_id)
        }
    }

    pub(crate) fn serial_hex(&self, name: &str) -> Result<u64> {
        hex_number(field(&self.serial, name)?.with_context(|| format!("USB serial has no {name}"))?)
    }

    pub fn parse(serial: &str, mode: Mode) -> Result<Self> {
        let hex_field = |name: &str| -> Result<Option<u64>> {
            field(serial, name)?
                .map(|raw| hex_number(raw).with_context(|| format!("invalid {name}: {raw}")))
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
            security_domain: hex_field("SDOM")?.map(u32::try_from).transpose()?,
            iboot_flags: hex_field("IBFL")?.map(u32::try_from).transpose()?,
            chip_fuse_mode: hex_field("CPFM")?.map(u32::try_from).transpose()?,
            mode,
            serial: serial.into(),
            ap_nonce: vec![],
            sep_nonce: vec![],
        })
    }

    pub fn set_nonces(&mut self, s: &str) -> Result<()> {
        let nonce = |name| {
            field(s, name)?
                .map(decode_hex)
                .transpose()
                .map(Option::unwrap_or_default)
        };
        (self.ap_nonce, self.sep_nonce) = (nonce("NONC")?, nonce("SNON")?);
        Ok(())
    }
}

fn field<'a>(s: &'a str, key: &str) -> Result<Option<&'a str>> {
    let mut values = s.split_ascii_whitespace().filter_map(|s| {
        let (k, v) = s.split_once(':')?;
        (k == key).then_some(v)
    });
    let value = values.next();
    ensure!(values.next().is_none(), "duplicate USB serial field {key}");
    Ok(value)
}

fn hex_number(value: &str) -> Result<u64> {
    let digits = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
        .unwrap_or(value);
    ensure!(
        !digits.is_empty() && digits.bytes().all(|byte| byte.is_ascii_hexdigit()),
        "expected hexadecimal digits"
    );
    Ok(u64::from_str_radix(digits, 16)?)
}

pub fn decode_hex(s: &str) -> Result<Vec<u8>> {
    hex::decode(s).context("expected an even number of hexadecimal digits")
}

pub fn parse_ecid(s: &str) -> std::result::Result<u64, String> {
    let n = hex_number(s).map_err(|error| error.to_string())?;
    if n == 0 {
        return Err("ECID must be nonzero".into());
    }
    Ok(n)
}
