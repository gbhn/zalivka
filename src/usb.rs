mod backend;
use crate::device::{DeviceInfo, Mode};
use anyhow::{Context, Result, bail};
use backend::{BulkInput, BulkOutput};
pub(crate) use backend::{UsbInterface, cancel_and_drain};
use nusb::{
    Device, MaybeFuture,
    transfer::{ControlIn, ControlOut, ControlType, Recipient},
};
use std::{sync::atomic::AtomicBool, time::Duration};

pub const APPLE_VENDOR: u16 = 0x05ac;
pub(crate) const MUX_INTERFACE: (u8, u8, u8) = (0xff, 0xfe, 2);
const TIMEOUT: Duration = Duration::from_secs(10);

fn recovery_devices() -> Result<impl Iterator<Item = (nusb::DeviceInfo, Mode)>> {
    Ok(nusb::list_devices()
        .wait()
        .context("enumerating USB devices")?
        .filter(|usb| usb.vendor_id() == APPLE_VENDOR)
        .filter_map(|usb| Mode::from_pid(usb.product_id()).map(|mode| (usb, mode))))
}

fn serial_number(device: &Device) -> Result<String> {
    let index = device
        .device_descriptor()
        .serial_number_string_index()
        .context("device has no serial descriptor")?;
    Ok(device
        .get_string_descriptor(index, 0x0409, TIMEOUT)
        .wait()?)
}

pub trait RecoveryTransport {
    fn control_in(
        &mut self,
        kind: u8,
        request: u8,
        value: u16,
        index: u16,
        length: u16,
    ) -> Result<Vec<u8>>;
    fn control_out(
        &mut self,
        kind: u8,
        request: u8,
        value: u16,
        index: u16,
        data: &[u8],
    ) -> Result<()>;
    fn bulk_out(&mut self, data: &[u8]) -> Result<()>;
    fn reset(&mut self) -> Result<()>;
}

pub struct RecoveryUsb {
    pub device: Device,
    interface: UsbInterface,
    bulk: Option<BulkOutput>,
    pub info: DeviceInfo,
    #[cfg(windows)]
    topology: nusb::DeviceInfo,
}

fn control_kind(kind: u8) -> Result<(ControlType, Recipient)> {
    let ty = match (kind >> 5) & 3 {
        0 => ControlType::Standard,
        1 => ControlType::Class,
        2 => ControlType::Vendor,
        _ => bail!("reserved USB request type"),
    };
    let recipient = match kind & 31 {
        0 => Recipient::Device,
        1 => Recipient::Interface,
        2 => Recipient::Endpoint,
        3 => Recipient::Other,
        _ => bail!("invalid USB recipient"),
    };
    Ok((ty, recipient))
}

impl RecoveryUsb {
    pub fn check_reset_access(&self) -> Result<()> {
        #[cfg(windows)]
        self.interface.check_reset_access(&self.topology)?;
        Ok(())
    }
    pub fn open(ecid: u64) -> Result<Self> {
        for (usb, mode) in recovery_devices()? {
            // Filter before claiming interfaces, when the OS has cached the serial.
            if let Some(serial) = usb.serial_number()
                && let Ok(info) = DeviceInfo::parse(serial, mode)
                && info.ecid != ecid
            {
                continue;
            }
            let device = usb.open().wait().context("opening Apple USB device (Linux: udev permissions; Windows: compatible USB driver required)")?;
            let serial = serial_number(&device)?;
            let mut info = DeviceInfo::parse(&serial, mode)?;
            if info.ecid != ecid {
                continue;
            }
            let mut selected = (0, 0);
            if mode == Mode::Recovery {
                for descriptor in device.active_configuration()?.interface_alt_settings() {
                    if descriptor.endpoints().any(|e| e.address() == 0x04) {
                        selected = (
                            descriptor.interface_number(),
                            descriptor.alternate_setting(),
                        );
                    }
                }
            }
            let interface = UsbInterface::claim(&device, &usb, selected.0)
                .context("claiming Apple USB interface; another process or driver may own it")?;
            interface.set_alt_setting(selected.1)?;
            let bulk = if mode == Mode::Recovery {
                Some(interface.bulk_out(0x04)?)
            } else {
                None
            };
            let nonces = device
                .get_string_descriptor(std::num::NonZeroU8::new(1).unwrap(), 0x0409, TIMEOUT)
                .wait()?;
            info.set_nonces(&nonces)?;
            return Ok(Self {
                device,
                interface,
                bulk,
                info,
                #[cfg(windows)]
                topology: usb,
            });
        }
        bail!("no Apple DFU/recovery device with ECID {ecid:016x}")
    }
}

impl RecoveryTransport for RecoveryUsb {
    fn control_in(
        &mut self,
        kind: u8,
        request: u8,
        value: u16,
        index: u16,
        length: u16,
    ) -> Result<Vec<u8>> {
        let (control_type, recipient) = control_kind(kind)?;
        self.interface.control_in(
            ControlIn {
                control_type,
                recipient,
                request,
                value,
                index,
                length,
            },
            TIMEOUT,
        )
    }
    fn control_out(
        &mut self,
        kind: u8,
        request: u8,
        value: u16,
        index: u16,
        data: &[u8],
    ) -> Result<()> {
        let (control_type, recipient) = control_kind(kind)?;
        self.interface.control_out(
            ControlOut {
                control_type,
                recipient,
                request,
                value,
                index,
                data,
            },
            TIMEOUT,
        )?;
        Ok(())
    }
    fn bulk_out(&mut self, data: &[u8]) -> Result<()> {
        let ep = self
            .bulk
            .as_mut()
            .context("device has no recovery bulk endpoint")?;
        ep.write(data)
    }
    fn reset(&mut self) -> Result<()> {
        #[cfg(windows)]
        {
            match &self.interface {
                UsbInterface::Native(_) => crate::windows::reset::cycle_port(&self.topology),
                UsbInterface::Apple(apple) => apple.reset(),
            }
        }
        #[cfg(not(windows))]
        {
            self.device.reset().wait().context("USB reset")
        }
    }
}

pub fn detect() -> Result<Vec<DeviceInfo>> {
    let mut out = Vec::new();
    for (usb, mode) in recovery_devices()? {
        let serial = if let Some(s) = usb.serial_number() {
            s.to_owned()
        } else {
            let d = usb.open().wait().context("reading DFU serial descriptor")?;
            serial_number(&d)?
        };
        out.push(DeviceInfo::parse(&serial, mode)?);
    }
    Ok(out)
}

/// USB mux interface, selected by the vendor-specific ff/fe/02 interface triple.
pub struct MuxUsb {
    _device: Device,
    _interface: UsbInterface,
    input: BulkInput,
    output: BulkOutput,
    packet_size: usize,
}

#[derive(Debug, PartialEq, Eq)]
struct MuxInterface {
    configuration: u8,
    number: u8,
    alternate: u8,
    output: u8,
    input: u8,
    packet_size: usize,
}

fn select_mux_interface<'a>(
    configurations: impl Iterator<Item = nusb::descriptors::ConfigurationDescriptor<'a>>,
    active: Option<u8>,
) -> Option<MuxInterface> {
    let mut fallback = None;
    for configuration in configurations {
        for descriptor in configuration.interface_alt_settings() {
            if (
                descriptor.class(),
                descriptor.subclass(),
                descriptor.protocol(),
            ) != MUX_INTERFACE
            {
                continue;
            }
            let out = descriptor.endpoints().find(|e| e.address() & 0x80 == 0);
            let input = descriptor.endpoints().find(|e| e.address() & 0x80 != 0);
            if let (Some(out), Some(input)) = (out, input) {
                let selected = MuxInterface {
                    configuration: configuration.configuration_value(),
                    number: descriptor.interface_number(),
                    alternate: descriptor.alternate_setting(),
                    output: out.address(),
                    input: input.address(),
                    packet_size: out.max_packet_size(),
                };
                // WinUSB cannot change configurations. Prefer the interface in
                // the configuration already selected by the OS, even when a
                // later configuration also contains a multiplex interface.
                if Some(configuration.configuration_value()) == active {
                    return Some(selected);
                }
                fallback.get_or_insert(selected);
            }
        }
    }
    fallback
}

impl MuxUsb {
    pub fn candidates() -> Result<Vec<nusb::DeviceInfo>> {
        Ok(nusb::list_devices()
            .wait()?
            .filter(|d| d.vendor_id() == APPLE_VENDOR && Mode::from_pid(d.product_id()).is_none())
            .collect())
    }

    pub fn open(info: &nusb::DeviceInfo) -> Result<Self> {
        let device = info.open().wait()?;
        let active = device
            .active_configuration()
            .ok()
            .map(|c| c.configuration_value());
        let selected = select_mux_interface(device.configurations(), active)
            .context("no Apple USB multiplex interface")?;
        if active != Some(selected.configuration) {
            device.set_configuration(selected.configuration).wait().context("selecting USB multiplex configuration (Windows requires an active WinUSB configuration)")?;
        }
        let interface = UsbInterface::claim(&device, info, selected.number).context("claiming USB multiplex interface; stop usbmuxd/Apple Mobile Device Service if it owns this interface")?;
        interface.set_alt_setting(selected.alternate)?;
        Ok(Self {
            input: interface.bulk_in(selected.input)?,
            output: interface.bulk_out(selected.output)?,
            _device: device,
            _interface: interface,
            packet_size: selected.packet_size,
        })
    }

    pub fn write_packet(&mut self, data: &[u8]) -> Result<()> {
        self.output.write(data)?;
        if data.len().is_multiple_of(self.packet_size) {
            self.output.write(&[])?;
        }
        Ok(())
    }

    pub(crate) fn write_packets(
        &mut self,
        packets: &[Vec<u8>],
        cancelled: &AtomicBool,
    ) -> Result<()> {
        // Keep each mux packet in its own USB request, including the existing
        // zero-length terminator when it ends on a physical packet boundary.
        let mut transfers = Vec::with_capacity(packets.len() * 2);
        for packet in packets {
            transfers.push(packet.as_slice());
            if packet.len().is_multiple_of(self.packet_size) {
                transfers.push(&[]);
            }
        }
        self.output.write_batch(&transfers, cancelled)
    }

    pub fn read_packet(&mut self) -> Result<Vec<u8>> {
        self.input.read()
    }

    pub(crate) fn input_ready(&self) -> Option<crate::mux::InputReady> {
        self.input.input_ready()
    }
}

#[cfg(test)]
#[path = "../tests/unit/usb.rs"]
mod tests;
