//! Mac NCM descriptors, USB requests and endpoint lifetime.
use super::ncm;
use anyhow::{Context, Result, ensure};
use nusb::{
    MaybeFuture,
    transfer::{Buffer, Bulk, ControlIn, ControlOut, ControlType, In, Out, Recipient},
};
use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct NcmInterface {
    pub control: u8,
    pub data: u8,
    pub alternate: u8,
    pub input: u8,
    pub output: u8,
    pub packet_size: usize,
}

pub(crate) fn pair(config: nusb::descriptors::ConfigurationDescriptor<'_>) -> Result<NcmInterface> {
    for control in config
        .interface_alt_settings()
        .filter(|i| i.class() == 2 && i.subclass() == 0x0d && i.alternate_setting() == 0)
    {
        let raw = control.as_bytes();
        let mut offset = 0;
        let mut data_number = None;
        while offset + 3 <= raw.len() {
            let len = raw[offset] as usize;
            ensure!(
                len >= 2 && offset + len <= raw.len(),
                "invalid USB descriptor length"
            );
            if len >= 5
                && raw[offset + 1] == 0x24
                && raw[offset + 2] == 6
                && raw[offset + 3] == control.interface_number()
            {
                data_number = Some(raw[offset + 4]);
            }
            offset += len;
        }
        let Some(number) = data_number else { continue };
        if let Some(data) = config.interface_alt_settings().find(|i| {
            i.interface_number() == number && i.class() == 0x0a && i.endpoints().count() == 2
        }) && data
            .endpoints()
            .all(|e| e.transfer_type() == nusb::descriptors::TransferType::Bulk)
        {
            let input = data
                .endpoints()
                .find(|e| e.address() & 0x80 != 0)
                .context("NCM IN endpoint missing")?
                .address();
            let output = data
                .endpoints()
                .find(|e| e.address() & 0x80 == 0)
                .context("NCM OUT endpoint missing")?;
            return Ok(NcmInterface {
                control: control.interface_number(),
                data: number,
                alternate: data.alternate_setting(),
                input,
                output: output.address(),
                packet_size: output.max_packet_size(),
            });
        }
    }
    anyhow::bail!("Mac does not expose a usable CDC-NCM interface")
}

pub(super) fn claim_pair(
    device: &nusb::Device,
    selected: NcmInterface,
) -> Result<(nusb::Interface, nusb::Interface)> {
    let control = device
        .claim_interface(selected.control)
        .wait()
        .context("NCM control is inaccessible; run usb-internet prepare on this connected Mac")?;
    let data = device
        .claim_interface(selected.data)
        .wait()
        .context("NCM data is inaccessible; run usb-internet prepare on this connected Mac")?;
    Ok((control, data))
}

pub(super) struct Link {
    _device: nusb::Device,
    control: nusb::Interface,
    data: nusb::Interface,
    input: nusb::Endpoint<Bulk, In>,
    output: nusb::Endpoint<Bulk, Out>,
    params: ncm::Parameters,
    sequence: u16,
    packet_size: usize,
    pub(super) rx_reads: u64,
    pub(super) tx_blocks: u64,
}
const RECEIVE_DEPTH: usize = 8;
impl Link {
    pub(super) fn open(info: &nusb::DeviceInfo) -> Result<Self> {
        let device = info.open().wait()?;
        let selected = pair(device.active_configuration()?)?;
        let (control, data) = claim_pair(&device, selected)?;
        let bytes = control
            .control_in(
                ControlIn {
                    control_type: ControlType::Class,
                    recipient: Recipient::Interface,
                    request: 0x80,
                    value: 0,
                    index: selected.control as u16,
                    length: 28,
                },
                Duration::from_secs(5),
            )
            .wait()
            .context("reading NCM parameters")?;
        let params = ncm::Parameters::parse(&bytes)?;
        let set = |request, value, bytes: &[u8]| -> Result<()> {
            control
                .control_out(
                    ControlOut {
                        control_type: ControlType::Class,
                        recipient: Recipient::Interface,
                        request,
                        value,
                        index: selected.control as u16,
                        data: bytes,
                    },
                    Duration::from_secs(5),
                )
                .wait()?;
            Ok(())
        };
        set(0x84, 0, &[]).context("selecting NCM NTB16")?;
        set(0x86, 0, &(params.input_size as u32).to_le_bytes())
            .context("setting NCM receive size")?;
        set(0x8a, 0, &[]).context("disabling NCM CRC")?;
        data.set_alt_setting(selected.alternate).wait()?;
        set(0x43, 0x0f, &[]).context("enabling Ethernet packet reception")?;
        let mut input = data.endpoint::<Bulk, In>(selected.input)?;
        let input_size = params.input_size.next_multiple_of(input.max_packet_size());
        for _ in 0..RECEIVE_DEPTH {
            input.submit(Buffer::new(input_size));
        }
        Ok(Self {
            input,
            output: data.endpoint(selected.output)?,
            _device: device,
            control,
            data,
            params,
            sequence: 0,
            packet_size: selected.packet_size,
            rx_reads: 0,
            tx_blocks: 0,
        })
    }
    pub(super) fn receive(&mut self, timeout: Duration) -> Result<Vec<Vec<u8>>> {
        let mut frames = vec![];
        for index in 0..RECEIVE_DEPTH {
            let wait = if index == 0 { timeout } else { Duration::ZERO };
            let Some(mut read) = self.input.wait_next_complete(wait) else {
                break;
            };
            read.status.context("reading Mac USB network")?;
            let decoded = ncm::decode(&read.buffer[..read.actual_len]);
            read.buffer.clear();
            self.input.submit(read.buffer);
            frames.extend(decoded?);
            self.rx_reads += 1;
        }
        Ok(frames)
    }
    pub(super) fn send(&mut self, frames: &[Vec<u8>]) -> Result<()> {
        let mut offset = 0;
        while offset < frames.len() {
            let (bytes, count) = self.params.encode(&frames[offset..], self.sequence)?;
            self.sequence = self.sequence.wrapping_add(1);
            let size = bytes.len();
            let sent = self
                .output
                .transfer_blocking(bytes.into(), Duration::from_secs(5));
            sent.status?;
            ensure!(sent.actual_len == size, "short USB network write");
            if size.is_multiple_of(self.packet_size) {
                self.output
                    .transfer_blocking(Vec::<u8>::new().into(), Duration::from_secs(5))
                    .status?;
            }
            self.tx_blocks += 1;
            offset += count;
        }
        Ok(())
    }
}
impl Drop for Link {
    fn drop(&mut self) {
        crate::usb::cancel_and_drain(&mut self.input);
        let _ = self.data.set_alt_setting(0).wait();
        let _ = self
            .control
            .control_out(
                ControlOut {
                    control_type: ControlType::Class,
                    recipient: Recipient::Interface,
                    request: 0x43,
                    value: 0,
                    index: self.control.interface_number() as u16,
                    data: &[],
                },
                Duration::from_secs(1),
            )
            .wait();
    }
}

#[cfg(test)]
#[path = "../../tests/unit/usb_internet/link.rs"]
mod tests;
