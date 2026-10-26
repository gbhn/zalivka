//! Mac NCM USB requests, receive queues and endpoint lifetime.
use super::ncm;
use crate::usb::{NcmInterface, ncm_interface};
use anyhow::{Context, Result, ensure};
use nusb::{
    MaybeFuture,
    transfer::{
        Buffer, Bulk, ControlIn, ControlOut, ControlType, EndpointDirection, In, Out, Recipient,
        TransferError,
    },
};
use std::time::{Duration, Instant};

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
    input_recovery: StallRecovery,
    output_recovery: StallRecovery,
}
const RECEIVE_DEPTH: usize = 8;

#[derive(Default)]
struct StallRecovery {
    attempts: u8,
    last_attempt: Option<Instant>,
}
impl StallRecovery {
    fn attempt(&mut self, now: Instant) -> Result<u8> {
        // An idle link must not accumulate unrelated stalls across its lifetime.
        if self
            .last_attempt
            .is_none_or(|last| now.duration_since(last) >= Duration::from_secs(5))
        {
            self.attempts = 0;
        }
        ensure!(
            self.attempts < 3,
            "Mac USB network endpoint keeps stalling after 3 recovery attempts"
        );
        self.attempts += 1;
        self.last_attempt = Some(now);
        Ok(self.attempts)
    }

    fn succeeded(&mut self) {
        *self = Self::default();
    }
}

fn recover_stall<Dir: EndpointDirection>(
    endpoint: &mut nusb::Endpoint<Bulk, Dir>,
    recovery: &mut StallRecovery,
) -> Result<()> {
    let attempt = recovery.attempt(Instant::now())?;
    // clear_halt requires all transfers, including cancellations, to be drained.
    crate::usb::cancel_and_drain(endpoint);
    endpoint
        .clear_halt()
        .wait()
        .with_context(|| format!("resetting Mac USB network endpoint {:?}", Dir::DIR))?;
    crate::log!(
        Info,
        "usb-internet",
        "USB-канал {:?} сброшен после Stall (попытка {attempt}/3); раздача интернета продолжается",
        Dir::DIR
    );
    Ok(())
}

fn queue_reads(input: &mut nusb::Endpoint<Bulk, In>, input_size: usize) {
    let size = input_size.next_multiple_of(input.max_packet_size());
    for _ in input.pending()..RECEIVE_DEPTH {
        input.submit(Buffer::new(size));
    }
}

impl Link {
    pub(super) fn open(info: &nusb::DeviceInfo) -> Result<Self> {
        let device = info.open().wait()?;
        let selected = ncm_interface(device.active_configuration()?)?;
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
        queue_reads(&mut input, params.input_size);
        Ok(Self {
            input,
            output: data.endpoint(selected.output)?,
            _device: device,
            control,
            data,
            params,
            sequence: 0,
            packet_size: selected.packet_size,
            input_recovery: StallRecovery::default(),
            output_recovery: StallRecovery::default(),
        })
    }
    pub(super) fn receive(&mut self, timeout: Duration) -> Result<Vec<Vec<u8>>> {
        let mut frames = vec![];
        for index in 0..RECEIVE_DEPTH {
            let wait = if index == 0 { timeout } else { Duration::ZERO };
            let Some(mut read) = self.input.wait_next_complete(wait) else {
                break;
            };
            if read.status == Err(TransferError::Stall) {
                recover_stall(&mut self.input, &mut self.input_recovery)
                    .context("reading Mac USB network")?;
                queue_reads(&mut self.input, self.params.input_size);
                break;
            }
            read.status.context("reading Mac USB network")?;
            self.input_recovery.succeeded();
            let decoded = ncm::decode(&read.buffer[..read.actual_len]);
            read.buffer.clear();
            self.input.submit(read.buffer);
            frames.extend(decoded?);
        }
        Ok(frames)
    }
    pub(super) fn send(&mut self, frames: &[Vec<u8>]) -> Result<()> {
        let mut offset = 0;
        while offset < frames.len() {
            let (bytes, count) = self.params.encode(&frames[offset..], self.sequence)?;
            self.sequence = self.sequence.wrapping_add(1);
            let size = bytes.len();
            self.write(bytes.into())?;
            if size.is_multiple_of(self.packet_size) {
                // Retry a stalled terminator separately from the delivered NTB.
                self.write(Vec::<u8>::new().into())?;
            }
            offset += count;
        }
        Ok(())
    }

    fn write(&mut self, mut buffer: Buffer) -> Result<()> {
        let size = buffer.len();
        loop {
            let sent = self
                .output
                .transfer_blocking(buffer, Duration::from_secs(5));
            if sent.status == Err(TransferError::Stall) {
                recover_stall(&mut self.output, &mut self.output_recovery)
                    .context("writing Mac USB network")?;
                ensure!(
                    sent.actual_len == 0,
                    "USB network write stalled after partial delivery; cannot replay the NTB"
                );
                buffer = sent.buffer;
                continue;
            }
            sent.status.context("writing Mac USB network")?;
            ensure!(sent.actual_len == size, "short USB network write");
            self.output_recovery.succeeded();
            return Ok(());
        }
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
