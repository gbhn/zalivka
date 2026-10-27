//! Native nusb and AppleUsbFilter endpoints, ordered bursts and pending reads.
use super::TIMEOUT;
#[cfg(windows)]
use anyhow::bail;
use anyhow::{Context, Result, ensure};
use nusb::{
    Device, Interface, MaybeFuture,
    transfer::{Buffer, Bulk, ControlIn, ControlOut, In, Out},
};
use std::{
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, Instant},
};

/// Use the normal OS USB backend first, then Apple's installed Windows filter.
pub(crate) enum UsbInterface {
    Native(Interface),
    #[cfg(windows)]
    Apple(std::sync::Arc<crate::windows::apple::AppleUsb>),
}

impl UsbInterface {
    pub(crate) fn claim(device: &Device, _info: &nusb::DeviceInfo, number: u8) -> Result<Self> {
        match device.claim_interface(number).wait() {
            Ok(interface) => Ok(Self::Native(interface)),
            Err(error) => {
                #[cfg(windows)]
                match crate::windows::apple::AppleUsb::open(_info, number) {
                    Ok(Some(apple)) => return Ok(Self::Apple(std::sync::Arc::new(apple))),
                    Ok(None) => {}
                    Err(apple) => {
                        return Err(apple).with_context(|| {
                            format!("WinUSB failed ({error}); Apple USB fallback failed")
                        });
                    }
                }
                Err(error).with_context(|| format!("claiming USB interface {number}"))
            }
        }
    }

    pub(crate) fn transport(&self) -> &'static str {
        match self {
            Self::Native(_) => {
                if cfg!(windows) {
                    "winusb"
                } else {
                    "usbfs"
                }
            }
            #[cfg(windows)]
            Self::Apple(_) => "apple_usb",
        }
    }

    #[cfg(windows)]
    pub(crate) fn check_reset_access(&self, info: &nusb::DeviceInfo) -> Result<()> {
        match self {
            Self::Native(_) => crate::windows::reset::check_access(info),
            // Reset uses the same already-open Apple handle as control transfers.
            Self::Apple(_) => Ok(()),
        }
    }

    pub(super) fn set_alt_setting(&self, alt: u8) -> Result<()> {
        if alt == 0 {
            return Ok(());
        }
        match self {
            Self::Native(i) => i.set_alt_setting(alt).wait().map_err(Into::into),
            #[cfg(windows)]
            Self::Apple(_) => bail!(
                "Apple USB driver does not expose alternate setting {alt}; use a compatible WinUSB driver for this interface"
            ),
        }
    }

    pub(crate) fn control_in(&self, request: ControlIn, timeout: Duration) -> Result<Vec<u8>> {
        match self {
            Self::Native(i) => i.control_in(request, timeout).wait().map_err(Into::into),
            #[cfg(windows)]
            Self::Apple(i) => i.control_in(request, timeout),
        }
    }

    pub(super) fn control_out(&self, request: ControlOut<'_>, timeout: Duration) -> Result<()> {
        match self {
            Self::Native(i) => i.control_out(request, timeout).wait().map_err(Into::into),
            #[cfg(windows)]
            Self::Apple(i) => i.control_out(request, timeout),
        }
    }

    pub(super) fn bulk_out(&self, address: u8) -> Result<BulkOutput> {
        match self {
            Self::Native(i) => Ok(BulkOutput::Native(i.endpoint(address)?)),
            #[cfg(windows)]
            Self::Apple(i) => Ok(BulkOutput::Apple(i.clone(), i.pipe(address)?)),
        }
    }

    pub(super) fn bulk_in(&self, address: u8) -> Result<BulkInput> {
        match self {
            Self::Native(i) => Ok(BulkInput::Native(i.endpoint(address)?)),
            #[cfg(windows)]
            Self::Apple(i) => Ok(BulkInput::Apple(
                i.clone(),
                i.pipe(address)?,
                None,
                crate::windows::apple::ReadSubmitter::new()?,
            )),
        }
    }
}

pub(super) enum BulkOutput {
    Native(nusb::Endpoint<Bulk, Out>),
    #[cfg(windows)]
    Apple(std::sync::Arc<crate::windows::apple::AppleUsb>, u8),
}

impl BulkOutput {
    pub(super) fn write(&mut self, data: &[u8]) -> Result<()> {
        match self {
            Self::Native(ep) => {
                let sent = ep.transfer_blocking(data.to_vec().into(), TIMEOUT);
                sent.status?;
                ensure!(sent.actual_len == data.len(), "short USB bulk write");
                Ok(())
            }
            #[cfg(windows)]
            Self::Apple(i, pipe) => i.bulk_out(*pipe, data, TIMEOUT),
        }
    }

    pub(super) fn write_batch(&mut self, packets: &[&[u8]], cancelled: &AtomicBool) -> Result<()> {
        match self {
            Self::Native(ep) => {
                let result = (|| {
                    for packet in packets {
                        ensure!(
                            !cancelled.load(Ordering::Acquire),
                            "USB mux session cancelled"
                        );
                        ep.submit(packet.to_vec().into());
                    }
                    let deadline = Instant::now() + TIMEOUT;
                    for packet in packets {
                        ensure!(
                            !cancelled.load(Ordering::Acquire),
                            "USB mux session cancelled"
                        );
                        let sent = ep
                            .wait_next_complete(deadline.saturating_duration_since(Instant::now()))
                            .context("USB bulk write burst timed out")?;
                        sent.status?;
                        ensure!(sent.actual_len == packet.len(), "short USB bulk write");
                    }
                    Ok(())
                })();
                if result.is_err() {
                    // Retain all buffers until the cancelled requests complete.
                    cancel_and_drain(ep);
                }
                result
            }
            #[cfg(windows)]
            Self::Apple(device, pipe) => {
                // AppleUsbFilter 538 dispatches OUT IOCTLs in parallel and
                // calls synchronous WinUsb_WritePipe from each handler. More
                // than one pending IOCTL can reorder mux/TCP frames before
                // WinUSB sees them. Complete each request before the next;
                // the shared mux batch and ready-ACK processing still apply.
                for packet in packets {
                    ensure!(
                        !cancelled.load(Ordering::Acquire),
                        "USB mux session cancelled"
                    );
                    device.bulk_out(*pipe, packet, TIMEOUT)?;
                }
                Ok(())
            }
        }
    }
}

pub(super) enum BulkInput {
    Native(nusb::Endpoint<Bulk, In>),
    #[cfg(windows)]
    Apple(
        std::sync::Arc<crate::windows::apple::AppleUsb>,
        u8,
        Option<crate::windows::apple::PendingRead>,
        // Drop/drain the pending request before its submitting thread exits.
        crate::windows::apple::ReadSubmitter,
    ),
}

impl BulkInput {
    pub(super) fn input_ready(&self) -> Option<crate::mux::InputReady> {
        match self {
            #[cfg(windows)]
            Self::Apple(_, _, Some(pending), _) => Some(pending.input_ready()),
            _ => None,
        }
    }

    pub(super) fn read(&mut self) -> Result<Vec<u8>> {
        // The IN request stays pending in the driver. Poll completion without
        // waiting under the mux lock; yield_link sleeps outside it when idle.
        let timeout = Duration::ZERO;
        match self {
            Self::Native(ep) => {
                if ep.pending() == 0 {
                    ep.submit(Buffer::new(65536));
                }
                let Some(mut completion) = ep.wait_next_complete(timeout) else {
                    return Ok(Vec::new());
                };
                match completion.status {
                    Ok(()) | Err(nusb::transfer::TransferError::Cancelled) => {
                        let data = completion.buffer[..completion.actual_len].to_vec();
                        // clear() preserves the capacity and requested read length.
                        completion.buffer.clear();
                        ep.submit(completion.buffer);
                        Ok(data)
                    }
                    Err(error) => Err(error.into()),
                }
            }
            #[cfg(windows)]
            Self::Apple(i, pipe, pending, submitter) => {
                if pending.is_none() {
                    *pending = Some(submitter.begin(i.clone(), *pipe, 65536)?);
                }
                match pending.as_mut().unwrap().poll(timeout)? {
                    Some(data) => {
                        // Keep ACK reception active while mux decodes the
                        // previous read and submits the next outgoing burst.
                        *pending = Some(submitter.begin(i.clone(), *pipe, 65536)?);
                        Ok(data)
                    }
                    None => Ok(Vec::new()),
                }
            }
        }
    }
}

/// Cancellation is asynchronous: retire every request before releasing its buffer.
pub(crate) fn cancel_and_drain<Dir: nusb::transfer::EndpointDirection>(
    endpoint: &mut nusb::Endpoint<Bulk, Dir>,
) {
    endpoint.cancel_all();
    while endpoint.pending() != 0 {
        let _ = endpoint.wait_next_complete(Duration::from_secs(1));
    }
}
