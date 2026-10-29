//! AppleUsbFilter exposes its MUX1 interface through Apple IOCTLs, not WinUSB.
//! Wire layouts were checked against AppleUsbFilter 538.0.0.0. No Apple code is linked.
use super::Ioctl;
use anyhow::{Context, Result, bail, ensure};
use nusb::transfer::{ControlIn, ControlOut};
use std::{
    cell::UnsafeCell,
    io,
    os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle},
    ptr,
    sync::{Arc, mpsc},
    thread::{self, JoinHandle},
    time::Duration,
};
use windows_sys::{
    Win32::{
        Devices::{
            DeviceAndDriverInstallation::{
                CM_Get_DevNode_PropertyW, CM_Get_Device_Interface_PropertyW, CM_Locate_DevNodeW,
                CR_SUCCESS,
            },
            Properties::{DEVPKEY_Device_InstanceId, DEVPKEY_Device_Parent, DEVPROP_TYPE_STRING},
        },
        Foundation::{
            ERROR_IO_INCOMPLETE, ERROR_IO_PENDING, ERROR_OPERATION_ABORTED, GENERIC_READ,
            GENERIC_WRITE, INVALID_HANDLE_VALUE, WAIT_OBJECT_0, WAIT_TIMEOUT,
        },
        Storage::FileSystem::{
            CreateFileW, FILE_FLAG_OVERLAPPED, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
        },
        System::{
            IO::{
                CancelIoEx, DeviceIoControl, GetOverlappedResult, GetOverlappedResultEx, OVERLAPPED,
            },
            Threading::{CreateEventW, WaitForSingleObject},
        },
    },
    core::GUID,
};

const DFU: GUID = GUID::from_u128(0xb8085869_feb9_404b_8cb1_1e5c14fa8c54);
const IBOOT: GUID = GUID::from_u128(0xed82a167_d61a_4af6_9ab6_11e52236c576);
const MUX: GUID = GUID::from_u128(0xf0b32be3_6678_4879_9230_e43845d805ee);
const RESET: u32 = 0x22000c;
const CONTROL: u32 = 0x2200a0;
const PIPE_INFO: u32 = 0x2200a4;
const INTERFACE_INFO: u32 = 0x2200a8;
const TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Clone)]
pub(crate) struct AppleUsb {
    handle: Arc<OwnedHandle>,
}

/// Keep submission on a persistent thread: Windows cancels IRPs when their
/// submitting thread exits. This endpoint also owns/rearms its pending read,
/// so ASR/FDR workers never need to manage that lifetime themselves.
pub(crate) struct BulkReader {
    pending: Option<IoctlRequest<'static>>,
    requests: Option<mpsc::SyncSender<()>>,
    completed: mpsc::Receiver<Result<IoctlRequest<'static>>>,
    worker: Option<JoinHandle<()>>,
}

impl BulkReader {
    pub(crate) fn new(device: AppleUsb, pipe: u8) -> Result<Self> {
        Self::new_using(device, pipe, DeviceIoControl)
    }

    fn new_using(device: AppleUsb, pipe: u8, submit: Ioctl) -> Result<Self> {
        pipe_ioctl(pipe, true)?;
        let (requests, incoming) = mpsc::sync_channel(1);
        let (finished, completed) = mpsc::sync_channel(1);
        let worker = thread::Builder::new().name("zalivka-usb-in".into()).spawn(
            crate::progress::inherit(move || {
                while incoming.recv().is_ok() {
                    let result = device.read_using(pipe, 65536, submit);
                    if finished.send(result).is_err() {
                        break;
                    }
                }
            }),
        )?;
        Ok(Self {
            pending: None,
            requests: Some(requests),
            completed,
            worker: Some(worker),
        })
    }

    fn rearm(&mut self) -> Result<()> {
        self.requests
            .as_ref()
            .context("Apple USB reader closed")?
            .send(())
            .map_err(|_| anyhow::anyhow!("Apple USB reader stopped"))?;
        self.pending = Some(
            self.completed
                .recv()
                .context("waiting for Apple USB read submission")??,
        );
        Ok(())
    }

    pub(crate) fn input_ready(&self) -> Option<crate::mux::InputReady> {
        self.pending.as_ref().map(IoctlRequest::input_ready)
    }

    pub(crate) fn read(&mut self) -> Result<Vec<u8>> {
        if self.pending.is_none() {
            self.rearm()?;
        }
        match self.pending.as_mut().unwrap().poll(Duration::ZERO)? {
            Some(data) => {
                // Keep ACK reception active while mux decodes this packet and
                // submits the next outgoing burst. Idle polls retain the read.
                self.rearm()?;
                Ok(data)
            }
            None => Ok(Vec::new()),
        }
    }
}

impl Drop for BulkReader {
    fn drop(&mut self) {
        // Drain before the submitting thread exits, on every shutdown path.
        drop(self.pending.take());
        drop(self.requests.take());
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

/// Own every allocation touched by Windows until completion or cancellation.
/// Reads keep this request across idle mux polls; control and OUT transfers
/// wait synchronously through the same submission and cleanup path.
struct IoctlRequest<'a> {
    handle: Arc<OwnedHandle>,
    input: &'a [u8],
    ready: crate::mux::InputReady,
    overlapped: Box<UnsafeCell<OVERLAPPED>>,
    output: Vec<u8>,
    transferred: Box<UnsafeCell<u32>>,
    pending: bool,
}
// SAFETY: Windows only touches heap allocations whose addresses stay fixed
// across moves. One mutable owner polls/drains the request; the input borrow
// prevents its caller from changing or freeing input before the request drops.
unsafe impl Send for IoctlRequest<'_> {}

impl<'a> IoctlRequest<'a> {
    fn begin(
        device: &AppleUsb,
        code: u32,
        input: &'a [u8],
        output_len: usize,
        submit: Ioctl,
    ) -> Result<Self> {
        let input_len = u32::try_from(input.len()).context("Apple USB input too large")?;
        let output_size = u32::try_from(output_len).context("Apple USB output too large")?;
        // SAFETY: unnamed manual-reset event, no borrowed security attributes.
        let event = unsafe { CreateEventW(ptr::null(), 1, 0, ptr::null()) };
        ensure!(
            !event.is_null(),
            "creating Apple USB event: {}",
            io::Error::last_os_error()
        );
        // SAFETY: newly created owned event.
        let event = unsafe { OwnedHandle::from_raw_handle(event) };
        let overlapped = Box::new(UnsafeCell::new(OVERLAPPED {
            hEvent: event.as_raw_handle(),
            ..Default::default()
        }));
        // A writer can wait after a reader retires this request. Every request
        // gets a new event; notification clones retain it until all waits end.
        let ready = crate::mux::InputReady::new(move |timeout| {
            // SAFETY: the closure owns the event for the entire bounded wait.
            match unsafe {
                WaitForSingleObject(
                    event.as_raw_handle(),
                    timeout.as_millis().min(u128::from(u32::MAX - 1)) as u32,
                )
            } {
                WAIT_OBJECT_0 => Ok(true),
                WAIT_TIMEOUT => Ok(false),
                _ => Err(io::Error::last_os_error()).context("waiting for Apple USB event"),
            }
        });
        let mut request = Self {
            handle: device.handle.clone(),
            input,
            ready,
            overlapped,
            output: vec![0; output_len],
            transferred: Box::new(UnsafeCell::new(0)),
            pending: false,
        };
        // SAFETY: the request retains input, output, count, OVERLAPPED and
        // event until completion/drain, including after a move to another thread.
        let ok = unsafe {
            submit(
                request.handle.as_raw_handle(),
                code,
                if request.input.is_empty() {
                    ptr::null()
                } else {
                    request.input.as_ptr().cast()
                },
                input_len,
                if request.output.is_empty() {
                    ptr::null_mut()
                } else {
                    request.output.as_mut_ptr().cast()
                },
                output_size,
                request.transferred.get(),
                request.overlapped.get(),
            )
        };
        if ok == 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() != Some(ERROR_IO_PENDING as i32) {
                return Err(error).with_context(|| format!("Apple USB IOCTL {code:#x}"));
            }
            request.pending = true;
        }
        Ok(request)
    }

    fn input_ready(&self) -> crate::mux::InputReady {
        self.ready.clone()
    }

    fn wait(&mut self, timeout: Duration) -> io::Result<bool> {
        if !self.pending {
            return Ok(true);
        }
        // SAFETY: Windows retains these heap allocations until we drain it.
        let ok = unsafe {
            GetOverlappedResultEx(
                self.handle.as_raw_handle(),
                self.overlapped.get(),
                self.transferred.get(),
                timeout.as_millis().min(u128::from(u32::MAX - 1)) as u32,
                0,
            )
        };
        if ok == 0 {
            let error = io::Error::last_os_error();
            // A zero timeout reports IO_INCOMPLETE rather than WAIT_TIMEOUT.
            if matches!(error.raw_os_error(), Some(code)
                if code == WAIT_TIMEOUT as i32 || code == ERROR_IO_INCOMPLETE as i32)
            {
                return Ok(false);
            }
            return Err(error);
        }
        self.pending = false;
        Ok(true)
    }

    fn take_output(&mut self) -> Result<Vec<u8>> {
        // SAFETY: wait/cancel has retired the request before output is read.
        let transferred = unsafe { *self.transferred.get() } as usize;
        ensure!(
            transferred <= self.output.len(),
            "Apple USB returned an invalid transfer length"
        );
        self.output.truncate(transferred);
        Ok(std::mem::take(&mut self.output))
    }

    fn poll(&mut self, timeout: Duration) -> Result<Option<Vec<u8>>> {
        // Idle reads stay pending. Cancelling a partial USB packet on each
        // short mux poll could silently discard bytes from the device stream.
        if !self
            .wait(timeout)
            .context("receiving Apple USB IN completion")?
        {
            return Ok(None);
        }
        self.take_output().map(Some)
    }

    fn finish(mut self, timeout: Duration) -> Result<Vec<u8>> {
        let waited = self.wait(timeout);
        if !matches!(waited, Ok(true)) {
            let timed_out = matches!(waited, Ok(false));
            if let Err(error) = self.cancel() {
                if timed_out && error.raw_os_error() == Some(ERROR_OPERATION_ABORTED as i32) {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "Apple USB transfer timed out",
                    )
                    .into());
                }
                return Err(error.into());
            }
            // Completion may win the race with cancellation. Preserve those
            // successfully transferred bytes, as the former synchronous path did.
        }
        self.take_output()
    }

    fn cancel(&mut self) -> io::Result<()> {
        if !self.pending {
            return Ok(());
        }
        // SAFETY: cancel only our request and drain before releasing buffers.
        let completed = unsafe {
            CancelIoEx(self.handle.as_raw_handle(), self.overlapped.get());
            GetOverlappedResult(
                self.handle.as_raw_handle(),
                self.overlapped.get(),
                self.transferred.get(),
                1,
            )
        };
        self.pending = false;
        if completed == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}

impl Drop for IoctlRequest<'_> {
    fn drop(&mut self) {
        let _ = self.cancel();
    }
}

fn interface_number(instance: &str) -> Option<u8> {
    let hardware = instance.split('\\').nth(1)?.to_ascii_uppercase();
    let (_, number) = hardware.rsplit_once("&MI_")?;
    (number.len() == 2)
        .then(|| u8::from_str_radix(number, 16).ok())
        .flatten()
}

fn path_instance(path: &[u16]) -> Result<Vec<u16>> {
    let mut buffer = vec![0u16; 1024];
    let mut size = (buffer.len() * 2) as u32;
    let mut ty = 0;
    // SAFETY: path is NUL terminated; buffer and size describe a live writable allocation.
    let status = unsafe {
        CM_Get_Device_Interface_PropertyW(
            path.as_ptr(),
            &DEVPKEY_Device_InstanceId,
            &mut ty,
            buffer.as_mut_ptr().cast(),
            &mut size,
            0,
        )
    };
    ensure!(
        status == CR_SUCCESS && ty == DEVPROP_TYPE_STRING,
        "reading Apple USB instance (CONFIGRET {status:#x})"
    );
    let end = buffer
        .iter()
        .position(|c| *c == 0)
        .context("unterminated Apple USB instance")?;
    buffer.truncate(end + 1);
    Ok(buffer)
}

fn parent_instance(instance: &[u16]) -> Option<String> {
    let mut node = 0;
    // SAFETY: instance is NUL terminated and node is writable.
    if unsafe { CM_Locate_DevNodeW(&mut node, instance.as_ptr(), 0) } != CR_SUCCESS {
        return None;
    }
    let mut buffer = [0u16; 1024];
    let mut size = size_of_val(&buffer) as u32;
    let mut ty = 0;
    // SAFETY: node is present; buffer, size and ty are valid output arguments.
    let status = unsafe {
        CM_Get_DevNode_PropertyW(
            node,
            &DEVPKEY_Device_Parent,
            &mut ty,
            buffer.as_mut_ptr().cast(),
            &mut size,
            0,
        )
    };
    if status != CR_SUCCESS || ty != DEVPROP_TYPE_STRING {
        return None;
    }
    let end = buffer.iter().position(|c| *c == 0)?;
    String::from_utf16(&buffer[..end]).ok()
}

fn matches_instance(actual: &str, parent: Option<&str>, wanted: &str, number: u8) -> bool {
    if actual.eq_ignore_ascii_case(wanted) {
        return interface_number(actual).unwrap_or(0) == number;
    }
    parent.is_some_and(|p| p.eq_ignore_ascii_case(wanted))
        && interface_number(actual) == Some(number)
}

impl AppleUsb {
    /// Opens only the requested device/interface. No invented MUX1 suffixes or driver changes.
    pub(crate) fn open(info: &nusb::DeviceInfo, number: u8) -> Result<Option<Self>> {
        let guid = match crate::device::Mode::from_pid(info.product_id()) {
            Some(crate::device::Mode::Dfu) => &DFU,
            Some(crate::device::Mode::Recovery) => &IBOOT,
            None => &MUX,
        };
        let wanted = info.instance_id().to_string_lossy();
        for path in super::interface_paths(guid, None, 1024 * 1024)? {
            let instance = path_instance(&path)?;
            let actual = String::from_utf16(&instance[..instance.len() - 1])?;
            let parent = parent_instance(&instance);
            if !matches_instance(&actual, parent.as_deref(), &wanted, number) {
                continue;
            }
            // SAFETY: path comes from Config Manager; optional pointer arguments are null.
            let handle = unsafe {
                CreateFileW(
                    path.as_ptr(),
                    GENERIC_READ | GENERIC_WRITE,
                    FILE_SHARE_READ | FILE_SHARE_WRITE,
                    ptr::null(),
                    OPEN_EXISTING,
                    FILE_FLAG_OVERLAPPED,
                    ptr::null_mut(),
                )
            };
            if handle == INVALID_HANDLE_VALUE {
                return Err(io::Error::last_os_error()).context("opening Apple MUX1 USB interface");
            }
            // SAFETY: CreateFileW returned a new owned, valid handle.
            let device = Self {
                handle: Arc::new(unsafe { OwnedHandle::from_raw_handle(handle) }),
            };
            // Verify the handle with a read-only USB request, not just a cached PnP name.
            let descriptor = device.control_in(
                ControlIn {
                    control_type: nusb::transfer::ControlType::Standard,
                    recipient: nusb::transfer::Recipient::Device,
                    request: 6,
                    value: 0x0100,
                    index: 0,
                    length: 18,
                },
                TIMEOUT,
            )?;
            ensure!(
                descriptor.len() == 18 && descriptor[0..2] == [18, 1],
                "invalid Apple USB device descriptor"
            );
            ensure!(
                u16::from_le_bytes([descriptor[8], descriptor[9]]) == info.vendor_id()
                    && u16::from_le_bytes([descriptor[10], descriptor[11]]) == info.product_id(),
                "Apple USB device changed during open"
            );
            return Ok(Some(device));
        }
        Ok(None)
    }

    fn ioctl(
        &self,
        code: u32,
        input: &[u8],
        output_len: usize,
        timeout: Duration,
    ) -> Result<Vec<u8>> {
        self.ioctl_using(code, input, output_len, timeout, DeviceIoControl)
    }

    fn ioctl_using(
        &self,
        code: u32,
        input: &[u8],
        output_len: usize,
        timeout: Duration,
        submit: Ioctl,
    ) -> Result<Vec<u8>> {
        IoctlRequest::begin(self, code, input, output_len, submit)?
            .finish(timeout)
            .with_context(|| format!("Apple USB IOCTL {code:#x}"))
    }

    /// AppleUsbFilter forwards this device reset to WinUSB; no hub port cycle.
    pub(crate) fn reset(&self) -> Result<()> {
        self.ioctl(RESET, &[], 0, TIMEOUT)
            .context("resetting Apple USB device")?;
        Ok(())
    }

    fn read_using(&self, pipe: u8, length: usize, submit: Ioctl) -> Result<IoctlRequest<'static>> {
        IoctlRequest::begin(self, pipe_ioctl(pipe, true)?, &[], length, submit)
    }

    pub(crate) fn control_in(&self, request: ControlIn, timeout: Duration) -> Result<Vec<u8>> {
        let packet = control_packet(
            0x80 | ((request.control_type as u8) << 5) | request.recipient as u8,
            request.request,
            request.value,
            request.index,
            request.length,
            &[],
        );
        let response = self.ioctl(CONTROL, &packet, packet.len(), timeout)?;
        ensure!(response.len() >= 8, "short Apple USB control response");
        Ok(response[8..].to_vec())
    }

    pub(crate) fn control_out(&self, request: ControlOut<'_>, timeout: Duration) -> Result<()> {
        let length =
            u16::try_from(request.data.len()).context("USB control payload exceeds 65535 bytes")?;
        let packet = control_packet(
            ((request.control_type as u8) << 5) | request.recipient as u8,
            request.request,
            request.value,
            request.index,
            length,
            request.data,
        );
        let response = self.ioctl(CONTROL, &packet, packet.len(), timeout)?;
        ensure!(
            response.len() == packet.len(),
            "short Apple USB control write"
        );
        Ok(())
    }

    /// The driver numbers pipes by descriptor order, not by endpoint address.
    pub(crate) fn pipe(&self, address: u8) -> Result<u8> {
        let interface = self.ioctl(INTERFACE_INFO, &[], 36, TIMEOUT)?;
        ensure!(
            interface.len() == 36 && interface[26..28] == [9, 4],
            "invalid Apple USB interface descriptor"
        );
        let count = interface[30];
        ensure!(count <= 7, "Apple USB driver supports at most 7 pipes");
        for index in 1..=count {
            let mut query = [0; 24];
            query[..4].copy_from_slice(&u32::from(index).to_le_bytes());
            let info = self.ioctl(PIPE_INFO, &query, query.len(), TIMEOUT)?;
            if pipe_address(&info)? == Some(address) {
                return Ok(index);
            }
        }
        bail!("Apple USB bulk endpoint {address:#04x} not found")
    }

    pub(crate) fn bulk_out(&self, pipe: u8, data: &[u8], timeout: Duration) -> Result<()> {
        let code = pipe_ioctl(pipe, false)?;
        let response = self.ioctl(code, data, data.len(), timeout)?;
        ensure!(response.len() == data.len(), "short Apple USB bulk write");
        Ok(())
    }
}

fn control_packet(
    kind: u8,
    request: u8,
    value: u16,
    index: u16,
    length: u16,
    data: &[u8],
) -> Vec<u8> {
    let mut packet = vec![0u8; 8 + usize::from(length)];
    packet[0] = kind;
    packet[1] = request;
    packet[2..4].copy_from_slice(&value.to_le_bytes());
    packet[4..6].copy_from_slice(&index.to_le_bytes());
    packet[6..8].copy_from_slice(&length.to_le_bytes());
    packet[8..8 + data.len()].copy_from_slice(data);
    packet
}

fn pipe_address(info: &[u8]) -> Result<Option<u8>> {
    ensure!(info.len() == 24, "invalid Apple USB pipe descriptor length");
    Ok((u32::from_le_bytes(info[8..12].try_into()?) == 2).then_some(info[6]))
}

fn pipe_ioctl(pipe: u8, input: bool) -> Result<u32> {
    ensure!((1..=7).contains(&pipe), "invalid Apple USB pipe index");
    Ok(if input { 0x220021 } else { 0x220042 } + u32::from(pipe) * 4)
}

#[cfg(test)]
#[path = "../../tests/unit/windows/apple.rs"]
mod tests;
