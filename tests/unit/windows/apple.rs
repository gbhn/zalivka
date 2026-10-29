use super::*;
use std::ffi::c_void;
use windows_sys::Win32::Foundation::HANDLE;

#[test]
fn kis_driver_info_decodes_its_own_layout_and_checks_the_device() {
    let mut bytes = vec![0; 1028];
    bytes[..4].copy_from_slice(&[0xac, 5, 0x27, 0x12]);
    for (offset, text) in [
        (8, "NONC:01020304 SNON:05060708"),
        (263, "ECID:2A CPID:8142 BDID:22 CPFM:03"),
    ] {
        bytes[offset..offset + text.len()].copy_from_slice(text.as_bytes());
    }
    let info = kis_info(&bytes).unwrap();
    assert_eq!(info.ecid, 42);
    assert_eq!(info.chip_id, 0x8142);
    assert_eq!(info.ap_nonce, [1, 2, 3, 4]);
    for length in 0..bytes.len() {
        assert!(kis_info(&bytes[..length]).is_err());
    }
    for offset in [0, 2, 8, 263] {
        let mut malformed = bytes.clone();
        malformed[offset] = 0xff;
        assert!(kis_info(&malformed).is_err());
    }
}

unsafe extern "system" fn read_pipe(
    handle: HANDLE,
    _code: u32,
    _input: *const c_void,
    _input_size: u32,
    output: *mut c_void,
    size: u32,
    returned: *mut u32,
    overlapped: *mut OVERLAPPED,
) -> i32 {
    // SAFETY: IoctlRequest owns the output/OVERLAPPED for this named-pipe I/O.
    unsafe {
        windows_sys::Win32::Storage::FileSystem::ReadFile(
            handle,
            output.cast(),
            size,
            returned,
            overlapped,
        )
    }
}

fn connected_pipe(label: &str) -> (AppleUsb, OwnedHandle) {
    use windows_sys::Win32::{
        Storage::FileSystem::PIPE_ACCESS_DUPLEX, System::Pipes::CreateNamedPipeW,
    };
    let name: Vec<u16> = format!(r"\\.\pipe\zalivka-{label}-{}", std::process::id())
        .encode_utf16()
        .chain(Some(0))
        .collect();
    // SAFETY: live NUL-terminated name; optional arguments are null.
    let server = unsafe {
        CreateNamedPipeW(
            name.as_ptr(),
            PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
            0,
            1,
            4096,
            4096,
            0,
            ptr::null(),
        )
    };
    assert!(server != INVALID_HANDLE_VALUE);
    // SAFETY: freshly created owned handle.
    let device = AppleUsb {
        handle: Arc::new(unsafe { OwnedHandle::from_raw_handle(server) }),
    };
    let connect = IoctlRequest::begin(&device, 0, &[], 0, connect_pipe).unwrap();
    // SAFETY: same live pipe name; client uses synchronous writes.
    let client = unsafe {
        CreateFileW(
            name.as_ptr(),
            GENERIC_WRITE,
            0,
            ptr::null(),
            OPEN_EXISTING,
            0,
            ptr::null_mut(),
        )
    };
    assert!(client != INVALID_HANDLE_VALUE);
    // SAFETY: freshly opened owned client handle.
    let client = unsafe { OwnedHandle::from_raw_handle(client) };
    connect.finish(Duration::from_secs(1)).unwrap();
    (device, client)
}

unsafe extern "system" fn removed_device(
    _handle: HANDLE,
    _code: u32,
    _input: *const c_void,
    _input_size: u32,
    _output: *mut c_void,
    _output_size: u32,
    _returned: *mut u32,
    _overlapped: *mut OVERLAPPED,
) -> i32 {
    unsafe { SetLastError(windows_sys::Win32::Foundation::ERROR_DEVICE_NOT_CONNECTED) };
    0
}

#[test]
fn immediate_input_submission_failure_preserves_device_removal_for_reconnect() {
    let (device, _client) = connected_pipe("removed-device");
    let error = device.read_using(1, 4096, removed_device).err().unwrap();
    assert!(crate::mux::is_device_removal(&error));
    assert_eq!(
        error.downcast_ref::<io::Error>().unwrap().raw_os_error(),
        Some(1167)
    );
}

#[test]
fn input_submission_outlives_service_workers_without_cancelling_or_losing_data() {
    use windows_sys::Win32::Storage::FileSystem::WriteFile;
    let (device, client) = connected_pipe("persistent-reader");
    let mut reader = BulkReader::new_using(device.clone(), 1, read_pipe).unwrap();
    for bytes in [
        b"first packet".as_slice(),
        b"packet after another worker exit",
    ] {
        reader = std::thread::spawn(move || {
            assert!(reader.read().unwrap().is_empty());
            reader
        })
        .join()
        .unwrap();
        // The service thread has exited; the endpoint's submission thread
        // still owns the Windows I/O. Direct submission would be cancelled.
        let ready = reader.input_ready().unwrap();
        assert!(!ready.wait(Duration::from_millis(10)).unwrap());
        let mut sent = 0;
        // SAFETY: synchronous client write from a live byte slice.
        assert_ne!(
            unsafe {
                WriteFile(
                    client.as_raw_handle(),
                    bytes.as_ptr(),
                    bytes.len() as u32,
                    &mut sent,
                    ptr::null_mut(),
                )
            },
            0
        );
        assert!(ready.wait(Duration::from_secs(1)).unwrap());
        assert_eq!(reader.read().unwrap(), bytes);
        // Consumption immediately rearms on the persistent thread. Old
        // notifications remain valid and the new read has its own event.
        assert!(ready.wait(Duration::ZERO).unwrap());
        assert!(!reader.input_ready().unwrap().wait(Duration::ZERO).unwrap());
    }
    drop(reader); // Cancel/drain the idle read before its submitting thread exits.
    // The same device handle remains usable after endpoint shutdown.
    let mut next = device.read_using(1, 4096, read_pipe).unwrap();
    assert!(next.poll(Duration::ZERO).unwrap().is_none());
}

#[test]
fn read_event_wakes_on_completion_and_remains_valid_after_retiring_request() {
    use windows_sys::Win32::Storage::FileSystem::WriteFile;
    let (device, client) = connected_pipe("read-event");
    let mut read = device.read_using(1, 4096, read_pipe).unwrap();
    let ready = read.input_ready();
    assert!(!ready.wait(Duration::ZERO).unwrap());
    assert!(!ready.wait(Duration::from_millis(1)).unwrap());
    let bytes = b"ACK wakes sender while shared mux is unlocked";
    let writer = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(5));
        let mut sent = 0;
        // SAFETY: synchronous write from a live static byte slice.
        assert_ne!(
            unsafe {
                WriteFile(
                    client.as_raw_handle(),
                    bytes.as_ptr(),
                    bytes.len() as u32,
                    &mut sent,
                    ptr::null_mut(),
                )
            },
            0
        );
        client
    });
    assert!(ready.wait(Duration::from_secs(1)).unwrap());
    let client = writer.join().unwrap();
    assert_eq!(read.poll(Duration::ZERO).unwrap().unwrap(), bytes);
    drop(read);
    // A different reader may retire/rearm before the waiting writer resumes.
    // Its old notification must retain a valid, still-signaled event handle.
    let next = device.read_using(1, 4096, read_pipe).unwrap();
    let next_ready = next.input_ready();
    assert!(ready.wait(Duration::ZERO).unwrap());
    assert!(!next_ready.wait(Duration::ZERO).unwrap());
    drop(next);
    assert!(next_ready.wait(Duration::from_secs(1)).unwrap()); // cancellation signals it.
    drop(client);
}

#[test]
fn persistent_read_survives_idle_polls_and_drains_on_drop_without_losing_bytes() {
    use windows_sys::Win32::Storage::FileSystem::WriteFile;
    let (device, client) = connected_pipe("persistent-read");
    let mut read = device.read_using(1, 4096, read_pipe).unwrap();
    for timeout in [Duration::ZERO, Duration::from_millis(1), Duration::ZERO] {
        assert!(read.poll(timeout).unwrap().is_none());
        assert!(read.pending);
    }
    let bytes = b"complete packet after several idle polls";
    let mut sent = 0;
    // SAFETY: synchronous client and live input buffer.
    assert_ne!(
        unsafe {
            WriteFile(
                client.as_raw_handle(),
                bytes.as_ptr(),
                bytes.len() as u32,
                &mut sent,
                ptr::null_mut(),
            )
        },
        0
    );
    assert_eq!(read.poll(Duration::from_secs(1)).unwrap().unwrap(), bytes);
    drop(read);
    let mut cancelled = device.read_using(1, 4096, read_pipe).unwrap();
    assert!(cancelled.poll(Duration::from_millis(1)).unwrap().is_none());
    drop(cancelled);
    // The same handle works after cancellation; the next packet is intact.
    let mut next = device.read_using(1, 4096, read_pipe).unwrap();
    assert_ne!(
        unsafe {
            WriteFile(
                client.as_raw_handle(),
                bytes.as_ptr(),
                bytes.len() as u32,
                &mut sent,
                ptr::null_mut(),
            )
        },
        0
    );
    assert_eq!(next.poll(Duration::from_secs(1)).unwrap().unwrap(), bytes);
}
use windows_sys::Win32::Foundation::{ERROR_GEN_FAILURE, ERROR_INVALID_PARAMETER, SetLastError};

#[test]
fn raw_read_reports_worker_exit_cancellation_and_keeps_the_handle_usable() {
    use windows_sys::Win32::{Foundation::ERROR_BROKEN_PIPE, Storage::FileSystem::WriteFile};
    let (device, client) = connected_pipe("worker-exit");
    let worker_device = device.clone();
    let mut read = std::thread::spawn(move || {
        let mut read = worker_device.read_using(1, 4096, read_pipe).unwrap();
        assert!(read.poll(Duration::ZERO).unwrap().is_none());
        read
    })
    .join()
    .unwrap();
    // A cancelled request cannot promise that all received bytes survived.
    // The endpoint owner tested above prevents this during normal restore.
    let error = read.poll(Duration::from_secs(1)).unwrap_err();
    assert_eq!(
        error.downcast_ref::<io::Error>().unwrap().raw_os_error(),
        Some(ERROR_OPERATION_ABORTED as i32)
    );
    drop(read);

    let mut next = device.read_using(1, 4096, read_pipe).unwrap();
    let bytes = b"restored message after ASR worker exit";
    let mut sent = 0;
    // SAFETY: synchronous client write from a live immutable byte slice.
    assert_ne!(
        unsafe {
            WriteFile(
                client.as_raw_handle(),
                bytes.as_ptr(),
                bytes.len() as u32,
                &mut sent,
                ptr::null_mut(),
            )
        },
        0
    );
    assert_eq!(next.poll(Duration::from_secs(1)).unwrap().unwrap(), bytes);
    drop(next);

    // A genuine pipe failure is still returned, rather than converted to an
    // empty successful read together with the recoverable cancellation.
    let mut broken = device.read_using(1, 4096, read_pipe).unwrap();
    assert!(broken.poll(Duration::ZERO).unwrap().is_none());
    drop(client);
    let error = broken.poll(Duration::from_secs(1)).unwrap_err();
    assert_eq!(
        error.downcast_ref::<io::Error>().unwrap().raw_os_error(),
        Some(ERROR_BROKEN_PIPE as i32)
    );
}

fn event_device() -> AppleUsb {
    // A harmless handle for injected IOCTL calls; no USB device is opened.
    // SAFETY: unnamed event, no optional pointer arguments.
    let event = unsafe { CreateEventW(ptr::null(), 1, 0, ptr::null()) };
    assert!(!event.is_null(), "{}", io::Error::last_os_error());
    AppleUsb {
        // SAFETY: CreateEventW returned a new owned handle.
        handle: Arc::new(unsafe { OwnedHandle::from_raw_handle(event) }),
    }
}

unsafe extern "system" fn reset_ok(
    handle: HANDLE,
    code: u32,
    input: *const c_void,
    input_size: u32,
    output: *mut c_void,
    output_size: u32,
    returned: *mut u32,
    overlapped: *mut OVERLAPPED,
) -> i32 {
    // Return a Win32 error on a bad ABI instead of unwinding across FFI.
    if handle.is_null()
        || code != 0x22000c
        || !input.is_null()
        || input_size != 0
        || !output.is_null()
        || output_size != 0
        || returned.is_null()
        || overlapped.is_null()
        || unsafe { (*overlapped).hEvent.is_null() }
    {
        unsafe { SetLastError(ERROR_INVALID_PARAMETER) };
        return 0;
    }
    // SAFETY: returned is the checked writable output count supplied by ioctl_using.
    unsafe { *returned = 0 };
    1
}

#[test]
fn device_reset_submits_the_apple_ioctl_with_null_buffers_and_an_event() {
    assert!(
        event_device()
            .ioctl_using(RESET, &[], 0, TIMEOUT, reset_ok)
            .unwrap()
            .is_empty()
    );
}

#[test]
fn device_reset_preserves_os_failure_and_rejects_an_invalid_response_length() {
    unsafe extern "system" fn os_error(
        _: HANDLE,
        _: u32,
        _: *const c_void,
        _: u32,
        _: *mut c_void,
        _: u32,
        _: *mut u32,
        _: *mut OVERLAPPED,
    ) -> i32 {
        unsafe { SetLastError(ERROR_GEN_FAILURE) };
        0
    }
    unsafe extern "system" fn invalid_response(
        h: HANDLE,
        c: u32,
        i: *const c_void,
        il: u32,
        o: *mut c_void,
        ol: u32,
        n: *mut u32,
        ov: *mut OVERLAPPED,
    ) -> i32 {
        let ok = unsafe { reset_ok(h, c, i, il, o, ol, n, ov) };
        if ok != 0 {
            // SAFETY: reset_ok has validated this output count.
            unsafe { *n = 1 };
        }
        ok
    }
    let device = event_device();
    let error = device
        .ioctl_using(RESET, &[], 0, TIMEOUT, os_error)
        .unwrap_err();
    assert_eq!(
        error.downcast_ref::<io::Error>().unwrap().raw_os_error(),
        Some(ERROR_GEN_FAILURE as i32)
    );
    assert!(format!("{error:#}").contains("0x22000c"));
    let error = device
        .ioctl_using(RESET, &[], 0, TIMEOUT, invalid_response)
        .unwrap_err();
    assert!(format!("{error:#}").contains("invalid transfer length"));
}

#[test]
fn synchronous_ioctl_waits_for_the_same_overlapped_input_completion() {
    use windows_sys::Win32::Storage::FileSystem::WriteFile;
    let (device, client) = connected_pipe("synchronous-input");
    let bytes = b"packet received through the synchronous IOCTL path";
    let writer = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(10));
        let mut sent = 0;
        // SAFETY: synchronous write from a live byte slice.
        assert_ne!(
            unsafe {
                WriteFile(
                    client.as_raw_handle(),
                    bytes.as_ptr(),
                    bytes.len() as u32,
                    &mut sent,
                    ptr::null_mut(),
                )
            },
            0
        );
        client
    });
    assert_eq!(
        device
            .ioctl_using(0, &[], 4096, Duration::from_secs(1), read_pipe)
            .unwrap(),
        bytes
    );
    drop(writer.join().unwrap());
}

#[test]
fn cancelling_one_request_keeps_other_reads_and_the_shared_handle_alive() {
    use windows_sys::Win32::Storage::FileSystem::WriteFile;
    let (device, client) = connected_pipe("independent-requests");
    let first = device.read_using(1, 4096, read_pipe).unwrap();
    let mut second = device.read_using(1, 4096, read_pipe).unwrap();
    drop(first);
    drop(device);
    assert!(second.poll(Duration::ZERO).unwrap().is_none());
    let bytes = b"only the abandoned request was cancelled";
    let mut sent = 0;
    // SAFETY: synchronous write from a live byte slice. The second request
    // retains the server handle even after the AppleUsb wrapper is dropped.
    assert_ne!(
        unsafe {
            WriteFile(
                client.as_raw_handle(),
                bytes.as_ptr(),
                bytes.len() as u32,
                &mut sent,
                ptr::null_mut(),
            )
        },
        0
    );
    assert_eq!(second.poll(Duration::from_secs(1)).unwrap().unwrap(), bytes);
}

#[test]
fn endpoint_submission_failure_preserves_device_removal_and_shuts_down() {
    let mut reader = BulkReader::new_using(event_device(), 1, removed_device).unwrap();
    let error = reader.read().unwrap_err();
    assert!(crate::mux::is_device_removal(&error));
    assert_eq!(
        error.downcast_ref::<io::Error>().unwrap().raw_os_error(),
        Some(1167)
    );
    assert!(reader.input_ready().is_none());
    drop(reader);
}

#[test]
fn selects_only_the_requested_device_and_interface() {
    let parent = r"USB\VID_05AC&PID_1281\ECID_A";
    let child = r"USB\VID_05AC&PID_1281&MI_01\CHILD";
    assert!(matches_instance(parent, None, &parent.to_lowercase(), 0));
    assert!(matches_instance(child, Some(parent), parent, 1));
    assert!(matches_instance(
        &child.to_lowercase(),
        Some(parent),
        parent,
        1
    ));
    assert!(!matches_instance(child, Some(parent), parent, 0));
    assert!(!matches_instance(
        child,
        Some(r"USB\VID_05AC&PID_1281\ECID_B"),
        parent,
        1
    ));
    assert!(!matches_instance(parent, None, parent, 1));
    assert!(!matches_instance(
        r"USB\VID_05AC&PID_1281&MI_01X\CHILD",
        Some(parent),
        parent,
        1
    ));
}

#[test]
fn kis_selects_the_rsm_child_of_the_requested_usb_device() {
    let usb = r"USB\VID_05AC&PID_1881\ECID_A";
    let rsm = r"KIS\VID_05AC&PID_0001\PORTAL_1";
    assert!(matches_kis_instance(rsm, Some(usb), usb));
    assert!(matches_kis_instance(
        &rsm.to_lowercase(),
        Some(&usb.to_lowercase()),
        usb
    ));
    assert!(matches_kis_instance(r"KIS\PORTAL\1", Some(usb), usb));
    assert!(matches_kis_instance(usb, None, usb));
    assert!(!matches_kis_instance(
        rsm,
        Some(r"USB\VID_05AC&PID_1881\ECID_B"),
        usb
    ));
    assert!(!matches_kis_instance(rsm, None, usb));
    assert!(!matches_kis_instance(r"HID\PORTAL\1", Some(usb), usb));
}

#[test]
fn encodes_usb_setup_and_data_without_padding() {
    assert_eq!(
        control_packet(0x21, 1, 0x1234, 0xabcd, 3, &[1, 2, 3]),
        [0x21, 1, 0x34, 0x12, 0xcd, 0xab, 3, 0, 1, 2, 3]
    );
    assert_eq!(
        control_packet(0xa1, 3, 0, 0, 6, &[]),
        [0xa1, 3, 0, 0, 0, 0, 6, 0, 0, 0, 0, 0, 0, 0]
    );
    assert_eq!(control_packet(0x21, 1, 0, 0, 0, &[]).len(), 8);
}

#[test]
fn resolves_pipe_ordinals_and_rejects_invalid_descriptors() {
    let mut pipe = [0; 24];
    pipe[..4].copy_from_slice(&1u32.to_le_bytes());
    pipe[6] = 0x84;
    pipe[8..12].copy_from_slice(&2u32.to_le_bytes());
    assert_eq!(pipe_address(&pipe).unwrap(), Some(0x84));
    assert!(pipe_address(&pipe[..23]).is_err());
    pipe[8] = 3;
    assert_eq!(pipe_address(&pipe).unwrap(), None);
    assert_eq!(pipe_ioctl(1, false).unwrap(), 0x220046);
    assert_eq!(pipe_ioctl(2, true).unwrap(), 0x220029);
    assert!(pipe_ioctl(0, true).is_err());
    assert!(pipe_ioctl(8, false).is_err());
}

unsafe extern "system" fn connect_pipe(
    handle: HANDLE,
    _: u32,
    _: *const c_void,
    _: u32,
    _: *mut c_void,
    _: u32,
    _: *mut u32,
    overlapped: *mut OVERLAPPED,
) -> i32 {
    // SAFETY: request owns the live handle and OVERLAPPED until completion/drain.
    unsafe { windows_sys::Win32::System::Pipes::ConnectNamedPipe(handle, overlapped) }
}

#[test]
fn cancels_and_drains_a_pending_ioctl_before_returning() {
    use windows_sys::Win32::{
        Storage::FileSystem::PIPE_ACCESS_DUPLEX, System::Pipes::CreateNamedPipeW,
    };
    // A real pending Windows I/O request, without requiring USB hardware.
    // No client connects, so the deadline must cancel and drain the request.
    let name: Vec<u16> = format!(r"\\.\pipe\zalivka-ioctl-test-{}", std::process::id())
        .encode_utf16()
        .chain(Some(0))
        .collect();
    // SAFETY: name is NUL terminated, other pointers are optional nulls.
    let handle = unsafe {
        CreateNamedPipeW(
            name.as_ptr(),
            PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
            0,
            1,
            4096,
            4096,
            0,
            ptr::null(),
        )
    };
    assert!(
        handle != INVALID_HANDLE_VALUE,
        "{}",
        io::Error::last_os_error()
    );
    // SAFETY: CreateNamedPipeW returned a new owned handle, closed at test exit.
    let device = AppleUsb {
        handle: Arc::new(unsafe { OwnedHandle::from_raw_handle(handle) }),
    };
    let error = device
        .ioctl_using(0, &[], 0, Duration::from_millis(10), connect_pipe)
        .unwrap_err();
    assert_eq!(
        error.downcast_ref::<io::Error>().unwrap().kind(),
        io::ErrorKind::TimedOut,
        "{error:#}"
    );
    // The handle remains usable after cancellation; invalid IOCTL fails promptly.
    assert!(device.ioctl(0, &[], 0, Duration::from_secs(1)).is_err());
}
