use super::*;
use windows_sys::Win32::Foundation::{ERROR_INSUFFICIENT_BUFFER, SetLastError};

unsafe extern "system" fn cycle_ok(
    handle: HANDLE,
    code: u32,
    input: *const c_void,
    input_size: u32,
    output: *mut c_void,
    output_size: u32,
    returned: *mut u32,
    overlapped: *mut OVERLAPPED,
) -> i32 {
    // Validate the exact ABI submitted to the OS. Returning an error instead
    // of panicking keeps this test callback from unwinding across an FFI boundary.
    if handle != ptr::dangling_mut::<c_void>()
        || code != IOCTL_USB_HUB_CYCLE_PORT
        || input.is_null()
        || input != output
        || input_size != 8
        || output_size != 8
        || returned.is_null()
        || !overlapped.is_null()
    {
        unsafe {
            SetLastError(ERROR_INSUFFICIENT_BUFFER);
        }
        return 0;
    }
    // SAFETY: caller supplied the checked 8-byte request and writable returned count.
    let mut request = unsafe { input.cast::<USB_CYCLE_PORT_PARAMS>().read_unaligned() };
    if request.ConnectionIndex != 3 {
        return 0;
    }
    request.StatusReturned = 0;
    unsafe {
        output
            .cast::<USB_CYCLE_PORT_PARAMS>()
            .write_unaligned(request);
        *returned = 8;
    }
    1
}

#[test]
fn port_cycle_passes_the_same_eight_byte_buffer_in_both_directions() {
    cycle_port_request(ptr::dangling_mut(), 3, cycle_ok).unwrap();
}

#[test]
fn port_cycle_checks_os_errors_and_the_returned_usbd_status() {
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
        unsafe {
            SetLastError(ERROR_INSUFFICIENT_BUFFER);
        }
        0
    }
    unsafe extern "system" fn hub_error(
        h: HANDLE,
        c: u32,
        i: *const c_void,
        il: u32,
        o: *mut c_void,
        ol: u32,
        n: *mut u32,
        ov: *mut OVERLAPPED,
    ) -> i32 {
        let ok = unsafe { cycle_ok(h, c, i, il, o, ol, n, ov) };
        if ok != 0 {
            let mut response = unsafe { o.cast::<USB_CYCLE_PORT_PARAMS>().read_unaligned() };
            response.StatusReturned = 0xc0000001;
            unsafe {
                o.cast::<USB_CYCLE_PORT_PARAMS>().write_unaligned(response);
            }
        }
        ok
    }
    unsafe extern "system" fn short_response(
        h: HANDLE,
        c: u32,
        i: *const c_void,
        il: u32,
        o: *mut c_void,
        ol: u32,
        n: *mut u32,
        ov: *mut OVERLAPPED,
    ) -> i32 {
        let ok = unsafe { cycle_ok(h, c, i, il, o, ol, n, ov) };
        if ok != 0 {
            unsafe {
                *n = 4;
            }
        }
        ok
    }
    let h = ptr::dangling_mut();
    let error = cycle_port_request(h, 3, os_error).unwrap_err();
    assert_eq!(
        error
            .downcast_ref::<std::io::Error>()
            .unwrap()
            .raw_os_error(),
        Some(122)
    );
    assert!(
        cycle_port_request(h, 3, hub_error)
            .unwrap_err()
            .to_string()
            .contains("0xc0000001")
    );
    assert!(
        cycle_port_request(h, 3, short_response)
            .unwrap_err()
            .to_string()
            .contains("returned 4 bytes")
    );
    assert!(
        cycle_port_request(h, 0, cycle_ok)
            .unwrap_err()
            .to_string()
            .contains("invalid USB port")
    );
}
