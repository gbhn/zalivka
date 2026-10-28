//! Diagnose the process token without relying on inherited account variables.
use anyhow::{Context, Result, ensure};
use std::{
    io,
    os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle},
    ptr,
};
use windows_sys::Win32::{
    Security::{
        GetSidSubAuthority, GetSidSubAuthorityCount, GetTokenInformation, IsWellKnownSid,
        LookupAccountSidW, TOKEN_GROUPS, TOKEN_INFORMATION_CLASS, TOKEN_MANDATORY_LABEL,
        TOKEN_QUERY, TOKEN_USER, TokenElevation, TokenElevationType, TokenGroups,
        TokenIntegrityLevel, TokenUser, WinBuiltinAdministratorsSid,
    },
    System::Threading::{GetCurrentProcess, OpenProcessToken},
};

fn information(token: &OwnedHandle, class: TOKEN_INFORMATION_CLASS) -> Result<Vec<usize>> {
    let mut size = 0;
    unsafe { GetTokenInformation(token.as_raw_handle(), class, ptr::null_mut(), 0, &mut size) };
    ensure!(
        (1..=65536).contains(&size),
        "Token information size: {}",
        io::Error::last_os_error()
    );
    // usize provides the alignment required by the token structures and SIDs.
    let mut buffer = vec![0usize; (size as usize).div_ceil(std::mem::size_of::<usize>())];
    ensure!(
        unsafe {
            GetTokenInformation(
                token.as_raw_handle(),
                class,
                buffer.as_mut_ptr().cast(),
                size,
                &mut size,
            )
        } != 0,
        "GetTokenInformation({class}): {}",
        io::Error::last_os_error()
    );
    Ok(buffer)
}

pub(super) fn log() -> Result<()> {
    let mut handle = ptr::null_mut();
    ensure!(
        unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut handle) } != 0,
        "OpenProcessToken: {}",
        io::Error::last_os_error()
    );
    let token = unsafe { OwnedHandle::from_raw_handle(handle) };
    let elevated = information(&token, TokenElevation)?;
    let kind = information(&token, TokenElevationType)?;
    crate::log!(
        Debug,
        "drivers:auth",
        "TokenIsElevated={}; TokenElevationType={}",
        elevated[0] as u32,
        kind[0] as u32
    );

    let groups = information(&token, TokenGroups)?;
    let groups = unsafe { &*groups.as_ptr().cast::<TOKEN_GROUPS>() };
    let attributes = (0..groups.GroupCount as usize).find_map(|index| {
        let group = unsafe { &*groups.Groups.as_ptr().add(index) };
        (unsafe { IsWellKnownSid(group.Sid, WinBuiltinAdministratorsSid) } != 0)
            .then_some(group.Attributes)
    });
    match attributes {
        Some(attributes) => crate::log!(
            Debug,
            "drivers:auth",
            "Administrators: attributes=0x{attributes:08X}"
        ),
        None => crate::log!(Debug, "drivers:auth", "Administrators: absent from token"),
    }

    let integrity = information(&token, TokenIntegrityLevel)?;
    let label = unsafe { &*integrity.as_ptr().cast::<TOKEN_MANDATORY_LABEL>() };
    let count = unsafe { *GetSidSubAuthorityCount(label.Label.Sid) };
    ensure!(count > 0, "Empty integrity level SID");
    let rid = unsafe { *GetSidSubAuthority(label.Label.Sid, u32::from(count - 1)) };
    crate::log!(
        Debug,
        "drivers:auth",
        "Integrity level: S-1-16-{rid} ({})",
        match rid {
            4096 => "Low",
            8192 => "Medium",
            8448 => "Medium Plus",
            12288 => "High",
            16384 => "System",
            _ => "other",
        }
    );

    let user = information(&token, TokenUser)?;
    let user = unsafe { &*user.as_ptr().cast::<TOKEN_USER>() };
    let mut name = [0u16; 512];
    let mut domain = [0u16; 512];
    let mut name_size = name.len() as u32;
    let mut domain_size = domain.len() as u32;
    let mut use_kind = 0;
    ensure!(
        unsafe {
            LookupAccountSidW(
                ptr::null(),
                user.User.Sid,
                name.as_mut_ptr(),
                &mut name_size,
                domain.as_mut_ptr(),
                &mut domain_size,
                &mut use_kind,
            )
        } != 0,
        "LookupAccountSidW: {}",
        io::Error::last_os_error()
    );
    let name = String::from_utf16(&name[..name_size as usize]).context("Windows account name")?;
    let domain =
        String::from_utf16(&domain[..domain_size as usize]).context("Windows account domain")?;
    crate::log!(Info, "drivers:auth", "Process account: {domain}\\{name}");
    Ok(())
}
