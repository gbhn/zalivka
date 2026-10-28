//! SSPI uses the calling user's logon credentials; no password is requested.
use super::wide;
use anyhow::{Context, Result, ensure};
use base64::{Engine, prelude::BASE64_STANDARD};
use std::ptr;
use windows_sys::Win32::{
    Foundation::{
        SEC_E_OK, SEC_I_COMPLETE_AND_CONTINUE, SEC_I_COMPLETE_NEEDED, SEC_I_CONTINUE_NEEDED,
    },
    Security::{
        Authentication::Identity::{
            AcquireCredentialsHandleW, CompleteAuthToken, DeleteSecurityContext, FreeContextBuffer,
            FreeCredentialsHandle, GetUserNameExW, ISC_REQ_ALLOCATE_MEMORY, ISC_REQ_CONNECTION,
            InitializeSecurityContextW, NameSamCompatible, SECBUFFER_TOKEN, SECBUFFER_VERSION,
            SECPKG_CRED_OUTBOUND, SECURITY_NATIVE_DREP, SecBuffer, SecBufferDesc,
        },
        Credentials::SecHandle,
    },
};

pub(crate) struct Negotiate {
    credential: SecHandle,
    context: Option<SecHandle>,
    target: Vec<u16>,
}

impl Negotiate {
    pub fn new(scheme: &str, proxy_host: &str) -> Result<Self> {
        ensure!(
            matches!(scheme, "Negotiate" | "NTLM"),
            "unsupported SSPI proxy scheme"
        );
        let mut credential = SecHandle::default();
        let package = wide(scheme);
        let status = unsafe {
            AcquireCredentialsHandleW(
                ptr::null(),
                package.as_ptr(),
                SECPKG_CRED_OUTBOUND,
                ptr::null(),
                ptr::null(),
                None,
                ptr::null(),
                &mut credential,
                ptr::null_mut(),
            )
        };
        ensure!(
            status == SEC_E_OK,
            "SSPI {scheme}: AcquireCredentialsHandleW failed (0x{:08X}); current Windows user credentials are unavailable",
            status as u32
        );
        let mut name = [0u16; 1024];
        let mut size = name.len() as u32;
        let account = if unsafe { GetUserNameExW(NameSamCompatible, name.as_mut_ptr(), &mut size) }
        {
            let end = name
                .iter()
                .position(|unit| *unit == 0)
                .unwrap_or(name.len());
            String::from_utf16_lossy(&name[..end])
        } else {
            "current Windows account".into()
        };
        crate::log!(
            Info,
            "proxy:auth",
            "Process account={account}; SPN=HTTP/{proxy_host}"
        );
        Ok(Self {
            credential,
            context: None,
            target: wide(format!("HTTP/{proxy_host}")),
        })
    }

    pub fn step(&mut self, challenge: Option<&str>) -> Result<String> {
        let mut bytes = challenge
            .map(|text| BASE64_STANDARD.decode(text))
            .transpose()
            .context("invalid proxy authentication token encoding")?
            .unwrap_or_default();
        ensure!(
            bytes.len() <= 65536,
            "proxy authentication token exceeds 64 KiB"
        );
        let mut input = SecBuffer {
            cbBuffer: bytes.len() as u32,
            BufferType: SECBUFFER_TOKEN,
            pvBuffer: bytes.as_mut_ptr().cast(),
        };
        let input = SecBufferDesc {
            ulVersion: SECBUFFER_VERSION,
            cBuffers: 1,
            pBuffers: &mut input,
        };
        let mut output = Output(SecBuffer {
            cbBuffer: 0,
            BufferType: SECBUFFER_TOKEN,
            pvBuffer: ptr::null_mut(),
        });
        let mut output_desc = SecBufferDesc {
            ulVersion: SECBUFFER_VERSION,
            cBuffers: 1,
            pBuffers: &mut output.0,
        };
        let mut context = self.context.unwrap_or_default();
        let mut attributes = 0;
        let status = unsafe {
            InitializeSecurityContextW(
                &self.credential,
                self.context.as_ref().map_or(ptr::null(), |context| context),
                self.target.as_ptr(),
                ISC_REQ_CONNECTION | ISC_REQ_ALLOCATE_MEMORY,
                0,
                SECURITY_NATIVE_DREP,
                if bytes.is_empty() {
                    ptr::null()
                } else {
                    &input
                },
                0,
                &mut context,
                &mut output_desc,
                &mut attributes,
                ptr::null_mut(),
            )
        };
        crate::log!(
            Trace,
            "proxy:auth",
            "InitializeSecurityContextW: status=0x{:08X}; attributes=0x{attributes:08X}; input={} B, output={} B",
            status as u32,
            bytes.len(),
            output.0.cbBuffer
        );
        // SSPI may return a partial context even on failure; release it too.
        if context.dwLower != 0 || context.dwUpper != 0 {
            self.context = Some(context);
        }
        ensure!(
            matches!(
                status,
                SEC_E_OK
                    | SEC_I_CONTINUE_NEEDED
                    | SEC_I_COMPLETE_NEEDED
                    | SEC_I_COMPLETE_AND_CONTINUE
            ),
            "SSPI: InitializeSecurityContextW failed (0x{:08X}); proxy authentication with the current Windows user failed",
            status as u32
        );
        self.context = Some(context);
        if matches!(status, SEC_I_COMPLETE_NEEDED | SEC_I_COMPLETE_AND_CONTINUE) {
            let status = unsafe { CompleteAuthToken(&context, &output_desc) };
            ensure!(
                status == SEC_E_OK,
                "SSPI: CompleteAuthToken failed (0x{:08X})",
                status as u32
            );
        }
        ensure!(
            output.0.cbBuffer <= 65536,
            "SSPI output token exceeds 64 KiB"
        );
        if output.0.cbBuffer == 0 {
            return Ok(String::new());
        }
        ensure!(
            !output.0.pvBuffer.is_null(),
            "SSPI returned an empty token buffer"
        );
        let token = unsafe {
            std::slice::from_raw_parts(output.0.pvBuffer.cast::<u8>(), output.0.cbBuffer as usize)
        };
        Ok(BASE64_STANDARD.encode(token))
    }
}

struct Output(SecBuffer);
impl Drop for Output {
    fn drop(&mut self) {
        if !self.0.pvBuffer.is_null() {
            unsafe {
                FreeContextBuffer(self.0.pvBuffer);
            }
        }
    }
}
impl Drop for Negotiate {
    fn drop(&mut self) {
        unsafe {
            if let Some(context) = &self.context {
                DeleteSecurityContext(context);
            }
            FreeCredentialsHandle(&self.credential);
        }
    }
}

#[cfg(test)]
#[path = "../../tests/unit/windows/negotiate.rs"]
mod tests;
