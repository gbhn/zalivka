//! One-way UTF-8 log forwarding from a UAC helper to its original caller.
use crate::logging::Record;
use anyhow::{Context, Result, ensure};
use std::{
    fs::File,
    io::{self, Read},
    os::windows::io::{AsRawHandle, FromRawHandle},
    ptr,
};
use windows_sys::Win32::{
    Foundation::{ERROR_NO_DATA, ERROR_PIPE_LISTENING, INVALID_HANDLE_VALUE},
    Storage::FileSystem::{FILE_FLAG_FIRST_PIPE_INSTANCE, PIPE_ACCESS_INBOUND},
    System::Pipes::{ConnectNamedPipe, CreateNamedPipeW, PIPE_NOWAIT, PIPE_REJECT_REMOTE_CLIENTS},
};

pub(super) struct LogPipe {
    pub id: uuid::Uuid,
    pipe: File,
    pending: Vec<u8>,
    pub received: bool,
}

impl LogPipe {
    pub fn new() -> Result<Self> {
        let id = uuid::Uuid::new_v4();
        let name = super::wide(format!(r"\\.\pipe\zalivka-elevated-{id}"));
        // Default pipe ACL grants access to its creator and administrators,
        // including when the UAC credentials belong to another account.
        let handle = unsafe {
            CreateNamedPipeW(
                name.as_ptr(),
                PIPE_ACCESS_INBOUND | FILE_FLAG_FIRST_PIPE_INSTANCE,
                PIPE_NOWAIT | PIPE_REJECT_REMOTE_CLIENTS,
                1,
                0,
                65536,
                0,
                ptr::null(),
            )
        };
        ensure!(
            handle != INVALID_HANDLE_VALUE,
            "Creating UAC log pipe: {}",
            io::Error::last_os_error()
        );
        let pipe = unsafe { File::from_raw_handle(handle) };
        if unsafe { ConnectNamedPipe(pipe.as_raw_handle(), ptr::null_mut()) } == 0 {
            let error = io::Error::last_os_error();
            ensure!(
                error.raw_os_error() == Some(ERROR_PIPE_LISTENING as i32),
                "Opening UAC log pipe: {error}"
            );
        }
        Ok(Self {
            id,
            pipe,
            pending: Vec::new(),
            received: false,
        })
    }

    pub fn drain(&mut self, mut publish: impl FnMut(Record)) -> Result<()> {
        // Nonblocking reads let the caller also observe helper exit, including
        // failures before it connects. Bound work and incomplete record size.
        let mut buffer = [0u8; 8192];
        for _ in 0..32 {
            let size = match self.pipe.read(&mut buffer) {
                Ok(0) => break,
                Ok(size) => size,
                Err(error)
                    if error.kind() == io::ErrorKind::BrokenPipe
                        || matches!(error.raw_os_error(), Some(code)
                            if code == ERROR_PIPE_LISTENING as i32 || code == ERROR_NO_DATA as i32) =>
                {
                    break;
                }
                Err(error) => return Err(error).context("Reading UAC journal"),
            };
            self.pending.extend_from_slice(&buffer[..size]);
            while let Some(end) = self.pending.iter().position(|byte| *byte == b'\n') {
                let line: Vec<_> = self.pending.drain(..=end).collect();
                ensure!(line.len() <= 65536, "UAC log record too long");
                let line =
                    std::str::from_utf8(&line).context("UAC journal contains invalid UTF-8")?;
                // Only records are accepted; helper output cannot change worker state.
                let record =
                    Record::parse_json(line.trim_end()).context("Invalid UAC log record")?;
                self.received = true;
                publish(record);
            }
            ensure!(self.pending.len() <= 65536, "UAC log record too long");
        }
        Ok(())
    }

    pub fn incomplete(&self) -> bool {
        !self.pending.is_empty()
    }
}

#[cfg(test)]
#[path = "../../../tests/unit/windows/setup/log.rs"]
mod tests;
