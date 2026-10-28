//! Desktop actions call the same native operations as the terminal.
use anyhow::{Result, ensure};
use std::path::Path;
use zalivka::device::parse_ecid;
use zalivka::{ipsw::Behavior, operations};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Action {
    Revive,
    Restore,
    Download,
    Verify,
    Doctor,
    PrepareWindows,
    ResetDrivers,
}

impl Action {
    pub(super) fn title(self) -> &'static str {
        match self {
            Self::Revive => "Revive",
            Self::Restore => "Restore",
            Self::Download => "Firmware download",
            Self::Verify => "IPSW verification",
            Self::Doctor => "USB diagnostics",
            Self::PrepareWindows => "Windows setup",
            Self::ResetDrivers => "Reset Apple USB drivers",
        }
    }
    pub(super) fn log_name(self) -> &'static str {
        match self {
            Self::Revive => "revive",
            Self::Restore => "restore",
            Self::Download => "fetch",
            Self::Verify => "verify",
            Self::Doctor => "doctor",
            Self::PrepareWindows | Self::ResetDrivers => "drivers",
        }
    }
    pub(super) fn completed_title(self) -> &'static str {
        match self {
            Self::Revive => "Revive complete",
            Self::Restore => "Restore complete",
            Self::Download => "Firmware downloaded",
            Self::Verify => "IPSW verified",
            Self::Doctor => "Diagnostics complete",
            Self::PrepareWindows => "Windows setup complete",
            Self::ResetDrivers => "USB driver reset complete",
        }
    }
    pub(super) fn writes_device(self) -> bool {
        matches!(self, Self::Revive | Self::Restore)
    }
}

#[derive(Clone)]
pub(super) struct Setup {
    pub(super) ecid: String,
    pub(super) automatic: bool,
    pub(super) ipsw: String,
    pub(super) cache: String,
    pub(super) tokens: String,
    pub(super) connect_data: String,
}

impl Default for Setup {
    fn default() -> Self {
        Self {
            ecid: String::new(),
            automatic: true,
            ipsw: String::new(),
            cache: String::new(),
            tokens: String::new(),
            connect_data: String::new(),
        }
    }
}

impl Setup {
    pub(super) fn local_file(&self) -> Result<&Path> {
        let path = Path::new(self.ipsw.trim());
        ensure!(
            path.extension()
                .is_some_and(|ext| ext.eq_ignore_ascii_case("ipsw")),
            "Select an .ipsw file"
        );
        ensure!(path.is_file(), "IPSW file not found");
        Ok(path)
    }
    pub(super) fn validate(&self, action: Action) -> Result<()> {
        if action == Action::Verify || (action.writes_device() && !self.automatic) {
            self.local_file()?;
        }
        if action.writes_device() || action == Action::Download {
            parse_ecid(self.ecid.trim()).map_err(anyhow::Error::msg)?;
        }
        Ok(())
    }

    pub(super) fn restore_options(&self, transcript: Option<&Path>) -> Result<operations::Restore> {
        let path = |text: &str| (!text.trim().is_empty()).then(|| text.trim().into());
        Ok(operations::Restore {
            ipsw: if self.automatic {
                None
            } else {
                Some(self.local_file()?.into())
            },
            firmware_dir: if self.automatic {
                path(&self.cache)
            } else {
                None
            },
            ecid: parse_ecid(self.ecid.trim()).map_err(anyhow::Error::msg)?,
            identity: None,
            transcript: transcript.map(Path::to_path_buf),
            authorization_tokens: path(&self.tokens),
            apple_connect_data: path(&self.connect_data),
        })
    }

    pub(super) fn run(&self, action: Action, transcript: &Path) -> Result<()> {
        self.validate(action)?;
        match action {
            Action::Restore | Action::Revive => {
                self.restore_options(Some(transcript))?
                    .run(if action == Action::Restore {
                        Behavior::Erase
                    } else {
                        Behavior::Update
                    })?
            }
            Action::Download => {
                let ecid = parse_ecid(self.ecid.trim()).map_err(anyhow::Error::msg)?;
                let directory =
                    (!self.cache.trim().is_empty()).then(|| Path::new(self.cache.trim()));
                operations::fetch(ecid, directory)?;
            }
            Action::Verify => {
                let report = operations::verify(self.local_file()?, None)?;
                zalivka::log!(Trace, "report", "{}", serde_json::to_string(&report)?);
            }
            Action::Doctor => {
                let report = operations::doctor()?;
                zalivka::log!(Trace, "report", "{}", serde_json::to_string(&report)?);
                ensure!(
                    report.iter().all(|device| device.accessible),
                    "USB diagnostics found inaccessible devices"
                );
            }
            Action::PrepareWindows => operations::prepare_windows()?,
            Action::ResetDrivers => operations::reset_drivers()?,
        }
        Ok(())
    }
}
