//! Actions and validated CLI arguments for GUI workers.
use anyhow::{Result, ensure};
use std::{ffi::OsString, path::Path};
use zalivka::device::parse_ecid;

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
            Self::Restore => "Восстановление",
            Self::Download => "Загрузка прошивки",
            Self::Verify => "Проверка IPSW",
            Self::Doctor => "Диагностика USB",
            Self::PrepareWindows => "Подготовка Windows",
            Self::ResetDrivers => "Сброс USB-драйверов Apple",
        }
    }
    pub(super) fn command(self) -> &'static str {
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
            Self::Revive => "Revive завершён",
            Self::Restore => "Восстановление завершено",
            Self::Download => "Прошивка загружена",
            Self::Verify => "IPSW проверен",
            Self::Doctor => "Диагностика завершена",
            Self::PrepareWindows => "Подготовка Windows завершена",
            Self::ResetDrivers => "Сброс USB-драйверов завершён",
        }
    }
    pub(super) fn writes_device(self) -> bool {
        matches!(self, Self::Revive | Self::Restore)
    }
}

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
            "Выберите файл .ipsw"
        );
        ensure!(path.is_file(), "Файл IPSW не найден");
        Ok(path)
    }
    pub(super) fn arguments(
        &self,
        action: Action,
        transcript: Option<&Path>,
    ) -> Result<Vec<OsString>> {
        let mut args = vec![action.command().into()];
        if action == Action::PrepareWindows {
            args.push("prepare".into());
            return Ok(args);
        }
        if action == Action::ResetDrivers {
            args.push("reset".into());
            return Ok(args);
        }
        if action == Action::Doctor {
            return Ok(args);
        }
        if action == Action::Verify {
            args.push(self.local_file()?.as_os_str().into());
            return Ok(args);
        }
        parse_ecid(self.ecid.trim()).map_err(anyhow::Error::msg)?;
        if action.writes_device() && !self.automatic {
            args.push(self.local_file()?.as_os_str().into());
        }
        args.extend(["--ecid".into(), self.ecid.trim().into()]);
        if (self.automatic || action == Action::Download) && !self.cache.trim().is_empty() {
            args.extend(["--firmware-dir".into(), self.cache.trim().into()]);
        }
        if action.writes_device() {
            args.push("--experimental".into());
            if action == Action::Restore {
                args.push("--erase".into());
            }
            if let Some(path) = transcript {
                args.extend(["--transcript".into(), path.as_os_str().into()]);
            }
            for (flag, path) in [
                ("--authorization-tokens", &self.tokens),
                ("--apple-connect-data", &self.connect_data),
            ] {
                if !path.trim().is_empty() {
                    args.extend([flag.into(), path.trim().into()]);
                }
            }
        }
        Ok(args)
    }
}
