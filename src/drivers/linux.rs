//! Install the bundled USB access rule with desktop authorization through Polkit.
use super::UDEV_RULES;
use anyhow::{Context, Result, bail, ensure};
use std::{
    io::Write,
    os::unix::fs::PermissionsExt,
    path::Path,
    process::{Command, Stdio},
};

pub(super) fn prepare() -> Result<()> {
    let executable = std::env::current_exe().context("locating the Zalivka executable")?;
    run_setup(&mut elevation_command(&executable))
}

fn elevation_command(executable: &Path) -> Command {
    let mut command = Command::new("pkexec");
    command
        .arg("--disable-internal-agent")
        .arg(executable)
        .args(["drivers", "install-udev"])
        .stdin(Stdio::null());
    command
}

fn run_setup(command: &mut Command) -> Result<()> {
    let output = command.output().context(
        "Could not start pkexec. Install Polkit and a desktop authentication agent, or run sudo ./zalivka drivers install-udev"
    )?;
    for bytes in [&output.stdout, &output.stderr] {
        for line in String::from_utf8_lossy(bytes).lines() {
            if output.status.success() {
                crate::log!(Info, "udev", "{line}");
            } else {
                crate::log!(Error, "udev", "{line}");
            }
        }
    }
    match output.status.code() {
        Some(0) => Ok(()),
        Some(126) => bail!("Administrator authentication was cancelled"),
        Some(127) => bail!(
            "Could not obtain administrator authorization. Check that a Polkit authentication agent is running in your desktop session"
        ),
        _ => bail!(
            "Linux USB setup failed ({}); see the journal for details",
            output.status
        ),
    }
}

pub(super) fn install() -> Result<()> {
    install_with(
        Path::new("/etc/udev/rules.d/70-zalivka.rules"),
        Command::new("udevadm").args(["control", "--reload-rules"]),
    )
}

fn install_with(path: &Path, reload: &mut Command) -> Result<()> {
    // Upgrade only our previous bundled rule; preserve administrator changes.
    const PREVIOUS: &[u8] = b"# Apple DFU/recovery and restore interfaces. Access for the active local seat.\nSUBSYSTEM==\"usb\", ATTR{idVendor}==\"05ac\", TAG+=\"uaccess\"\n";
    let replace = match std::fs::read(path) {
        Ok(existing) if existing == UDEV_RULES.as_bytes() => None,
        Ok(existing) if existing == PREVIOUS => Some(true),
        Ok(_) => bail!("different udev rule already exists; refusing to overwrite"),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Some(false),
        Err(error) => return Err(error).context("reading existing udev rule"),
    };
    if let Some(replace) = replace {
        let directory = path.parent().context("udev rule path has no parent")?;
        std::fs::create_dir_all(directory)
            .context("creating udev rule directory (requires root)")?;
        let mut file = tempfile::NamedTempFile::new_in(directory)
            .context("writing udev rule (requires root)")?;
        file.write_all(UDEV_RULES.as_bytes())?;
        file.as_file()
            .set_permissions(std::fs::Permissions::from_mode(0o644))?;
        if replace {
            file.persist(path).context("upgrading bundled udev rule")?;
        } else {
            file.persist_noclobber(path)
                .context("installing udev rule without overwriting existing files")?;
        }
    }
    let output = reload
        .output()
        .context("starting udevadm to reload rules; rule file was saved")?;
    ensure!(
        output.status.success(),
        "udevadm could not reload rules; rule file was saved: {}",
        String::from_utf8_lossy(&output.stderr).trim()
    );
    Ok(())
}

#[cfg(test)]
#[path = "../../tests/unit/drivers/linux.rs"]
mod tests;
