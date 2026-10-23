use super::{Action, Event, Job, Setup};
use anyhow::{Context, Result};
use eframe::egui;
use std::{
    fs::File,
    io::{BufRead, BufReader},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::mpsc::Sender,
    time::{Instant, SystemTime, UNIX_EPOCH},
};

impl Job {
    // The exit code can arrive before the final stdout/stderr lines.
    pub(super) fn finished(&mut self) -> std::io::Result<Option<bool>> {
        if self.success.is_none() {
            self.success = self.child.try_wait()?.map(|status| status.success());
        }
        Ok(self.success.filter(|_| self.readers == 0))
    }

    pub(super) fn spawn(
        id: u64,
        action: Action,
        setup: &Setup,
        tx: &Sender<Event>,
        ctx: &egui::Context,
    ) -> Result<(Self, PathBuf)> {
        let directory = zalivka::storage::log_directory()?;
        let stamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let name = format!("{}-{}-{stamp}", action.command(), setup.ecid.trim());
        let path = directory.join(format!("{name}.log"));
        let log = File::options().write(true).create_new(true).open(&path)?;
        let transcript = directory.join(format!("{name}.jsonl"));
        let args = setup.arguments(action, Some(&transcript))?;
        let mut command = Command::new(std::env::current_exe()?);
        command
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            command.creation_flags(0x08000000);
        }
        let mut child = command.spawn().context("starting worker")?;
        let stdout = child.stdout.take().context("worker has no stdout")?;
        let stderr = child.stderr.take().context("worker has no stderr")?;
        for pipe in [
            Box::new(stdout) as Box<dyn std::io::Read + Send>,
            Box::new(stderr),
        ] {
            let tx = tx.clone();
            let ctx = ctx.clone();
            if let Err(e) = std::thread::Builder::new()
                .name("zalivka-log".into())
                .spawn(move || {
                    for line in BufReader::new(pipe).lines() {
                        let line = match line {
                            Ok(line) => line,
                            Err(e) => {
                                let _ = tx.send(Event::Line(id, format!("Log read error: {e}")));
                                break;
                            }
                        };
                        if tx.send(Event::Line(id, line)).is_err() {
                            break;
                        }
                        ctx.request_repaint();
                    }
                    let _ = tx.send(Event::ReaderDone(id));
                    ctx.request_repaint();
                })
            {
                let _ = child.kill();
                let _ = child.wait();
                return Err(e.into());
            }
        }
        Ok((
            Job {
                id,
                action,
                started: Instant::now(),
                child,
                log,
                success: None,
                readers: 2,
                cancelled: false,
            },
            path,
        ))
    }
}

pub(super) fn save_log(path: PathBuf, source: Option<&Path>, text: &str) -> Result<PathBuf> {
    if let Some(source) = source {
        let same = source
            .canonicalize()
            .ok()
            .zip(path.canonicalize().ok())
            .is_some_and(|(a, b)| a == b);
        if !same {
            std::fs::copy(source, &path)?;
        }
    } else {
        std::fs::write(&path, text)?;
    }
    Ok(path)
}
