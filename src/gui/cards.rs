//! Device, firmware, operation and Windows preparation cards.
use super::theme::{BLUE, Tone};
use super::widgets::{
    caption, card, elapsed_text, human_bytes, laptop, metric, pill, progress_bar, section,
};
use super::{App, Confirmation, Picker, setup::Action};
use eframe::egui::{self, Color32, RichText, Vec2, containers::frame::Prepared};
use std::{
    path::Path,
    time::{Duration, Instant},
};
use zalivka::localization::{format as trf, text as tr};
use zalivka::{device::Mode, drivers};

impl App {
    pub(super) fn prepare_device_card(
        &mut self,
        ui: &mut egui::Ui,
        ctx: &egui::Context,
    ) -> Prepared {
        let mut frame = card(ctx).begin(ui);
        let ui = &mut frame.content_ui;
        ui.set_width(ui.available_width());
        section(ui, "01", "Device");
        ui.horizontal_wrapped(|ui| {
            laptop(ui, self.target().is_some());
            ui.allocate_ui_with_layout(
                Vec2::new((ui.available_width() - 100.0).max(220.0), 54.0),
                egui::Layout::top_down(egui::Align::Min),
                |ui| {
                    let title = self
                        .target()
                        .map(|device| {
                            trf("Mac (CPID {:04x})", &[&format!("{:04x}", device.chip_id)])
                        })
                        .unwrap_or_else(|| {
                            if self.devices.is_empty() {
                                "No Mac connected"
                            } else {
                                "Select a Mac"
                            }
                            .into()
                        });
                    ui.label(RichText::new(tr(title)).size(19.0).strong());
                    if let Some(device) = self.target() {
                        ui.label(
                            RichText::new(trf("ECID {:016x}", &[&format!("{:016x}", device.ecid)]))
                                .monospace()
                                .size(12.0)
                                .color(ui.visuals().weak_text_color()),
                        );
                    } else {
                        ui.label(
                            RichText::new(tr("Connect your Mac with a USB-C cable"))
                                .color(ui.visuals().weak_text_color()),
                        );
                    }
                },
            );
            if let Some(d) = self.target() {
                pill(
                    ui,
                    if d.mode == Mode::Dfu {
                        "DFU"
                    } else {
                        "Recovery"
                    },
                    if d.mode == Mode::Dfu {
                        Tone::Success.color(ui.visuals())
                    } else {
                        ui.visuals().weak_text_color()
                    },
                );
            }
        });
        if self.devices.len() > 1 || (!self.devices.is_empty() && self.target().is_none()) {
            ui.add_space(4.0);
            egui::ComboBox::from_id_salt("devices")
                .selected_text(tr("Select a device"))
                .width(ui.available_width())
                .show_ui(ui, |ui| {
                    for d in &self.devices {
                        let ecid = format!("{:016x}", d.ecid);
                        ui.selectable_value(
                            &mut self.setup.ecid,
                            ecid.clone(),
                            trf("Mac, {ecid}, {:?}", &[&ecid, &tr(format!("{:?}", d.mode))]),
                        );
                    }
                });
        }
        if self.scan_error.is_some() {
            ui.horizontal_wrapped(|ui| {
                ui.label(
                    RichText::new(tr("Could not check USB")).color(ui.visuals().error_fg_color),
                );
                if ui.link(tr("Diagnostics")).clicked() {
                    self.start(Action::Doctor, ctx);
                }
            });
        }
        frame
    }
    pub(super) fn prepare_firmware_card(
        &mut self,
        ui: &mut egui::Ui,
        ctx: &egui::Context,
    ) -> Prepared {
        let mut frame = card(ctx).begin(ui);
        let ui = &mut frame.content_ui;
        ui.set_width(ui.available_width());
        section(ui, "02", "Firmware");
        ui.horizontal_wrapped(|ui| {
            for (automatic, title) in [(true, "Automatic"), (false, "Local IPSW")] {
                let selected = self.setup.automatic == automatic;
                let color = if selected {
                    Color32::WHITE
                } else {
                    ui.visuals().text_color()
                };
                let stroke = if selected {
                    egui::Stroke::new(1.0_f32, BLUE)
                } else {
                    ui.visuals().widgets.noninteractive.bg_stroke
                };
                if ui
                    .add(
                        egui::Button::new(RichText::new(tr(title)).color(color))
                            .selected(selected)
                            .stroke(stroke)
                            .min_size(Vec2::new(152.0, 38.0)),
                    )
                    .clicked()
                {
                    self.setup.automatic = automatic;
                }
            }
        });
        ui.add_space(5.0);
        if self.setup.automatic {
            self.refresh_firmware(ctx, false);
            match self.firmware.as_ref().map(|firmware| &firmware.release) {
                None => {
                    ui.strong(tr("No firmware selected"));
                    caption(
                        ui,
                        if self.devices.is_empty() {
                            "Connect a Mac to find compatible firmware"
                        } else {
                            "Select a Mac to find compatible firmware"
                        },
                    );
                }
                Some(None) => {
                    ui.strong(tr("Finding firmware…"));
                    caption(ui, "Checking the Apple catalog for the selected Mac");
                }
                Some(Some(Ok(release))) => {
                    ui.strong(trf(
                        "Version {}, build {}",
                        &[&release.version, &release.build],
                    ));
                    caption(ui, &release.product_type);
                }
                Some(Some(Err(error))) => {
                    ui.strong(tr("Could not find compatible firmware"))
                        .on_hover_text(tr(error));
                    caption(ui, "Check your internet connection and try again");
                }
            }
        } else {
            let path = Path::new(self.setup.ipsw.trim());
            let name = path
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_else(|| tr("Drop an IPSW file here"));
            ui.add(egui::Label::new(RichText::new(name).strong()).truncate())
                .on_hover_text(&self.setup.ipsw);
            let detail = path
                .metadata()
                .ok()
                .map(|m| human_bytes(m.len()))
                .unwrap_or_else(|| "Apple firmware file".into());
            caption(ui, detail);
        }
        ui.add_space(5.0);
        ui.allocate_ui_with_layout(
            Vec2::new(ui.available_width(), 34.0),
            egui::Layout::right_to_left(egui::Align::Center).with_main_wrap(true),
            |ui| {
                if self.setup.automatic {
                    if ui
                        .add_enabled(self.target().is_some(), egui::Button::new(tr("Download")))
                        .clicked()
                    {
                        self.start(Action::Download, ctx);
                    }
                } else {
                    if ui
                        .add_enabled(!self.picking, egui::Button::new(tr("Choose file")))
                        .clicked()
                    {
                        self.pick(Picker::Firmware, ctx);
                    }
                    if self.setup.local_file().is_ok() && ui.button(tr("Verify")).clicked() {
                        self.start(Action::Verify, ctx);
                    }
                }
                if ui
                    .button(tr("Open folder"))
                    .on_hover_text(tr("Downloaded firmware folder"))
                    .clicked()
                    && let Err(error) = self.open_firmware_folder()
                {
                    self.error("Could not open the firmware folder", format!("{error:#}"));
                }
                if self.setup.automatic
                    && let Some(release) = self
                        .firmware
                        .as_ref()
                        .and_then(|firmware| firmware.release.as_ref())
                    && ui
                        .button(tr(if release.is_err() { "Retry" } else { "Refresh" }))
                        .clicked()
                {
                    self.refresh_firmware(ctx, true);
                }
            },
        );
        frame
    }
    pub(super) fn actions(&mut self, ui: &mut egui::Ui) {
        card(ui.ctx()).show(ui, |ui| {
            section(ui, "03", "Action");
            let ready = self.blocked_reason().is_none() && !self.picking;
            let column_count = if ui.available_width() < 640.0 { 1 } else { 2 };
            ui.columns(column_count, |columns| {
                for (index, (action, title, detail, button)) in [
                    (
                        Action::Revive,
                        "Revive",
                        "Update firmware and recoveryOS",
                        "Start Revive",
                    ),
                    (
                        Action::Restore,
                        "Full restore",
                        "Erase the Mac and reinstall the system",
                        "Erase and restore",
                    ),
                ]
                .into_iter()
                .enumerate()
                {
                    let ui = &mut columns[index % column_count];
                    if column_count == 1 && index > 0 {
                        ui.add_space(14.0);
                    }
                    ui.label(RichText::new(tr(title)).size(18.0).strong());
                    caption(ui, detail);
                    ui.add_space(7.0);
                    let button = if action == Action::Revive {
                        egui::Button::new(RichText::new(tr(button)).color(Color32::WHITE))
                            .fill(BLUE)
                    } else {
                        egui::Button::new(
                            RichText::new(tr(button)).color(ui.visuals().error_fg_color),
                        )
                    };
                    if ui
                        .add_enabled(
                            ready,
                            button.min_size(Vec2::new(ui.available_width(), 42.0)),
                        )
                        .clicked()
                        && let Some(target) = self.target()
                    {
                        self.confirmation = Some(Confirmation {
                            action,
                            ecid: target.ecid,
                            accepted: false,
                        });
                    }
                }
            });
            if let Some(reason) = self.blocked_reason()
                && reason != "Connect a Mac in DFU mode"
            {
                ui.add_space(5.0);
                caption(ui, reason);
            }
        });
    }
    pub(super) fn active_job(&mut self, ui: &mut egui::Ui) {
        card(ui.ctx()).show(ui, |ui| {
            ui.set_width(ui.available_width());
            let Some(job) = self.job.as_ref() else { return };
            ui.horizontal_wrapped(|ui| {
                pill(ui, "In progress", BLUE);
                ui.label(RichText::new(tr(job.action.title())).size(21.0).strong());
            });
            ui.add_space(12.0);
            ui.label(
                RichText::new(
                    job.phase
                        .strip_prefix("Stage: ")
                        .map_or_else(|| tr(&job.phase), |stage| trf("Stage: {}", &[stage])),
                )
                .size(16.0),
            );
            if job.action.writes_device() {
                progress_bar(ui, job.overall_fraction);
            } else if job.transfers.is_empty() {
                progress_bar(ui, None);
            }
            ui.add_space(14.0);
            metric(
                ui,
                "Elapsed",
                &elapsed_text(job.started.elapsed().as_secs()),
            );
            ui.add_space(14.0);
            let idle = job.last_activity.elapsed();
            if !job.can_stop() && !job.action.writes_device() {
                ui.label(tr(
                    "Wait for driver installation and the Windows service check to finish.",
                ));
            } else if job.can_stop()
                && ui
                    .add_enabled(!job.cancelled, egui::Button::new(tr("Stop")))
                    .clicked()
                && let Some(job) = &mut self.job
                && let Err(e) = job.stop()
            {
                self.error("Could not stop the operation", e);
            }
            if idle > Duration::from_secs(5) {
                caption(
                    ui,
                    trf(
                        "Waiting for a response, {}",
                        &[&elapsed_text(idle.as_secs())],
                    ),
                );
            }
        });
        let Some(job) = &self.job else { return };
        let now = Instant::now();
        for (id, transfer) in &job.transfers {
            ui.add_space(12.0);
            ui.push_id(id, |ui| {
                card(ui.ctx()).show(ui, |ui| {
                    ui.set_width(ui.available_width());
                    ui.label(
                        RichText::new(super::widgets::transfer_stage(&transfer.update.stage))
                            .size(16.0)
                            .strong(),
                    );
                    progress_bar(ui, transfer.update.fraction());
                    let size = format!(
                        "{}{}",
                        human_bytes(transfer.update.completed),
                        transfer
                            .update
                            .total
                            .map(|total| trf(" of {}", &[&human_bytes(total)]))
                            .unwrap_or_default()
                    );
                    caption(ui, trf("Transferred: {size}", &[&size]));
                    ui.add_space(8.0);
                    ui.columns(2, |columns| {
                        metric(
                            &mut columns[0],
                            "Speed",
                            &trf(
                                "{:.1} MiB/s",
                                &[&format!("{:.1}", transfer.speed(now) / 1048576.0)],
                            ),
                        );
                        let remaining = transfer
                            .remaining(now)
                            .map(elapsed_text)
                            .unwrap_or_else(|| "—".into());
                        metric(&mut columns[1], "Time remaining", &remaining);
                    });
                });
            });
        }
    }
    pub(super) fn windows_card(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        let host = match &self.host {
            Ok(Some(host)) => host,
            Ok(None) => return,
            Err(error) => {
                let retry = card(ui.ctx())
                    .show(ui, |ui| {
                        ui.label(
                            RichText::new(tr("Could not check Windows"))
                                .strong()
                                .color(ui.visuals().error_fg_color),
                        );
                        ui.label(tr(error));
                        ui.button(tr("Check again")).clicked()
                    })
                    .inner;
                if retry {
                    self.detect(ctx);
                }
                ui.add_space(12.0);
                return;
            }
        };
        if !host.needs_preparation() && !host.apple_service_installed {
            return;
        }
        let mut prepare = false;
        let mut open_apps = false;
        card(ui.ctx()).show(ui, |ui| {
            ui.strong(tr("Windows setup"));
            if host.apple_service_running {
                ui.label(
                    RichText::new(tr("Apple Mobile Device Service is running and may interfere with the Mac connection."))
                        .color(ui.visuals().error_fg_color),
                );
                ui.label(tr("The button below stops the service. If it starts again, uninstall Apple Mobile Device Support in Windows apps."));
            } else if host.apple_service_installed {
                ui.label(
                    RichText::new(tr("Apple Mobile Device Service is stopped."))
                        .color(Tone::Success.color(ui.visuals())),
                );
            }
            if !host.apple_driver_installed {
                ui.label(tr("The Apple USB driver is missing. Install the signed driver bundled with Zalivka; internet access and iTunes are not required."));
            }
            if host.needs_preparation() {
                ui.add_space(6.0);
                let label = if !host.apple_driver_installed {
                    "Install missing drivers"
                } else if host.apple_service_running {
                    "Stop Apple service"
                } else {
                    "Check drivers again"
                };
                prepare = ui.button(tr(label)).clicked();
                caption(ui, "Windows will request administrator access.");
            }
            if host.apple_service_installed {
                open_apps = ui.link(tr("Open Windows apps to uninstall")).clicked();
            }
        });
        if prepare {
            self.start(Action::PrepareWindows, ctx);
        }
        if open_apps && let Err(error) = drivers::open_installed_apps() {
            self.error("Could not open Windows apps", format!("{error:#}"));
        }
        ui.add_space(12.0);
    }
}
