//! Descriptor selection shared by USB transport and diagnostics.
use super::MUX_INTERFACE;
use anyhow::{Context, Result};
use nusb::descriptors::{
    ConfigurationDescriptor, EndpointDescriptor, InterfaceDescriptor, TransferType,
};

fn bulk_endpoint<'a>(
    interface: &InterfaceDescriptor<'a>,
    input: bool,
) -> Option<EndpointDescriptor<'a>> {
    interface.endpoints().find(|endpoint| {
        endpoint.transfer_type() == TransferType::Bulk
            && endpoint.address() & 0x0f != 0
            && endpoint.address() & 0x70 == 0
            && (endpoint.address() & 0x80 != 0) == input
            && endpoint.max_packet_size() != 0
    })
}

pub(crate) fn recovery_interface(config: ConfigurationDescriptor<'_>) -> Result<(u8, u8)> {
    config
        .interface_alt_settings()
        .filter(|interface| {
            interface.endpoints().any(|endpoint| {
                endpoint.address() == 0x04
                    && endpoint.transfer_type() == TransferType::Bulk
                    && endpoint.max_packet_size() != 0
            })
        })
        .map(|interface| (interface.interface_number(), interface.alternate_setting()))
        .last()
        .context("no Apple recovery bulk OUT endpoint 0x04")
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct MuxInterface {
    pub configuration: u8,
    pub number: u8,
    pub alternate: u8,
    pub output: u8,
    pub input: u8,
    pub packet_size: usize,
}

fn select_mux_interface<'a>(
    configurations: impl Iterator<Item = ConfigurationDescriptor<'a>>,
    active: Option<u8>,
) -> Option<MuxInterface> {
    let mut fallback = None;
    for configuration in configurations {
        for interface in configuration.interface_alt_settings() {
            if (
                interface.class(),
                interface.subclass(),
                interface.protocol(),
            ) != MUX_INTERFACE
            {
                continue;
            }
            let (Some(output), Some(input)) = (
                bulk_endpoint(&interface, false),
                bulk_endpoint(&interface, true),
            ) else {
                continue;
            };
            let selected = MuxInterface {
                configuration: configuration.configuration_value(),
                number: interface.interface_number(),
                alternate: interface.alternate_setting(),
                output: output.address(),
                input: input.address(),
                packet_size: output.max_packet_size(),
            };
            // WinUSB cannot change configurations. Prefer the one selected by the OS.
            if Some(selected.configuration) == active {
                return Some(selected);
            }
            fallback.get_or_insert(selected);
        }
    }
    fallback
}

pub(crate) fn mux_interface(device: &nusb::Device) -> Result<MuxInterface> {
    select_mux_interface(
        device.configurations(),
        device
            .active_configuration()
            .ok()
            .map(|c| c.configuration_value()),
    )
    .context("no Apple USB multiplex interface")
}

#[cfg(test)]
#[path = "../../tests/unit/usb.rs"]
mod tests;
