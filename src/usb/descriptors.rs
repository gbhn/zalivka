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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct NcmInterface {
    pub control: u8,
    pub data: u8,
    pub alternate: u8,
    pub input: u8,
    pub output: u8,
    pub packet_size: usize,
}

pub(crate) fn ncm_interface(config: ConfigurationDescriptor<'_>) -> Result<NcmInterface> {
    for control in config
        .interface_alt_settings()
        .filter(|i| i.class() == 2 && i.subclass() == 0x0d && i.alternate_setting() == 0)
    {
        let data_number = control
            .descriptors()
            .filter(|descriptor| {
                descriptor.len() >= 5
                    && descriptor.descriptor_type() == 0x24
                    && descriptor[2] == 6 // CDC Union functional descriptor.
                    && descriptor[3] == control.interface_number()
            })
            .map(|descriptor| descriptor[4])
            .last();
        let Some(number) = data_number.filter(|number| *number != control.interface_number())
        else {
            continue;
        };
        for data in config.interface_alt_settings().filter(|i| {
            i.interface_number() == number && i.class() == 0x0a && i.endpoints().count() == 2
        }) {
            let (Some(input), Some(output)) =
                (bulk_endpoint(&data, true), bulk_endpoint(&data, false))
            else {
                continue;
            };
            return Ok(NcmInterface {
                control: control.interface_number(),
                data: number,
                alternate: data.alternate_setting(),
                input: input.address(),
                output: output.address(),
                packet_size: output.max_packet_size(),
            });
        }
    }
    anyhow::bail!("Mac does not expose a usable CDC-NCM interface")
}

#[cfg(test)]
#[path = "../../tests/unit/usb.rs"]
mod tests;

#[cfg(test)]
#[path = "../../tests/unit/usb/ncm.rs"]
mod ncm_tests;
