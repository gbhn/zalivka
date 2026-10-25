//! AEA prefix classification, public FCS keys and restored key exchanges.
use super::data_type::DataType;
use crate::{
    mux::{MuxStream, Session},
    net, wire,
};
use anyhow::{Context, Result, ensure};
use plist::Value;
use std::time::Duration;

pub(super) enum ImagePrefix {
    Collecting(Vec<u8>),
    Plain,
    Aea,
    Public {
        fcs: Box<crate::aea::PublicFcs>,
        key: Option<[u8; 32]>,
    },
}

impl ImagePrefix {
    /// Return true once the prefix is classified and its buffer can be released.
    pub(super) fn observe(&mut self, data: &[u8]) -> Result<bool> {
        let Self::Collecting(prefix) = self else {
            return Ok(false);
        };
        let remaining = crate::aea::MAX_PREFIX - prefix.len();
        prefix.extend_from_slice(&data[..data.len().min(remaining)]);
        if prefix.len() < 4 {
            return Ok(false);
        }
        *self = if !prefix.starts_with(b"AEA1") {
            Self::Plain
        } else {
            match crate::aea::PublicFcs::from_prefix(prefix)? {
                crate::aea::Prefix::Incomplete => return Ok(false),
                crate::aea::Prefix::Unsupported => Self::Aea,
                crate::aea::Prefix::Public(fcs) => Self::Public { fcs, key: None },
            }
        };
        Ok(true)
    }

    pub(super) fn is_aea(&self) -> bool {
        match self {
            Self::Collecting(prefix) => prefix.starts_with(b"AEA1"),
            Self::Plain => false,
            Self::Aea | Self::Public { .. } => true,
        }
    }

    pub(super) fn response(&mut self, request: &Value, assets: &net::AssetClient) -> Result<Value> {
        if let Self::Public { fcs, key } = self
            && net::wrapped_key_request(request)?
        {
            let archive_key = if let Some(key) = *key {
                key
            } else {
                match fcs.fetch_key() {
                    Ok(found) => {
                        *key = Some(found);
                        found
                    }
                    Err(error) => {
                        return assets.response(request).with_context(|| {
                            format!("public FCS failed ({error:#}); WKMS fallback failed")
                        });
                    }
                }
            };
            return Ok(wire::dict([
                ("KeyData", Value::Data(archive_key.to_vec())),
                ("KeySource", "LocalUnwrapped".into()),
            ]));
        }
        assets.response(request)
    }
}

pub(super) fn key_exchange(
    stream: &mut MuxStream,
    session: &Session,
    key_requests: &mut usize,
    mut reply: impl FnMut(&Value) -> Result<Value>,
) -> Result<()> {
    while let Some(request) = wire::try_receive(stream)? {
        *key_requests += 1;
        ensure!(*key_requests <= 64, "too many AEA key requests");
        let name = wire::data_type(&request)?;
        let data_type =
            DataType::parse(name).with_context(|| format!("unexpected AEA data type {name}"))?;
        ensure!(
            data_type == DataType::Asset,
            "unexpected AEA data type {name}"
        );
        let asynchronous =
            wire::string(&request, &["MsgType"]).is_ok_and(|kind| kind == "AsyncDataRequestMsg");
        let port = data_type.data_port(&request, asynchronous)?;
        crate::log!(Debug, "aea", "Запрос ключа AEA: {name}, DataPort={port}");
        let response = reply(&request)?;
        if port != 0 {
            let mut service = session.connect_retry(port, Duration::from_secs(60))?;
            wire::send_binary(&mut service, &response)?;
        } else {
            wire::send_binary(stream, &response)?;
        }
        if !stream.has_pending_input()? {
            break;
        }
    }
    Ok(())
}
