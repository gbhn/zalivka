use super::assets::*;
use super::download::{download_from, firmware_request, retryable_download};
use super::request::*;
use super::*;
use crate::wire;
use plist::Value;
use sha2::{Digest, Sha256};
use std::io::{Read, Write};
use std::path::Path;
use std::{net::TcpListener, thread};

// Local fixtures must not depend on the developer's Windows/PAC/env policy.
fn send_http(agent: &ureq::Agent, request: &Request<Vec<u8>>) -> Result<Response<ureq::Body>> {
    send_http_via(agent, request, None)
}

// Read only headers: binary payload already buffered by TCP must remain unread.
fn read_header(stream: &mut impl Read) -> String {
    let mut bytes = Vec::new();
    while !bytes.ends_with(b"\r\n\r\n") {
        let mut byte = [0];
        stream.read_exact(&mut byte).unwrap();
        bytes.push(byte[0]);
        assert!(bytes.len() < 65536);
    }
    String::from_utf8(bytes).unwrap()
}

mod assets;
mod download;
mod request;
mod transport;
