use super::assets::*;
use super::download::{download_from, firmware_request, retryable_download};
use super::request::*;
use super::*;
use crate::{
    test_net::{accept, read_header},
    wire,
};
use plist::Value;
use sha2::{Digest, Sha256};
use std::io::{Read, Write};
use std::path::Path;
use std::{net::TcpListener, thread};

// Local fixtures must not depend on the developer's Windows/PAC/env policy.
fn send_http(agent: &ureq::Agent, request: &Request<Vec<u8>>) -> Result<Response<ureq::Body>> {
    send_http_via(agent, request, None)
}

mod assets;
mod download;
mod request;
mod transport;
