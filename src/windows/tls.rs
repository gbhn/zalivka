//! Native Windows chain validation, including user and enterprise trust roots.
use anyhow::Result;
use rustls::{
    ClientConfig, ClientConnection, StreamOwned,
    client::danger::ServerCertVerifier,
    pki_types::{CertificateDer, ServerName},
};
use std::{
    fmt,
    io::{Read, Write},
    sync::Arc,
};
use ureq::unversioned::transport::{
    Buffers, ConnectionDetails, LazyBuffers, NextTimeout, Transport, TransportAdapter,
};

fn verifier(extra: Option<CertificateDer<'static>>) -> Result<Arc<dyn ServerCertVerifier>> {
    let provider = Arc::new(oxitls_rustcrypto_provider::provider());
    Ok(Arc::new(if let Some(root) = extra {
        rustls_platform_verifier::Verifier::new_with_extra_roots([root], provider)?
    } else {
        rustls_platform_verifier::Verifier::new(provider)?
    }))
}

pub(crate) fn config(extra: Option<CertificateDer<'static>>) -> Result<Arc<ClientConfig>> {
    let provider = Arc::new(oxitls_rustcrypto_provider::provider());
    Ok(Arc::new(
        ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()?
            // This supplies the Windows verifier, not a verification bypass.
            .dangerous()
            .with_custom_certificate_verifier(verifier(extra)?)
            .with_no_client_auth(),
    ))
}

/// TSS also needs Apple's private root, which is not in the public OS store.
/// Keep that additional trust anchor out of CDN and HTTPS proxy connections.
pub(crate) fn connect_tss(
    details: &ConnectionDetails,
    transport: Box<dyn Transport>,
) -> Result<Box<dyn Transport>, ureq::Error> {
    let config = config(Some(CertificateDer::from(
        include_bytes!("../../certs/AppleIncRootCertificate.cer").as_slice(),
    )))
    .map_err(|error| ureq::Error::Other(error.into()))?;
    crate::log!(
        Debug,
        "tls",
        "TSS: проверка цепочки сертификатов Windows с дополнительным корнем Apple; проверка имени сервера включена"
    );
    connect_with_config(details, transport, config)
}

fn connect_with_config(
    details: &ConnectionDetails,
    transport: Box<dyn Transport>,
    config: Arc<ClientConfig>,
) -> Result<Box<dyn Transport>, ureq::Error> {
    let host = details.uri.host().ok_or(ureq::Error::ConnectionFailed)?;
    let name = ServerName::try_from(host.to_owned())
        .map_err(|_| ureq::Error::Tls("invalid TSS hostname"))?;
    let mut connection = ClientConnection::new(config, name)?;
    let mut socket = TransportAdapter::new(transport);
    socket.set_timeout(details.timeout);
    connection.complete_io(&mut socket)?;
    Ok(Box::new(WindowsTls {
        stream: StreamOwned::new(connection, socket),
        buffers: LazyBuffers::new(
            details.config.input_buffer_size(),
            details.config.output_buffer_size(),
        ),
    }))
}

struct WindowsTls {
    stream: StreamOwned<ClientConnection, TransportAdapter>,
    buffers: LazyBuffers,
}
impl fmt::Debug for WindowsTls {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WindowsTls").finish_non_exhaustive()
    }
}
impl Transport for WindowsTls {
    fn buffers(&mut self) -> &mut dyn Buffers {
        &mut self.buffers
    }
    fn transmit_output(&mut self, amount: usize, timeout: NextTimeout) -> Result<(), ureq::Error> {
        self.stream.sock.set_timeout(timeout);
        self.stream.write_all(&self.buffers.output()[..amount])?;
        self.stream.flush()?;
        Ok(())
    }
    fn await_input(&mut self, timeout: NextTimeout) -> Result<bool, ureq::Error> {
        self.stream.sock.set_timeout(timeout);
        let amount = self.stream.read(self.buffers.input_append_buf())?;
        self.buffers.input_appended(amount);
        Ok(amount > 0)
    }
    fn is_open(&mut self) -> bool {
        self.stream.sock.get_mut().is_open()
    }
    fn is_tls(&self) -> bool {
        true
    }
}

#[cfg(test)]
#[path = "../../tests/unit/windows/tls.rs"]
mod tests;
