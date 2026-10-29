//! GSSAPI uses the current user's Kerberos cache / platform SSO credentials.
use anyhow::{Context, Result, ensure};
use base64::{Engine, prelude::BASE64_STANDARD};
use libgssapi::{
    context::{ClientCtx, CtxFlags, SecurityContext},
    name::Name,
    oid::{GSS_MECH_SPNEGO, GSS_NT_HOSTBASED_SERVICE, Oid},
};

pub(super) struct Negotiate {
    context: ClientCtx,
}

impl Negotiate {
    pub(super) fn new(scheme: &str, proxy_host: &str) -> Result<Self> {
        ensure!(
            matches!(scheme, "Negotiate" | "NTLM"),
            "unsupported GSSAPI proxy scheme"
        );
        let target = Name::new(
            format!("HTTP@{proxy_host}").as_bytes(),
            Some(GSS_NT_HOSTBASED_SERVICE),
        )
        .context("creating GSSAPI proxy service name")?;
        let mechanism = if scheme == "NTLM" {
            // GSS-NTLMSSP, if installed, provides the standard NTLM mechanism.
            Oid::from_slice(b"\x2b\x06\x01\x04\x01\x82\x37\x02\x02\x0a")
        } else {
            GSS_MECH_SPNEGO
        };
        crate::log!(
            Debug,
            "proxy:auth",
            "GSSAPI {scheme}; service=HTTP/{proxy_host}; default user credentials"
        );
        Ok(Self {
            context: ClientCtx::new(None, target, CtxFlags::GSS_C_MUTUAL_FLAG, Some(mechanism)),
        })
    }

    pub(super) fn step(&mut self, challenge: Option<&str>) -> Result<String> {
        let token = challenge
            .map(|value| BASE64_STANDARD.decode(value))
            .transpose()
            .context("invalid proxy authentication token encoding")?;
        ensure!(
            token.as_ref().map_or(0, Vec::len) <= 65536,
            "proxy authentication token exceeds 64 KiB"
        );
        let output = self.context.step(token.as_deref(), None)
            .context("GSSAPI proxy authentication failed; check the current user's Kerberos ticket / SSO credentials and proxy service principal")?;
        let output = output.as_deref().unwrap_or_default();
        ensure!(output.len() <= 65536, "GSSAPI output token exceeds 64 KiB");
        Ok(BASE64_STANDARD.encode(output))
    }

    pub(super) fn finish(&self) -> Result<()> {
        ensure!(
            self.context.is_complete(),
            "proxy accepted CONNECT before GSSAPI mutual authentication completed"
        );
        Ok(())
    }
}

#[cfg(test)]
#[path = "../../tests/unit/proxy/kerberos.rs"]
mod tests;
