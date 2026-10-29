mod assets;
mod download;
mod request;
pub use assets::AssetClient;
pub(crate) use assets::wrapped_key_request;
pub use download::{download, download_verified, verify_file};

use anyhow::{Context, Result, ensure};
use std::{sync::Arc, time::Duration};
use ureq::http::{Method, Request, Response, StatusCode, Uri};

pub fn agent() -> ureq::Agent {
    agent_with_body_timeout(Some(Duration::from_secs(120)))
}

pub(crate) fn public_roots() -> ureq::tls::RootCerts {
    #[cfg(windows)]
    {
        ureq::tls::RootCerts::PlatformVerifier
    }
    #[cfg(not(windows))]
    {
        ureq::tls::RootCerts::WebPki
    }
}

/// gs.apple.com uses Apple's private PKI, absent from Mozilla's public roots.
/// Keep this additional trust anchor scoped to TSS; Windows trust applies too.
pub(crate) fn tss_agent() -> ureq::Agent {
    let root =
        ureq::tls::Certificate::from_der(include_bytes!("../certs/AppleIncRootCertificate.cer"));
    let config = agent_config(
        Some(Duration::from_secs(120)),
        ureq::tls::RootCerts::new_with_certs(&[root]),
    );
    let proxy_config = ureq::Agent::config_builder()
        .tls_config(tls_config(public_roots()))
        .proxy(None)
        .build();
    #[cfg(windows)]
    let connector = crate::proxy::HttpConnector::for_tss(proxy_config);
    #[cfg(not(windows))]
    let connector = crate::proxy::HttpConnector::new(proxy_config);
    configured_agent(config, connector)
}

pub(crate) fn tls_config(roots: ureq::tls::RootCerts) -> ureq::tls::TlsConfig {
    ureq::tls::TlsConfig::builder()
        .root_certs(roots)
        .unversioned_rustls_crypto_provider(Arc::new(oxitls_rustcrypto_provider::provider()))
        .build()
}

fn agent_with_body_timeout(body_timeout: Option<Duration>) -> ureq::Agent {
    let config = agent_config(body_timeout, public_roots());
    let connector = crate::proxy::HttpConnector::new(config.clone());
    configured_agent(config, connector)
}

fn configured_agent(
    config: ureq::config::Config,
    connector: crate::proxy::HttpConnector,
) -> ureq::Agent {
    let agent = ureq::Agent::with_parts(
        config,
        connector,
        ureq::unversioned::resolver::DefaultResolver::default(),
    );
    let cancellation = agent.clone();
    crate::progress::on_cancel(move || cancellation.shutdown());
    agent
}

fn agent_config(
    body_timeout: Option<Duration>,
    roots: ureq::tls::RootCerts,
) -> ureq::config::Config {
    ureq::Agent::config_builder()
        .proxy(None)
        .tls_config(tls_config(roots))
        .timeout_connect(Some(Duration::from_secs(30)))
        .timeout_recv_response(Some(Duration::from_secs(120)))
        .timeout_recv_body(body_timeout)
        .timeout_per_read(Some(Duration::from_secs(120)))
        .timeout_per_write(Some(Duration::from_secs(120)))
        .max_redirects(0)
        .user_agent(concat!("zalivka/", env!("CARGO_PKG_VERSION")))
        .build()
}

/// Limit firmware/asset downloads to Apple's public HTTPS distribution hosts.
pub fn validate_apple_url(url: &str) -> Result<()> {
    apple_url(url).map(|_| ())
}

pub(crate) fn is_apple_host(host: &str) -> bool {
    host.len() <= 253
        && host.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
        && (host == "apple.com" || host.ends_with(".apple.com") || host.ends_with(".cdn-apple.com"))
}

/// Return the validated URI so callers can use it without parsing again.
pub(crate) fn apple_url(url: &str) -> Result<Uri> {
    ensure!(!url.contains('#'), "Apple URL contains a fragment");
    let uri: Uri = url.parse().context("invalid URL")?;
    validate_apple_uri(&uri)?;
    Ok(uri)
}

pub(crate) fn validate_apple_uri(uri: &Uri) -> Result<()> {
    ensure!(
        uri.scheme_str() == Some("https"),
        "only HTTPS Apple URLs are accepted"
    );
    let host = uri.host().context("URL has no host")?.to_ascii_lowercase();
    ensure!(
        is_apple_host(&host),
        "URL host is not an Apple distribution host: {host}"
    );
    ensure!(
        !uri.authority().is_some_and(|a| a.as_str().contains('@')),
        "URL credentials are not allowed"
    );
    ensure!(
        uri.authority().is_some_and(|a| {
            a.as_str().eq_ignore_ascii_case(&host)
                || a.as_str().eq_ignore_ascii_case(&format!("{host}:443"))
        }),
        "only HTTPS port 443 is accepted"
    );
    Ok(())
}

pub fn get(url: &str) -> Result<ureq::http::Response<ureq::Body>> {
    let response = fetch(Request::get(url).body(Vec::new())?, &agent())?;
    ensure!(
        response.status().is_success(),
        "Apple HTTPS request returned {}",
        response.status()
    );
    Ok(response)
}

fn fetch(mut request: Request<Vec<u8>>, agent: &ureq::Agent) -> Result<Response<ureq::Body>> {
    for redirects in 0..=5 {
        validate_apple_uri(request.uri())?;
        let response = send_http(agent, &request)?;
        if !matches!(response.status().as_u16(), 301 | 302 | 303 | 307 | 308) {
            return Ok(response);
        }
        ensure!(redirects < 5, "too many Apple HTTP redirects");
        let location = response
            .headers()
            .get("location")
            .context("redirect without Location")?
            .to_str()?;
        redirect_request(&mut request, response.status(), location)?;
    }
    unreachable!()
}

pub(crate) fn send_http(
    agent: &ureq::Agent,
    request: &Request<Vec<u8>>,
) -> Result<Response<ureq::Body>> {
    send_http_via(agent, request, crate::proxy::for_url(request.uri())?)
}

fn send_http_via(
    agent: &ureq::Agent,
    request: &Request<Vec<u8>>,
    proxy: Option<ureq::Proxy>,
) -> Result<Response<ureq::Body>> {
    crate::log!(
        Trace,
        "http",
        "{} {}; body={} B",
        request.method(),
        request.uri(),
        request.body().len()
    );
    let request = agent
        .configure_request(request.clone())
        .proxy(proxy)
        .http_status_as_error(false)
        .build();
    let response = if request.method() == Method::GET {
        agent.run(request.map(|_| ()))
    } else {
        agent.run(request)
    };
    let response = response.context("Apple HTTPS request failed")?;
    crate::log!(
        Trace,
        "http",
        "HTTP {}; headers={:?}",
        response.status(),
        response.headers()
    );
    Ok(response)
}

fn redirect_request(
    request: &mut Request<Vec<u8>>,
    status: StatusCode,
    location: &str,
) -> Result<()> {
    let next = redirect_url(&request.uri().to_string(), location)?;
    crate::log!(
        Trace,
        "http",
        "Redirect {status}: {} -> {next}",
        request.uri()
    );
    let same_origin = next
        .host()
        .zip(request.uri().host())
        .is_some_and(|(next, current)| next.eq_ignore_ascii_case(current))
        && next.port_u16().unwrap_or(443) == request.uri().port_u16().unwrap_or(443);
    if !same_origin {
        for name in ["authorization", "cookie", "proxy-authorization"] {
            request.headers_mut().remove(name);
        }
    }
    if status == StatusCode::SEE_OTHER
        || (request.method() == Method::POST && matches!(status.as_u16(), 301 | 302))
    {
        *request.method_mut() = Method::GET;
        request.body_mut().clear();
        for name in [
            "content-type",
            "content-length",
            "content-encoding",
            "transfer-encoding",
            "trailer",
            "expect",
        ] {
            request.headers_mut().remove(name);
        }
    }
    *request.uri_mut() = next;
    Ok(())
}

/// Resolve the Location forms used by HTTP redirects without decoding escaped
/// path segments. Validate every destination before a second request is made.
fn redirect_url(base: &str, location: &str) -> Result<Uri> {
    apple_url(base)?;
    let base = oxiri::Iri::parse(base).context("invalid redirect base URI")?;
    let reference = oxiri::IriRef::parse(location.split('#').next().unwrap_or(""))
        .context("invalid redirect Location")?;
    let resolved = base
        .resolve(&reference)
        .context("resolving redirect Location")?;
    apple_url(resolved.as_str())
}

#[cfg(test)]
#[path = "../tests/unit/net/mod.rs"]
mod tests;
