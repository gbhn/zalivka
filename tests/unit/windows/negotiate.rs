use super::*;

#[test]
fn sspi_uses_current_logon_credentials_without_an_explicit_identity_or_password() {
    for scheme in ["Negotiate", "NTLM"] {
        let mut auth = Negotiate::new(scheme, "localhost").unwrap();
        let token = auth.step(None).unwrap();
        assert!(!token.is_empty());
        let bytes = BASE64_STANDARD.decode(token).unwrap();
        assert!(!bytes.is_empty());
        assert!(auth.context.is_some());
    }
}

#[test]
fn sspi_rejects_unsupported_schemes_and_invalid_challenge_encoding() {
    assert!(Negotiate::new("Basic", "localhost").is_err());
    let mut auth = Negotiate::new("Negotiate", "localhost").unwrap();
    assert!(auth.step(Some("not-valid-base64")).is_err());
    assert!(auth.context.is_none());
}
