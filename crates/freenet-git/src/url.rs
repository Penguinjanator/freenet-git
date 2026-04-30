//! Parsing and formatting of `freenet:` URLs.
//!
//! A repo URL looks like `freenet:<base58-contract-id>`. Anything before the
//! `:` is the scheme; anything after is the bytes of the [`ContractInstanceId`]
//! encoded in Bitcoin-alphabet base58 (matching `freenet-stdlib`).
//!
//! [`ContractInstanceId`]: freenet_stdlib::prelude::ContractInstanceId

use freenet_stdlib::prelude::ContractInstanceId;

/// Errors when parsing a `freenet:` URL.
#[derive(Debug, thiserror::Error)]
pub enum UrlError {
    /// URL did not start with `freenet:`.
    #[error("not a freenet URL (expected `freenet:<contract-id>`)")]
    BadScheme,
    /// Body did not decode as a base58 contract id.
    #[error("invalid contract id in URL: {0}")]
    BadId(String),
}

/// Parse a `freenet:<id>` URL into the underlying contract instance id.
pub fn parse(url: &str) -> Result<ContractInstanceId, UrlError> {
    let body = url.strip_prefix("freenet:").ok_or(UrlError::BadScheme)?;
    ContractInstanceId::from_bytes(body).map_err(|e| UrlError::BadId(e.to_string()))
}

/// Format a contract instance id as a `freenet:` URL.
pub fn format(id: &ContractInstanceId) -> String {
    format!("freenet:{}", id.encode())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let id = ContractInstanceId::new([0x42; 32]);
        let url = format(&id);
        assert!(url.starts_with("freenet:"));
        let back = parse(&url).unwrap();
        assert_eq!(back, id);
    }

    #[test]
    fn rejects_other_schemes() {
        assert!(parse("https://github.com/").is_err());
        assert!(parse("freenet").is_err());
    }
}
