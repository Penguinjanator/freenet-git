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

/// Parse one of the freenet URL shapes into the underlying contract
/// instance id.
///
/// Accepted shapes:
///
/// | Form              | Where it appears                                   |
/// |-------------------|----------------------------------------------------|
/// | `freenet:<id>`    | user-facing URL we display                         |
/// | `freenet::<id>`   | form passed to `git remote add` / `git clone`      |
/// | `<id>`            | what `git` actually hands the remote helper after  |
/// |                   | stripping the `freenet::` prefix                   |
///
/// The remote helper invocation form is the load-bearing reason we
/// accept the bare-id form — git's remote helper protocol strips the
/// scheme before exec'ing the helper.
pub fn parse(url: &str) -> Result<ContractInstanceId, UrlError> {
    let body = url
        .strip_prefix("freenet::")
        .or_else(|| url.strip_prefix("freenet:"))
        .unwrap_or(url);
    ContractInstanceId::from_bytes(body).map_err(|e| UrlError::BadId(e.to_string()))
}

/// Format a contract instance id as the short `freenet:<id>` URL (used
/// for display).
pub fn format(id: &ContractInstanceId) -> String {
    format!("freenet:{}", id.encode())
}

/// Format a contract instance id as the `freenet::<id>` URL git wants
/// for `git remote add` and `git clone`.
pub fn format_git_url(id: &ContractInstanceId) -> String {
    format!("freenet::{}", id.encode())
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
    fn accepts_double_colon_and_bare_forms() {
        let id = ContractInstanceId::new([0x55; 32]);
        let bare = id.encode();
        assert_eq!(parse(&format!("freenet::{bare}")).unwrap(), id);
        assert_eq!(parse(&bare).unwrap(), id);
    }

    #[test]
    fn rejects_garbage() {
        assert!(parse("https://github.com/").is_err());
        assert!(parse("not-a-base58-id").is_err());
    }
}
