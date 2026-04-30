//! Parsing and formatting of `freenet:` URLs.
//!
//! A repo URL has two parts: a **prefix** (the canonical identifier) and
//! an optional **label** (a human-readable display name).
//!
//! ```text
//! freenet:<prefix>                              (display, no label)
//! freenet:<prefix>/<label>                      (display, with label)
//! freenet::<prefix>            ($ git remote add)
//! freenet::<prefix>/<label>    ($ git remote add)
//! ```
//!
//! ## What the prefix is
//!
//! The prefix is the first N (default 12) base58 characters of the
//! owner's ed25519 public key. The full contract key is then computed
//! as `BLAKE3(BLAKE3(repo-contract.wasm) || serialize({prefix}))`.
//! Anyone with the URL plus the bundled WASM can compute the contract
//! key — the prefix IS the URL.
//!
//! Why the prefix and not the full contract key:
//!
//! - The prefix is short (~12 chars vs 44 for the full key).
//! - The prefix is a **public-key fingerprint** — seeing
//!   `freenet:RtTzy58hMx...` tells you "this repo is signed by the key
//!   whose base58 fingerprint starts with `RtTzy58hMx...`."
//! - The prefix survives contract-WASM upgrades. The full contract key
//!   changes when the WASM hash changes (because it's
//!   `BLAKE3(WASM || prefix)`); the URL doesn't, because it's just the
//!   prefix. Migration is permissionless: any client with the new WASM
//!   computes the new contract key from the same URL.
//!
//! ## What the label is
//!
//! The label is a human-readable name (typically the repo's name) that
//! follows the prefix after a `/`. It is purely cosmetic:
//!
//! - Two URLs that differ only in their label resolve to the same repo.
//! - Git uses the label as the default clone directory name (since
//!   `git clone <url>` derives the directory from the last path
//!   component).
//! - The label is never sent to the network and never signed against.

use freenet_git_types::limits;

/// Errors when parsing a `freenet:` URL.
#[derive(Debug, thiserror::Error)]
pub enum UrlError {
    /// Prefix length is outside the valid range.
    #[error("prefix length {len} outside valid range [{min}..={max}]")]
    InvalidPrefixLength {
        /// Observed length.
        len: usize,
        /// Minimum allowed.
        min: usize,
        /// Maximum allowed.
        max: usize,
    },
    /// Prefix contains characters that are not in the Bitcoin base58
    /// alphabet.
    #[error("prefix contains invalid base58 characters")]
    InvalidPrefixChars,
    /// URL body was completely empty.
    #[error("empty URL")]
    Empty,
}

/// A parsed `freenet:` URL: the canonical prefix plus an optional
/// human-readable label.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedUrl {
    /// The owner-pubkey prefix. The only part that participates in
    /// identity, signatures, or network routing.
    pub prefix: String,
    /// Optional human-readable label (e.g. `"freenet-core"`). Display
    /// only. Never sent to the network.
    pub label: Option<String>,
}

/// Parse a freenet URL into a [`ParsedUrl`].
///
/// Accepts every shape the user or git might hand us:
///
/// | Input                            | What we get back                       |
/// |----------------------------------|----------------------------------------|
/// | `freenet:<prefix>`               | `ParsedUrl { prefix, label: None }`    |
/// | `freenet:<prefix>/<label>`       | `ParsedUrl { prefix, label: Some(.) }` |
/// | `freenet::<prefix>`              | same                                   |
/// | `freenet::<prefix>/<label>`      | same                                   |
/// | `<prefix>` (helper invocation)   | `ParsedUrl { prefix, label: None }`    |
/// | `<prefix>/<label>` (helper)      | `ParsedUrl { prefix, label: Some(.) }` |
pub fn parse(url: &str) -> Result<ParsedUrl, UrlError> {
    let body = url
        .strip_prefix("freenet::")
        .or_else(|| url.strip_prefix("freenet:"))
        .unwrap_or(url);
    if body.is_empty() {
        return Err(UrlError::Empty);
    }
    let (prefix, label) = match body.split_once('/') {
        None => (body, None),
        Some((p, rest)) => {
            let label = if rest.is_empty() {
                None
            } else {
                Some(rest.to_string())
            };
            (p, label)
        }
    };
    if prefix.len() < limits::MIN_PREFIX_LEN || prefix.len() > limits::MAX_PREFIX_LEN {
        return Err(UrlError::InvalidPrefixLength {
            len: prefix.len(),
            min: limits::MIN_PREFIX_LEN,
            max: limits::MAX_PREFIX_LEN,
        });
    }
    // Verify the prefix is valid base58 (catches typos, control chars, etc.)
    bs58::decode(prefix)
        .into_vec()
        .map_err(|_| UrlError::InvalidPrefixChars)?;
    Ok(ParsedUrl {
        prefix: prefix.to_string(),
        label,
    })
}

/// Convenience: parse and discard the label, returning just the prefix.
pub fn parse_prefix(url: &str) -> Result<String, UrlError> {
    parse(url).map(|p| p.prefix)
}

/// Format a prefix as the short display URL `freenet:<prefix>`.
pub fn format(prefix: &str) -> String {
    format!("freenet:{prefix}")
}

/// Format a prefix with an optional label as the short display URL.
pub fn format_with_label(prefix: &str, label: Option<&str>) -> String {
    match label {
        None => format!("freenet:{prefix}"),
        Some(l) => format!("freenet:{prefix}/{l}"),
    }
}

/// Format a prefix as the `freenet::<prefix>` URL git wants for
/// `git remote add` and `git clone`.
pub fn format_git_url(prefix: &str) -> String {
    format!("freenet::{prefix}")
}

/// Format a prefix with an optional label as the git URL. With a label,
/// `git clone` will use `<label>/` as the default directory.
pub fn format_git_url_with_label(prefix: &str, label: Option<&str>) -> String {
    match label {
        None => format!("freenet::{prefix}"),
        Some(l) => format!("freenet::{prefix}/{l}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_no_label() {
        let prefix = "abc1234567XX"; // 12 chars
        let url = format(prefix);
        let parsed = parse(&url).unwrap();
        assert_eq!(parsed.prefix, prefix);
        assert_eq!(parsed.label, None);
    }

    #[test]
    fn round_trip_with_label() {
        let prefix = "abc1234567XX";
        let url = format_with_label(prefix, Some("freenet-core"));
        let parsed = parse(&url).unwrap();
        assert_eq!(parsed.prefix, prefix);
        assert_eq!(parsed.label.as_deref(), Some("freenet-core"));
    }

    #[test]
    fn accepts_all_shapes() {
        let p = "abc1234567XX";
        assert_eq!(parse(&format!("freenet:{p}")).unwrap().prefix, p);
        assert_eq!(parse(&format!("freenet::{p}")).unwrap().prefix, p);
        assert_eq!(parse(p).unwrap().prefix, p);
        assert_eq!(
            parse(&format!("freenet::{p}/freenet-core"))
                .unwrap()
                .label
                .as_deref(),
            Some("freenet-core"),
        );
        assert_eq!(
            parse(&format!("{p}/freenet-core"))
                .unwrap()
                .label
                .as_deref(),
            Some("freenet-core"),
        );
    }

    #[test]
    fn label_does_not_change_prefix() {
        let p = "abc1234567XX";
        let a = parse(&format!("freenet::{p}")).unwrap().prefix;
        let b = parse(&format!("freenet::{p}/anything")).unwrap().prefix;
        let c = parse(&format!("freenet::{p}/something-else"))
            .unwrap()
            .prefix;
        assert_eq!(a, b);
        assert_eq!(a, c);
    }

    #[test]
    fn empty_label_treated_as_no_label() {
        let p = "abc1234567XX";
        let parsed = parse(&format!("freenet::{p}/")).unwrap();
        assert_eq!(parsed.prefix, p);
        assert_eq!(parsed.label, None);
    }

    #[test]
    fn rejects_too_short_prefix() {
        match parse("freenet:abc") {
            Err(UrlError::InvalidPrefixLength { len: 3, .. }) => {}
            other => panic!("expected InvalidPrefixLength(3), got {other:?}"),
        }
    }

    #[test]
    fn rejects_too_long_prefix() {
        // 33 chars > MAX (32)
        let long = "a".repeat(33);
        match parse(&format!("freenet:{long}")) {
            Err(UrlError::InvalidPrefixLength { len: 33, .. }) => {}
            other => panic!("expected InvalidPrefixLength(33), got {other:?}"),
        }
    }

    #[test]
    fn rejects_non_base58_chars() {
        // Includes '0' which is NOT in the Bitcoin base58 alphabet.
        match parse("freenet:0123456789XX") {
            Err(UrlError::InvalidPrefixChars) => {}
            other => panic!("expected InvalidPrefixChars, got {other:?}"),
        }
    }

    #[test]
    fn rejects_garbage() {
        assert!(parse("https://github.com/").is_err());
        assert!(parse("").is_err());
    }
}
