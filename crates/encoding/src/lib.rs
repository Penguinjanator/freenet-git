//! Wire-format encoding pin for freenet-git.
//!
//! This crate is the single source of truth for two byte formats that both the
//! contract WASM and the on-host helpers must agree on exactly:
//!
//! 1. **Signed-payload encoding** ([`signed`]) — the byte string fed into
//!    ed25519 signatures. Hand-rolled length-prefixed concatenation. Every
//!    element (including the domain prefix) is wrapped in a 4-byte
//!    little-endian length followed by raw bytes.
//!
//! 2. **Canonical encoding for content-addressed hashes** ([`canonical`]) — a
//!    minimal deterministic CBOR encoder for the structured types we hash to
//!    derive bundle ids. RFC 8949 §4.2.1 deterministic rules: definite-length
//!    items, smallest-encoding-of-integers, sorted map keys.
//!
//! ## Why "v1" appears in domain prefixes
//!
//! Every signed payload starts with a domain string like
//! `b"freenet-git/v1/ref-update"`. The `v1` is the wire-format version. When
//! either of the two encodings here changes in a way that produces different
//! bytes for the same input, the domain version must bump to `v2` in lockstep
//! with a contract WASM change. Without the version bump, signatures from the
//! two implementations would silently disagree and fork the network.

#![deny(unsafe_code)]
#![warn(missing_docs)]

pub mod canonical;
pub mod signed;

/// The current wire-format version. Embedded in every domain prefix.
pub const WIRE_VERSION: &str = "v1";

/// Compute BLAKE3-256 of a byte slice.
///
/// Returned as a `[u8; 32]` so callers can convert into whatever hash type
/// they use without depending on the `blake3` crate directly.
pub fn blake3_32(input: &[u8]) -> [u8; 32] {
    *blake3::hash(input).as_bytes()
}
