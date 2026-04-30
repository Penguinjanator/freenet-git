//! Length-prefixed signed-payload encoding.
//!
//! Every signed message in freenet-git is constructed by concatenating
//! length-prefixed fields, with the domain prefix as the *first* field. This
//! makes the encoding self-describing in the trivial sense that no field can
//! be confused with any other field, and makes a domain-version bump
//! syntactically distinguishable from a same-domain message that happened to
//! start with the same bytes.
//!
//! ```text
//! payload = field(domain)
//!         || field(repo_key)
//!         || field(...)
//!         || ...
//!
//! field(x) = u32_le(len(x)) || raw(x)
//! ```
//!
//! Primitive encodings:
//!
//! | Type        | Bytes (inside the length prefix)                                        |
//! |-------------|--------------------------------------------------------------------------|
//! | `bool`      | `0x00` (false) or `0x01` (true)                                          |
//! | `u32`       | 4 bytes, little-endian                                                   |
//! | `u64`       | 8 bytes, little-endian                                                   |
//! | `[u8; N]`   | the N raw bytes                                                          |
//! | `&[u8]` /`String`/`&str` | the raw bytes                                              |
//! | `Option<T>` | `0x00` for `None`; `0x01` followed by the encoded payload of `T`         |
//!
//! Each one of these primitives is then wrapped in the standard
//! length-prefix envelope when it appears as a field of a payload.
//!
//! There are no nested structures in any v1 signed payload. If a future
//! version adds nesting, it recursively follows the same length-prefix-
//! everything rule.

use crate::WIRE_VERSION;

/// A buffer for accumulating a signed payload.
///
/// The buffer always begins with a domain field. Construct with
/// [`Builder::new`].
#[derive(Debug, Clone)]
pub struct Builder {
    buf: Vec<u8>,
}

impl Builder {
    /// Start a new payload for the given domain suffix (e.g. `"ref-update"`,
    /// `"object-bundle"`, `"name"`). The full domain string written is
    /// `"freenet-git/v1/<suffix>"`.
    pub fn new(domain_suffix: &str) -> Self {
        let mut me = Self {
            buf: Vec::with_capacity(64),
        };
        let domain = format!("freenet-git/{}/{}", WIRE_VERSION, domain_suffix);
        me.field_bytes(domain.as_bytes());
        me
    }

    /// Append a field consisting of the given raw bytes.
    pub fn field_bytes(&mut self, bytes: &[u8]) -> &mut Self {
        let len: u32 = bytes
            .len()
            .try_into()
            .expect("freenet-git signed payloads do not contain >4GiB fields");
        self.buf.extend_from_slice(&len.to_le_bytes());
        self.buf.extend_from_slice(bytes);
        self
    }

    /// Append a string field.
    pub fn field_str(&mut self, s: &str) -> &mut Self {
        self.field_bytes(s.as_bytes())
    }

    /// Append a `u32` field (4 bytes little-endian inside the length prefix).
    pub fn field_u32(&mut self, x: u32) -> &mut Self {
        self.field_bytes(&x.to_le_bytes())
    }

    /// Append a `u64` field (8 bytes little-endian inside the length prefix).
    pub fn field_u64(&mut self, x: u64) -> &mut Self {
        self.field_bytes(&x.to_le_bytes())
    }

    /// Append a boolean field (1 byte).
    pub fn field_bool(&mut self, b: bool) -> &mut Self {
        self.field_bytes(&[u8::from(b)])
    }

    /// Append an `Option<&[u8]>` field.
    ///
    /// Encoded as `[0x00]` for `None` or `[0x01, ...payload...]` for `Some`,
    /// where `payload` is the raw bytes (still inside the outer length prefix
    /// of the field).
    pub fn field_option_bytes(&mut self, value: Option<&[u8]>) -> &mut Self {
        match value {
            None => self.field_bytes(&[0x00]),
            Some(b) => {
                let mut tagged = Vec::with_capacity(1 + b.len());
                tagged.push(0x01);
                tagged.extend_from_slice(b);
                self.field_bytes(&tagged)
            }
        }
    }

    /// Finish the builder and return the assembled byte string.
    pub fn finish(self) -> Vec<u8> {
        self.buf
    }
}

/// Convenience: build a payload by chaining mutations on a `Builder`.
///
/// ```ignore
/// let bytes = build("ref-update", |b| {
///     b.field_bytes(&repo_key);
///     b.field_str("refs/heads/main");
///     b.field_bytes(&commit_hash);
///     b.field_u64(update_seq);
///     b.field_u64(auth_epoch);
/// });
/// ```
pub fn build<F>(domain_suffix: &str, f: F) -> Vec<u8>
where
    F: FnOnce(&mut Builder),
{
    let mut b = Builder::new(domain_suffix);
    f(&mut b);
    b.finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Worked example: domain alone.
    ///
    /// The domain string `"freenet-git/v1/example"` is 22 bytes. The encoded
    /// payload is therefore the little-endian u32 `22` (`16 00 00 00`)
    /// followed by the raw bytes of the domain.
    #[test]
    fn domain_only_payload_is_length_prefixed() {
        let bytes = Builder::new("example").finish();
        assert_eq!(&bytes[..4], &22u32.to_le_bytes());
        assert_eq!(&bytes[4..], b"freenet-git/v1/example");
    }

    /// Worked example: every primitive type.
    ///
    /// Pinned hex output. If this test fails because the expected bytes
    /// changed, that is a wire-format break and the domain must bump from
    /// `v1` to `v2` together with a contract WASM change.
    #[test]
    fn every_primitive_round_trip() {
        let payload = build("worked-example", |b| {
            b.field_bytes(&[0xAA, 0xBB, 0xCC]);
            b.field_str("hi");
            b.field_u32(0x01020304);
            b.field_u64(0x0807060504030201);
            b.field_bool(true);
            b.field_bool(false);
            b.field_option_bytes(None);
            b.field_option_bytes(Some(&[0xDE, 0xAD]));
        });

        // Domain: "freenet-git/v1/worked-example" = 29 bytes
        // (1d 00 00 00) || domain
        // Field bytes [AA BB CC] => (03 00 00 00) || AA BB CC
        // Field str "hi"         => (02 00 00 00) || 68 69
        // Field u32 0x01020304   => (04 00 00 00) || 04 03 02 01
        // Field u64 ...          => (08 00 00 00) || 01 02 03 04 05 06 07 08
        // Field bool true        => (01 00 00 00) || 01
        // Field bool false       => (01 00 00 00) || 00
        // Option None            => (01 00 00 00) || 00
        // Option Some(DE AD)     => (03 00 00 00) || 01 DE AD
        let expected = hex::decode(concat!(
            "1d000000",
            "667265656e65742d6769742f76312f776f726b65642d6578616d706c65",
            "03000000",
            "aabbcc",
            "02000000",
            "6869",
            "04000000",
            "04030201",
            "08000000",
            "0102030405060708",
            "01000000",
            "01",
            "01000000",
            "00",
            "01000000",
            "00",
            "03000000",
            "01dead",
        ))
        .unwrap();
        assert_eq!(payload, expected);
    }

    /// Worked example: a real ref-update signed payload, signed with a fixed
    /// test ed25519 key. Verifies the resulting signature against the same
    /// public key.
    ///
    /// ed25519 signatures are deterministic given the key and payload, so an
    /// independent implementation building the same payload and signing with
    /// the same key MUST produce identical signature bytes. We pin those
    /// bytes in [`signed_fixtures`] in the integration tests once the values
    /// are computed.
    #[test]
    fn ref_update_signs_and_verifies() {
        use ed25519_dalek::{Signer, SigningKey, Verifier};

        // Fixed test key (NOT for production use). 32 bytes of 0x00..0x1f.
        let mut secret_bytes = [0u8; 32];
        for (i, b) in secret_bytes.iter_mut().enumerate() {
            *b = i as u8;
        }
        let signing_key = SigningKey::from_bytes(&secret_bytes);
        let verifying_key = signing_key.verifying_key();

        let repo_key = [0xAAu8; 32];
        let commit_hash = [0xBBu8; 20];

        let payload = build("ref-update", |b| {
            b.field_bytes(&repo_key);
            b.field_str("refs/heads/main");
            b.field_bytes(&commit_hash);
            b.field_u64(1);
            b.field_u64(0);
        });

        let sig = signing_key.sign(&payload);
        assert!(verifying_key.verify(&payload, &sig).is_ok());

        // Cross-check that domain confusion is impossible: a different
        // domain prefix produces a different payload, so the same signature
        // does not verify.
        let other_payload = build("object-bundle", |b| {
            b.field_bytes(&repo_key);
            b.field_str("refs/heads/main");
            b.field_bytes(&commit_hash);
            b.field_u64(1);
            b.field_u64(0);
        });
        assert!(verifying_key.verify(&other_payload, &sig).is_err());
    }
}
