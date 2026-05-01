//! ChunkedPack manifest format and validation.
//!
//! When a packfile exceeds [`DEFAULT_CHUNK_SIZE`], the on-host helper
//! splits it across multiple [`ObjectBundle::ChunkedPack`] contracts:
//! one immutable `pack-contract` per chunk plus one immutable
//! `pack-contract` for the manifest. The repo state's
//! `ObjectBundle::ChunkedPack { manifest_hash, total_size, chunk_count }`
//! refers to the manifest, which in turn lists the chunks.
//!
//! Anything in this module is "view-only" from the contract WASM's
//! perspective — the contract just sees opaque bytes whose BLAKE3 hash
//! must equal the manifest hash that the repo state declares. All the
//! schema and validation logic here runs in the on-host helper.
//!
//! ## Wire format (v1)
//!
//! ```text
//! manifest = bincode<{
//!   version:      u8 = 1,
//!   chunk_size:   u32,        // bytes per non-final chunk
//!   total_size:   u64,        // sum of all chunk lengths
//!   chunk_count:  u32,        // == chunk_hashes.len()
//!   chunk_hashes: Vec<[u8; 32]>,  // BLAKE3-32 of each chunk's bytes, in order
//! }>
//! ```
//!
//! `bincode` with default config is deterministic for this shape (only
//! fixed-size primitives and a length-prefixed Vec of fixed-size byte
//! arrays). A worked-example test pins the bytes; any change is a
//! wire-format break.
//!
//! ## Validation rules (enforced at decode time)
//!
//! [`ChunkedPackManifestV1::validate`] rejects manifests where any of:
//!
//! - `version != 1`
//! - `chunk_count == 0`
//! - `chunk_count != chunk_hashes.len()`
//! - `chunk_size == 0`
//! - `total_size == 0`
//! - `total_size > chunk_size as u64 * chunk_count as u64` — would imply
//!   the final chunk is larger than `chunk_size`.
//! - `total_size <= chunk_size as u64 * (chunk_count - 1) as u64` — would
//!   imply the final chunk is empty.
//!
//! Per-chunk byte length verification (each non-final chunk equals
//! `chunk_size`, final equals `total_size - (chunk_count-1)*chunk_size`)
//! is enforced when the helper actually fetches and concatenates the
//! chunks.

use serde::{Deserialize, Serialize};

use crate::PackHash;

/// Default chunk size used by the on-host helper when splitting large
/// packs. 1 MiB = 1,048,576 bytes. A pack of exactly 1 MiB is
/// `SinglePack`; 1 MiB + 1 byte is `ChunkedPack` with two chunks.
pub const DEFAULT_CHUNK_SIZE: u32 = 1024 * 1024;

/// Errors when validating or decoding a manifest.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ManifestError {
    /// `bincode` failed to decode the bytes.
    #[error("manifest decode: {0}")]
    Decode(String),
    /// Unknown wire-format version.
    #[error("manifest version {0} is not supported")]
    UnsupportedVersion(u8),
    /// Internal field disagreement (chunk_count vs chunk_hashes.len, etc).
    #[error("manifest internal inconsistency: {0}")]
    Inconsistent(&'static str),
    /// `total_size` cannot match the declared chunk count and chunk size.
    #[error("manifest total_size {total} cannot fit {count} chunks of size {chunk}")]
    SizeOutOfRange {
        /// Total size (bytes).
        total: u64,
        /// Declared chunk count.
        count: u32,
        /// Declared per-chunk size (bytes).
        chunk: u32,
    },
}

/// On-the-wire manifest for a chunked pack.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ChunkedPackManifestV1 {
    /// Wire-format version. Currently always 1.
    pub version: u8,
    /// Bytes per non-final chunk. The final chunk is in
    /// `(0, chunk_size]`.
    pub chunk_size: u32,
    /// Sum of all chunk lengths, equal to the original pack size.
    pub total_size: u64,
    /// `== chunk_hashes.len()`. Carried explicitly for cheap size
    /// checks before we allocate the Vec on decode.
    pub chunk_count: u32,
    /// BLAKE3-32 of each chunk's bytes, in stream order.
    #[serde(with = "serde_bytes_array_vec")]
    pub chunk_hashes: Vec<PackHash>,
}

impl ChunkedPackManifestV1 {
    /// Build a fresh manifest from the chunked pack bytes.
    pub fn from_chunks(chunk_size: u32, chunks: &[Vec<u8>]) -> Self {
        let chunk_count = u32::try_from(chunks.len())
            .expect("freenet-git ChunkedPack with >4G chunks is not supported");
        let total_size: u64 = chunks.iter().map(|c| c.len() as u64).sum();
        let chunk_hashes: Vec<PackHash> =
            chunks.iter().map(|c| *blake3::hash(c).as_bytes()).collect();
        Self {
            version: 1,
            chunk_size,
            total_size,
            chunk_count,
            chunk_hashes,
        }
    }

    /// Encode to bytes via `bincode` with default config.
    pub fn to_bytes(&self) -> Vec<u8> {
        bincode::serialize(self).expect("ChunkedPackManifestV1 serialization is infallible")
    }

    /// Decode from bytes and run [`Self::validate`].
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ManifestError> {
        let manifest: Self =
            bincode::deserialize(bytes).map_err(|e| ManifestError::Decode(e.to_string()))?;
        manifest.validate()?;
        Ok(manifest)
    }

    /// Run all internal-consistency checks. Does NOT verify that the
    /// chunk bytes themselves match `chunk_hashes` — that is the
    /// fetcher's job once it actually has the bytes.
    pub fn validate(&self) -> Result<(), ManifestError> {
        if self.version != 1 {
            return Err(ManifestError::UnsupportedVersion(self.version));
        }
        if self.chunk_count == 0 {
            return Err(ManifestError::Inconsistent("chunk_count must be > 0"));
        }
        if self.chunk_size == 0 {
            return Err(ManifestError::Inconsistent("chunk_size must be > 0"));
        }
        if self.total_size == 0 {
            return Err(ManifestError::Inconsistent("total_size must be > 0"));
        }
        if self.chunk_count as usize != self.chunk_hashes.len() {
            return Err(ManifestError::Inconsistent(
                "chunk_count does not match chunk_hashes length",
            ));
        }
        // total_size must be in (chunk_size * (count - 1), chunk_size * count].
        // Compute as u64 to avoid overflow.
        let chunk_size_u64 = self.chunk_size as u64;
        let count_u64 = self.chunk_count as u64;
        let upper = chunk_size_u64
            .checked_mul(count_u64)
            .ok_or(ManifestError::SizeOutOfRange {
                total: self.total_size,
                count: self.chunk_count,
                chunk: self.chunk_size,
            })?;
        let lower =
            chunk_size_u64
                .checked_mul(count_u64 - 1)
                .ok_or(ManifestError::SizeOutOfRange {
                    total: self.total_size,
                    count: self.chunk_count,
                    chunk: self.chunk_size,
                })?;
        if self.total_size > upper || self.total_size <= lower {
            return Err(ManifestError::SizeOutOfRange {
                total: self.total_size,
                count: self.chunk_count,
                chunk: self.chunk_size,
            });
        }
        Ok(())
    }

    /// Length of the i-th chunk in bytes. All non-final chunks are
    /// `chunk_size`; the final chunk is `total_size - chunk_size *
    /// (chunk_count - 1)`. Caller must ensure the manifest has been
    /// validated.
    pub fn chunk_len(&self, i: u32) -> u64 {
        debug_assert!(i < self.chunk_count, "chunk index out of range");
        if i + 1 < self.chunk_count {
            self.chunk_size as u64
        } else {
            self.total_size - (self.chunk_size as u64) * ((self.chunk_count - 1) as u64)
        }
    }
}

/// Split a packfile's bytes into chunks of `chunk_size` (final chunk
/// may be smaller). Always produces at least one chunk; `pack` must
/// not be empty.
pub fn split_pack(pack: &[u8], chunk_size: u32) -> Vec<Vec<u8>> {
    assert!(!pack.is_empty(), "split_pack: empty pack");
    assert!(chunk_size > 0, "split_pack: zero chunk_size");
    pack.chunks(chunk_size as usize)
        .map(|c| c.to_vec())
        .collect()
}

// `serde_bytes` does not have an array-element variant, so we hand-roll
// one. We serialize `Vec<[u8; 32]>` as a length-prefixed sequence of
// 32-byte arrays — exactly what bincode would do by default, with the
// shape pinned explicitly so future encoder changes do not silently
// break the wire format.
mod serde_bytes_array_vec {
    use serde::de::{SeqAccess, Visitor};
    use serde::ser::SerializeSeq;
    use serde::{Deserializer, Serializer};

    pub fn serialize<S: Serializer>(value: &[[u8; 32]], ser: S) -> Result<S::Ok, S::Error> {
        let mut seq = ser.serialize_seq(Some(value.len()))?;
        for item in value {
            seq.serialize_element(serde_bytes::Bytes::new(item))?;
        }
        seq.end()
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(de: D) -> Result<Vec<[u8; 32]>, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = Vec<[u8; 32]>;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("a sequence of 32-byte arrays")
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
                let mut out = Vec::with_capacity(seq.size_hint().unwrap_or(0));
                while let Some(b) = seq.next_element::<serde_bytes::ByteBuf>()? {
                    let arr: [u8; 32] = b
                        .as_ref()
                        .try_into()
                        .map_err(|_| serde::de::Error::custom("expected 32-byte chunk hash"))?;
                    out.push(arr);
                }
                Ok(out)
            }
        }
        de.deserialize_seq(V)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_small_manifest() {
        let chunks: Vec<Vec<u8>> = vec![vec![0xAA; 100], vec![0xBB; 50]];
        let m = ChunkedPackManifestV1::from_chunks(100, &chunks);
        let bytes = m.to_bytes();
        let decoded = ChunkedPackManifestV1::from_bytes(&bytes).expect("valid");
        assert_eq!(decoded, m);
        assert_eq!(decoded.total_size, 150);
        assert_eq!(decoded.chunk_count, 2);
        assert_eq!(decoded.chunk_len(0), 100);
        assert_eq!(decoded.chunk_len(1), 50);
    }

    #[test]
    fn rejects_zero_chunk_count() {
        let m = ChunkedPackManifestV1 {
            version: 1,
            chunk_size: 1024,
            total_size: 1024,
            chunk_count: 0,
            chunk_hashes: vec![],
        };
        let bytes = m.to_bytes();
        let err = ChunkedPackManifestV1::from_bytes(&bytes).unwrap_err();
        assert!(matches!(err, ManifestError::Inconsistent(_)));
    }

    #[test]
    fn rejects_count_hashes_mismatch() {
        let m = ChunkedPackManifestV1 {
            version: 1,
            chunk_size: 100,
            total_size: 200,
            chunk_count: 2,
            chunk_hashes: vec![[0; 32]],
        };
        let bytes = m.to_bytes();
        let err = ChunkedPackManifestV1::from_bytes(&bytes).unwrap_err();
        assert!(matches!(err, ManifestError::Inconsistent(_)));
    }

    #[test]
    fn rejects_total_too_large() {
        let m = ChunkedPackManifestV1 {
            version: 1,
            chunk_size: 100,
            total_size: 250, // > 100 * 2
            chunk_count: 2,
            chunk_hashes: vec![[0; 32]; 2],
        };
        let bytes = m.to_bytes();
        let err = ChunkedPackManifestV1::from_bytes(&bytes).unwrap_err();
        assert!(matches!(err, ManifestError::SizeOutOfRange { .. }));
    }

    #[test]
    fn rejects_total_too_small_for_count() {
        // chunk_count=2 implies the final chunk has length total -
        // chunk_size * 1 > 0. total_size = 100 with chunk_size = 100
        // means the final chunk is empty; reject.
        let m = ChunkedPackManifestV1 {
            version: 1,
            chunk_size: 100,
            total_size: 100,
            chunk_count: 2,
            chunk_hashes: vec![[0; 32]; 2],
        };
        let bytes = m.to_bytes();
        let err = ChunkedPackManifestV1::from_bytes(&bytes).unwrap_err();
        assert!(matches!(err, ManifestError::SizeOutOfRange { .. }));
    }

    #[test]
    fn split_then_manifest_then_validate() {
        let pack: Vec<u8> = (0..2500u32).map(|i| (i & 0xFF) as u8).collect();
        let chunks = split_pack(&pack, 1000);
        assert_eq!(chunks.len(), 3);
        assert_eq!(chunks[0].len(), 1000);
        assert_eq!(chunks[1].len(), 1000);
        assert_eq!(chunks[2].len(), 500);

        let m = ChunkedPackManifestV1::from_chunks(1000, &chunks);
        assert!(m.validate().is_ok());
        assert_eq!(m.total_size, 2500);
        assert_eq!(m.chunk_len(0), 1000);
        assert_eq!(m.chunk_len(1), 1000);
        assert_eq!(m.chunk_len(2), 500);

        // Re-assemble and confirm bit-for-bit.
        let reassembled: Vec<u8> = chunks.into_iter().flatten().collect();
        assert_eq!(reassembled, pack);
    }

    /// Wire-format pin. Any drift in either the byte sequence or the
    /// BLAKE3 hash is a wire-format break and must come together with
    /// bumping `version` to 2 (and updating every consumer).
    #[test]
    fn manifest_wire_format_fixture() {
        let m = ChunkedPackManifestV1 {
            version: 1,
            chunk_size: 4,
            total_size: 7,
            chunk_count: 2,
            chunk_hashes: vec![[0xAA; 32], [0xBB; 32]],
        };
        let bytes = m.to_bytes();

        // bincode default config:
        //   version u8                  -> 01
        //   chunk_size u32 LE           -> 04 00 00 00
        //   total_size u64 LE           -> 07 00 00 00 00 00 00 00
        //   chunk_count u32 LE          -> 02 00 00 00
        //   Vec<bytes> length u64 LE    -> 02 00 00 00 00 00 00 00
        //   bytes #1: length u64 LE     -> 20 00 00 00 00 00 00 00
        //             32 * 0xAA
        //   bytes #2: length u64 LE     -> 20 00 00 00 00 00 00 00
        //             32 * 0xBB
        let expected_hex = "010400000007000000000000000200000002000000000000002000000000000000\
             aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
             2000000000000000\
             bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        let mut actual_hex = String::with_capacity(bytes.len() * 2);
        for b in &bytes {
            use std::fmt::Write as _;
            write!(actual_hex, "{b:02x}").unwrap();
        }
        let expected_clean: String = expected_hex
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect();
        assert_eq!(
            actual_hex, expected_clean,
            "ChunkedPackManifestV1 wire format drift — bump version and update consumers"
        );

        // Pinned BLAKE3 of the wire bytes.
        assert_eq!(
            blake3::hash(&bytes).to_hex().as_str(),
            "7b792da2fc4b787ff10abdbc480596c118e88ad1209da7d0c4d10d0bc060264e",
            "ChunkedPackManifestV1 BLAKE3 drift",
        );

        let decoded = ChunkedPackManifestV1::from_bytes(&bytes).unwrap();
        assert_eq!(decoded, m);
    }
}
