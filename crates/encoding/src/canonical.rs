//! Minimal deterministic CBOR encoder for content-addressed hashes.
//!
//! Used for the [`ObjectBundle`] -> [`ObjectBundleId`] derivation so that two
//! independent implementations agree on the bundle id given the same logical
//! contents. We encode by hand rather than depending on a CBOR library so the
//! exact byte format is part of *this* crate's wire-format pin and cannot
//! drift due to a transitive dependency upgrade.
//!
//! [`ObjectBundle`]: ../../../types/struct.ObjectBundle.html
//! [`ObjectBundleId`]: ../../../types/struct.ObjectBundleId.html
//!
//! ## Determinism rules (RFC 8949 §4.2.1 subset)
//!
//! - **Definite-length items only.** Maps and arrays carry their element
//!   count in the major-type header.
//! - **Smallest-encoding-of-integers.** A `u64` value of `5` is encoded in
//!   one byte (`0x05`), not eight.
//! - **Map keys sorted by their canonical encoded byte representation.**
//!   Lexicographic byte order, after each key has been canonically encoded.
//! - **No floating-point.**
//! - **No tags, no semantic types.** A bundle id is a hash of structure, not
//!   a typed CBOR document.
//!
//! Only the subset of CBOR we actually use is implemented:
//!
//! | Major type | Used for                          |
//! |------------|-----------------------------------|
//! | 0 (uint)   | counts, sizes (`u32`, `u64`)      |
//! | 2 (bytes)  | hash bytes                        |
//! | 3 (text)   | enum variant tags, field labels   |
//! | 4 (array)  | not used in v1, but encoder ready |
//! | 5 (map)    | the structured envelope itself    |

use std::collections::BTreeMap;

/// Encode a length-headed major type byte.
fn write_uint(out: &mut Vec<u8>, major: u8, value: u64) {
    debug_assert!(major < 8, "CBOR major type fits in 3 bits");
    let prefix = major << 5;
    if value < 24 {
        out.push(prefix | (value as u8));
    } else if value < 0x100 {
        out.push(prefix | 24);
        out.push(value as u8);
    } else if value < 0x1_0000 {
        out.push(prefix | 25);
        out.extend_from_slice(&(value as u16).to_be_bytes());
    } else if value < 0x1_0000_0000 {
        out.push(prefix | 26);
        out.extend_from_slice(&(value as u32).to_be_bytes());
    } else {
        out.push(prefix | 27);
        out.extend_from_slice(&value.to_be_bytes());
    }
}

/// A canonical CBOR value. Use [`Value::map`] / [`Value::text`] / etc. to
/// build, then [`Value::encode`] to serialize.
#[derive(Debug, Clone)]
pub enum Value {
    /// Major type 0: unsigned integer.
    UInt(u64),
    /// Major type 2: byte string.
    Bytes(Vec<u8>),
    /// Major type 3: UTF-8 text string.
    Text(String),
    /// Major type 4: definite-length array.
    Array(Vec<Value>),
    /// Major type 5: definite-length map. Keys are sorted by their canonical
    /// encoded byte representation at serialize time.
    Map(BTreeMap<Vec<u8>, Value>),
}

impl Value {
    /// Construct a UInt.
    pub fn uint(v: u64) -> Self {
        Self::UInt(v)
    }

    /// Construct a Bytes.
    pub fn bytes(b: impl Into<Vec<u8>>) -> Self {
        Self::Bytes(b.into())
    }

    /// Construct a Text.
    pub fn text(s: impl Into<String>) -> Self {
        Self::Text(s.into())
    }

    /// Construct a map. The internal storage is a `BTreeMap` keyed by the
    /// pre-encoded key bytes, which gives canonical sort order automatically.
    pub fn map() -> MapBuilder {
        MapBuilder {
            entries: BTreeMap::new(),
        }
    }

    /// Serialize to bytes.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.encode_into(&mut out);
        out
    }

    fn encode_into(&self, out: &mut Vec<u8>) {
        match self {
            Self::UInt(v) => write_uint(out, 0, *v),
            Self::Bytes(b) => {
                write_uint(out, 2, b.len() as u64);
                out.extend_from_slice(b);
            }
            Self::Text(s) => {
                write_uint(out, 3, s.len() as u64);
                out.extend_from_slice(s.as_bytes());
            }
            Self::Array(items) => {
                write_uint(out, 4, items.len() as u64);
                for v in items {
                    v.encode_into(out);
                }
            }
            Self::Map(m) => {
                write_uint(out, 5, m.len() as u64);
                // BTreeMap iteration is in key byte order, which is exactly
                // the canonical CBOR ordering rule.
                for (k_bytes, v) in m {
                    out.extend_from_slice(k_bytes);
                    v.encode_into(out);
                }
            }
        }
    }
}

/// Builder for a canonical CBOR map.
///
/// Keys can be any [`Value`]. Each key is encoded once at insert time so
/// the underlying `BTreeMap` automatically yields entries in canonical
/// (encoded-byte-lexicographic) order.
#[derive(Debug, Default)]
pub struct MapBuilder {
    entries: BTreeMap<Vec<u8>, Value>,
}

impl MapBuilder {
    /// Insert a `(key, value)` pair. Subsequent calls with the same encoded
    /// key replace the previous entry (canonical CBOR forbids duplicate
    /// keys, so this is the right behavior in practice).
    pub fn entry(mut self, key: Value, value: Value) -> Self {
        self.entries.insert(key.encode(), value);
        self
    }

    /// Convenience for `text` keys.
    pub fn text_entry(self, key: &str, value: Value) -> Self {
        self.entry(Value::text(key), value)
    }

    /// Finish.
    pub fn build(self) -> Value {
        Value::Map(self.entries)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn small_uint_uses_short_form() {
        assert_eq!(Value::uint(5).encode(), vec![0x05]);
        assert_eq!(Value::uint(23).encode(), vec![0x17]);
        assert_eq!(Value::uint(24).encode(), vec![0x18, 0x18]);
        assert_eq!(Value::uint(0xFF).encode(), vec![0x18, 0xFF]);
        assert_eq!(Value::uint(0x100).encode(), vec![0x19, 0x01, 0x00]);
        assert_eq!(
            Value::uint(0x1_0000_0000).encode(),
            vec![0x1B, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00],
        );
    }

    #[test]
    fn bytes_carry_length_prefix() {
        assert_eq!(
            Value::bytes(vec![0xDE, 0xAD]).encode(),
            vec![0x42, 0xDE, 0xAD]
        );
    }

    #[test]
    fn text_carries_length_prefix() {
        assert_eq!(Value::text("hi").encode(), vec![0x62, b'h', b'i']);
    }

    /// The exact byte format that [`bundle_id_for_single_pack`] in
    /// `freenet-git-types` will rely on. Two independent encoders MUST
    /// produce these bytes for these inputs.
    #[test]
    fn single_pack_bundle_id_fixture() {
        let pack_hash = [0xAAu8; 32];
        let size_bytes: u64 = 4096;

        let encoded = Value::map()
            .text_entry("kind", Value::text("single-pack"))
            .text_entry("pack_hash", Value::bytes(pack_hash.to_vec()))
            .text_entry("size_bytes", Value::uint(size_bytes))
            .build()
            .encode();

        // Map of 3 entries: 0xA3
        // Key "kind" (text 4): 0x64 6b 69 6e 64
        // Value "single-pack" (text 11): 0x6B 73696e676c652d7061636b
        // Key "pack_hash" (text 9): 0x69 7061636b5f68617368
        // Value bytes(32): 0x58 20 followed by 32 * 0xAA
        // Key "size_bytes" (text 10): 0x6A 73697a655f6279746573
        // Value uint 4096 = 0x19 10 00
        //
        // The keys must come out in encoded-byte-lex order: "kind",
        // "pack_hash", "size_bytes". Their encoded forms start with
        // 0x64, 0x69, 0x6A respectively, so that ordering is correct.
        let expected = hex::decode(concat!(
            "a3",
            "646b696e64",
            "6b73696e676c652d7061636b",
            "697061636b5f68617368",
            "5820",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "6a73697a655f6279746573",
            "191000",
        ))
        .unwrap();

        assert_eq!(encoded, expected);
    }

    #[test]
    fn map_keys_sort_canonically_regardless_of_insertion_order() {
        let a = Value::map()
            .text_entry("zzz", Value::uint(1))
            .text_entry("aaa", Value::uint(2))
            .build()
            .encode();
        let b = Value::map()
            .text_entry("aaa", Value::uint(2))
            .text_entry("zzz", Value::uint(1))
            .build()
            .encode();
        assert_eq!(a, b);
    }
}
