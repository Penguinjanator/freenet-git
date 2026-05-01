//! ChunkedPack publish and fetch flows for the on-host helper.
//!
//! Chunked-pack publish is a four-phase commit:
//!
//! ```text
//! 1. PUT every chunk contract.
//! 2. Re-GET each chunk; verify BLAKE3(bytes) == declared hash.
//! 3. PUT the manifest contract.
//! 4. Re-GET the manifest; verify BLAKE3(manifest_bytes) == manifest_hash.
//! 5. (Caller) Sign and submit the BundleAdd delta to the repo contract.
//! ```
//!
//! The forbidden case — the repo state advancing while the chunks or
//! manifest are not yet remotely retrievable — is impossible because
//! step 5 only runs after step 2 and step 4 have re-GET-verified.
//! Crashes between steps 1 and 5 produce harmless orphan contracts on
//! the network; the next push does not reference them and they evict
//! naturally.
//!
//! See [`docs/0001-large-repos.md`](../../../../docs/0001-large-repos.md)
//! for the full design.

use std::time::Duration;

use anyhow::{bail, Context, Result};
use freenet_git_types::chunked::{split_pack, ChunkedPackManifestV1};
use freenet_git_types::ObjectBundle;
use freenet_stdlib::client_api::WebApi;

use crate::wsclient;

/// Result of a chunked-pack publish: the [`ObjectBundle`] the caller
/// should reference in its `BundleAdd` delta to the repo contract.
#[derive(Debug, Clone)]
pub struct PublishedChunkedPack {
    /// The bundle entry to drop into `RepoState.object_index`.
    pub bundle: ObjectBundle,
    /// Number of chunks actually PUT (== `manifest.chunk_count`).
    pub chunk_count: u32,
    /// Total bytes published (== `manifest.total_size`, == original pack size).
    pub total_size: u64,
}

/// Publish a packfile as a [`ObjectBundle::ChunkedPack`].
///
/// Splits `pack_bytes` into chunks of `chunk_size`, PUTs each chunk as
/// a `pack-contract` instance, builds the manifest, PUTs the manifest
/// (also as a `pack-contract` since manifest bytes are just opaque
/// content-addressed bytes), and re-GET-verifies everything before
/// returning. The caller is responsible for signing and submitting
/// the resulting [`PublishedChunkedPack::bundle`] in a `BundleAdd`
/// delta to the repo contract — only after this function returns
/// successfully.
pub async fn publish_chunked_pack(
    web_api: &mut WebApi,
    pack_wasm: Vec<u8>,
    pack_bytes: Vec<u8>,
    chunk_size: u32,
    timeout_per_op: Duration,
) -> Result<PublishedChunkedPack> {
    if pack_bytes.is_empty() {
        bail!("publish_chunked_pack: empty pack");
    }
    if chunk_size == 0 {
        bail!("publish_chunked_pack: zero chunk_size");
    }

    let chunks = split_pack(&pack_bytes, chunk_size);
    let manifest = ChunkedPackManifestV1::from_chunks(chunk_size, &chunks);
    manifest
        .validate()
        .context("manifest self-check before publish")?;

    // Phase 1: PUT every chunk contract.
    for (i, chunk) in chunks.iter().enumerate() {
        wsclient::put_pack(web_api, pack_wasm.clone(), chunk.clone(), timeout_per_op)
            .await
            .with_context(|| format!("PUT chunk {i}"))?;
    }

    // Phase 2: re-GET each chunk and verify.
    for (i, expected_hash) in manifest.chunk_hashes.iter().enumerate() {
        let got = wsclient::get_pack(web_api, &pack_wasm, *expected_hash, timeout_per_op)
            .await
            .with_context(|| format!("re-GET chunk {i} for verification"))?;
        let got_hash = *blake3::hash(&got).as_bytes();
        if got_hash != *expected_hash {
            bail!(
                "chunk {i} verification failed: got {} expected {}",
                hex_lower(&got_hash),
                hex_lower(expected_hash),
            );
        }
    }

    // Phase 3: PUT the manifest as a pack-contract.
    let manifest_bytes = manifest.to_bytes();
    let manifest_hash = *blake3::hash(&manifest_bytes).as_bytes();
    wsclient::put_pack(
        web_api,
        pack_wasm.clone(),
        manifest_bytes.clone(),
        timeout_per_op,
    )
    .await
    .context("PUT manifest")?;

    // Phase 4: re-GET the manifest and verify.
    let got_manifest = wsclient::get_pack(web_api, &pack_wasm, manifest_hash, timeout_per_op)
        .await
        .context("re-GET manifest for verification")?;
    if got_manifest != manifest_bytes {
        bail!("manifest re-GET returned different bytes");
    }

    Ok(PublishedChunkedPack {
        bundle: ObjectBundle::ChunkedPack {
            manifest_hash,
            total_size: manifest.total_size,
            chunk_count: manifest.chunk_count,
        },
        chunk_count: manifest.chunk_count,
        total_size: manifest.total_size,
    })
}

/// Fetch and reassemble a [`ObjectBundle::ChunkedPack`].
///
/// 1. GET the manifest by `manifest_hash`. Verify `BLAKE3 == manifest_hash`.
/// 2. Decode the manifest. Re-validate internal consistency rules.
/// 3. Verify `total_size` and `chunk_count` from the bundle entry
///    match the manifest. **Mismatch fails hard.**
/// 4. GET each chunk in order. Verify `BLAKE3(chunk_i) ==
///    manifest.chunk_hashes[i]`. Verify chunk length matches the
///    manifest's expectation (`chunk_size` for non-final, computed
///    remainder for final).
/// 5. Concatenate in order and return.
pub async fn fetch_chunked_pack(
    web_api: &mut WebApi,
    pack_wasm: &[u8],
    manifest_hash: [u8; 32],
    expected_total_size: u64,
    expected_chunk_count: u32,
    timeout_per_op: Duration,
) -> Result<Vec<u8>> {
    // 1. GET the manifest. wsclient::get_pack already verifies BLAKE3.
    let manifest_bytes = wsclient::get_pack(web_api, pack_wasm, manifest_hash, timeout_per_op)
        .await
        .context("GET manifest")?;

    // 2. Decode and re-validate.
    let manifest = ChunkedPackManifestV1::from_bytes(&manifest_bytes).context("decode manifest")?;

    // 3. Authority check: bundle entry must agree with manifest.
    if manifest.total_size != expected_total_size {
        bail!(
            "object_index entry total_size {} disagrees with manifest {}",
            expected_total_size,
            manifest.total_size,
        );
    }
    if manifest.chunk_count != expected_chunk_count {
        bail!(
            "object_index entry chunk_count {} disagrees with manifest {}",
            expected_chunk_count,
            manifest.chunk_count,
        );
    }

    // 4. GET each chunk in order. (Phase 1.0: serial. Parallel is a
    //    later optimization once we hammer this on a real network.)
    let mut assembled: Vec<u8> = Vec::with_capacity(manifest.total_size as usize);
    for (i, expected_hash) in manifest.chunk_hashes.iter().enumerate() {
        let chunk = wsclient::get_pack(web_api, pack_wasm, *expected_hash, timeout_per_op)
            .await
            .with_context(|| format!("GET chunk {i}"))?;

        // Length check. wsclient::get_pack already verified BLAKE3 match.
        let expected_len = manifest.chunk_len(i as u32);
        if (chunk.len() as u64) != expected_len {
            bail!(
                "chunk {i} length {} disagrees with manifest expectation {}",
                chunk.len(),
                expected_len,
            );
        }
        assembled.extend_from_slice(&chunk);
    }

    if (assembled.len() as u64) != manifest.total_size {
        bail!(
            "assembled length {} disagrees with manifest total_size {}",
            assembled.len(),
            manifest.total_size,
        );
    }

    Ok(assembled)
}

fn hex_lower(b: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(b.len() * 2);
    for byte in b {
        let _ = write!(s, "{byte:02x}");
    }
    s
}
