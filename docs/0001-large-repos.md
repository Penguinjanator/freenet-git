# Design 0001: Large repos on Freenet

**Status:** proposed
**Target:** freenet-git 0.1.x (incremental over 0.1.0 already published)

## Problem

Phase 1.0 ships `SinglePack` only — a push uploads its packfile as one
immutable Freenet contract. Freenet has a practical per-contract size
limit in the low single-MB range. Real Freenet-ecosystem repos exceed
this:

- `freenet-stdlib` HEAD pack: 552 KB ✓ fits today
- `river/main` HEAD pack: 8.7 MB ✗ too big
- `freenet-core/main` HEAD pack: 176 MB ✗ way too big (and that's just
  HEAD — full history doesn't even compute)

Without a way to host a HEAD snapshot of medium repos, the announce
story ("Freenet hosts Freenet") is hollow. Hosting `freenet-stdlib` is
proof of concept; hosting `freenet-core` is dogfood.

## Question we already answered

> Should freenet-git try to keep every byte of git history alive on
> Freenet forever?

No. Freenet is a communication medium, not a storage medium. Cold
contracts get evicted. That's the medium working as designed.

The model that fits Freenet is: **the network hosts what is being
communicated; clones are the archive.** This matches git's actual
access pattern — HEAD and recent commits are hot, old history is cold,
and contributors with full clones can re-PUT bytes the network has
forgotten.

## Question we are answering here

> Given the "communication, not storage" framing, what is the minimum
> we must build for `freenet-core` to be reachable from Freenet?

## Decision

Build two things:

### 1. ChunkedPack — split large packs across multiple contracts

The schema already reserves
`ObjectBundle::ChunkedPack { manifest_hash, total_size, chunk_count }`.
Implement it in the helper:

**On push:**
1. Build the packfile as today.
2. If the pack is below `CHUNK_SIZE_THRESHOLD` (default 1 MB), use
   `SinglePack` exactly as today — no behavior change for small repos.
3. Otherwise split the pack bytes into N fixed-size chunks of
   `CHUNK_SIZE` (default 1 MB), with the final chunk possibly smaller.
4. PUT each chunk as a `pack-contract` instance (the existing
   pack-contract WASM works — its only check is
   `BLAKE3(state) == params`, agnostic to chunking).
5. Build a manifest: an ordered list of chunk pack hashes plus
   `total_size` and `chunk_count`.
6. PUT the manifest as a `pack-contract` (manifest is just
   `bincode<ManifestV1>` and the same content-addressed wrapper works).
7. Sign and submit a `BundleAdd` delta carrying
   `ObjectBundle::ChunkedPack { manifest_hash, total_size, chunk_count }`
   to the repo contract.

**On fetch:**
1. For each `ChunkedPack` in `object_index`, GET the manifest contract
   by `manifest_hash` + bundled pack-contract WASM.
2. Re-verify `BLAKE3(manifest_bytes) == manifest_hash` locally.
3. Decode the manifest, GET each chunk in parallel.
4. Re-verify each chunk against its declared hash.
5. Concatenate in manifest order, hand to `git index-pack --stdin`.

**Manifest format (v1):**
```rust
struct ChunkedPackManifestV1 {
    version: u8,                  // = 1
    chunk_size: u32,              // bytes per chunk (last may be smaller)
    total_size: u64,
    chunk_count: u32,
    chunk_hashes: Vec<[u8; 32]>,  // BLAKE3-32 of each chunk's bytes
}
```

`bincode`-serialized; manifest hash is `BLAKE3(manifest_bytes)`. The
manifest itself is hosted as a regular pack-contract (so the same
content-addressed validation works).

### 2. `freenet-git rescue` — re-PUT bytes the network has forgotten

The Phase 1 spec already calls this out as the load-bearing self-heal
primitive. Implement it now so the "communication, not storage" claim
is actually backed by code:

```
freenet-git rescue freenet:<prefix>/<label>
```

Walks `object_index`, GETs each referenced bundle (or manifest +
chunks for ChunkedPack), and for any GET that fails or returns empty:

1. Look in the local `.git/freenet-cache/packs/<hash>.pack` and the
   regular git object DB for the bytes.
2. Verify `BLAKE3(bytes) == expected_hash` before re-uploading
   (defends against a local attacker swapping cache files).
3. PUT the bytes back to Freenet.

Reports a per-bundle status line: re-uploaded, already-present, or
unrecoverable (we don't have the bytes locally).

### What we are explicitly NOT doing in 0.1.x

- **Erasure coding (Reed-Solomon, fountain codes).** Real argument:
  if the network's per-chunk availability is < 100% and a repo splits
  into N chunks, plain ChunkedPack availability is `p^N`. Erasure
  coding makes that nearly 1.0 with parity overhead. Counter-argument:
  this only matters if we expect cold packs to need long-term
  availability without contributor involvement, which contradicts
  the "communication, not storage" framing. Defer to Phase 4 when
  storage-promise contracts come online.

- **History pruning.** The repo contract today accumulates every
  bundle ever pushed in `object_index`. We could prune older bundles
  to bound state size, but that's orthogonal — `validate_state`
  doesn't require historic bundles to remain reachable. If a bundle's
  contract goes cold and `freenet-git rescue` doesn't restore it, the
  user gets a "missing object" error on `git fetch` and goes to find
  a clone with those bytes. That's the model; don't try to hide it.

- **Reading old packs from the contributor's filesystem on demand.**
  Sketch: on fetch, when a chunk GET fails, check if any local clone
  in `~/.config/freenet/git-cache/<prefix>/` has the pack bytes and
  use them. Nice-to-have; not required for announce.

## Cross-cutting considerations

### Will this paint us into a corner?

- The ChunkedPack manifest format is versioned (`version: u8`). A
  future erasure-coded variant (`ChunkedPackManifestV2` with `K` and
  `M` fields) loads cleanly: `validate_state` of the repo contract
  doesn't change because `ObjectBundle::ChunkedPack` is opaque to it
  beyond the canonical bundle id; only the on-host helper interprets
  the manifest.
- A future erasure-coded variant could even be a NEW
  `ObjectBundle::ErasureCodedPack` enum variant, which the repo
  contract WASM just accepts (same signature shape, different bundle
  id derivation). This is the same pattern the issue spec already
  uses for the SinglePack/ChunkedPack split.

### Determinism

Manifest serialization must be deterministic — two implementations
producing different manifests for the same logical content would
fork. Use `bincode` with default config (deterministic for this
shape: u8/u32/u64/Vec of fixed bytes). Add a worked-example test in
`freenet-git-encoding` with pinned hex output, same pattern as the
existing canonical-CBOR fixtures.

### Self-healing for ChunkedPack

When `rescue` finds a missing manifest contract, it re-PUTs the
manifest from local cache. When it finds a missing chunk, it re-PUTs
that chunk. Same content-addressing guarantees apply (BLAKE3 verify
before upload).

### CLI default

`freenet-git create --chunk-size <N>` lets the user override (e.g.
to 512 KB for safer-margin, or 4 MB for bigger contracts on networks
that allow it). Default 1 MB.

The `git-remote-freenet` helper picks SinglePack vs ChunkedPack
automatically based on pack size. No user-facing flag on push.

## Test plan

Unit tests in `freenet-git-types`:
- Manifest serialize/deserialize round-trip.
- Worked-example fixture: input bytes → manifest → BLAKE3 → pinned hex.

Unit tests in the on-host helper:
- Encode-then-decode round-trip with multiple chunks.
- Decode rejects manifest with chunk count != chunk_hashes.len().
- Decode rejects manifest where any chunk's BLAKE3 != declared hash.

E2E test (uses local Freenet node):
- Push a 5 MB synthetic pack → expect ChunkedPack.
- Clone from second working dir → working tree matches.
- Delete one chunk contract from the local node, run `rescue` from a
  third dir that has the bytes locally → expect re-PUT, then clone
  succeeds again.

Live demo:
- Push `freenet-stdlib` HEAD (552 KB → 1 chunk via ChunkedPack path).
- Push `river/main` HEAD (8.7 MB → 9 chunks).
- Push `freenet-core/main` shallow HEAD (depth 100 or so) → ChunkedPack
  with however many 1 MB chunks that requires.

## Out-of-scope follow-ups (file as issues, do not implement now)

- **Erasure coding.** Phase 4ish, gated on storage-promise contracts.
- **Local-clone fallback fetcher** (try local sibling clones before
  failing on a missing chunk).
- **Pack repacking** (re-PUT a smaller delta-compressed pack covering
  multiple historical bundles, then prune old object_index entries
  the repacked pack supersedes).

## Why this is the right shape

- It's incremental over 0.1.0: no schema change to the repo contract,
  no URL change, no migration. Strictly additive.
- It matches git's natural access pattern (hot HEAD, cold history)
  to Freenet's natural availability profile (hot stays alive, cold
  evicts). We're not fighting either system.
- The "rescue" primitive turns the medium's eviction behavior from a
  bug into a workflow: anyone with a clone can heal the network.
- The work is bounded: ~1-2 days for ChunkedPack helper code, ~half
  day for rescue, ~half day for tests + demo. Erasure coding would
  add ~1-2 more days and meaningful code complexity for no
  announce-blocking benefit.

## Decision points the reviewer should challenge

1. **Default chunk size 1 MB** — is this safe given current Freenet
   per-contract limits? We've seen 552 KB pushes succeed; 8 MB
   pushes fail under load. 1 MB is a guess.
2. **Manifest as a pack-contract** vs. a dedicated manifest-contract
   WASM. Reusing pack-contract is one fewer WASM to ship; the
   manifest is just opaque bytes from the contract's view.
3. **Skipping erasure coding for announce.** Is the "communication,
   not storage" framing strong enough to defend in public against
   "but my old commits!" complaints?
4. **Skipping history pruning.** Should `object_index` have a max
   length, with the contract enforcing it? Today it's unbounded.
