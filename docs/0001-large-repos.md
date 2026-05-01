# Design 0001: Large repos on Freenet

**Status:** proposed (revision 2, post-Codex review)
**Target:** freenet-git 0.1.x (incremental over 0.1.0 already published)

## Problem

Phase 1.0 ships `SinglePack` only — a push uploads its packfile as one
immutable Freenet contract. Freenet has a practical per-contract size
limit in the low single-MB range. Real Freenet-ecosystem repos exceed
this:

- `freenet-stdlib` HEAD pack: 552 KB ✓ fits today
- `river/main` HEAD pack: 8.7 MB ✗ too big
- `freenet-core/main` HEAD pack: 176 MB ✗ way too big

Without a way to host a HEAD snapshot of medium repos, the announce
story ("Freenet hosts Freenet") is hollow.

## Framing decisions

### Freenet is a communication medium, not a storage medium

Freenet's natural behavior — popular contracts replicate, cold
contracts evict — fits git's actual access pattern. HEAD and recent
commits are hot. Old history is cold. Contributors with full clones
are the redundancy.

**But** "communication, not storage" does not mean "any availability
floor is acceptable." If a user can see a repo's URL but cannot clone
its HEAD, that is a *communication failure* of the medium, not an
expected consequence of cold archival. The risk we have to manage is
not "old commits going dark." It is "freshly-published HEAD becoming
unreachable because one chunk in the middle of the manifest evicted
before the repo got popular enough to replicate."

Worst case for plain ChunkedPack: a 176-chunk pack with per-chunk
availability `p=0.99` has full-fetch availability `0.99^176 ≈ 17%`.
That is announce-broken.

### Operational model for announced repos (load-bearing)

The repo owner — or a designated mirror — runs a Freenet node that
**subscribes** to every contract their repo references. Subscription
turns those contracts into hot data on the subscribed peer, so they
do not evict regardless of overall network demand. As soon as anyone
clones, they too become a subscribed peer (the helper subscribes on
fetch by default).

Concrete responsibilities of the owner / mirror:

1. Keep one node running and subscribed.
2. Run `freenet-git rescue freenet:<prefix>` periodically (e.g. as a
   cron job) to re-PUT any chunk that evicted from the wider network
   while no other subscriber held it.
3. If the owner-side node goes down without a designated mirror, the
   floor of the repo's availability is "whatever copies exist among
   recent cloners," which can be zero.

This is documented as part of the announce story, not hidden.

## Decision

Build two things in 0.1.x:

### 1. ChunkedPack — split large packs across multiple contracts

The schema already reserves
`ObjectBundle::ChunkedPack { manifest_hash, total_size, chunk_count }`.
Implement it in the helper.

#### Push protocol (atomic visibility)

Critical: the repo state must NEVER reference a `ChunkedPack` whose
chunks or manifest are not retrievable. The helper enforces this
with a four-phase commit:

```
1. PUT every chunk contract.
2. Re-GET each chunk and verify BLAKE3(bytes) == declared hash.
3. PUT the manifest contract.
4. Re-GET the manifest and verify BLAKE3(manifest_bytes) == manifest_hash.
5. Sign and submit the BundleAdd delta to the repo contract.
```

Failure modes:

- **Crash between 1 and 3:** orphan chunks on the network. Harmless;
  the next push won't reference them, and they evict on their own.
- **Crash between 3 and 5:** orphan chunks + orphan manifest. Same:
  harmless leakage, no broken references in any repo state.
- **Crash during 5:** repo state never advances. User retries; the
  push is idempotent because all the chunks and the manifest are
  content-addressed.
- **The forbidden case** — repo state advances while chunks are not
  yet remotely retrievable — is impossible because step 5 only
  happens after step 2 and 4 have re-GET-verified.

#### SinglePack vs ChunkedPack threshold (one rule)

```
if pack_size <= CHUNK_SIZE: SinglePack
else: ChunkedPack
```

Default `CHUNK_SIZE = 1 MiB = 1_048_576 bytes` (one rule for both
threshold and chunk size). A pack of exactly 1 MiB is `SinglePack`.
A pack of 1 MiB + 1 byte is `ChunkedPack` with two chunks (1 MiB +
1 byte). User can override via `--chunk-size`.

#### Manifest format (v1)

```rust
struct ChunkedPackManifestV1 {
    version: u8,                  // = 1
    chunk_size: u32,              // bytes per non-final chunk
    total_size: u64,              // sum of all chunk sizes
    chunk_count: u32,             // = chunk_hashes.len()
    chunk_hashes: Vec<[u8; 32]>,  // BLAKE3-32 of each chunk's bytes, in order
}
```

`bincode`-serialized; manifest hash is `BLAKE3(manifest_bytes)`.
The manifest is hosted as a regular `pack-contract` (one fewer WASM
to ship; manifest bytes are just opaque from the contract's view).

#### Manifest validity rules (verified at decode time)

A manifest is rejected if any of:

- `version != 1` — unknown future version.
- `chunk_count == 0` — empty bundles are illegal.
- `chunk_count != chunk_hashes.len()` — internal inconsistency.
- Any chunk's actual byte length, after fetch, differs from
  `chunk_size` (for the first `chunk_count - 1` chunks) or from
  `total_size - chunk_size * (chunk_count - 1)` (for the final
  chunk).
- `sum(chunk_lengths) != total_size`.
- The final chunk has length 0 or > `chunk_size`.
- `chunk_size == 0` — degenerate.

These are enforced in the on-host helper, not in the contract WASM
(the contract only does content-address verification on opaque bytes).

#### Authority of duplicated metadata

`ObjectBundle::ChunkedPack { manifest_hash, total_size, chunk_count }`
duplicates `total_size` and `chunk_count` from the manifest. The
**manifest is authoritative**. The fetcher:

1. Fetches the manifest (via `manifest_hash` from the bundle).
2. Verifies `BLAKE3(manifest_bytes) == manifest_hash`.
3. Decodes the manifest.
4. Verifies `bundle.total_size == manifest.total_size` AND
   `bundle.chunk_count == manifest.chunk_count`. **Mismatch fails
   hard** with "object_index entry is inconsistent with manifest" —
   this should never happen in honest operation, and if it does we
   refuse to use the bundle.

### 2. `freenet-git rescue` — reconstruct missing bytes from local sources

Walks `object_index`. For each referenced bundle:

1. Probe the network: GET the bundle's manifest (or pack for
   `SinglePack`). Classify into one of:
   - `RemotelyAvailable` — content-addressed verify passes.
   - `RemotelyMissing` — GET returned not-found / empty.
   - `RemotelyCorrupt` — GET returned bytes that fail
     `BLAKE3 == declared`. This shouldn't happen given the network's
     content-addressed contract validation, but we still re-verify.
2. For any non-`RemotelyAvailable` chunk, reconstruct from local
   sources in this priority order:
   1. **Local chunk cache** at `.git/freenet-cache/chunks/<hash>.bin`.
   2. **Local pack cache** at `.git/freenet-cache/packs/<hash>.pack`,
      with **deterministic re-chunking**: split the same way the
      original push would have, using the manifest's `chunk_size`,
      and re-derive each chunk by index.
   3. **Sibling clones** under configured search roots. The user
      passes `--from <path>` (repeatable) or sets
      `FREENET_GIT_RESCUE_FROM` to a colon-separated list of
      directories. The helper looks for git repos under each root,
      tries to find a pack containing the missing objects, and
      re-derives chunks from it.
3. Verify `BLAKE3(reconstructed_bytes) == expected_hash` BEFORE
   re-PUTting (defends against local cache tampering and against
   the helper's own re-chunking having a bug).
4. PUT the bytes. Wait for confirmation.

#### Reconstruction of the manifest itself

If the manifest contract is missing but the bundle entry still gives
`manifest_hash`, `total_size`, and `chunk_count`, and a local pack
source is available:

1. Re-derive what the manifest's `chunk_size` would have been
   (from the metadata fields available in the bundle entry).
2. Build candidate manifest bytes by re-chunking the local pack
   and listing the resulting chunk hashes.
3. Verify `BLAKE3(candidate) == manifest_hash`. If yes, PUT. If no,
   report `LocalSourceDoesNotMatch` — the local pack is not the
   one that produced this manifest.

#### Output classification

For each bundle in `object_index`, rescue prints one of:

```
already-present     freenet:<bundle_id>
re-uploaded         freenet:<bundle_id> (3 chunks, 2 from cache, 1 re-chunked)
unrepairable        freenet:<bundle_id> reason="no local source for chunk #14"
inconsistent        freenet:<bundle_id> reason="object_index entry disagrees with manifest"
remotely-corrupt    freenet:<bundle_id> chunk_hash=...
```

The exit code is 0 if every bundle is `already-present` or
`re-uploaded`, 1 otherwise. Cron-friendly.

### What we are explicitly NOT doing in 0.1.x

- **Erasure coding (Reed-Solomon, fountain codes).** Active mitigation
  (owner subscription + periodic rescue) substitutes for parity for
  the 0.1.x announce. Erasure coding becomes a Phase 4 feature for
  unattended-availability use cases (storage-promise contracts).
  We commit publicly to "0.1.x does not promise unattended
  availability of multi-chunk bundles." See "Operational model" above.
- **History pruning.** `object_index` continues to grow unbounded.
  We commit to a documented state-size ceiling instead (e.g. 4 MB);
  past that, the user has to start a new repo or wait for Phase 1.x
  pack-repacking.
- **Sibling-clone fallback on `git fetch`** (vs. on `rescue` only).
  Fetch fails fast; rescue is the human-driven repair path.

### Cross-cutting

#### Determinism

Manifest serialization must be deterministic — two implementations
producing different manifests for the same logical content would
produce different `manifest_hash`es and fork. Use `bincode` with
default config (deterministic for this shape: u8/u32/u64/Vec of
fixed-size byte arrays). Add a worked-example test in
`freenet-git-encoding`: for a fixed input pack and chunk_size, pin
the manifest bytes (hex) and the resulting `BLAKE3(manifest_bytes)`.

#### Forward compatibility

A future erasure-coded variant lands as a new `ObjectBundle`
variant (`ObjectBundle::ErasureCodedPack { ... }`). The repo
contract WASM does not need to interpret it — `validate_state`
handles `ObjectBundle` opaquely beyond the canonical bundle id.
Adding a variant is a contract WASM upgrade (which already implies
a new contract key per the URL prefix design), but no schema break
for existing `SinglePack` and `ChunkedPack` repos.

#### Visibility and leakage

It is fine for the network to hold orphan chunks and orphan
manifests. They evict on their own; no resource leak that requires
operator action. We do not implement an explicit "garbage collect
orphan contracts" path because there is no global view of orphan-ness
— a chunk that looks orphan from one repo could be referenced by a
fork.

## Decision points the reviewer should challenge

1. **Push atomicity protocol.** Is the four-phase commit (PUT chunks
   → re-GET verify → PUT manifest → re-GET verify → BundleAdd)
   sufficient? Specifically, is "re-GET against the local node" the
   right check, given the local node may serve from its own write
   cache rather than from any remote replica?
2. **Default `CHUNK_SIZE = 1 MiB`.** Is this safe given current
   Freenet per-contract limits? We've seen 552 KB pushes succeed and
   8.7 MB pushes fail. 1 MB is conservative but a guess. Is dynamic
   sizing (probe-then-pick) worth doing in 0.1.x or is a static
   default OK?
3. **No erasure coding for announce, gated on owner-side
   subscription + periodic rescue.** Is the operational burden
   acceptable for what we're trying to demo? Concretely: a maintainer
   running one always-on node + a `freenet-git rescue` cron entry per
   announced repo.
4. **`rescue` recovery sources.** The plan is cache → local pack
   re-chunking → `--from` sibling clones, all in 0.1.x. Is sibling-
   clone search worth doing now, or is "cache + local pack"
   sufficient and `--from` slips to 0.1.x+1?
5. **Manifest authority on mismatch.** Bundle entry vs manifest:
   manifest wins, mismatch is hard fail. Should there be a forgiving
   mode (use manifest, log warning, keep going) for libraries that
   over-eagerly re-read state and might see transient inconsistency?
6. **`object_index` unbounded.** What documented size ceiling do we
   commit to? Once we hit it, what's the user-visible behavior?
   Reject-on-push? Auto-prune (and lose history)?

## Implementation budget

- ChunkedPack helper code: ~1 day.
- Manifest format + validation + canonical fixture test: ~half day.
- `rescue` cache + local-pack reconstruction: ~half day.
- `rescue --from` sibling-clone search: ~half day.
- E2E test (push 5 MB synthetic pack, clone, delete one chunk on the
  local node, rescue from a third dir, clone again succeeds): ~half day.
- Live demo: push `freenet-stdlib`, `river`, and a shallow
  `freenet-core` HEAD: ~half day, mostly waiting on the gateway.

Total: ~3 days focused.
