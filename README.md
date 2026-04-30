# freenet-git

Git over [Freenet](https://freenet.org). Push, fetch, and clone Git
repositories through the Freenet network instead of a centralized host.

> **Live demo:** this README is also hosted on Freenet at
> `freenet::3ECc6j4vtAjL/freenet-git`. After
> `cargo install freenet-git` and starting a local Freenet node:
> `git clone freenet::3ECc6j4vtAjL/freenet-git`.

> **Status: Phase 1 demo working end-to-end** against the live Freenet
> network. Tracked in
> [freenet-core#3985](https://github.com/freenet/freenet-core/issues/3985).
>
> Phase 1.0 is **single-writer** — the repo owner is the only writer.
> Collaboration follows the original Linus-style Git model: every
> contributor has their own clone of the repo as a Freenet contract,
> and changes flow by pulling from each other's URLs. Multi-writer ACL
> is Phase 1.1 (issue #3); schema is forward-compatible so it lands as
> a contract WASM upgrade, not a new schema.

## What this is

Git was originally designed as a fully-decentralized version control
system — every clone is a complete repository, and any two clones can
synchronize directly without a central authority. GitHub layered a
centralized social and review experience on top of that distributed
substrate. Hosting Git on Freenet returns Git to its original
architecture, while rebuilding the social layer (pull requests, issues,
CI) in a way that matches Git's decentralization rather than fighting
it.

## URLs

A freenet-git URL looks like:

```
freenet:RtTzy58hMxAB/my-project
        ^~~~~~~~~~~~ ^~~~~~~~~~
        prefix       label (optional)
```

The **prefix** is the first 12 base58 characters of the repo owner's
ed25519 public key (~70 bits). It's the only part that participates
in identity, signatures, and network routing. The full Freenet
contract key is computed from the prefix plus the bundled contract
WASM (`BLAKE3(BLAKE3(repo-contract.wasm) || serialize({prefix}))`)
— anyone with the URL plus a current `freenet-git` install resolves
the same key.

The **label** is a human-readable name (typically the repo's name)
that follows the prefix after a `/`. It is purely cosmetic: two URLs
that differ only in their label resolve to the same repo. `git clone`
uses the label as the default clone-into directory name.

For `git remote add` and `git clone`, use the double-colon form
`freenet::RtTzy58hMxAB/my-project` (git's
[remote-helper protocol][git-remote-helpers] requires the doubled
colon to disambiguate from SCP-style URLs).

## Quick start

### Prerequisites

You need:

1. A Rust toolchain. If you don't have one, install via
   [rustup.rs](https://rustup.rs):

   ```bash
   curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
   ```

2. A running local Freenet node. See the
   [Freenet getting-started guide](https://docs.freenet.org/) to run
   one — the WebSocket API endpoint is `ws://127.0.0.1:50509/v1/contract/command`
   by default.

### Install

```bash
cargo install freenet-git
```

This installs both `freenet-git` (the companion CLI) and
`git-remote-freenet` (the Git remote helper). Make sure
`~/.cargo/bin` is on your `PATH`.

### Use

```bash
# 1. One-time identity setup. Generates an encrypted bundle at
#    ~/.config/freenet/git-identity.bundle. The "identity" key is
#    used for things that follow you across repos (PR comments in
#    Phase 2). Each repo gets its own per-repo signing key on create.
freenet-git init-identity --name "Your Name" --email you@example.com

# 2. Publish a repo. Generates a fresh per-repo keypair and PUTs the
#    contract to the local node.
cd ~/code/my-project
freenet-git create --name my-project --description "A thing"
#   URL:     freenet:RtTzy58hMxAB/my-project
#   git URL: freenet::RtTzy58hMxAB/my-project

# 3. Push commits.
git remote add freenet freenet::RtTzy58hMxAB/my-project
git push freenet main

# 4. Anyone, anywhere can clone.
git clone freenet::RtTzy58hMxAB/my-project   # creates a `my-project/` dir
```

The helper reads the per-repo signing key from your identity bundle.
Because git owns stdin/stdout while running a remote helper, you must
provide your bundle passphrase via the `FREENET_GIT_PASSPHRASE`
environment variable for `git push`/`git pull`. (`freenet-git`
sub-commands prompt interactively when stdin is a TTY.)

```bash
export FREENET_GIT_PASSPHRASE='...'
git push freenet main
```

## Identity model

Each repo carries its own ed25519 keypair, mirroring the
[delta site](https://github.com/freenet/delta) model:

- The bundle's "default" identity (created by `init-identity`) is
  reserved for cross-repo signing — PR comments and reviews in
  Phase 2.
- The bundle's `repos` registry holds one keypair per repo created
  with this bundle. The URL prefix is derived from each repo's
  per-repo public key.
- Losing one repo's key compromises only that one repo, not your
  entire identity.
- The same identity bundle on two machines (via `export-identity` /
  `import-identity`) shares all repos.

## Roadmap

- **Phase 1.0 (current):** Single-writer push/fetch/clone. Identity
  custody as a passphrase-encrypted bundle on disk.
- **Phase 1.1:** Multi-writer ACL (epoch model with grant/revoke).
  Schema is forward-compatible from day one — adding ACL is a
  contract WASM upgrade, not a new schema.
- **Phase 2:** Pull requests. Proposal contracts referencing source
  repos by URL prefix; signed comments and reviews.
- **Phase 3:** CI with cryptographic attestation.
- **Phase 4+:** Issues, releases, identity, registry, names.

See [freenet-core#3985](https://github.com/freenet/freenet-core/issues/3985)
for the full design.

## Repository layout

```
crates/
  encoding/         # length-prefixed signed payloads + canonical CBOR
                    # (the wire format both contracts and binaries pin to)
  types/            # RepoState, deltas, validate_state, update_state,
                    # CRDT merge — pure Rust, unit-tested without WASM
  identity/         # passphrase-encrypted ed25519 keypair bundle
  repo-contract/    # WASM contract: mutable repo state (refs + bundle index)
  pack-contract/    # WASM contract: immutable packfile bytes
  freenet-git/      # both binaries (the CLI + the git remote helper)
                    #   and the bundled contract WASMs
```

[git-remote-helpers]: https://git-scm.com/docs/gitremote-helpers

## License

LGPL-3.0-only. See `LICENSE`.
