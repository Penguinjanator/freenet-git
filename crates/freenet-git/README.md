# freenet-git

Git over [Freenet](https://freenet.org). Push, fetch, and clone Git repositories
through the Freenet network instead of a centralized host.

> **Status: Phase 1 demo working end-to-end.** Tracked in
> [freenet-core#3985](https://github.com/freenet/freenet-core/issues/3985).
>
> Demonstrated against the live Freenet network: `freenet-git create`
> publishes a repo contract, `git push freenet::<id> main` uploads
> objects and signs a ref-update, `git clone freenet::<id>` materializes
> a working tree on a fresh machine, and `git pull` brings down
> incremental changes.
>
> Phase 1.0 is **single-writer** — the repo owner is the only writer.
> Multi-writer ACL is Phase 1.1 (issue #3). Schema is forward-compatible
> so it lands as a contract WASM upgrade, not a new schema.

## What this is

Git was originally designed as a fully-decentralized version control system —
every clone is a complete repository, and any two clones can synchronize
directly without a central authority. GitHub layered a centralized social and
review experience on top of that distributed substrate. Hosting Git on Freenet
returns Git to its original architecture, while rebuilding the social layer
(pull requests, issues, CI) in a way that matches Git's decentralization
rather than fighting it.

## Phase 1: just Git

Phase 1 ships two binaries:

- `git-remote-freenet` — the [Git remote helper][git-remote-helpers] that lets
  Git push and fetch via Freenet. Drop it on your `PATH` and `git clone
  freenet:<repo-key>` works natively.
- `freenet-git` — companion CLI for actions Git itself does not have native
  commands for: identity management, repo creation, inspection, subscription.

Phase 1 is **single-writer**: the user who creates a repo is the only writer.
Collaboration follows the original Linus-style Git model — every contributor
has their own clone of the repo as a Freenet contract, and changes flow by
pulling from each other's URLs. This is the same workflow that built the Linux
kernel.

[git-remote-helpers]: https://git-scm.com/docs/gitremote-helpers

## Roadmap

- **Phase 1.0 (current):** Single-writer push/fetch/clone. Identity custody as a
  passphrase-encrypted bundle on disk.
- **Phase 1.1:** Multi-writer ACL (epoch model with grant/revoke). Schema is
  forward-compatible from day one — adding ACL is a contract WASM upgrade, not
  a new schema.
- **Phase 2:** Pull requests. Proposal contracts referencing source repos by
  contract key; signed comments and reviews.
- **Phase 3:** CI with cryptographic attestation.
- **Phase 4+:** Issues, releases, identity, registry, names.

See [freenet-core#3985](https://github.com/freenet/freenet-core/issues/3985)
for the full design.

## Quick start

> Requires a running local Freenet node on port 7509 (the default). See the
> [Freenet getting-started guide](https://docs.freenet.org/) to run one.

```bash
# 1. One-time identity setup
freenet-git init-identity --name "Your Name" --email you@example.com

# 2. Publish a repo
cd ~/code/my-project
freenet-git create --name my-project --description "A thing"
# -> freenet:7Hk9pQrS3VxNmL2tBdFcWyR8EzAj5K4nVcUtPq

# 3. Push to it
git remote add freenet freenet:7Hk9pQrS3VxNmL2tBdFcWyR8EzAj5K4nVcUtPq
git push freenet main

# 4. Anyone, anywhere can clone
git clone freenet:7Hk9pQrS3VxNmL2tBdFcWyR8EzAj5K4nVcUtPq
```

## Repository layout

```
crates/
  encoding/            # length-prefixed signed payloads + canonical CBOR
                       # (the wire format both contracts and binaries pin to)
  types/               # RepoState, deltas, validate_state and update_state
                       # logic — pure Rust so it can be unit-tested without WASM
  identity/            # passphrase-encrypted ed25519 keypair bundle
  client/              # WebSocket client for talking to the local Freenet node
  repo-contract/       # WASM contract: mutable repo state (refs + bundle index)
  pack-contract/       # WASM contract: immutable packfile bytes
  git-remote-freenet/  # binary: Git remote helper
  freenet-git/         # binary: companion CLI
```

## License

LGPL-3.0-only. See `LICENSE`.
