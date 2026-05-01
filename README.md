# freenet-git

Git repositories hosted directly on [Freenet](https://freenet.org).

`freenet-git` lets you publish, push, fetch, and clone Git repositories
through the Freenet network using normal Git commands. There is no
central Git host, no federation layer, and no server you need to
operate. A repository is a Freenet contract; Git sees it through a
standard remote helper.

## Status

Experimental — Phase 1 of the design tracked in
[freenet-core#3985](https://github.com/freenet/freenet-core/issues/3985).

Working today:

- create a Freenet-hosted Git repository
- push commits (single pack and multi-chunk)
- fetch and clone through Git's remote-helper protocol
- clone live demo repos from the public Freenet network

Not yet supported:

- multi-writer ACL — only the repo owner can push (Phase 1.1)
- pull requests, issues, CI (Phases 2–4)
- releases / package registry, human-readable names (Phase 4+)
- self-healing `freenet-git rescue` command (filed; not yet shipped)
- parallel chunk uploads — pushing repos with hundreds of chunks is
  currently slow (filed; not yet shipped)

## Try a live Freenet-hosted repo

These are real Freenet contracts, hosted on the network and clonable
right now:

```sh
# freenet-core HEAD source snapshot (no full history)
git clone freenet::AaRxPZVdWrPh/freenet-core

# freenet-stdlib full git history (177 commits)
git clone freenet::2pyvKxrozxgT/freenet-stdlib
```

Requires `cargo install freenet-git` and a running local Freenet node.
See "Quick start" below.

## What this is

Git is already decentralized: every clone is a complete repository,
and any two clones can synchronize directly. What Git usually lacks
is decentralized *hosting* and *discovery*. GitHub, GitLab, and
Forgejo provide that layer by centralizing it on servers.

`freenet-git` moves the hosting layer onto Freenet. Repository state
lives in Freenet contracts; Git interacts with those contracts
through a standard remote helper. The long-term goal is **a
decentralized software forge**: repos first, then pull requests,
issues, CI attestations, releases, and names.

## Quick start

### 1. Install

You need a Rust toolchain. If you don't have one, install via
[rustup.rs](https://rustup.rs):

```sh
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

Then:

```sh
cargo install freenet-git
```

This installs both `freenet-git` (the companion CLI) and
`git-remote-freenet` (the Git remote helper). Make sure
`~/.cargo/bin` is on your `PATH`.

### 2. Run a local Freenet node

You need a Freenet node running locally to talk to. See the
[Freenet getting-started guide](https://docs.freenet.org/) — the
WebSocket API endpoint defaults to
`ws://127.0.0.1:50509/v1/contract/command`.

### 3. Clone a live repo

```sh
git clone freenet::2pyvKxrozxgT/freenet-stdlib
```

That's the lowest-friction first success: no identity, no setup,
just `git clone` against a real Freenet-hosted repository.

### 4. Publish your own repo

```sh
freenet-git init-identity --name "Your Name" --email you@example.com
cd ~/code/my-project
freenet-git create --name my-project --description "A thing"
# -> URL: freenet:RtTzy58hMxAB/my-project

git remote add freenet freenet::RtTzy58hMxAB/my-project

# git push needs the bundle passphrase via env var (see "Passphrase
# handling" below for why)
export FREENET_GIT_PASSPHRASE='your-passphrase'
git push freenet main
```

### Passphrase handling

`git push` and `git fetch` go through `git-remote-freenet`, which
runs as a child process of git. Git owns stdin and stdout for the
remote-helper protocol, so the helper can't prompt you for a
passphrase interactively. For now you must provide it via
`FREENET_GIT_PASSPHRASE`.

This is a Phase 1 UX compromise. Avoid putting the passphrase in
shell history or long-lived environment files. A future release
will add OS-keychain integration.

## How URLs work

A freenet-git URL looks like:

```text
freenet:RtTzy58hMxAB/my-project
        ^~~~~~~~~~~~ ^~~~~~~~~~
        prefix       label (optional)
```

For `git remote add` and `git clone`, use the **double-colon** form:

```text
freenet::RtTzy58hMxAB/my-project
```

The double colon is required by Git's
[remote-helpers protocol](https://git-scm.com/docs/gitremote-helpers)
to disambiguate from SCP-style URLs.

### Prefix

The prefix is the first 12 base58 characters of the repo owner's
ed25519 public key (~70 bits). It's the only part that participates
in identity, signatures, and network routing. The full Freenet
contract key is computed locally as
`BLAKE3(BLAKE3(repo-contract.wasm) || serialize({prefix}))`.

Anyone with a current `freenet-git` install resolves the same
contract key from the same prefix. The URL stays stable across
contract WASM upgrades — only the underlying contract key changes,
which the on-host helper handles transparently.

### Label

The label is a human-readable name following the prefix after a `/`.
It's purely cosmetic:

- Two URLs that differ only in their label resolve to the **same**
  repo.
- Git uses the label as the default clone-into directory name, so
  `git clone freenet::RtTzy58hMxAB/my-project` produces a
  `my-project/` directory.
- The label is never sent to the network and never signed against.

## Identity model

In Phase 1, only the repo owner can push to a given Freenet repo.
Other developers can still publish their own Freenet-hosted clones,
and maintainers can pull from them — the same workflow that built
the Linux kernel before centralized forges became dominant. Phase
1.1 will add multi-writer ACL.

Each repo has its own ed25519 keypair, mirroring the
[delta site](https://github.com/freenet/delta) model (a Freenet
project that hosts websites the same way):

- `freenet-git init-identity` creates a default identity (used for
  cross-repo signing in Phase 2 — PR comments and reviews).
- `freenet-git create` generates a fresh per-repo keypair and
  stores it in your bundle's `repos` registry. The URL prefix is
  derived from this per-repo public key.
- Losing one repo's key compromises only that repo, not your
  identity.
- Bundles are passphrase-encrypted with `scrypt` + ChaCha20-Poly1305.
  Move them between machines via `freenet-git export-identity`
  and `freenet-git import-identity`.

## Roadmap

The goal is not just "Git transport over Freenet"; it is a
decentralized software forge, built incrementally:

- **Phase 1.0 (current):** single-writer push/fetch/clone.
- **Phase 1.1:** multi-writer ACL with epoch model and grant/revoke.
- **Phase 2:** pull requests as proposal contracts; signed comments
  and reviews.
- **Phase 3:** CI with cryptographic attestation.
- **Phase 4+:** issues, releases, identity, registry, names.

See [freenet-core#3985](https://github.com/freenet/freenet-core/issues/3985)
for the design and rationale.

## Repository layout

```
crates/
  encoding/         length-prefixed signed payloads + canonical CBOR.
                    Wire format both contracts and binaries pin to.
  types/            RepoState, deltas, validate_state, update_state,
                    CRDT merge, ChunkedPack manifest. Pure Rust,
                    unit-tested without WASM.
  identity/         passphrase-encrypted ed25519 keypair bundle.
  repo-contract/    WASM contract: mutable repo state (refs + bundle index).
  pack-contract/    WASM contract: immutable packfile bytes.
  freenet-git/      both binaries (`freenet-git` CLI + `git-remote-freenet`
                    helper) and the bundled contract WASMs.
docs/
  0001-large-repos.md   ChunkedPack design (incl. Codex review).
```

## License

LGPL-3.0-only. See `LICENSE`.
