# freenet-git

Git repositories hosted directly on [Freenet](https://freenet.org).
Push, fetch, and clone through the Freenet network using normal Git
commands, without GitHub, GitLab, federation, or a server you operate.
A repository is a Freenet contract; Git sees it through a standard
remote helper.

## Status

Experimental. Phase 1 of the design tracked in
[freenet-core#3985](https://github.com/freenet/freenet-core/issues/3985).

Working today:

- create a Freenet-hosted Git repository
- push commits (single pack and multi-chunk)
- fetch and clone through Git's remote-helper protocol
- clone live demo repos from the public Freenet network

Not yet supported:

- **Multi-writer ACL.** Today only the repo owner can push directly.
  This is closer to Git's original Linus-kernel model: every
  contributor publishes their own Freenet-hosted clone, maintainers
  pull from them. ACL (Phase 1.1) is for people who prefer the
  GitHub-style "everyone pushes to one canonical repo" workflow.
- **Pull requests** as proposal contracts with signed comments and
  reviews (Phase 2).
- **Issues** as per-repo append-only contracts with signed status
  changes and labels (Phase 4+).
- **CI / GitHub Actions equivalent.** The hard part isn't running
  the jobs (anyone can run their own runner). The forge-shaped
  problem is *coordinating* runner queues, posting signed results,
  and giving viewers a way to verify "this commit's tests passed."
  freenet-git will provide the coordination contracts (job queue,
  result attestations); the runners themselves are out-of-process
  workers users opt into running. Runner trust models, ranging from
  N-of-M reproducible-build agreement to TEE attestation to simple
  whitelisted runners, are sketched in
  [freenet-core#3985](https://github.com/freenet/freenet-core/issues/3985).
- **Releases / package registry, human-readable names** (Phase 4+).
- **Self-healing `freenet-git rescue` command** for re-PUTting bytes
  the network has forgotten (filed; not yet shipped).
- **Parallel chunk uploads.** Pushing repos with hundreds of chunks
  is currently slow (filed; not yet shipped).

## Live demos

Hosted on Freenet and clonable today:

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
[Freenet getting-started guide](https://docs.freenet.org/). The
WebSocket API endpoint defaults to
`ws://127.0.0.1:50509/v1/contract/command`.

### 3. Clone a live repo

```sh
git clone freenet::2pyvKxrozxgT/freenet-stdlib
```

No identity, no setup. Just `git clone` against a real
Freenet-hosted repository.

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
shell history or long-lived environment files. A future release will
add OS-keychain integration.

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
contract WASM upgrades; only the underlying contract key changes,
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

Today, only the repo owner can push to a given Freenet repo. Other
developers publish their own Freenet-hosted clones and maintainers
pull from them. This is the same workflow that built the Linux
kernel before centralized forges became dominant.

Phase 1.1 adds opt-in multi-writer ACL for projects that prefer the
GitHub-style "everyone pushes to one canonical repo" model. Both
modes will coexist.

Each repo has its own ed25519 keypair, so compromising one repo's
key does not compromise your cross-repo identity:

- `freenet-git init-identity` creates a default identity (used for
  cross-repo signing in Phase 2: PR comments and reviews).
- `freenet-git create` generates a fresh per-repo keypair and stores
  it in your bundle's `repos` registry. The URL prefix is derived
  from this per-repo public key.
- Bundles are passphrase-encrypted with `scrypt` + ChaCha20-Poly1305.
  Move them between machines via `freenet-git export-identity` and
  `freenet-git import-identity`.

## Roadmap

The goal is a decentralized software forge, built incrementally:

- **Phase 1.0 (current):** single-writer push/fetch/clone (the
  Linus-kernel model).
- **Phase 1.1:** opt-in multi-writer ACL for projects that want a
  GitHub-style canonical repo with shared write access.
- **Phase 2:** pull requests as proposal contracts; signed comments
  and reviews; cross-repo references (your fork to maintainer's
  upstream).
- **Phase 3:** CI coordination. Job-queue contracts, signed result
  attestations. Runners are out-of-process workers that users opt
  into running; trust model can range from a simple
  maintainer-whitelist to N-of-M reproducible-build agreement to
  TEE attestation.
- **Phase 4+:** issues (per-repo append-only signed timelines),
  releases (signed tag refs + artifact contracts), human-readable
  names (a Freenet-native ENS-style layer), per-user identity
  contracts that link to PGP/SSH/GitHub identities for continuity.

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
