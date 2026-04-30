//! Library half of `freenet-git`. Holds the bits that are easier to test
//! when not wrapped in `clap`.

#![deny(unsafe_code)]
#![warn(missing_docs)]

pub mod ids;
pub mod state_init;
pub mod url;
pub mod wsclient;

/// The compiled `repo-contract` WASM bytes, embedded at build time.
///
/// Bundling the WASM means a `cargo install freenet-git` user does not
/// have to download or compile contracts separately. The bytes are pinned
/// against the `freenet-git` package version: every release carries the
/// exact contract WASM it was tested against.
pub const REPO_CONTRACT_WASM: &[u8] = include_bytes!("../contracts/repo-contract.wasm");

/// The compiled `pack-contract` WASM bytes, embedded at build time.
pub const PACK_CONTRACT_WASM: &[u8] = include_bytes!("../contracts/pack-contract.wasm");
