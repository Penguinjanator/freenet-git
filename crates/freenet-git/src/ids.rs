//! Helpers for deriving Freenet contract ids for the repo and pack
//! contracts. Wraps `ContractInstanceId::from_params_and_code` so the rest
//! of the CLI can derive ids without depending on the stdlib's `ContractCode`
//! constructor at every call site.

use freenet_stdlib::prelude::{ContractCode, ContractInstanceId, Parameters};

use freenet_git_types::{RepoNonce, RepoParams};

/// Compute the [`ContractInstanceId`] of a repo contract from its parameters
/// and the WASM bytes of `freenet-git-repo-contract`.
pub fn repo_contract_id(repo_wasm: &[u8], params: &RepoParams) -> ContractInstanceId {
    let parameters = Parameters::from(params.to_bytes());
    let code = ContractCode::from(repo_wasm.to_vec());
    ContractInstanceId::from_params_and_code(parameters, code)
}

/// Compute the [`ContractInstanceId`] of a pack contract for a packfile of
/// `pack_bytes`. The pack contract's parameters are exactly the BLAKE3-32 of
/// the pack bytes, so this also tells us the canonical content-addressed
/// id under which to PUT the pack.
pub fn pack_contract_id(pack_wasm: &[u8], pack_bytes: &[u8]) -> ContractInstanceId {
    let pack_hash = *blake3::hash(pack_bytes).as_bytes();
    let parameters = Parameters::from(pack_hash.to_vec());
    let code = ContractCode::from(pack_wasm.to_vec());
    ContractInstanceId::from_params_and_code(parameters, code)
}

/// Generate a random 16-byte [`RepoNonce`] for a freshly-created repo.
pub fn fresh_repo_nonce() -> RepoNonce {
    use rand::RngCore;
    let mut nonce = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    nonce
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Same parameters and wasm produce the same contract id (sanity check
    /// that the stdlib helper is doing what we think).
    #[test]
    fn repo_id_is_stable_for_fixed_inputs() {
        let wasm = b"fake-repo-wasm-bytes".to_vec();
        let params = RepoParams {
            owner: [9u8; 32],
            repo_nonce: [3u8; 16],
        };
        let id_a = repo_contract_id(&wasm, &params);
        let id_b = repo_contract_id(&wasm, &params);
        assert_eq!(id_a, id_b);
    }

    /// Different repo nonces produce different ids — that's the whole
    /// reason `repo_nonce` is in parameters.
    #[test]
    fn repo_nonce_changes_id() {
        let wasm = b"fake-repo-wasm-bytes".to_vec();
        let p1 = RepoParams {
            owner: [9u8; 32],
            repo_nonce: [3u8; 16],
        };
        let p2 = RepoParams {
            owner: [9u8; 32],
            repo_nonce: [4u8; 16],
        };
        assert_ne!(repo_contract_id(&wasm, &p1), repo_contract_id(&wasm, &p2));
    }

    #[test]
    fn pack_id_is_content_addressed() {
        let wasm = b"fake-pack-wasm-bytes".to_vec();
        let id_a = pack_contract_id(&wasm, b"hello pack");
        let id_b = pack_contract_id(&wasm, b"hello pack");
        let id_c = pack_contract_id(&wasm, b"hello pack!");
        assert_eq!(id_a, id_b);
        assert_ne!(id_a, id_c);
    }
}
