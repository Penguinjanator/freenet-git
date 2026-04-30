//! Helpers for deriving Freenet contract ids for the repo and pack
//! contracts. Wraps `ContractInstanceId::from_params_and_code` so the rest
//! of the CLI can derive ids without depending on the stdlib's `ContractCode`
//! constructor at every call site.

use freenet_stdlib::prelude::{ContractCode, ContractInstanceId, Parameters};

use freenet_git_types::RepoParams;

/// Compute the [`ContractInstanceId`] of a repo contract from a URL prefix
/// (the value the user shared) and the WASM bytes of
/// `freenet-git-repo-contract`. The contract key is
/// `BLAKE3(BLAKE3(WASM) || serialize({prefix}))`.
pub fn repo_contract_id_from_prefix(repo_wasm: &[u8], prefix: &str) -> ContractInstanceId {
    let params = RepoParams {
        prefix: prefix.to_string(),
    };
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Same prefix and wasm produce the same contract id (sanity check
    /// that the stdlib helper is doing what we think).
    #[test]
    fn repo_id_is_stable_for_fixed_inputs() {
        let wasm = b"fake-repo-wasm-bytes".to_vec();
        let id_a = repo_contract_id_from_prefix(&wasm, "abc1234567");
        let id_b = repo_contract_id_from_prefix(&wasm, "abc1234567");
        assert_eq!(id_a, id_b);
    }

    /// Different prefixes produce different ids.
    #[test]
    fn different_prefix_changes_id() {
        let wasm = b"fake-repo-wasm-bytes".to_vec();
        assert_ne!(
            repo_contract_id_from_prefix(&wasm, "abc1234567"),
            repo_contract_id_from_prefix(&wasm, "xyz1234567"),
        );
    }

    /// Different prefix lengths for the same logical owner produce
    /// different contract ids — same owner key, two different repos.
    #[test]
    fn prefix_length_changes_id() {
        let wasm = b"fake-repo-wasm-bytes".to_vec();
        assert_ne!(
            repo_contract_id_from_prefix(&wasm, "abc1234567"),
            repo_contract_id_from_prefix(&wasm, "abc12345678"),
        );
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
