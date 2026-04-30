//! Build the *initial* signed `RepoState` that gets PUT to the repo
//! contract on `freenet-git create`.

use ed25519_dalek::SigningKey;

use freenet_git_types::signing::{
    sign_acl_field, sign_optional_repo_key_field, sign_ref_list_field, sign_string_field,
};
use freenet_git_types::{AclState, RepoParams, RepoState};

/// Build the initial state for a brand-new repo: name, description,
/// default branch, empty force-push set, ACL placeholder (epoch 0, no
/// grants), no upgrade pointer. No refs and no bundles yet — those land
/// on the first push.
#[allow(clippy::field_reassign_with_default)]
pub fn initial_repo_state(
    params: &RepoParams,
    owner: &SigningKey,
    name: &str,
    description: &str,
    default_branch: &str,
) -> RepoState {
    let mut state = RepoState::default();
    state.name = Some(sign_string_field(
        params,
        owner,
        "name",
        name.to_string(),
        1,
    ));
    state.description = Some(sign_string_field(
        params,
        owner,
        "description",
        description.to_string(),
        1,
    ));
    state.default_branch = Some(sign_string_field(
        params,
        owner,
        "default_branch",
        default_branch.to_string(),
        1,
    ));
    state.force_push_allowed = Some(sign_ref_list_field(
        params,
        owner,
        "force_push_allowed",
        vec![],
        1,
    ));
    state.acl = Some(sign_acl_field(
        params,
        owner,
        "acl",
        AclState {
            epoch: 0,
            grants: std::collections::BTreeMap::new(),
        },
        1,
    ));
    state.upgrade = Some(sign_optional_repo_key_field(
        params, owner, "upgrade", None, 1,
    ));
    state
}

#[cfg(test)]
mod tests {
    use super::*;
    use freenet_git_types::validate_state;

    #[test]
    fn initial_state_validates() {
        let signing = SigningKey::from_bytes(&[7u8; 32]);
        let params = RepoParams {
            owner: signing.verifying_key().to_bytes(),
            repo_nonce: [11u8; 16],
        };
        let state = initial_repo_state(
            &params,
            &signing,
            "freenet-git",
            "self-hosted git over freenet",
            "refs/heads/main",
        );
        validate_state(&params, &state).expect("freshly-built initial state should validate");
    }
}
