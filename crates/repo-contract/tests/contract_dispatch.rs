//! Round-trip the repo contract's WASM-facing entrypoints with realistic
//! signed states. Confirms the stdlib boundary (Parameters / State /
//! StateDelta / StateSummary serde) is wired correctly to the pure logic
//! in `freenet-git-types`.

use ed25519_dalek::SigningKey;
use freenet_git_repo_contract::Contract;
use freenet_git_types::signing::{sign_ref_entry, sign_string_field};
use freenet_git_types::{RepoParams, RepoState, RepoSummary};
use freenet_stdlib::prelude::{
    ContractInterface, Parameters, RelatedContracts, State, StateDelta, StateSummary, UpdateData,
    ValidateResult,
};

fn fixed_key(seed: u8) -> SigningKey {
    let mut bytes = [0u8; 32];
    for (i, b) in bytes.iter_mut().enumerate() {
        *b = seed.wrapping_add(i as u8);
    }
    SigningKey::from_bytes(&bytes)
}

fn make_params(owner: &SigningKey) -> RepoParams {
    let pub_bytes = owner.verifying_key().to_bytes();
    RepoParams::from_owner(&pub_bytes, freenet_git_types::limits::DEFAULT_PREFIX_LEN)
}

fn make_signed_state(owner: &SigningKey, params: &RepoParams, target: [u8; 20]) -> RepoState {
    let owner_pub = owner.verifying_key().to_bytes();
    let mut state = RepoState {
        owner: owner_pub,
        name: Some(sign_string_field(params, owner, "name", "demo".into(), 1)),
        ..Default::default()
    };
    state.refs.insert(
        "refs/heads/main".into(),
        sign_ref_entry(params, owner, "refs/heads/main", target, 1, 0),
    );
    state
}

#[test]
fn validate_state_accepts_owner_signed() {
    let owner = fixed_key(0x30);
    let params = make_params(&owner);
    let state = make_signed_state(&owner, &params, [0xAB; 20]);

    let result = Contract::validate_state(
        Parameters::from(params.to_bytes()),
        State::from(state.to_bytes()),
        RelatedContracts::default(),
    );
    assert!(
        matches!(result, Ok(ValidateResult::Valid)),
        "got {result:?}"
    );
}

#[test]
fn validate_state_rejects_forged_signature() {
    let owner = fixed_key(0x31);
    let params = make_params(&owner);
    let mut state = make_signed_state(&owner, &params, [0xAB; 20]);

    // Forge: tamper with the signed name field signature.
    state.name.as_mut().unwrap().signature[0] ^= 0xFF;

    let result = Contract::validate_state(
        Parameters::from(params.to_bytes()),
        State::from(state.to_bytes()),
        RelatedContracts::default(),
    );
    assert!(result.is_err(), "expected forged signature to be rejected");
}

#[test]
fn update_state_with_delta_advances_ref() {
    let owner = fixed_key(0x32);
    let params = make_params(&owner);
    let initial = make_signed_state(&owner, &params, [0xAB; 20]);

    // Build a delta state that bumps the ref.
    let mut delta = RepoState::default();
    delta.refs.insert(
        "refs/heads/main".into(),
        sign_ref_entry(&params, &owner, "refs/heads/main", [0xCD; 20], 2, 0),
    );

    let result = Contract::update_state(
        Parameters::from(params.to_bytes()),
        State::from(initial.to_bytes()),
        vec![UpdateData::Delta(StateDelta::from(delta.to_bytes()))],
    )
    .expect("update_state should succeed");

    let new_state = RepoState::from_bytes(result.new_state.expect("new state").as_ref()).unwrap();
    let entry = new_state.refs.get("refs/heads/main").unwrap();
    assert_eq!(entry.target, [0xCD; 20]);
    assert_eq!(entry.update_seq, 2);
}

#[test]
fn summarize_then_get_state_delta_round_trips() {
    let owner = fixed_key(0x33);
    let params = make_params(&owner);
    let state = make_signed_state(&owner, &params, [0xAB; 20]);

    let summary = Contract::summarize_state(
        Parameters::from(params.to_bytes()),
        State::from(state.to_bytes()),
    )
    .expect("summarize");
    assert!(!summary.as_ref().is_empty());

    // Decode summary and assert it captured what we expect.
    let parsed: RepoSummary = bincode::deserialize(summary.as_ref()).unwrap();
    assert_eq!(parsed.field_seqs.get("name"), Some(&1));
    assert_eq!(parsed.ref_seqs.get("refs/heads/main"), Some(&1));

    // A peer that already has this state asks for a delta against the same
    // summary; we expect an empty delta.
    let delta = Contract::get_state_delta(
        Parameters::from(params.to_bytes()),
        State::from(state.to_bytes()),
        StateSummary::from(summary.as_ref().to_vec()),
    )
    .expect("delta");
    assert!(delta.as_ref().is_empty(), "no-op delta should be empty");
}
