//! End-to-end: sign every kind of entry with the owner's key, build a
//! `RepoState`, and confirm `validate_state` accepts it.
//!
//! Then exercise tampering: forge each entry in turn and confirm
//! `validate_state` rejects each one with the expected error variant.
//!
//! These tests run against the pure-Rust implementation, not the WASM
//! contract. The contract's `validate_state` just dispatches into the
//! same function, so passing here is the relevant security check.

#![cfg(feature = "signing")]
#![allow(clippy::field_reassign_with_default)]

use std::collections::BTreeMap;

use ed25519_dalek::SigningKey;
use freenet_git_types::signing::{
    sign_acl_field, sign_bundle_record, sign_extension, sign_optional_repo_key_field,
    sign_ref_entry, sign_ref_list_field, sign_string_field,
};
use freenet_git_types::{
    validate_state, AclState, ObjectBundle, RepoParams, RepoState, ValidateError,
};

fn fixed_key(seed: u8) -> SigningKey {
    let mut bytes = [0u8; 32];
    for (i, b) in bytes.iter_mut().enumerate() {
        *b = seed.wrapping_add(i as u8);
    }
    SigningKey::from_bytes(&bytes)
}

fn build_owner_state(owner: &SigningKey) -> (RepoParams, RepoState) {
    let params = RepoParams {
        owner: owner.verifying_key().to_bytes(),
        repo_nonce: [7u8; 16],
    };

    let mut state = RepoState::default();
    state.name = Some(sign_string_field(&params, owner, "name", "demo".into(), 1));
    state.description = Some(sign_string_field(
        &params,
        owner,
        "description",
        "a demo repo".into(),
        1,
    ));
    state.default_branch = Some(sign_string_field(
        &params,
        owner,
        "default_branch",
        "refs/heads/main".into(),
        1,
    ));
    state.force_push_allowed = Some(sign_ref_list_field(
        &params,
        owner,
        "force_push_allowed",
        vec![],
        1,
    ));
    state.acl = Some(sign_acl_field(
        &params,
        owner,
        "acl",
        AclState {
            epoch: 0,
            grants: BTreeMap::new(),
        },
        1,
    ));
    state.upgrade = Some(sign_optional_repo_key_field(
        &params, owner, "upgrade", None, 1,
    ));

    let entry = sign_ref_entry(&params, owner, "refs/heads/main", [0xAB; 20], 1, 0);
    state.refs.insert("refs/heads/main".into(), entry);

    let bundle = ObjectBundle::SinglePack {
        pack_hash: [0xCD; 32],
        size_bytes: 4096,
    };
    let bundle_id = bundle.id();
    let record = sign_bundle_record(&params, owner, bundle, 0);
    state.object_index.insert(bundle_id, record);

    let ext = sign_extension(
        &params,
        owner,
        "homepage",
        b"https://freenet.org".to_vec(),
        1,
    );
    state.extensions.insert("homepage".into(), ext);

    (params, state)
}

#[test]
fn fully_signed_state_validates() {
    let owner = fixed_key(0x10);
    let (params, state) = build_owner_state(&owner);
    validate_state(&params, &state).expect("freshly signed state must validate");
}

#[test]
fn forged_name_signature_is_rejected() {
    let owner = fixed_key(0x11);
    let (params, mut state) = build_owner_state(&owner);
    let field = state.name.as_mut().expect("set above");
    field.signature[0] ^= 0xFF;
    match validate_state(&params, &state) {
        Err(ValidateError::InvalidSignature(field)) => assert_eq!(field, "name"),
        other => panic!("expected InvalidSignature(name), got {:?}", other),
    }
}

#[test]
fn ref_signed_by_non_owner_is_rejected() {
    let owner = fixed_key(0x12);
    let attacker = fixed_key(0x22);
    let (params, mut state) = build_owner_state(&owner);
    let bad_entry = sign_ref_entry(&params, &attacker, "refs/heads/main", [0xEE; 20], 2, 0);
    state.refs.insert("refs/heads/main".into(), bad_entry);
    match validate_state(&params, &state) {
        Err(ValidateError::NonOwnerSigner) => {}
        other => panic!("expected NonOwnerSigner, got {:?}", other),
    }
}

#[test]
fn bundle_record_with_wrong_id_is_rejected() {
    let owner = fixed_key(0x13);
    let (params, mut state) = build_owner_state(&owner);

    // Take the existing record but file it under a wrong key.
    let (real_id, record) = state
        .object_index
        .iter()
        .next()
        .map(|(k, v)| (*k, v.clone()))
        .unwrap();
    state.object_index.clear();
    let mut wrong_id = real_id;
    wrong_id[0] ^= 0xFF;
    state.object_index.insert(wrong_id, record);

    match validate_state(&params, &state) {
        Err(ValidateError::BundleIdMismatch) => {}
        other => panic!("expected BundleIdMismatch, got {:?}", other),
    }
}

#[test]
fn bundle_record_signed_by_non_owner_is_rejected() {
    let owner = fixed_key(0x14);
    let attacker = fixed_key(0x24);
    let (params, mut state) = build_owner_state(&owner);

    let bundle = ObjectBundle::SinglePack {
        pack_hash: [0x99; 32],
        size_bytes: 1024,
    };
    let bundle_id = bundle.id();
    let bad_record = sign_bundle_record(&params, &attacker, bundle, 0);
    state.object_index.insert(bundle_id, bad_record);

    match validate_state(&params, &state) {
        Err(ValidateError::NonOwnerSigner) => {}
        other => panic!("expected NonOwnerSigner, got {:?}", other),
    }
}

#[test]
fn description_size_limit_enforced_before_signature_check() {
    let owner = fixed_key(0x15);
    let (params, mut state) = build_owner_state(&owner);
    let field = state.description.as_mut().expect("set above");
    field.value = "x".repeat(freenet_git_types::limits::MAX_DESCRIPTION_BYTES + 1);
    // Even though the signature no longer matches the new oversized value,
    // we expect FieldTooLong rather than InvalidSignature -- the size
    // check is the first guard so a malicious peer cannot cheaply force
    // expensive crypto verification.
    match validate_state(&params, &state) {
        Err(ValidateError::FieldTooLong { field, .. }) => assert_eq!(field, "description"),
        other => panic!("expected FieldTooLong(description), got {:?}", other),
    }
}

#[test]
fn extension_signed_by_non_owner_is_rejected() {
    let owner = fixed_key(0x16);
    let attacker = fixed_key(0x26);
    let (params, mut state) = build_owner_state(&owner);
    let bad_ext = sign_extension(&params, &attacker, "homepage", b"hijacked".to_vec(), 99);
    state.extensions.insert("homepage".into(), bad_ext);
    match validate_state(&params, &state) {
        Err(ValidateError::InvalidSignature(field)) => assert_eq!(field, "extension entry"),
        other => panic!(
            "expected InvalidSignature(extension entry), got {:?}",
            other
        ),
    }
}

#[test]
fn merge_picks_higher_seq_string_field() {
    use freenet_git_types::merge_state;

    let owner = fixed_key(0x17);
    let (params, mut state_a) = build_owner_state(&owner);
    let mut state_b = state_a.clone();

    state_a.name = Some(sign_string_field(
        &params,
        &owner,
        "name",
        "first".into(),
        5,
    ));
    state_b.name = Some(sign_string_field(
        &params,
        &owner,
        "name",
        "second".into(),
        6,
    ));

    let merged = merge_state(&state_a, &state_b);
    assert_eq!(
        merged.name.as_ref().expect("merged should have name").value,
        "second",
    );

    let merged_other_order = merge_state(&state_b, &state_a);
    assert_eq!(
        merged_other_order
            .name
            .as_ref()
            .expect("merged should have name")
            .value,
        "second",
    );
    assert!(validate_state(&params, &merged).is_ok());
}

#[test]
fn ref_crdt_convergence_under_concurrent_pushes() {
    use freenet_git_types::merge_state;

    let owner = fixed_key(0x18);
    let (params, base) = build_owner_state(&owner);

    // Two writers race from the same parent. Each produces a ref-update
    // with update_seq = current + 1 = 2.
    let mut a = base.clone();
    let mut b = base.clone();
    a.refs.insert(
        "refs/heads/main".into(),
        sign_ref_entry(&params, &owner, "refs/heads/main", [0x11; 20], 2, 0),
    );
    b.refs.insert(
        "refs/heads/main".into(),
        sign_ref_entry(&params, &owner, "refs/heads/main", [0x22; 20], 2, 0),
    );

    let merged_ab = merge_state(&a, &b);
    let merged_ba = merge_state(&b, &a);

    // Order-independent convergence.
    assert_eq!(merged_ab, merged_ba);

    // Exactly one ref entry survives.
    let ref_entry = &merged_ab.refs["refs/heads/main"];
    assert!(ref_entry.target == [0x11; 20] || ref_entry.target == [0x22; 20]);
    assert_eq!(ref_entry.update_seq, 2);

    assert!(validate_state(&params, &merged_ab).is_ok());
}
