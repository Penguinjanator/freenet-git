//! Signing helpers used by the `freenet-git` and `git-remote-freenet`
//! binaries. Behind the `signing` feature flag because contract WASM does
//! not need a full ed25519 signing key (it only verifies).

use ed25519_dalek::{Signer, SigningKey};

use crate::{
    signature_domain_key, signed_payload_acl_field, signed_payload_bundle_record,
    signed_payload_extension, signed_payload_optional_repo_key_field, signed_payload_ref_entry,
    signed_payload_ref_list_field, signed_payload_string_field, AclState, CommitHash,
    ExtensionEntry, ObjectBundle, ObjectBundleRecord, RefEntry, RefName, RepoKey, RepoParams,
    Signature, SignedField,
};

/// Produce a [`SignedField<String>`] for the `name`, `description`, or
/// `default_branch` fields. The `field_name` argument MUST match what
/// [`crate::validate_state`] expects for the corresponding field.
pub fn sign_string_field(
    params: &RepoParams,
    key: &SigningKey,
    field_name: &str,
    value: String,
    update_seq: u64,
) -> SignedField<String> {
    let repo_key = signature_domain_key(params);
    let payload = signed_payload_string_field(&repo_key, field_name, &value, update_seq);
    let sig = sign_to_array(key, &payload);
    SignedField {
        value,
        update_seq,
        signature: sig,
    }
}

/// Produce a [`SignedField<Vec<RefName>>`] for `force_push_allowed`.
pub fn sign_ref_list_field(
    params: &RepoParams,
    key: &SigningKey,
    field_name: &str,
    value: Vec<RefName>,
    update_seq: u64,
) -> SignedField<Vec<RefName>> {
    let repo_key = signature_domain_key(params);
    let payload = signed_payload_ref_list_field(&repo_key, field_name, &value, update_seq);
    let sig = sign_to_array(key, &payload);
    SignedField {
        value,
        update_seq,
        signature: sig,
    }
}

/// Produce a [`SignedField<AclState>`].
pub fn sign_acl_field(
    params: &RepoParams,
    key: &SigningKey,
    field_name: &str,
    value: AclState,
    update_seq: u64,
) -> SignedField<AclState> {
    let repo_key = signature_domain_key(params);
    let payload = signed_payload_acl_field(&repo_key, field_name, &value, update_seq);
    let sig = sign_to_array(key, &payload);
    SignedField {
        value,
        update_seq,
        signature: sig,
    }
}

/// Produce a [`SignedField<Option<RepoKey>>`] for `upgrade`.
pub fn sign_optional_repo_key_field(
    params: &RepoParams,
    key: &SigningKey,
    field_name: &str,
    value: Option<RepoKey>,
    update_seq: u64,
) -> SignedField<Option<RepoKey>> {
    let repo_key = signature_domain_key(params);
    let payload =
        signed_payload_optional_repo_key_field(&repo_key, field_name, value.as_ref(), update_seq);
    let sig = sign_to_array(key, &payload);
    SignedField {
        value,
        update_seq,
        signature: sig,
    }
}

/// Produce a [`RefEntry`] signed by the given key. In Phase 1.0 this key
/// must be the owner's; the helper enforces that at construction time by
/// supplying `params.owner` as the public-key field.
pub fn sign_ref_entry(
    params: &RepoParams,
    key: &SigningKey,
    ref_name: &str,
    target: CommitHash,
    update_seq: u64,
    auth_epoch: u64,
) -> RefEntry {
    let repo_key = signature_domain_key(params);
    let payload = signed_payload_ref_entry(&repo_key, ref_name, &target, update_seq, auth_epoch);
    let sig = sign_to_array(key, &payload);
    RefEntry {
        target,
        update_seq,
        updater: key.verifying_key().to_bytes(),
        auth_epoch,
        signature: sig,
    }
}

/// Produce an [`ObjectBundleRecord`] signed by the given key.
pub fn sign_bundle_record(
    params: &RepoParams,
    key: &SigningKey,
    bundle: ObjectBundle,
    auth_epoch: u64,
) -> ObjectBundleRecord {
    let repo_key = signature_domain_key(params);
    let payload = signed_payload_bundle_record(&repo_key, &bundle, auth_epoch);
    let sig = sign_to_array(key, &payload);
    ObjectBundleRecord {
        bundle,
        added_by: key.verifying_key().to_bytes(),
        auth_epoch,
        signature: sig,
    }
}

/// Produce an [`ExtensionEntry`] signed by the owner.
pub fn sign_extension(
    params: &RepoParams,
    key: &SigningKey,
    ext_key: &str,
    value: Vec<u8>,
    update_seq: u64,
) -> ExtensionEntry {
    let repo_key = signature_domain_key(params);
    let payload = signed_payload_extension(&repo_key, ext_key, &value, update_seq);
    let sig = sign_to_array(key, &payload);
    ExtensionEntry {
        value,
        update_seq,
        signature: sig,
    }
}

fn sign_to_array(key: &SigningKey, payload: &[u8]) -> Signature {
    key.sign(payload).to_bytes()
}
