//! Repo contract: mutable repo state for freenet-git.
//!
//! This file is a thin shim: it deserializes the [`Parameters`] / [`State`] /
//! delta payloads, dispatches into the pure-Rust logic in
//! [`freenet_git_types`], and re-serializes results back into stdlib types.
//! All security-relevant logic (signature verification, ACL gating,
//! freshness rules, CRDT merge) lives in `freenet-git-types`, where it can
//! be exhaustively unit-tested without booting a WASM runtime.
//!
//! Phase 1.0 is **single-writer**. The schema contains the full ACL fields
//! ([`AclState`], [`WriterGrant`]) so that Phase 1.1's multi-writer ACL
//! becomes a contract WASM upgrade rather than a fundamentally different
//! schema. `validate_state` rejects any entry whose `updater` is not the
//! repo owner.

#![deny(unsafe_code)]

use freenet_git_types as types;
use freenet_git_types::{RepoParams, RepoState, RepoSummary};
use freenet_stdlib::prelude::*;

/// Marker type implementing [`ContractInterface`]. Re-exported so
/// integration tests can dispatch through the same boundary the host
/// runtime calls into.
pub struct Contract;

#[contract]
impl ContractInterface for Contract {
    fn validate_state(
        parameters: Parameters<'static>,
        state: State<'static>,
        _related: RelatedContracts<'static>,
    ) -> Result<ValidateResult, ContractError> {
        let params = decode_params(&parameters)?;
        let state = decode_state(&state)?;
        match types::validate_state(&params, &state) {
            Ok(()) => Ok(ValidateResult::Valid),
            Err(e) => Err(ContractError::InvalidUpdateWithInfo {
                reason: format!("validate_state: {e}"),
            }),
        }
    }

    fn update_state(
        parameters: Parameters<'static>,
        state: State<'static>,
        data: Vec<UpdateData<'static>>,
    ) -> Result<UpdateModification<'static>, ContractError> {
        let params = decode_params(&parameters)?;
        let mut current = decode_state(&state)?;

        for update in data {
            match update {
                UpdateData::State(new_state_bytes) => {
                    let incoming = decode_state(new_state_bytes.as_ref())?;
                    current = types::update_state(&params, &current, &incoming).map_err(|e| {
                        ContractError::InvalidUpdateWithInfo {
                            reason: format!("update_state (full state): {e}"),
                        }
                    })?;
                }
                UpdateData::Delta(delta_bytes) => {
                    if delta_bytes.as_ref().is_empty() {
                        continue;
                    }
                    let delta = decode_state(delta_bytes.as_ref())?;
                    current = types::update_state(&params, &current, &delta).map_err(|e| {
                        ContractError::InvalidUpdateWithInfo {
                            reason: format!("update_state (delta): {e}"),
                        }
                    })?;
                }
                UpdateData::StateAndDelta { state, delta } => {
                    let incoming_state = decode_state(state.as_ref())?;
                    current =
                        types::update_state(&params, &current, &incoming_state).map_err(|e| {
                            ContractError::InvalidUpdateWithInfo {
                                reason: format!("update_state (state+delta state half): {e}"),
                            }
                        })?;
                    if !delta.as_ref().is_empty() {
                        let incoming_delta = decode_state(delta.as_ref())?;
                        current = types::update_state(&params, &current, &incoming_delta).map_err(
                            |e| ContractError::InvalidUpdateWithInfo {
                                reason: format!("update_state (state+delta delta half): {e}"),
                            },
                        )?;
                    }
                }
                UpdateData::RelatedState { .. }
                | UpdateData::RelatedDelta { .. }
                | UpdateData::RelatedStateAndDelta { .. } => {
                    // Phase 1.0 has no cross-contract references in repo state.
                    // Reject rather than silently accept so a future schema
                    // that *does* use related state can land cleanly.
                    return Err(ContractError::InvalidUpdate);
                }
                _ => {
                    return Err(ContractError::InvalidUpdate);
                }
            }
        }

        let bytes =
            bincode::serialize(&current).map_err(|e| ContractError::InvalidUpdateWithInfo {
                reason: format!("re-serialize updated state: {e}"),
            })?;
        Ok(UpdateModification::valid(bytes.into()))
    }

    fn summarize_state(
        parameters: Parameters<'static>,
        state: State<'static>,
    ) -> Result<StateSummary<'static>, ContractError> {
        let _params = decode_params(&parameters)?;
        let state = decode_state(&state)?;
        let summary = types::summarize_state(&state);
        let bytes =
            bincode::serialize(&summary).map_err(|e| ContractError::InvalidUpdateWithInfo {
                reason: format!("serialize summary: {e}"),
            })?;
        Ok(StateSummary::from(bytes))
    }

    fn get_state_delta(
        parameters: Parameters<'static>,
        state: State<'static>,
        summary: StateSummary<'static>,
    ) -> Result<StateDelta<'static>, ContractError> {
        let _params = decode_params(&parameters)?;
        let state = decode_state(&state)?;
        let summary = decode_summary(&summary)?;
        let delta = types::get_state_delta(&state, &summary);
        // We use the same RepoState wire format for deltas. Empty delta
        // means "you are caught up"; encode as empty bytes so the host can
        // short-circuit without a full deserialize.
        if is_empty_delta(&delta) {
            return Ok(StateDelta::from(Vec::new()));
        }
        let bytes =
            bincode::serialize(&delta).map_err(|e| ContractError::InvalidUpdateWithInfo {
                reason: format!("serialize delta: {e}"),
            })?;
        Ok(StateDelta::from(bytes))
    }
}

fn decode_params(p: &Parameters<'_>) -> Result<RepoParams, ContractError> {
    RepoParams::from_bytes(p.as_ref()).map_err(|e| ContractError::InvalidUpdateWithInfo {
        reason: format!("decode params: {e}"),
    })
}

fn decode_state(bytes: &[u8]) -> Result<RepoState, ContractError> {
    RepoState::from_bytes(bytes).map_err(|e| ContractError::InvalidUpdateWithInfo {
        reason: format!("decode state: {e}"),
    })
}

fn decode_summary(s: &StateSummary<'_>) -> Result<RepoSummary, ContractError> {
    let bytes = s.as_ref();
    if bytes.is_empty() {
        return Ok(RepoSummary::default());
    }
    bincode::deserialize::<RepoSummary>(bytes).map_err(|e| ContractError::InvalidUpdateWithInfo {
        reason: format!("decode summary: {e}"),
    })
}

fn is_empty_delta(s: &RepoState) -> bool {
    s.name.is_none()
        && s.description.is_none()
        && s.default_branch.is_none()
        && s.force_push_allowed.is_none()
        && s.acl.is_none()
        && s.upgrade.is_none()
        && s.refs.is_empty()
        && s.object_index.is_empty()
        && s.extensions.is_empty()
    // We deliberately also accept the merged state output of
    // `update_state` as a delta; the contract framework permits this.
    // For internal use, we never construct merged states with all of
    // these empty.
}

// Reference merge_state once so it's part of the contract's link surface
// even if a future refactor stops calling it from update_state directly.
// Cheap, doesn't run at runtime.
#[allow(dead_code)]
fn _force_link_merge_state() -> RepoState {
    let a = RepoState::default();
    let b = RepoState::default();
    types::merge_state(&a, &b)
}
