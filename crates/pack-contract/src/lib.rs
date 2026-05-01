//! Pack contract: an immutable, content-addressed wrapper around a packfile.
//!
//! Every push to a freenet-git repo uploads its new packfile as a separate
//! contract instance of *this* WASM. The instance's parameters are the
//! BLAKE3-32 hash of the pack bytes, and `validate_state` enforces that the
//! state's BLAKE3-32 equals those parameter bytes. Updates are rejected
//! (the state is one-shot and content-addressed; nothing can ever modify
//! it).
//!
//! The Freenet contract key for a particular pack instance is therefore
//! `BLAKE3(BLAKE3(WASM) || pack_hash)`. Two peers that hold the same pack
//! bytes deterministically agree on its key without coordination.
//!
//! ## Why a contract per pack
//!
//! Per-object contracts would lose Git's delta compression and pay the
//! per-contract overhead for thousands of tiny blobs. Per-pack contracts
//! match Git's natural unit (one packfile per push) and let the network
//! treat them as immutable, deduplicatable, optionally chunked blobs.

#![deny(unsafe_code)]
#![cfg_attr(not(test), no_std)]
#![cfg_attr(target_family = "wasm", allow(unused_imports))]

extern crate alloc;

use freenet_stdlib::prelude::*;

/// Length, in bytes, of the BLAKE3-32 hash that parameters must equal.
const PACK_HASH_BYTES: usize = 32;

#[allow(dead_code)]
struct Contract;

#[contract]
impl ContractInterface for Contract {
    fn validate_state(
        parameters: Parameters<'static>,
        state: State<'static>,
        _related: RelatedContracts<'static>,
    ) -> Result<ValidateResult, ContractError> {
        if parameters.as_ref().len() != PACK_HASH_BYTES {
            return Err(ContractError::InvalidUpdateWithInfo {
                reason: alloc::format!(
                    "pack contract parameters must be exactly {PACK_HASH_BYTES} bytes (the BLAKE3-32 of the pack)",
                ),
            });
        }
        let expected: [u8; 32] = parameters
            .as_ref()
            .try_into()
            .map_err(|_| ContractError::InvalidUpdate)?;
        let actual = *blake3::hash(state.as_ref()).as_bytes();
        if actual == expected {
            Ok(ValidateResult::Valid)
        } else {
            Err(ContractError::InvalidUpdateWithInfo {
                reason: alloc::string::String::from(
                    "pack contract state hash does not match parameters",
                ),
            })
        }
    }

    /// Pack contracts are content-addressed: the only legitimate state
    /// is the unique blob whose `BLAKE3-32` equals `parameters`. Accept
    /// any update whose new state passes that check (a no-op, since
    /// the host is delivering the same canonical bytes the contract
    /// already has). Reject everything else.
    ///
    /// Why we accept rather than reject identical re-PUTs: when the
    /// network already hosts the contract and a peer issues another
    /// PUT for the same content, the host routes it as an update to
    /// the existing contract, not as a fresh insertion. Rejecting all
    /// updates breaks legitimate re-PUTs (e.g. `freenet-git rescue`,
    /// or a second client publishing the same chunk concurrently).
    fn update_state(
        parameters: Parameters<'static>,
        state: State<'static>,
        data: alloc::vec::Vec<UpdateData<'static>>,
    ) -> Result<UpdateModification<'static>, ContractError> {
        // The host expects update_state to return the (possibly
        // unchanged) merged state. For pack contracts there is at
        // most one valid state, so we can validate any candidate the
        // host hands us and return whichever one we believe.
        let mut current = state;
        for update in data {
            match update {
                UpdateData::State(new_state) => {
                    Self::validate_state(
                        parameters.clone(),
                        new_state.clone(),
                        RelatedContracts::default(),
                    )?;
                    current = new_state;
                }
                UpdateData::Delta(_)
                | UpdateData::StateAndDelta { .. }
                | UpdateData::RelatedState { .. }
                | UpdateData::RelatedDelta { .. }
                | UpdateData::RelatedStateAndDelta { .. } => {
                    return Err(ContractError::InvalidUpdateWithInfo {
                        reason: alloc::string::String::from(
                            "pack contracts only accept full-state updates",
                        ),
                    });
                }
                _ => {
                    return Err(ContractError::InvalidUpdate);
                }
            }
        }
        Ok(UpdateModification::valid(current))
    }

    /// The summary of a pack is its hash. Two peers comparing summaries can
    /// short-circuit a fetch when they already hold the same content.
    fn summarize_state(
        parameters: Parameters<'static>,
        _state: State<'static>,
    ) -> Result<StateSummary<'static>, ContractError> {
        Ok(StateSummary::from(parameters.as_ref().to_vec()))
    }

    /// Immutable contracts have no deltas. Always return empty.
    fn get_state_delta(
        _parameters: Parameters<'static>,
        _state: State<'static>,
        _summary: StateSummary<'static>,
    ) -> Result<StateDelta<'static>, ContractError> {
        Ok(StateDelta::from(alloc::vec::Vec::new()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn validate(params: &[u8], state: &[u8]) -> Result<ValidateResult, ContractError> {
        let parameters = Parameters::from(params.to_vec());
        let state = State::from(state.to_vec());
        Contract::validate_state(parameters, state, RelatedContracts::default())
    }

    #[test]
    fn matching_hash_validates() {
        let payload = b"hello pack";
        let hash = blake3::hash(payload);
        validate(hash.as_bytes(), payload).expect("matching hash should validate");
    }

    #[test]
    fn mismatched_hash_is_rejected() {
        let payload = b"hello pack";
        let mut hash = *blake3::hash(payload).as_bytes();
        hash[0] ^= 0xFF;
        match validate(&hash, payload) {
            Err(ContractError::InvalidUpdateWithInfo { .. }) => {}
            other => panic!("expected InvalidUpdateWithInfo, got {other:?}"),
        }
    }

    #[test]
    fn wrong_length_parameters_is_rejected() {
        match validate(&[0u8; 16], b"") {
            Err(ContractError::InvalidUpdateWithInfo { .. }) => {}
            other => panic!("expected InvalidUpdateWithInfo, got {other:?}"),
        }
    }

    #[test]
    fn update_with_correct_state_is_accepted() {
        let payload = b"hello pack";
        let hash = blake3::hash(payload);
        let parameters = Parameters::from(hash.as_bytes().to_vec());
        let state = State::from(payload.to_vec());
        let result = Contract::update_state(
            parameters.clone(),
            state.clone(),
            vec![UpdateData::State(state.clone())],
        );
        assert!(result.is_ok());
    }

    #[test]
    fn update_with_wrong_state_is_rejected() {
        let payload = b"hello pack";
        let hash = blake3::hash(payload);
        let parameters = Parameters::from(hash.as_bytes().to_vec());
        let state = State::from(payload.to_vec());
        let bad_state = State::from(b"different bytes".to_vec());
        let result = Contract::update_state(parameters, state, vec![UpdateData::State(bad_state)]);
        assert!(result.is_err());
    }

    #[test]
    fn update_with_delta_is_rejected() {
        let parameters = Parameters::from(vec![0u8; 32]);
        let state = State::from(vec![0u8; 32]);
        let result = Contract::update_state(
            parameters,
            state,
            vec![UpdateData::Delta(StateDelta::from(vec![1, 2, 3]))],
        );
        assert!(matches!(
            result,
            Err(ContractError::InvalidUpdateWithInfo { .. })
        ));
    }
}
