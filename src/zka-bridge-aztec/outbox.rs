// Copyright 2026 ZKA Contributors
// SPDX-License-Identifier: Apache-2.0

//! Outbox-side settlement gates: the proven-block finality gate and the
//! adapter-level once-only consumption tracker (replay gate).
//!
//! Ground truth lives on-chain: the Aztec rollup contract only makes outbox
//! entries consumable after the containing L2 block is **proven**, and the
//! L1 Outbox enforces **strict once-only consumption** per entry. These
//! gates mirror both rules on the adapter side so an unproven or replayed
//! consumption is rejected BEFORE any submission is planned, and a
//! reconstructed event stream that violates them is flagged as
//! corrupt/replayed (fail-closed).

use std::collections::BTreeSet;

use crate::errors::{AztecBridgeError, Result};

/// The Aztec finality gate: an L2 block's outbox entries are consumable only
/// once the block is proven (rollup proof settled on L1). Fail-closed —
/// never settles against unproven state.
pub fn enforce_proven(l2_block_number: u64, proven_block_number: u64) -> Result<()> {
    if l2_block_number > proven_block_number {
        return Err(AztecBridgeError::NotProven {
            l2_block_number,
            proven_block_number,
        });
    }
    Ok(())
}

/// Adapter-side reconstruction of v5 outbox consumption: which entries
/// (keyed `(epoch_number, leaf_id)`, exactly the Outbox's once-only key)
/// have been consumed.
#[derive(Debug, Clone, Default)]
pub struct OutboxState {
    consumed: BTreeSet<(u64, u128)>,
}

impl OutboxState {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a consumption. A duplicate means the event stream is corrupt
    /// or replayed (the L1 Outbox can never consume an entry twice) — hard
    /// error, mirroring the on-chain rule.
    pub fn apply_consumed(
        &mut self,
        epoch_number: u64,
        num_checkpoints_in_epoch: u64,
        leaf_index: u64,
        leaf_id: u128,
    ) -> Result<()> {
        validate_v5_key(num_checkpoints_in_epoch, leaf_index, leaf_id)?;
        if !self.consumed.insert((epoch_number, leaf_id)) {
            return Err(AztecBridgeError::AlreadyConsumed {
                epoch_number,
                num_checkpoints_in_epoch,
                leaf_index,
                leaf_id,
            });
        }
        Ok(())
    }

    /// Replay gate: would consuming this entry be a replay?
    pub fn check_replay(
        &self,
        epoch_number: u64,
        num_checkpoints_in_epoch: u64,
        leaf_index: u64,
        leaf_id: u128,
    ) -> Result<()> {
        validate_v5_key(num_checkpoints_in_epoch, leaf_index, leaf_id)?;
        if self.consumed.contains(&(epoch_number, leaf_id)) {
            return Err(AztecBridgeError::AlreadyConsumed {
                epoch_number,
                num_checkpoints_in_epoch,
                leaf_index,
                leaf_id,
            });
        }
        Ok(())
    }

    /// Number of consumed entries reconstructed.
    pub fn len(&self) -> usize {
        self.consumed.len()
    }

    pub fn is_empty(&self) -> bool {
        self.consumed.is_empty()
    }
}

fn validate_v5_key(num_checkpoints_in_epoch: u64, leaf_index: u64, leaf_id: u128) -> Result<()> {
    if num_checkpoints_in_epoch == 0 || num_checkpoints_in_epoch > 32 {
        return Err(AztecBridgeError::InvalidOutboxEntry(format!(
            "numCheckpointsInEpoch must be in 1..=32, got {num_checkpoints_in_epoch}"
        )));
    }
    if leaf_id <= leaf_index as u128 {
        return Err(AztecBridgeError::InvalidOutboxEntry(format!(
            "leafId {leaf_id} must include the tree-level prefix and exceed leafIndex {leaf_index}"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proven_gate_rejects_unproven_blocks() {
        // Proven head at 90: block 91 is not consumable yet.
        let err = enforce_proven(91, 90).unwrap_err();
        assert!(err.to_string().contains("not proven"), "{err}");
        // At or below the proven head passes.
        enforce_proven(90, 90).unwrap();
        enforce_proven(1, 90).unwrap();
    }

    #[test]
    fn outbox_entries_are_single_consumption() {
        let mut state = OutboxState::new();
        state.apply_consumed(9, 2, 3, 7).unwrap();
        // Same (epoch, leafId) again: corrupt/replayed stream, fail-closed.
        let err = state.apply_consumed(9, 3, 3, 7).unwrap_err();
        assert!(err.to_string().contains("already consumed"), "{err}");
        // Same leaf index with a different path length can be a different
        // stable leafId, and the same leafId in a different epoch is distinct.
        state.apply_consumed(9, 2, 3, 11).unwrap();
        state.apply_consumed(10, 2, 3, 7).unwrap();
        assert_eq!(state.len(), 3);
    }

    #[test]
    fn replay_gate_rejects_consumed_entries() {
        let mut state = OutboxState::new();
        state.apply_consumed(9, 2, 3, 7).unwrap();
        assert!(matches!(
            state.check_replay(9, 2, 3, 7),
            Err(AztecBridgeError::AlreadyConsumed {
                epoch_number: 9,
                leaf_id: 7,
                ..
            })
        ));
        // A fresh entry passes the gate.
        state.check_replay(9, 2, 4, 8).unwrap();
    }
}
