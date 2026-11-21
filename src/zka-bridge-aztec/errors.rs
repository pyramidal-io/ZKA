// Copyright 2026 ZKA Contributors
// SPDX-License-Identifier: Apache-2.0

//! Structured, fail-closed error taxonomy for the Aztec settlement adapter.

use thiserror::Error;

/// Errors raised at the Aztec adapter boundary.
#[derive(Debug, Error)]
pub enum AztecBridgeError {
    /// Configuration shape/registry validation failure (fail-closed at
    /// construction, before any network traffic).
    #[error("configuration error: {0}")]
    Config(String),

    /// Wire-level failure talking to the Aztec node or the L1 endpoint.
    #[error("transport error: {0}")]
    Transport(String),

    /// Registry lookup failure (unregistered chain, adapter mismatch, policy
    /// violation) — settlement is allowlisted to registry entries.
    #[error(transparent)]
    Registry(#[from] zka_registry::RegistryError),

    /// The L2 block holding the outbox entry is not proven on L1 yet, so the
    /// entry is not consumable. Settlement waits for the rollup proof —
    /// never settles against unproven state.
    #[error("L2 block {l2_block_number} is not proven (proven head {proven_block_number}): its outbox entries are not consumable yet (fail-closed)")]
    NotProven {
        l2_block_number: u64,
        proven_block_number: u64,
    },

    /// The outbox entry was already consumed — replay rejected. (The L1
    /// Outbox enforces once-only consumption on-chain; this is the adapter's
    /// own gate so a replay never reaches submission.)
    #[error("outbox entry (epoch {epoch_number}, numCheckpointsInEpoch {num_checkpoints_in_epoch}, leafIndex {leaf_index}, leafId {leaf_id}) already consumed: replay rejected")]
    AlreadyConsumed {
        epoch_number: u64,
        num_checkpoints_in_epoch: u64,
        leaf_index: u64,
        leaf_id: u128,
    },

    /// The v5 Outbox witness or event carried impossible replay-key metadata.
    #[error("invalid outbox entry: {0}")]
    InvalidOutboxEntry(String),

    /// No portal submitter is wired. Default state: every submission path
    /// errors here before any network traffic (fail-closed).
    #[error("portal submitter not configured: L1 outbox consumption is disabled (fail-closed); wire an operator-controlled PortalSubmitter")]
    SubmitterNotConfigured,
}

pub type Result<T> = std::result::Result<T, AztecBridgeError>;
