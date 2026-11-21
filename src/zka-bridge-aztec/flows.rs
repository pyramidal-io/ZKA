// Copyright 2026 ZKA Contributors
// SPDX-License-Identifier: Apache-2.0

//! Withdrawal settlement flow: prepare an L1 outbox consumption for a
//! proven L2 withdrawal, behind a fail-closed submission boundary.
//!
//! Order of gates (all fail-closed, all BEFORE any submission):
//!
//! 1. **Proven gate** — the L2 block must be proven ([`crate::outbox::enforce_proven`]);
//! 2. **Witness** — the rollup node must produce an inclusion witness for
//!    the exact reconstructed message (a message the L2 never emitted has no
//!    witness);
//! 3. **Replay gate** — the v5 (epoch, stable leafId) entry must not already be
//!    consumed ([`crate::outbox::OutboxState::check_replay`]).
//!
//! Submission itself goes through [`PortalSubmitter`], whose default is
//! [`UnconfiguredSubmitter`]: every call errors before any network traffic.
//! The L1 submission key is relayer-side only (the EVM `SignerSource`
//! convention) — no Aztec-side viewing/spending keys ever touch this crate.

use async_trait::async_trait;

use crate::client::{AztecClient, MembershipWitness};
use crate::errors::{AztecBridgeError, Result};
use crate::outbox::{enforce_proven, OutboxState};
use crate::types::{AztecBridgeConfig, L2ToL1Msg, Withdrawal};

/// A withdrawal to settle: the L2 effect plus the L2 block it landed in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WithdrawalFlow {
    pub withdrawal: Withdrawal,
    pub l2_block_number: u64,
    pub l2_tx_hash: String,
}

/// A fully gated, ready-to-submit outbox consumption
/// (`ZKAAztecPortal.withdraw(recipient, amount, epoch, leafIndex, path)`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreparedConsume {
    pub message: L2ToL1Msg,
    pub withdrawal: Withdrawal,
    pub l2_block_number: u64,
    pub l2_tx_hash: String,
    pub epoch_number: u64,
    pub num_checkpoints_in_epoch: u64,
    pub root: [u8; 32],
    pub leaf_index: u64,
    pub leaf_id: u128,
    pub sibling_path: Vec<[u8; 32]>,
}

impl WithdrawalFlow {
    /// Run every settlement gate and produce the consumption plan.
    pub async fn prepare<C: AztecClient>(
        &self,
        client: &C,
        config: &AztecBridgeConfig,
        outbox: &OutboxState,
    ) -> Result<PreparedConsume> {
        let proven = client.proven_block_number().await?;
        enforce_proven(self.l2_block_number, proven)?;

        let message = config.l2_to_l1_message(&self.withdrawal);
        let MembershipWitness {
            epoch_number,
            num_checkpoints_in_epoch,
            root,
            leaf_index,
            sibling_path,
        } = client
            .l2_to_l1_membership_witness(&self.l2_tx_hash, &message)
            .await?;
        let leaf_id = MembershipWitness::leaf_id_from_path(leaf_index, sibling_path.len())?;

        outbox.check_replay(epoch_number, num_checkpoints_in_epoch, leaf_index, leaf_id)?;

        Ok(PreparedConsume {
            message,
            withdrawal: self.withdrawal,
            l2_block_number: self.l2_block_number,
            l2_tx_hash: self.l2_tx_hash.clone(),
            epoch_number,
            num_checkpoints_in_epoch,
            root,
            leaf_index,
            leaf_id,
            sibling_path,
        })
    }
}

/// L1 submission boundary for portal consumptions. Implementations hold a
/// REFERENCE to an operator signer (env var name / keystore path), never key
/// material.
#[async_trait]
pub trait PortalSubmitter: Send + Sync {
    /// Submit `ZKAAztecPortal.withdraw` for a prepared consumption and
    /// return the L1 transaction hash.
    async fn submit_withdraw(&self, prepared: &PreparedConsume) -> Result<String>;
}

/// Fail-closed default: no submitter is configured, every submission path
/// errors before any network traffic.
#[derive(Debug, Clone, Copy, Default)]
pub struct UnconfiguredSubmitter;

#[async_trait]
impl PortalSubmitter for UnconfiguredSubmitter {
    async fn submit_withdraw(&self, _prepared: &PreparedConsume) -> Result<String> {
        Err(AztecBridgeError::SubmitterNotConfigured)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::MockAztecClient;

    fn config() -> AztecBridgeConfig {
        let mut config = AztecBridgeConfig::new(
            "http://localhost:8080",
            "sandbox",
            "http://localhost:8545",
            31337,
        );
        config.portal_address = [0x11u8; 20];
        config.outbox_address = [0x22u8; 20];
        config.l2_bridge = [0x33u8; 32];
        config.rollup_version = 6;
        config.validate().unwrap();
        config
    }

    fn flow() -> WithdrawalFlow {
        WithdrawalFlow {
            withdrawal: Withdrawal {
                recipient: [0xbe; 20],
                amount: 1000,
            },
            l2_block_number: 7,
            l2_tx_hash: "0xtx7".to_string(),
        }
    }

    fn witness() -> MembershipWitness {
        MembershipWitness {
            epoch_number: 9,
            num_checkpoints_in_epoch: 2,
            root: [0xCC; 32],
            leaf_index: 3,
            sibling_path: vec![[0xAA; 32], [0xBB; 32]],
        }
    }

    #[tokio::test]
    async fn prepare_gates_then_plans() {
        let config = config();
        let flow = flow();
        let message = config.l2_to_l1_message(&flow.withdrawal);
        let client = MockAztecClient::new(10, 9).with_witness("0xtx7", &message, witness());
        let outbox = OutboxState::new();

        let prepared = flow.prepare(&client, &config, &outbox).await.unwrap();
        assert_eq!(prepared.epoch_number, 9);
        assert_eq!(prepared.num_checkpoints_in_epoch, 2);
        assert_eq!(prepared.root, [0xCC; 32]);
        assert_eq!(prepared.leaf_index, 3);
        assert_eq!(prepared.leaf_id, 7);
        assert_eq!(prepared.message, message);
        assert_eq!(prepared.sibling_path.len(), 2);
    }

    #[tokio::test]
    async fn prepare_rejects_unproven_blocks_before_any_witness_call() {
        let config = config();
        let flow = flow();
        // Proven head 6 < flow block 7; no witness registered AT ALL — the
        // proven gate must fire first.
        let client = MockAztecClient::new(10, 6);
        let err = flow
            .prepare(&client, &config, &OutboxState::new())
            .await
            .unwrap_err();
        assert!(matches!(err, AztecBridgeError::NotProven { .. }), "{err}");
    }

    #[tokio::test]
    async fn prepare_rejects_replayed_entries() {
        let config = config();
        let flow = flow();
        let message = config.l2_to_l1_message(&flow.withdrawal);
        let client = MockAztecClient::new(10, 9).with_witness("0xtx7", &message, witness());
        let mut outbox = OutboxState::new();
        outbox.apply_consumed(9, 2, 3, 7).unwrap();

        let err = flow.prepare(&client, &config, &outbox).await.unwrap_err();
        assert!(
            matches!(err, AztecBridgeError::AlreadyConsumed { .. }),
            "{err}"
        );
    }

    #[tokio::test]
    async fn prepare_fails_when_the_message_has_no_witness() {
        // A message the L2 never emitted (different amount) has no inclusion
        // witness: structured error from the node surface.
        let config = config();
        let message = config.l2_to_l1_message(&Withdrawal {
            recipient: [0xbe; 20],
            amount: 1000,
        });
        let client = MockAztecClient::new(10, 9).with_witness("0xtx7", &message, witness());
        let tampered = WithdrawalFlow {
            withdrawal: Withdrawal {
                recipient: [0xbe; 20],
                amount: 999,
            },
            l2_block_number: 7,
            l2_tx_hash: "0xtx7".to_string(),
        };
        assert!(tampered
            .prepare(&client, &config, &OutboxState::new())
            .await
            .is_err());
    }

    #[tokio::test]
    async fn unconfigured_submitter_fails_closed() {
        let config = config();
        let flow = flow();
        let message = config.l2_to_l1_message(&flow.withdrawal);
        let client = MockAztecClient::new(10, 9).with_witness("0xtx7", &message, witness());
        let prepared = flow
            .prepare(&client, &config, &OutboxState::new())
            .await
            .unwrap();
        let err = UnconfiguredSubmitter
            .submit_withdraw(&prepared)
            .await
            .unwrap_err();
        assert!(
            matches!(err, AztecBridgeError::SubmitterNotConfigured),
            "{err}"
        );
    }
}
