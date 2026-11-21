// Copyright 2026 ZKA Contributors
// SPDX-License-Identifier: Apache-2.0

//! # zka-bridge-aztec
//!
//! ZKA settlement adapter boundary for the Aztec deployment
//! (`aztec/zka_transfer_aztec` on L2 + `contracts/ethereum/ZKAAztecPortal.sol`
//! on L1).
//!
//! Settlement model (the L1↔L2 message-portal design from
//! `docs/operations/aztec_outbox.md`): the rollup proves every L2
//! transaction, so withdrawals carry **no ZKA proof on L1**.
//! `ZKATransfer.withdraw` burns the holder's notes on L2 and emits an L2→L1
//! message to the immutable, ownerless per-asset portal; once the containing
//! L2 block is **proven**, anyone may consume the message from the rollup
//! Outbox (strict once-only) and release the underlying ERC-20 to the bound
//! recipient.
//!
//! This crate is the Rust half of that pipeline:
//!
//! * [`types::withdraw_content_hash`] — the cross-environment content hash,
//!   byte-locked against the Noir L2 golden AND the Solidity portal
//!   (`(0xbeef, 1000)` vector);
//! * [`transport::AztecTransport`] — typed JSON-RPC 2.0 transport to the
//!   Aztec node (`aztec_*`) and the L1 endpoint (`eth_*`); the live
//!   implementation is [`transport::HttpJsonRpcTransport`];
//! * [`client::AztecClient`] — read surface (proven/latest L2 heights,
//!   outbox membership witnesses, portal `Withdrawn` events), with
//!   [`client::NodeAztecClient`] (live) and [`client::MockAztecClient`]
//!   (tests);
//! * [`outbox::enforce_proven`] / [`outbox::OutboxState`] — the proven-block
//!   finality gate and the once-only consumption (replay) gate;
//! * [`flows::WithdrawalFlow`] — gate-then-plan settlement preparation,
//!   behind the fail-closed [`flows::UnconfiguredSubmitter`] default.
//!
//! Everything is **fail-closed**: configuration must resolve in the
//! canonical encoding registry (`aztec:<reference>` for the `aztec` adapter
//! plus a registered eip155 anchor), configured depths must satisfy the
//! chain's finality-policy floor (tighten-not-loosen), and no submission
//! path works until an operator wires a [`flows::PortalSubmitter`].

pub mod client;
pub mod errors;
pub mod flows;
pub mod outbox;
pub mod transport;
pub mod types;

pub use client::{
    AztecClient, MembershipWitness, MockAztecClient, NodeAztecClient, PortalEvent, PortalEventBatch,
};
pub use errors::{AztecBridgeError, Result};
pub use flows::{PortalSubmitter, PreparedConsume, UnconfiguredSubmitter, WithdrawalFlow};
pub use outbox::{enforce_proven, OutboxState};
pub use transport::{AztecTransport, HttpJsonRpcTransport};
pub use types::{
    parse_bytes32, parse_eth_address, pinned_rollup, sha256_to_field, withdraw_content_hash,
    AztecBridgeConfig, AztecProtocolVersion, L2ToL1Msg, PinnedRollup, Withdrawal, PINNED_ROLLUPS,
    WITHDRAWN_EVENT_TOPIC, WITHDRAW_SELECTOR,
};
