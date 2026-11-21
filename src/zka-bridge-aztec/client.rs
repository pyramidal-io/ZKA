// Copyright 2026 ZKA Contributors
// SPDX-License-Identifier: Apache-2.0

//! Aztec settlement client: typed read surface over the L2 node + L1
//! endpoints, with a live [`NodeAztecClient`] (backed by an
//! [`AztecTransport`]) and an in-memory [`MockAztecClient`] for tests.
//!
//! The client is **read-only by design**: it polls public rollup state
//! (latest/proven block numbers), fetches outbox membership witnesses, and
//! indexes the portal's `Withdrawn` events on L1. Submission goes through
//! the separate [`crate::flows::PortalSubmitter`] boundary, which defaults
//! to fail-closed `Unconfigured`.

use async_trait::async_trait;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::sync::Arc;

use crate::errors::{AztecBridgeError, Result};
use crate::transport::AztecTransport;
use crate::types::{AztecBridgeConfig, L2ToL1Msg, WITHDRAWN_EVENT_TOPIC};
use base64::Engine as _;

/// Inclusion witness for an L2→L1 message in the rollup's settled output
/// tree, as returned by `aztec_getL2ToL1MembershipWitness`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MembershipWitness {
    /// Epoch that owns the Outbox root.
    pub epoch_number: u64,
    /// v5 multiple-roots-per-epoch selector.
    pub num_checkpoints_in_epoch: u64,
    /// Outbox root for `(epoch_number, num_checkpoints_in_epoch)`.
    pub root: [u8; 32],
    /// Leaf index of the message within the selected Outbox root.
    pub leaf_index: u64,
    /// Sibling path proving inclusion (consumed by `ZKAAztecPortal.withdraw`).
    pub sibling_path: Vec<[u8; 32]>,
}

impl MembershipWitness {
    /// v5 Outbox stable leaf id: `2^path_len + leafIndex`.
    pub fn leaf_id(&self) -> Result<u128> {
        Self::leaf_id_from_path(self.leaf_index, self.sibling_path.len())
    }

    pub fn leaf_id_from_path(leaf_index: u64, path_len: usize) -> Result<u128> {
        if path_len >= 128 {
            return Err(AztecBridgeError::InvalidOutboxEntry(format!(
                "sibling path length {path_len} cannot be represented as a u128 leafId"
            )));
        }
        Ok((1u128 << path_len) + leaf_index as u128)
    }
}

/// One typed portal event indexed from L1.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PortalEvent {
    /// `ZKAAztecPortal.Withdrawn(...)` — an outbox
    /// entry was consumed and the underlying released.
    Withdrawn {
        recipient: [u8; 20],
        amount: u128,
        epoch_number: u64,
        num_checkpoints_in_epoch: u64,
        leaf_index: u64,
        leaf_id: u128,
        root: [u8; 32],
        /// L1 block the consumption landed in.
        l1_block_number: u64,
        /// L1 transaction hash of the consumption.
        l1_tx_hash: String,
    },
}

/// One batch of portal events plus the L1 head observed for cursoring.
#[derive(Debug, Clone, Default)]
pub struct PortalEventBatch {
    pub events: Vec<PortalEvent>,
    /// L1 head at query time (the indexer resumes after this).
    pub l1_head: u64,
}

/// Read surface of the Aztec settlement adapter.
#[async_trait]
pub trait AztecClient: Send + Sync {
    /// Latest L2 block number known to the node.
    async fn latest_block_number(&self) -> Result<u64>;
    /// Latest L2 block number whose rollup proof has settled on L1. Blocks
    /// at or below this are final; outbox entries above it are not yet
    /// consumable.
    async fn proven_block_number(&self) -> Result<u64>;
    /// Inclusion witness for an L2→L1 message in `l2_tx_hash`'s effects
    /// (errors if the message is not in that transaction).
    async fn l2_to_l1_membership_witness(
        &self,
        l2_tx_hash: &str,
        message: &L2ToL1Msg,
    ) -> Result<MembershipWitness>;
    /// Current L1 head.
    async fn l1_head(&self) -> Result<u64>;
    /// Portal `Withdrawn` events from `from_l1_block` to the L1 head.
    async fn query_portal_events(&self, from_l1_block: u64) -> Result<PortalEventBatch>;
}

// ---------------------------------------------------------------------------
// Live client
// ---------------------------------------------------------------------------

/// Live client over an [`AztecTransport`]. Construction is fail-closed: the
/// configuration must validate against the canonical registry first.
pub struct NodeAztecClient<T: AztecTransport> {
    config: AztecBridgeConfig,
    transport: Arc<T>,
}

fn as_u64(method: &str, value: &Value) -> Result<u64> {
    // Aztec node methods return JSON numbers; eth_* methods return 0x-hex
    // quantities. Accept both shapes, fail closed on anything else.
    if let Some(n) = value.as_u64() {
        return Ok(n);
    }
    if let Some(s) = value.as_str() {
        let trimmed = s.trim();
        let parsed = if let Some(raw) = trimmed.strip_prefix("0x") {
            u64::from_str_radix(raw, 16)
        } else {
            trimmed.parse()
        };
        if let Ok(n) = parsed {
            return Ok(n);
        }
    }
    Err(AztecBridgeError::Transport(format!(
        "{method}: expected a block number, got {value}"
    )))
}

fn hex_word(method: &str, value: &str) -> Result<[u8; 32]> {
    let raw = hex::decode(value.strip_prefix("0x").unwrap_or(value))
        .map_err(|e| AztecBridgeError::Transport(format!("{method}: invalid hex: {e}")))?;
    raw.try_into()
        .map_err(|_| AztecBridgeError::Transport(format!("{method}: expected 32 bytes")))
}

impl<T: AztecTransport> NodeAztecClient<T> {
    /// Build a live client. Validates the configuration (registry
    /// membership + finality-policy floors) before anything else.
    pub fn new(mut config: AztecBridgeConfig, transport: Arc<T>) -> Result<Self> {
        config.validate()?;
        Ok(Self { config, transport })
    }

    pub fn config(&self) -> &AztecBridgeConfig {
        &self.config
    }
}

#[async_trait]
impl<T: AztecTransport> AztecClient for NodeAztecClient<T> {
    async fn latest_block_number(&self) -> Result<u64> {
        let result = self
            .transport
            .node_rpc("aztec_getBlockNumber", json!([]))
            .await?;
        as_u64("aztec_getBlockNumber(latest)", &result)
    }

    async fn proven_block_number(&self) -> Result<u64> {
        let result = self
            .transport
            .node_rpc("aztec_getBlockNumber", json!(["proven"]))
            .await?;
        as_u64("aztec_getBlockNumber(proven)", &result)
    }

    async fn l2_to_l1_membership_witness(
        &self,
        l2_tx_hash: &str,
        message: &L2ToL1Msg,
    ) -> Result<MembershipWitness> {
        let leaf = format!("0x{}", hex::encode(message.leaf()));
        let result = self
            .transport
            .node_rpc(
                "aztec_getL2ToL1MembershipWitness",
                json!([l2_tx_hash, leaf]),
            )
            .await?;
        if result.is_null() {
            return Err(AztecBridgeError::Transport(format!(
                "aztec_getL2ToL1MembershipWitness: message {leaf} not found in tx {l2_tx_hash}"
            )));
        }
        let epoch_number = as_u64(
            "aztec_getL2ToL1MembershipWitness.epochNumber",
            &result["epochNumber"],
        )?;
        let num_checkpoints_in_epoch = as_u64(
            "aztec_getL2ToL1MembershipWitness.numCheckpointsInEpoch",
            &result["numCheckpointsInEpoch"],
        )?;
        let root = hex_word(
            "aztec_getL2ToL1MembershipWitness.root",
            result["root"].as_str().unwrap_or_default(),
        )?;
        let leaf_index = as_u64(
            "aztec_getL2ToL1MembershipWitness.leafIndex",
            &result["leafIndex"],
        )?;
        let sibling_path = parse_sibling_path(
            "aztec_getL2ToL1MembershipWitness.siblingPath",
            &result["siblingPath"],
        )?;
        let witness = MembershipWitness {
            epoch_number,
            num_checkpoints_in_epoch,
            root,
            leaf_index,
            sibling_path,
        };
        witness.leaf_id()?;
        Ok(witness)
    }

    async fn l1_head(&self) -> Result<u64> {
        let result = self.transport.l1_rpc("eth_blockNumber", json!([])).await?;
        as_u64("eth_blockNumber", &result)
    }

    async fn query_portal_events(&self, from_l1_block: u64) -> Result<PortalEventBatch> {
        let head = self.l1_head().await?;
        let filter = json!([{
            "address": format!("0x{}", hex::encode(self.config.portal_address)),
            "topics": [WITHDRAWN_EVENT_TOPIC],
            "fromBlock": format!("0x{from_l1_block:x}"),
            "toBlock": format!("0x{head:x}"),
        }]);
        let result = self.transport.l1_rpc("eth_getLogs", filter).await?;
        let logs = result.as_array().ok_or_else(|| {
            AztecBridgeError::Transport("eth_getLogs: expected an array of logs".into())
        })?;
        let mut events = Vec::with_capacity(logs.len());
        for log in logs {
            events.push(parse_withdrawn_log(log)?);
        }
        Ok(PortalEventBatch {
            events,
            l1_head: head,
        })
    }
}

fn parse_sibling_path(method: &str, value: &Value) -> Result<Vec<[u8; 32]>> {
    if let Some(encoded) = value.as_str() {
        return parse_serialized_sibling_path(method, encoded);
    }
    let (nodes, declared_len) = if let Some(nodes) = value.as_array() {
        (nodes, None)
    } else {
        let nodes = value["path"]
            .as_array()
            .ok_or_else(|| AztecBridgeError::Transport(format!("{method}: missing path array")))?;
        let declared_len = value
            .get("pathSize")
            .filter(|v| !v.is_null())
            .map(|v| as_u64(method, v))
            .transpose()?;
        (nodes, declared_len)
    };
    if let Some(path_size) = declared_len {
        if path_size as usize != nodes.len() {
            return Err(AztecBridgeError::Transport(format!(
                "{method}: pathSize {path_size} does not match {} nodes",
                nodes.len()
            )));
        }
    }
    let mut sibling_path = Vec::with_capacity(nodes.len());
    for node in nodes {
        let s = node.as_str().ok_or_else(|| {
            AztecBridgeError::Transport(format!("{method}: non-string path node"))
        })?;
        sibling_path.push(hex_word("siblingPath", s)?);
    }
    Ok(sibling_path)
}

fn parse_serialized_sibling_path(method: &str, encoded: &str) -> Result<Vec<[u8; 32]>> {
    let raw = if let Some(hex) = encoded.strip_prefix("0x") {
        hex::decode(hex)
            .map_err(|e| AztecBridgeError::Transport(format!("{method}: invalid hex: {e}")))?
    } else {
        base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .map_err(|e| AztecBridgeError::Transport(format!("{method}: invalid base64: {e}")))?
    };
    if raw.len() < 4 {
        return Err(AztecBridgeError::Transport(format!(
            "{method}: serialized sibling path shorter than length prefix"
        )));
    }
    let path_size = u32::from_be_bytes(raw[..4].try_into().unwrap()) as usize;
    let expected_len = path_size
        .checked_mul(32)
        .and_then(|len| len.checked_add(4))
        .ok_or_else(|| {
            AztecBridgeError::Transport(format!("{method}: serialized sibling path too large"))
        })?;
    if raw.len() != expected_len {
        return Err(AztecBridgeError::Transport(format!(
            "{method}: pathSize {path_size} expects {expected_len} bytes, got {}",
            raw.len()
        )));
    }
    let mut sibling_path = Vec::with_capacity(path_size);
    for node in raw[4..].chunks_exact(32) {
        sibling_path.push(node.try_into().unwrap());
    }
    Ok(sibling_path)
}

/// Decode one v5 `Withdrawn` log: topic1 = padded recipient, topic2 = epoch,
/// data = five 32-byte words (amount, numCheckpointsInEpoch, leafIndex,
/// leafId, root).
fn parse_withdrawn_log(log: &Value) -> Result<PortalEvent> {
    let topics = log["topics"]
        .as_array()
        .ok_or_else(|| AztecBridgeError::Transport("eth_getLogs: log without topics".into()))?;
    if topics.len() != 3 || topics[0].as_str() != Some(WITHDRAWN_EVENT_TOPIC) {
        return Err(AztecBridgeError::Transport(format!(
            "eth_getLogs: unexpected topics for a Withdrawn log: {topics:?}"
        )));
    }
    let recipient_word = hex_word(
        "Withdrawn.recipient",
        topics[1].as_str().unwrap_or_default(),
    )?;
    if recipient_word[..12] != [0u8; 12] {
        return Err(AztecBridgeError::Transport(
            "Withdrawn.recipient: non-zero address padding".into(),
        ));
    }
    let mut recipient = [0u8; 20];
    recipient.copy_from_slice(&recipient_word[12..]);
    let epoch_word = hex_word("Withdrawn.epoch", topics[2].as_str().unwrap_or_default())?;
    let epoch_number = word_u64("Withdrawn.epoch", &epoch_word)?;

    let data = log["data"].as_str().unwrap_or_default();
    let raw = hex::decode(data.strip_prefix("0x").unwrap_or(data))
        .map_err(|e| AztecBridgeError::Transport(format!("Withdrawn.data: invalid hex: {e}")))?;
    if raw.len() != 160 {
        return Err(AztecBridgeError::Transport(format!(
            "Withdrawn.data: expected 160 bytes, got {}",
            raw.len()
        )));
    }
    let amount = word_u128("Withdrawn.amount", &raw[0..32])?;
    let num_checkpoints_in_epoch = word_u64("Withdrawn.numCheckpointsInEpoch", &raw[32..64])?;
    let leaf_index = word_u64("Withdrawn.leafIndex", &raw[64..96])?;
    let leaf_id = word_u128("Withdrawn.leafId", &raw[96..128])?;
    let root: [u8; 32] = raw[128..160].try_into().unwrap();

    Ok(PortalEvent::Withdrawn {
        recipient,
        amount,
        epoch_number,
        num_checkpoints_in_epoch,
        leaf_index,
        leaf_id,
        root,
        l1_block_number: as_u64("Withdrawn.blockNumber", &log["blockNumber"])?,
        l1_tx_hash: log["transactionHash"]
            .as_str()
            .unwrap_or_default()
            .to_string(),
    })
}

fn word_u64(field: &str, word: &[u8]) -> Result<u64> {
    if word.len() != 32 {
        return Err(AztecBridgeError::Transport(format!(
            "{field}: expected 32 bytes, got {}",
            word.len()
        )));
    }
    if word[..24] != [0u8; 24] {
        return Err(AztecBridgeError::Transport(format!(
            "{field} exceeds u64 (refusing to truncate)"
        )));
    }
    Ok(u64::from_be_bytes(word[24..32].try_into().unwrap()))
}

fn word_u128(field: &str, word: &[u8]) -> Result<u128> {
    if word.len() != 32 {
        return Err(AztecBridgeError::Transport(format!(
            "{field}: expected 32 bytes, got {}",
            word.len()
        )));
    }
    if word[..16] != [0u8; 16] {
        return Err(AztecBridgeError::Transport(format!(
            "{field} exceeds u128 (refusing to truncate)"
        )));
    }
    Ok(u128::from_be_bytes(word[16..32].try_into().unwrap()))
}

// ---------------------------------------------------------------------------
// Mock client (tests)
// ---------------------------------------------------------------------------

/// In-memory mock implementing the same trait surface as the live client.
#[derive(Debug, Clone, Default)]
pub struct MockAztecClient {
    latest_block: u64,
    proven_block: u64,
    l1_head: u64,
    /// Witnesses keyed by (L2 tx hash, message leaf).
    witnesses: BTreeMap<(String, [u8; 32]), MembershipWitness>,
    events: Vec<PortalEvent>,
}

impl MockAztecClient {
    pub fn new(latest_block: u64, proven_block: u64) -> Self {
        Self {
            latest_block,
            proven_block,
            ..Default::default()
        }
    }

    pub fn with_witness(
        mut self,
        l2_tx_hash: impl Into<String>,
        message: &L2ToL1Msg,
        witness: MembershipWitness,
    ) -> Self {
        self.witnesses
            .insert((l2_tx_hash.into(), message.leaf()), witness);
        self
    }

    pub fn with_events(mut self, events: Vec<PortalEvent>, l1_head: u64) -> Self {
        self.events = events;
        self.l1_head = l1_head;
        self
    }
}

#[async_trait]
impl AztecClient for MockAztecClient {
    async fn latest_block_number(&self) -> Result<u64> {
        Ok(self.latest_block)
    }

    async fn proven_block_number(&self) -> Result<u64> {
        Ok(self.proven_block)
    }

    async fn l2_to_l1_membership_witness(
        &self,
        l2_tx_hash: &str,
        message: &L2ToL1Msg,
    ) -> Result<MembershipWitness> {
        self.witnesses
            .get(&(l2_tx_hash.to_string(), message.leaf()))
            .cloned()
            .ok_or_else(|| {
                AztecBridgeError::Transport(format!(
                    "mock: message not found in L2 tx {l2_tx_hash}"
                ))
            })
    }

    async fn l1_head(&self) -> Result<u64> {
        Ok(self.l1_head)
    }

    async fn query_portal_events(&self, from_l1_block: u64) -> Result<PortalEventBatch> {
        Ok(PortalEventBatch {
            events: self
                .events
                .iter()
                .filter(|e| {
                    let PortalEvent::Withdrawn {
                        l1_block_number, ..
                    } = e;
                    *l1_block_number >= from_l1_block
                })
                .cloned()
                .collect(),
            l1_head: self.l1_head,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn withdrawn_log_decoding_is_fail_closed() {
        let good = serde_json::json!({
            "topics": [
                WITHDRAWN_EVENT_TOPIC,
                format!("0x{}{}", "00".repeat(12), "be".repeat(20)),
                format!("0x{:064x}", 9u64),
            ],
            "data": format!(
                "0x{:064x}{:064x}{:064x}{:064x}{}",
                1000u64,
                2u64,
                3u64,
                7u64,
                "cc".repeat(32)
            ),
            "blockNumber": "0x10",
            "transactionHash": "0xabc",
        });
        let event = parse_withdrawn_log(&good).unwrap();
        let PortalEvent::Withdrawn {
            recipient,
            amount,
            epoch_number,
            num_checkpoints_in_epoch,
            leaf_index,
            leaf_id,
            root,
            l1_block_number,
            ..
        } = event;
        assert_eq!(recipient, [0xbe; 20]);
        assert_eq!(amount, 1000);
        assert_eq!(epoch_number, 9);
        assert_eq!(num_checkpoints_in_epoch, 2);
        assert_eq!(leaf_index, 3);
        assert_eq!(leaf_id, 7);
        assert_eq!(root, [0xCC; 32]);
        assert_eq!(l1_block_number, 16);

        // Wrong topic0 fails closed.
        let mut bad = good.clone();
        bad["topics"][0] = serde_json::json!(format!("0x{}", "11".repeat(32)));
        assert!(parse_withdrawn_log(&bad).is_err());

        // Truncated data fails closed.
        let mut bad = good.clone();
        bad["data"] = serde_json::json!("0x00");
        assert!(parse_withdrawn_log(&bad).is_err());

        // An amount above u128 is a structured error, never a truncation.
        let mut bad = good.clone();
        bad["data"] = serde_json::json!(format!(
            "0x{}{:064x}{:064x}{:064x}{}",
            "ff".repeat(32),
            2u64,
            3u64,
            7u64,
            "cc".repeat(32)
        ));
        let err = parse_withdrawn_log(&bad).unwrap_err();
        assert!(err.to_string().contains("u128"), "{err}");
    }

    #[test]
    fn quantity_parsing_accepts_number_and_hex() {
        assert_eq!(as_u64("m", &serde_json::json!(42)).unwrap(), 42);
        assert_eq!(as_u64("m", &serde_json::json!("42")).unwrap(), 42);
        assert_eq!(as_u64("m", &serde_json::json!("0x2a")).unwrap(), 42);
        assert!(as_u64("m", &serde_json::json!("nope")).is_err());
        assert!(as_u64("m", &serde_json::json!(null)).is_err());
    }
}
