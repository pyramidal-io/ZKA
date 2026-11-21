// Copyright 2026 ZKA Contributors
// SPDX-License-Identifier: Apache-2.0

//! Live-client tests over a recording mock transport speaking the exact
//! wire shapes [`NodeAztecClient`] expects: Aztec node JSON-RPC (`aztec_*`)
//! and Ethereum execution JSON-RPC (`eth_*`).

use async_trait::async_trait;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use zka_bridge_aztec::{
    AztecBridgeConfig, AztecClient, AztecTransport, NodeAztecClient, PortalEvent, Withdrawal,
    WITHDRAWN_EVENT_TOPIC,
};

/// Recording transport with canned responses keyed `node:<method>` /
/// `l1:<method>`.
#[derive(Default)]
struct RecordingTransport {
    responses: HashMap<String, Value>,
    calls: Arc<Mutex<Vec<(String, Value)>>>,
}

impl RecordingTransport {
    fn respond(mut self, key: &str, value: Value) -> Self {
        self.responses.insert(key.to_string(), value);
        self
    }
}

#[async_trait]
impl AztecTransport for RecordingTransport {
    async fn node_rpc(&self, method: &str, params: Value) -> zka_bridge_aztec::Result<Value> {
        let key = format!("node:{method}");
        let exact_key = format!("{key}:{params}");
        self.calls.lock().unwrap().push((key.clone(), params));
        self.responses
            .get(&exact_key)
            .or_else(|| self.responses.get(&key))
            .cloned()
            .ok_or_else(|| {
                zka_bridge_aztec::AztecBridgeError::Transport(format!(
                    "no canned response for {key}"
                ))
            })
    }

    async fn l1_rpc(&self, method: &str, params: Value) -> zka_bridge_aztec::Result<Value> {
        let key = format!("l1:{method}");
        self.calls.lock().unwrap().push((key.clone(), params));
        self.responses.get(&key).cloned().ok_or_else(|| {
            zka_bridge_aztec::AztecBridgeError::Transport(format!("no canned response for {key}"))
        })
    }
}

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
    config
}

#[tokio::test]
async fn client_construction_is_fail_closed_on_config() {
    let mut bad = config();
    bad.reference = "not-registered".into();
    let Err(err) = NodeAztecClient::new(bad, Arc::new(RecordingTransport::default())) else {
        panic!("unregistered chain must fail closed");
    };
    assert!(err.to_string().contains("unknown chain"), "{err}");
}

#[tokio::test]
async fn heights_round_trip_the_node_api() {
    let transport = RecordingTransport::default()
        .respond("node:aztec_getBlockNumber:[]", json!(42))
        .respond("node:aztec_getBlockNumber:[\"proven\"]", json!(40));
    let client = NodeAztecClient::new(config(), Arc::new(transport)).unwrap();
    assert_eq!(client.latest_block_number().await.unwrap(), 42);
    assert_eq!(client.proven_block_number().await.unwrap(), 40);
}

#[tokio::test]
async fn membership_witness_round_trips_and_misses_are_structured() {
    let cfg = {
        let mut c = config();
        c.validate().unwrap();
        c
    };
    let message = cfg.l2_to_l1_message(&Withdrawal {
        recipient: [0xbe; 20],
        amount: 1000,
    });
    let leaf_hex = format!("0x{}", hex::encode(message.leaf()));

    let transport = RecordingTransport::default().respond(
        "node:aztec_getL2ToL1MembershipWitness",
        json!({
            "epochNumber": 9,
            "numCheckpointsInEpoch": 2,
            "root": format!("0x{}", "cc".repeat(32)),
            "leafIndex": 3,
            "siblingPath": "AAAAAqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqu7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7s=",
        }),
    );
    let calls = transport.calls.clone();
    let client = NodeAztecClient::new(config(), Arc::new(transport)).unwrap();
    let witness = client
        .l2_to_l1_membership_witness("0xtx7", &message)
        .await
        .unwrap();
    assert_eq!(witness.epoch_number, 9);
    assert_eq!(witness.num_checkpoints_in_epoch, 2);
    assert_eq!(witness.root, [0xCC; 32]);
    assert_eq!(witness.leaf_index, 3);
    assert_eq!(witness.sibling_path, vec![[0xAA; 32], [0xBB; 32]]);
    // The v5 node was asked for exactly (tx hash, message hash).
    let recorded = calls.lock().unwrap();
    assert_eq!(recorded[0].1, json!(["0xtx7", leaf_hex]));
    drop(recorded);

    // An unknown message (null result) is a structured error.
    let transport =
        RecordingTransport::default().respond("node:aztec_getL2ToL1MembershipWitness", Value::Null);
    let client = NodeAztecClient::new(config(), Arc::new(transport)).unwrap();
    let err = client
        .l2_to_l1_membership_witness("0xtx7", &message)
        .await
        .unwrap_err();
    assert!(err.to_string().contains("not found"), "{err}");
}

#[tokio::test]
async fn portal_events_filter_on_the_portal_address_and_topic() {
    let log = json!({
        "topics": [
            WITHDRAWN_EVENT_TOPIC,
            format!("0x{}{}", "00".repeat(12), "be".repeat(20)),
            format!("0x{:064x}", 9u64),
        ],
        "data": format!("0x{:064x}{:064x}{:064x}{:064x}{}", 1000u64, 2u64, 3u64, 7u64, "cc".repeat(32)),
        "blockNumber": "0x10",
        "transactionHash": "0xfeed",
    });
    let transport = RecordingTransport::default()
        .respond("l1:eth_blockNumber", json!("0x20"))
        .respond("l1:eth_getLogs", json!([log]));
    let calls = transport.calls.clone();
    let client = NodeAztecClient::new(config(), Arc::new(transport)).unwrap();

    let batch = client.query_portal_events(5).await.unwrap();
    assert_eq!(batch.l1_head, 0x20);
    assert_eq!(batch.events.len(), 1);
    let PortalEvent::Withdrawn {
        recipient,
        amount,
        epoch_number,
        num_checkpoints_in_epoch,
        leaf_index,
        leaf_id,
        root,
        l1_block_number,
        l1_tx_hash,
    } = &batch.events[0];
    assert_eq!(*recipient, [0xbe; 20]);
    assert_eq!(*amount, 1000);
    assert_eq!(*epoch_number, 9);
    assert_eq!(*num_checkpoints_in_epoch, 2);
    assert_eq!(*leaf_index, 3);
    assert_eq!(*leaf_id, 7);
    assert_eq!(*root, [0xCC; 32]);
    assert_eq!(*l1_block_number, 16);
    assert_eq!(l1_tx_hash, "0xfeed");

    // The filter pinned the portal address + Withdrawn topic + cursor range.
    let recorded = calls.lock().unwrap();
    let filter = &recorded
        .iter()
        .find(|(k, _)| k == "l1:eth_getLogs")
        .unwrap()
        .1[0];
    assert_eq!(filter["address"], format!("0x{}", "11".repeat(20)));
    assert_eq!(filter["topics"][0], WITHDRAWN_EVENT_TOPIC);
    assert_eq!(filter["fromBlock"], "0x5");
    assert_eq!(filter["toBlock"], "0x20");
}
