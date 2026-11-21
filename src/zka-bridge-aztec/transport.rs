// Copyright 2026 ZKA Contributors
// SPDX-License-Identifier: Apache-2.0

//! Typed transport boundary for live Aztec endpoints.
//!
//! Two REAL wire protocols, both JSON-RPC 2.0 over HTTP — documented
//! honestly, no invented protocols:
//!
//! * [`AztecTransport::node_rpc`] — the **Aztec node HTTP API**
//!   (AZUP-2/v5). The node serves JSON-RPC 2.0; this is the same
//!   wire surface `createAztecNodeClient` speaks in `aztec.js` (`aztec_*`
//!   methods: `aztec_getBlockNumber`, `aztec_getL2ToL1MembershipWitness`,
//!   ...). The PXE is NOT on this
//!   surface by design: the adapter only reads public rollup state (block
//!   numbers, outbox witnesses) — no Aztec-side viewing/spending keys ever
//!   touch the ops boundary.
//! * [`AztecTransport::l1_rpc`] — standard **Ethereum execution JSON-RPC**
//!   (`eth_blockNumber`, `eth_getLogs`, ...) against the L1 anchor, used to
//!   index the portal's `Withdrawn` events.
//!
//! The trait keeps both mockable byte-for-byte in CI; the live
//! implementation is [`HttpJsonRpcTransport`].

use async_trait::async_trait;
use serde_json::Value;

use crate::errors::{AztecBridgeError, Result};

/// Wire transport for live Aztec (L2 node) + L1 endpoints.
#[async_trait]
pub trait AztecTransport: Send + Sync {
    /// JSON-RPC 2.0 call against the Aztec node HTTP API (`aztec_*` methods).
    async fn node_rpc(&self, method: &str, params: Value) -> Result<Value>;

    /// JSON-RPC 2.0 call against the L1 execution endpoint (`eth_*` methods).
    async fn l1_rpc(&self, method: &str, params: Value) -> Result<Value>;
}

/// HTTP implementation of [`AztecTransport`]. Holds endpoint URLs only —
/// never key material.
pub struct HttpJsonRpcTransport {
    l2_node_url: String,
    l1_rpc_url: String,
    http: reqwest::Client,
}

impl HttpJsonRpcTransport {
    /// Build a transport from endpoint URLs. Validates configuration shape
    /// (scheme/host present); never probes liveness.
    pub fn new(l2_node_url: impl Into<String>, l1_rpc_url: impl Into<String>) -> Result<Self> {
        let l2_node_url = l2_node_url.into();
        let l1_rpc_url = l1_rpc_url.into();
        // Canonical fail-closed transport policy (zka_registry::transport):
        // TLS for every non-loopback host, cleartext only for an explicit
        // loopback authority, no credentials in the URL. Both endpoints are
        // plain HTTP posters (the Aztec node JSON-RPC API and the L1
        // execution JSON-RPC), so WebSocket schemes they could never dial are
        // rejected outright. Everything read over these channels is
        // security-relevant: block numbers, outbox membership witnesses, and
        // the portal `Withdrawn` events the adapter settles on.
        for (field, url) in [("l2_node_url", &l2_node_url), ("l1_rpc_url", &l1_rpc_url)] {
            zka_registry::transport::RpcEndpoint::parse_http(field, url.trim())
                .map_err(|e| AztecBridgeError::Config(e.to_string()))?;
        }
        let http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(15))
            .build()
            .map_err(|e| AztecBridgeError::Transport(e.to_string()))?;
        Ok(Self {
            l2_node_url,
            l1_rpc_url,
            http,
        })
    }

    async fn json_rpc(&self, url: &str, method: &str, params: Value) -> Result<Value> {
        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": method,
            "params": params,
        });
        let response = self
            .http
            .post(url)
            .json(&body)
            .send()
            .await
            .map_err(|e| AztecBridgeError::Transport(format!("{method}: {e}")))?;
        let status = response.status();
        if !status.is_success() {
            return Err(AztecBridgeError::Transport(format!(
                "{method}: HTTP {status}"
            )));
        }
        let envelope: Value = response
            .json()
            .await
            .map_err(|e| AztecBridgeError::Transport(format!("{method}: {e}")))?;
        if let Some(err) = envelope.get("error").filter(|e| !e.is_null()) {
            return Err(AztecBridgeError::Transport(format!(
                "{method}: JSON-RPC error {err}"
            )));
        }
        envelope
            .get("result")
            .cloned()
            .ok_or_else(|| AztecBridgeError::Transport(format!("{method}: missing `result`")))
    }
}

#[async_trait]
impl AztecTransport for HttpJsonRpcTransport {
    async fn node_rpc(&self, method: &str, params: Value) -> Result<Value> {
        self.json_rpc(&self.l2_node_url, method, params).await
    }

    async fn l1_rpc(&self, method: &str, params: Value) -> Result<Value> {
        self.json_rpc(&self.l1_rpc_url, method, params).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transport_follows_the_shared_policy() {
        // `HttpJsonRpcTransport` deliberately does not implement `Debug` (it
        // holds the endpoint URLs, which may carry provider credentials), so
        // rejections are inspected by matching rather than `unwrap_err`.
        fn rejection(l2: &str, l1: &str) -> String {
            match HttpJsonRpcTransport::new(l2, l1) {
                Err(e) => e.to_string(),
                Ok(_) => panic!("expected `{l2}` / `{l1}` to be rejected"),
            }
        }

        // TLS to remote endpoints is valid.
        assert!(HttpJsonRpcTransport::new(
            "https://aztec-node.example:8080",
            "https://l1-rpc.example:8545"
        )
        .is_ok());

        // Cleartext to a remote host fails closed on either endpoint, and the
        // rejection never echoes a path or query.
        let err = rejection("http://aztec-node:8080/v1/API-KEY", "http://localhost:8545");
        assert!(err.contains("l2_node_url must use https://"), "{err}");
        assert!(err.contains("loopback"), "{err}");
        assert!(!err.contains("API-KEY"), "{err}");

        let err = rejection("http://localhost:8080", "http://l1-rpc:8545");
        assert!(err.contains("l1_rpc_url must use https://"), "{err}");

        // WebSocket schemes these HTTP posters could never dial are rejected,
        // even though the L1 endpoint speaks Ethereum JSON-RPC.
        let err = rejection("http://localhost:8080", "wss://l1-rpc.example:8545");
        assert!(err.contains("must be an https endpoint"), "{err}");

        // Synthetic URL userinfo fails closed without echoing either value.
        for (username, password) in [
            ("fixture-user", Some("fixture-password")),
            ("fixture-user", None),
            ("", Some("fixture-password")),
        ] {
            let mut endpoint = reqwest::Url::parse("https://aztec-node.example:8080").unwrap();
            endpoint.set_username(username).unwrap();
            endpoint.set_password(password).unwrap();
            assert_eq!(endpoint.username(), username);
            assert_eq!(endpoint.password(), password);
            let err = rejection(endpoint.as_str(), "http://localhost:8545");
            assert!(err.contains("must not embed credentials"), "{err}");
            if !username.is_empty() {
                assert!(!err.contains(username), "{err}");
            }
            if let Some(password) = password {
                assert!(!err.contains(password), "{err}");
            }
        }
    }

    #[test]
    fn transport_validates_url_shape() {
        assert!(
            HttpJsonRpcTransport::new("http://localhost:8080", "http://localhost:8545").is_ok()
        );
        assert!(
            HttpJsonRpcTransport::new("ftp://localhost:8080", "http://localhost:8545").is_err()
        );
        assert!(HttpJsonRpcTransport::new("http://localhost:8080", "").is_err());
        assert!(HttpJsonRpcTransport::new("https://", "http://x").is_err());
    }
}
