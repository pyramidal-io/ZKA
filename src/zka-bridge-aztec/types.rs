// Copyright 2026 ZKA Contributors
// SPDX-License-Identifier: Apache-2.0

//! Core Aztec settlement types: configuration (registry + finality-policy
//! validated, fail-closed), the L2→L1 withdrawal message model, and the
//! cross-environment content hashing that binds all three implementations
//! (Noir `zka_transfer_aztec::withdraw_content_hash`, Solidity
//! `ZKAAztecPortal.withdrawContentHash`, and this module) byte-for-byte.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::time::Duration;

use crate::errors::{AztecBridgeError, Result};

/// `bytes4(keccak256("withdraw(address,uint256)"))` — the selector prefix of
/// the withdrawal content preimage. Pinned as a constant (this crate carries
/// no keccak dependency); cross-locked by the golden-vector test below
/// against the L2 (`zka_transfer_aztec`) and L1 (`ZKAAztecPortal`) values.
pub const WITHDRAW_SELECTOR: [u8; 4] = [0xf3, 0xfe, 0xf3, 0xa3];

/// `keccak256("Withdrawn(address,uint256,uint256,uint256,uint256,uint256,bytes32)")`
/// — topic0 of the portal's v5 `Withdrawn` event, used by the indexer's
/// `eth_getLogs` filter. Pinned as a constant; cross-checked against
/// `ethers::utils::keccak256` in the settlement-ops smoke.
pub const WITHDRAWN_EVENT_TOPIC: &str =
    "0x0bd6400946bb9c460112e81921009ecb18dca546a777718240ae403e899ac8e7";

/// Aztec L2→L1 content hashing: SHA-256 truncated to a BN254 field element.
/// Mirrors `AztecHash.sha256ToField`: the digest's first 31 bytes, prefixed
/// with a zero byte.
pub fn sha256_to_field(data: &[u8]) -> [u8; 32] {
    let digest = Sha256::digest(data);
    let mut field = [0u8; 32];
    field[1..].copy_from_slice(&digest[..31]);
    field
}

/// The L2→L1 content hash for a `(recipient, amount)` withdrawal:
/// `sha256_to_field(selector ++ recipient_be(32) ++ amount_be(32))`.
///
/// MUST equal the L2 `zka_transfer_aztec::withdraw_content_hash` and the L1
/// `ZKAAztecPortal.withdrawContentHash` for the same inputs — the golden
/// vector `(0xbeef, 1000)` pins all three (see `test_ContentHashMatchesL2Golden`
/// in `test/ZKAAztecPortal.t.sol`).
pub fn withdraw_content_hash(recipient: [u8; 20], amount: u128) -> [u8; 32] {
    let mut preimage = Vec::with_capacity(4 + 32 + 32);
    preimage.extend_from_slice(&WITHDRAW_SELECTOR);
    let mut word = [0u8; 32];
    word[12..].copy_from_slice(&recipient);
    preimage.extend_from_slice(&word);
    let mut amount_word = [0u8; 32];
    amount_word[16..].copy_from_slice(&amount.to_be_bytes());
    preimage.extend_from_slice(&amount_word);
    sha256_to_field(&preimage)
}

/// One ZKA withdrawal exiting the Aztec deployment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Withdrawal {
    /// L1 recipient the released asset goes to.
    pub recipient: [u8; 20],
    /// Withdrawn amount (in the underlying's base units).
    pub amount: u128,
}

/// A complete L2→L1 message as the rollup Outbox hashes it
/// (`AztecDataStructures.L2ToL1Msg`): (sender, recipient, content).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct L2ToL1Msg {
    /// The L2 ZKATransfer contract (Aztec address) that emitted the message.
    pub sender_actor: [u8; 32],
    /// The Aztec protocol/rollup version the message was emitted under.
    pub sender_version: u64,
    /// The L1 portal authorised to consume the message.
    pub recipient_actor: [u8; 20],
    /// Chain id of the L1 the portal is deployed on.
    pub recipient_chain_id: u64,
    /// `withdraw_content_hash(recipient, amount)`.
    pub content: [u8; 32],
}

impl L2ToL1Msg {
    /// The message leaf as inserted into the rollup's L2→L1 message tree:
    /// `sha256_to_field(abi.encodePacked(sender.actor, sender.version,
    /// recipient.actor, recipient.chainId, content))` — 32 + 32 + 20 + 32 +
    /// 32 bytes, matching the Outbox hashing of
    /// `AztecDataStructures.L2ToL1Msg`.
    pub fn leaf(&self) -> [u8; 32] {
        let mut preimage = Vec::with_capacity(32 + 32 + 20 + 32 + 32);
        preimage.extend_from_slice(&self.sender_actor);
        let mut version = [0u8; 32];
        version[24..].copy_from_slice(&self.sender_version.to_be_bytes());
        preimage.extend_from_slice(&version);
        preimage.extend_from_slice(&self.recipient_actor);
        let mut chain_id = [0u8; 32];
        chain_id[24..].copy_from_slice(&self.recipient_chain_id.to_be_bytes());
        preimage.extend_from_slice(&chain_id);
        preimage.extend_from_slice(&self.content);
        sha256_to_field(&preimage)
    }
}

/// Aztec protocol surface the adapter is allowed to speak.
///
/// AZUP-2/v5 changes both the node RPC names and the Outbox membership
/// witness shape. v6 is a new rollup from genesis but keeps the v5 L1
/// Outbox, L2→L1 message leaf, `aztec_getL2ToL1MembershipWitness` and
/// `aztec_getBlockNumber` wire shapes, so both variants share one codec; the
/// variant pins which rollup the deployment binding was qualified against.
/// v6 is the default: it has been the canonical rollup on mainnet and testnet
/// since 2026-10-26. v5 stays an explicit option until the V5 rollup sunsets.
/// Unsupported versions fail during config parsing/validation instead of
/// silently falling back to legacy aliases.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum AztecProtocolVersion {
    #[serde(rename = "v5")]
    V5,
    #[default]
    #[serde(rename = "v6")]
    V6,
}

impl AztecProtocolVersion {
    pub fn minimum_rollup_version(self) -> u64 {
        match self {
            Self::V5 => 5,
            Self::V6 => 6,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::V5 => "v5",
            Self::V6 => "v6",
        }
    }
}

/// The exact rollup a public Aztec network runs for one protocol version, as
/// its node reports it in `node_getNodeInfo` (`rollupVersion`, `l1ChainId`).
/// The rollup version is the L2→L1 message `sender.version`, so a wrong value
/// reconstructs messages the Outbox never holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PinnedRollup {
    /// Registry reference of the Aztec chain (`aztec:<reference>`).
    pub reference: &'static str,
    pub protocol_version: AztecProtocolVersion,
    pub rollup_version: u64,
    /// Chain id of the L1 the rollup settles on.
    pub l1_chain_id: u64,
    /// The rollup instance on the L1 anchor.
    pub rollup_address: [u8; 20],
    /// That rollup's Inbox, which a portal's deposits pass through.
    pub inbox_address: [u8; 20],
    /// That rollup's Outbox, which a portal's exits consume from.
    pub outbox_address: [u8; 20],
}

/// Decode a 0x-prefixed address at compile time, so a malformed pin cannot build.
const fn pinned_address(address: &str) -> [u8; 20] {
    const fn nibble(digit: u8) -> u8 {
        match digit {
            b'0'..=b'9' => digit - b'0',
            b'a'..=b'f' => digit - b'a' + 10,
            b'A'..=b'F' => digit - b'A' + 10,
            _ => panic!("pinned address has a non-hex digit"),
        }
    }
    let text = address.as_bytes();
    assert!(text.len() == 42, "pinned address must be 0x plus 40 digits");
    let mut bytes = [0u8; 20];
    let mut index = 0;
    while index < 20 {
        bytes[index] = nibble(text[2 + 2 * index]) * 16 + nibble(text[3 + 2 * index]);
        index += 1;
    }
    bytes
}

/// Pinned rollups of the public Aztec networks. V6 versions were read from
/// aztec-mainnet.drpc.org and aztec-testnet.drpc.org on 2026-10-26; V5 versions
/// come from the 2026-09-06 fee probe and v5.testnet.rpc.aztec-labs.com.
/// Addresses were read on 2026-11-06 from each L1 `Registry.getRollup(version)`
/// and that rollup's `getInbox()` and `getOutbox()`, at Ethereum block 26357000
/// and Sepolia block 12077743.
/// Every non-dev `aztec` chain must have an entry here for the protocol it is
/// configured with.
pub const PINNED_ROLLUPS: &[PinnedRollup] = &[
    PinnedRollup {
        reference: "mainnet",
        protocol_version: AztecProtocolVersion::V6,
        rollup_version: 2_070_860_440,
        l1_chain_id: 1,
        rollup_address: pinned_address("0xE37A2663Cc9c119BA41572C40fAb0bbb23a5402f"),
        inbox_address: pinned_address("0x603B06cEcC1d537Aad83f1d46651e32014c5B6aD"),
        outbox_address: pinned_address("0xFD2a12658A82d7156DA56c7A8d49A69fC966c8D1"),
    },
    PinnedRollup {
        reference: "alpha-testnet",
        protocol_version: AztecProtocolVersion::V6,
        rollup_version: 679_261_766,
        l1_chain_id: 11_155_111,
        rollup_address: pinned_address("0x1f435a7F2dA358caF887A470FAeEE7d5D5f4eFBA"),
        inbox_address: pinned_address("0x7cdC32Dd7d008870A95f1837Ffd7229ef676EF8A"),
        outbox_address: pinned_address("0xA5A0f7a7BDAf280964a1922A68C83462E5F6E15b"),
    },
    PinnedRollup {
        reference: "mainnet",
        protocol_version: AztecProtocolVersion::V5,
        rollup_version: 4_248_422_647,
        l1_chain_id: 1,
        rollup_address: pinned_address("0x91fF8bbD8Ebb07893010D50A48A1609e5EBd8E34"),
        inbox_address: pinned_address("0x7d4Ef0676c2032bbCC09227501D34d86641ab8cA"),
        outbox_address: pinned_address("0x5B062aB5fD3A66BC7e73b04CeD38587673b6A2D7"),
    },
    PinnedRollup {
        reference: "alpha-testnet",
        protocol_version: AztecProtocolVersion::V5,
        rollup_version: 1_821_665_230,
        l1_chain_id: 11_155_111,
        rollup_address: pinned_address("0xD73A91bdcF6891C7642F3e460036e1ef2CC23178"),
        inbox_address: pinned_address("0x3047dBF2b7dd9f58AC41113525480F94745a4f7C"),
        outbox_address: pinned_address("0x905f80009bBef9d9426675B45009922971eD42fF"),
    },
];

/// The pinned rollup for `aztec:<reference>` under `protocol_version`, if any.
pub fn pinned_rollup(
    reference: &str,
    protocol_version: AztecProtocolVersion,
) -> Option<&'static PinnedRollup> {
    PINNED_ROLLUPS
        .iter()
        .find(|pin| pin.reference == reference && pin.protocol_version == protocol_version)
}

/// Parse a 0x-prefixed 20-byte hex address.
pub fn parse_eth_address(field: &str, value: &str) -> Result<[u8; 20]> {
    let raw = hex::decode(value.trim().strip_prefix("0x").unwrap_or(value.trim()))
        .map_err(|e| AztecBridgeError::Config(format!("{field}: invalid hex: {e}")))?;
    let bytes: [u8; 20] = raw
        .try_into()
        .map_err(|_| AztecBridgeError::Config(format!("{field}: expected 20 bytes")))?;
    Ok(bytes)
}

/// Parse a 0x-prefixed 32-byte hex value.
pub fn parse_bytes32(field: &str, value: &str) -> Result<[u8; 32]> {
    let raw = hex::decode(value.trim().strip_prefix("0x").unwrap_or(value.trim()))
        .map_err(|e| AztecBridgeError::Config(format!("{field}: invalid hex: {e}")))?;
    let bytes: [u8; 32] = raw
        .try_into()
        .map_err(|_| AztecBridgeError::Config(format!("{field}: expected 32 bytes")))?;
    Ok(bytes)
}

/// Adapter configuration. Holds endpoint URLs and deployment bindings only —
/// never key material. Validation is fail-closed against the canonical
/// encoding registry: the Aztec chain must be registered for the `aztec`
/// adapter, the L1 anchor must be a registered eip155 chain, and the
/// configured depths must satisfy the chain's finality-policy floor
/// (tighten-not-loosen).
#[derive(Debug, Clone)]
pub struct AztecBridgeConfig {
    /// Aztec node HTTP endpoint (JSON-RPC 2.0, `aztec_*` methods).
    pub l2_node_url: String,
    /// Registry reference of the Aztec chain (`mainnet` / `alpha-testnet` /
    /// `sandbox`) — together with the `aztec` namespace this is the
    /// fail-closed registry key.
    pub reference: String,
    /// L1 execution JSON-RPC endpoint (standard `eth_*` methods).
    pub l1_rpc_url: String,
    /// Chain id of the L1 anchor (must be a registered eip155 chain).
    pub l1_chain_id: u64,
    /// Deployed `ZKAAztecPortal` address on the L1 anchor.
    pub portal_address: [u8; 20],
    /// The rollup's L1 Outbox the portal consumes from. Public networks must
    /// match their pinned Outbox.
    pub outbox_address: [u8; 20],
    /// The L2 ZKATransfer contract (Aztec address) bound as message sender.
    pub l2_bridge: [u8; 32],
    /// Protocol surface to use (v5 or v6; v6 is the default).
    pub protocol_version: AztecProtocolVersion,
    /// Aztec rollup version the deployment runs under (`node_getNodeInfo`
    /// `rollupVersion`). Public networks must match their pinned rollup;
    /// zero means "use the pinned value". A dev chain has no pin and must set
    /// it explicitly.
    pub rollup_version: u64,
    /// Receipt confirmations before an L1 consume tx is `Confirmed`
    /// (floor: the aztec chain's `minConfirmations`).
    pub confirmations: u64,
    /// L1 blocks the rollup proof must be buried under before an outbox
    /// entry is treated as final (floor: the aztec chain's
    /// `minFinalityDepth`).
    pub finality_depth: u64,
    /// HTTP timeout.
    pub timeout: Duration,
}

impl AztecBridgeConfig {
    /// Build a config with the chain's policy floors as the default depths and
    /// its pinned rollup as the default rollup version (both resolved at
    /// validation; zero here means "use the registry floor / the pin").
    pub fn new(
        l2_node_url: impl Into<String>,
        reference: impl Into<String>,
        l1_rpc_url: impl Into<String>,
        l1_chain_id: u64,
    ) -> Self {
        Self {
            l2_node_url: l2_node_url.into(),
            reference: reference.into(),
            l1_rpc_url: l1_rpc_url.into(),
            l1_chain_id,
            portal_address: [0u8; 20],
            outbox_address: [0u8; 20],
            l2_bridge: [0u8; 32],
            protocol_version: AztecProtocolVersion::default(),
            rollup_version: 0,
            confirmations: 0,
            finality_depth: 0,
            timeout: Duration::from_secs(15),
        }
    }

    /// Validate configuration shape (not liveness) and resolve zero depths
    /// to the registry policy floors. Fail-closed on: non-http(s) URLs,
    /// unregistered aztec chain, unregistered L1 anchor, zero deployment
    /// addresses, depths below the policy floor, or a rollup version, Outbox
    /// or L1 anchor that differs from the network's pinned rollup.
    pub fn validate(&mut self) -> Result<()> {
        // Canonical fail-closed transport policy (zka_registry::transport,
        // `TransportProfile::Http`): TLS for every non-loopback host,
        // cleartext only for an explicit loopback authority, no credentials
        // in the URL, and no WebSocket schemes these HTTP posters could never
        // dial. Checked before the registry/finality checks below, which
        // trust answers arriving over these channels.
        for (field, url) in [
            ("l2_node_url", &self.l2_node_url),
            ("l1_rpc_url", &self.l1_rpc_url),
        ] {
            zka_registry::transport::RpcEndpoint::parse_http(field, url.trim())
                .map_err(|e| AztecBridgeError::Config(e.to_string()))?;
        }
        // Both ends of the portal binding must be registered in the
        // canonical encoding registry: the Aztec chain (`aztec:<reference>`
        // under the `aztec` adapter) and the eip155 anchor the portal is
        // deployed on. Fail closed on either.
        let registry = zka_registry::Registry::embedded();
        let chain = registry.settlement_chain("aztec", self.reference.trim(), "aztec")?;
        registry.eip155_chain(self.l1_chain_id)?;
        if self.confirmations == 0 {
            self.confirmations = chain.finality_policy.min_confirmations;
        }
        if self.finality_depth == 0 {
            self.finality_depth = chain.finality_policy.min_finality_depth;
        }
        // Tighten-not-loosen: configured depths may exceed the floor but
        // never sit below it.
        chain.finality_policy.require_depths(
            &chain.chain_id,
            self.confirmations,
            self.finality_depth,
        )?;
        if self.portal_address == [0u8; 20] {
            return Err(AztecBridgeError::Config(
                "portal_address is the zero address".into(),
            ));
        }
        if self.outbox_address == [0u8; 20] {
            return Err(AztecBridgeError::Config(
                "outbox_address is the zero address".into(),
            ));
        }
        if self.l2_bridge == [0u8; 32] {
            return Err(AztecBridgeError::Config(
                "l2_bridge is the zero actor".into(),
            ));
        }
        self.resolve_rollup(&chain.chain_id, &chain.tier)
    }

    /// Bind the rollup: a public network must match its pinned rollup version
    /// (zero resolves to the pin) and pinned Outbox, on the pinned L1 anchor; a
    /// dev chain has no pin and must name its rollup explicitly.
    fn resolve_rollup(&mut self, chain_id: &str, tier: &str) -> Result<()> {
        let protocol = self.protocol_version.label();
        match pinned_rollup(self.reference.trim(), self.protocol_version) {
            Some(pin) => {
                if self.l1_chain_id != pin.l1_chain_id {
                    return Err(AztecBridgeError::Config(format!(
                        "{chain_id} {protocol} settles on eip155:{}, got l1_chain_id {}",
                        pin.l1_chain_id, self.l1_chain_id
                    )));
                }
                if self.rollup_version == 0 {
                    self.rollup_version = pin.rollup_version;
                } else if self.rollup_version != pin.rollup_version {
                    return Err(AztecBridgeError::Config(format!(
                        "{chain_id} {protocol} pins rollup_version {}, got {}",
                        pin.rollup_version, self.rollup_version
                    )));
                }
                if self.outbox_address != pin.outbox_address {
                    return Err(AztecBridgeError::Config(format!(
                        "{chain_id} {protocol} pins outbox_address 0x{}, got 0x{}",
                        hex::encode(pin.outbox_address),
                        hex::encode(self.outbox_address)
                    )));
                }
            }
            None if tier == "dev" => {
                if self.rollup_version == 0 {
                    return Err(AztecBridgeError::Config(format!(
                        "{chain_id} has no pinned rollup: set rollup_version to the node's \
                         node_getNodeInfo rollupVersion"
                    )));
                }
                if self.rollup_version < self.protocol_version.minimum_rollup_version() {
                    return Err(AztecBridgeError::Config(format!(
                        "protocol {protocol} requires rollup_version >= {}, got {}",
                        self.protocol_version.minimum_rollup_version(),
                        self.rollup_version
                    )));
                }
            }
            None => {
                return Err(AztecBridgeError::Config(format!(
                    "{chain_id} has no pinned {protocol} rollup; refusing an unpinned public network"
                )));
            }
        }
        Ok(())
    }

    /// Reconstruct the exact L2→L1 message `ZKATransfer._process_withdrawal`
    /// emits for a withdrawal under this deployment binding.
    pub fn l2_to_l1_message(&self, withdrawal: &Withdrawal) -> L2ToL1Msg {
        L2ToL1Msg {
            sender_actor: self.l2_bridge,
            sender_version: self.rollup_version,
            recipient_actor: self.portal_address,
            recipient_chain_id: self.l1_chain_id,
            content: withdraw_content_hash(withdrawal.recipient, withdrawal.amount),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn beef_recipient() -> [u8; 20] {
        let mut r = [0u8; 20];
        r[18] = 0xbe;
        r[19] = 0xef;
        r
    }

    fn valid_config() -> AztecBridgeConfig {
        let mut config = AztecBridgeConfig::new(
            "http://localhost:8080",
            "sandbox",
            "http://localhost:8545",
            31337,
        );
        config.portal_address = [0x11u8; 20];
        config.outbox_address = [0x22u8; 20];
        config.l2_bridge = [0x33u8; 32];
        // The sandbox has no pinned rollup, so it names one explicitly.
        config.rollup_version = 6;
        config
    }

    /// `valid_config` moved to aztec:mainnet on the pinned V6 Outbox, leaving
    /// the rollup version to the pin.
    fn mainnet_config() -> AztecBridgeConfig {
        let mut config = valid_config();
        config.reference = "mainnet".into();
        config.l1_chain_id = 1;
        config.rollup_version = 0;
        config.outbox_address = pinned_rollup("mainnet", AztecProtocolVersion::V6)
            .unwrap()
            .outbox_address;
        config
    }

    #[test]
    fn config_endpoints_follow_the_shared_transport_policy() {
        // The loopback sandbox config stays valid.
        valid_config().validate().unwrap();

        // TLS to remote endpoints is valid.
        let mut config = valid_config();
        config.l2_node_url = "https://aztec-node.example:8080".into();
        config.l1_rpc_url = "https://l1-rpc.example:8545".into();
        config.validate().unwrap();

        // Cleartext to a remote host fails closed on either endpoint, and the
        // error never echoes the endpoint's path or query.
        let mut config = valid_config();
        config.l2_node_url = "http://aztec-node:8080/v1/API-KEY".into();
        let err = config.validate().unwrap_err().to_string();
        assert!(err.contains("l2_node_url must use https://"), "{err}");
        assert!(err.contains("loopback"), "{err}");
        assert!(!err.contains("API-KEY"), "{err}");

        let mut config = valid_config();
        config.l1_rpc_url = "http://l1-rpc:8545".into();
        let err = config.validate().unwrap_err().to_string();
        assert!(err.contains("l1_rpc_url must use https://"), "{err}");

        // WebSocket schemes these HTTP posters could never dial are rejected.
        let mut config = valid_config();
        config.l1_rpc_url = "wss://l1-rpc.example:8545".into();
        let err = config.validate().unwrap_err().to_string();
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
            let mut config = valid_config();
            config.l2_node_url = endpoint.into();
            let err = config.validate().unwrap_err().to_string();
            assert!(err.contains("must not embed credentials"), "{err}");
            if !username.is_empty() {
                assert!(!err.contains(username), "{err}");
            }
            if let Some(password) = password {
                assert!(!err.contains(password), "{err}");
            }
        }
    }

    /// THE cross-environment lock: the Rust content hash for (0xbeef, 1000)
    /// must equal the L2 `zka_transfer_aztec::withdraw_content_hash` golden
    /// and the L1 `ZKAAztecPortal.withdrawContentHash` value
    /// (test_ContentHashMatchesL2Golden).
    #[test]
    fn content_hash_matches_l2_and_l1_golden() {
        let golden = "002c54ccb6af0251a12093d39b5dd48465cf1061ebf84a15c54cb7839261ef99";
        assert_eq!(
            hex::encode(withdraw_content_hash(beef_recipient(), 1000)),
            golden
        );
    }

    #[test]
    fn content_hash_binds_recipient_and_amount() {
        let base = withdraw_content_hash(beef_recipient(), 1000);
        let mut other_recipient = beef_recipient();
        other_recipient[19] = 0xee;
        assert_ne!(base, withdraw_content_hash(other_recipient, 1000));
        assert_ne!(base, withdraw_content_hash(beef_recipient(), 1001));
    }

    #[test]
    fn sha256_to_field_top_byte_is_zero() {
        let field = sha256_to_field(b"any preimage");
        assert_eq!(field[0], 0, "field form must be < 2^248");
        // And the remaining bytes are the digest's first 31 bytes.
        let digest = Sha256::digest(b"any preimage");
        assert_eq!(&field[1..], &digest[..31]);
    }

    #[test]
    fn message_leaf_binds_every_field() {
        let config = {
            let mut c = valid_config();
            c.validate().unwrap();
            c
        };
        let withdrawal = Withdrawal {
            recipient: beef_recipient(),
            amount: 1000,
        };
        let base = config.l2_to_l1_message(&withdrawal);
        let leaf = base.leaf();

        let mut m = base;
        m.sender_actor[0] ^= 1;
        assert_ne!(leaf, m.leaf(), "leaf binds the L2 sender");
        let mut m = base;
        m.sender_version += 1;
        assert_ne!(leaf, m.leaf(), "leaf binds the rollup version");
        let mut m = base;
        m.recipient_actor[0] ^= 1;
        assert_ne!(leaf, m.leaf(), "leaf binds the portal");
        let mut m = base;
        m.recipient_chain_id += 1;
        assert_ne!(leaf, m.leaf(), "leaf binds the L1 chain id");
        let mut m = base;
        m.content[31] ^= 1;
        assert_ne!(leaf, m.leaf(), "leaf binds the content");
    }

    #[test]
    fn message_leaf_matches_aztec_v5_outbox_golden() {
        // Observed from a v5 sandbox withdrawal tx effect and cross-checked
        // against Aztec's Hash.sha256ToField(DataStructures.L2ToL1Msg).
        let message = L2ToL1Msg {
            sender_actor: parse_bytes32(
                "sender_actor",
                "0x284a851b75227ae455088d906be3d1d2448317b10f39527e8946c4d2b269ea8e",
            )
            .unwrap(),
            sender_version: 2_283_412_736,
            recipient_actor: parse_eth_address(
                "recipient_actor",
                "0x71C95911E9a5D330f4D621842EC243EE1343292e",
            )
            .unwrap(),
            recipient_chain_id: 31_337,
            content: parse_bytes32(
                "content",
                "0x002c54ccb6af0251a12093d39b5dd48465cf1061ebf84a15c54cb7839261ef99",
            )
            .unwrap(),
        };

        assert_eq!(
            hex::encode(message.leaf()),
            "004c7f197cd1a34e62c32a6d0df62794a8eb2cb834968710fd1edfe86280bea9"
        );
    }

    #[test]
    fn config_validation_accepts_registered_chain_and_resolves_floors() {
        let mut config = valid_config();
        config.validate().unwrap();
        assert_eq!(config.protocol_version, AztecProtocolVersion::V6);
        assert_eq!(config.rollup_version, 6);
        // Sandbox floors (instant finality) resolved from the registry.
        assert_eq!(config.confirmations, 1);
        assert_eq!(config.finality_depth, 1);

        // Mainnet floors are the eip155:1-anchored depths.
        let mut config = mainnet_config();
        config.validate().unwrap();
        assert_eq!(config.confirmations, 2);
        assert_eq!(config.finality_depth, 64);
    }

    #[test]
    fn public_networks_bind_their_pinned_rollup() {
        // A new config defaults to v6 and resolves each public network's pin.
        let mut config = mainnet_config();
        assert_eq!(config.protocol_version, AztecProtocolVersion::V6);
        config.validate().unwrap();
        assert_eq!(config.rollup_version, 2_070_860_440);
        // The pin is the L2→L1 message sender.version.
        let message = config.l2_to_l1_message(&Withdrawal {
            recipient: beef_recipient(),
            amount: 1000,
        });
        assert_eq!(message.sender_version, 2_070_860_440);

        let mut config = valid_config();
        config.reference = "alpha-testnet".into();
        config.l1_chain_id = 11_155_111;
        config.rollup_version = 0;
        config.outbox_address = pinned_rollup("alpha-testnet", AztecProtocolVersion::V6)
            .unwrap()
            .outbox_address;
        config.validate().unwrap();
        assert_eq!(config.rollup_version, 679_261_766);

        // The exact pin is accepted; any other value fails closed, including
        // the V5 rollup under v6.
        let mut config = mainnet_config();
        config.rollup_version = 2_070_860_440;
        config.validate().unwrap();
        let mut config = mainnet_config();
        config.rollup_version = 4_248_422_647;
        let err = config.validate().unwrap_err();
        assert!(
            err.to_string()
                .contains("aztec:mainnet v6 pins rollup_version 2070860440, got 4248422647"),
            "{err}"
        );

        // v5 stays an explicit option with its own pin until the V5 rollup
        // sunsets.
        let mut config = mainnet_config();
        config.protocol_version = AztecProtocolVersion::V5;
        config.outbox_address = pinned_rollup("mainnet", AztecProtocolVersion::V5)
            .unwrap()
            .outbox_address;
        config.validate().unwrap();
        assert_eq!(config.rollup_version, 4_248_422_647);

        // A pinned network refuses a different L1 anchor.
        let mut config = mainnet_config();
        config.l1_chain_id = 11_155_111;
        let err = config.validate().unwrap_err();
        assert!(
            err.to_string()
                .contains("aztec:mainnet v6 settles on eip155:1, got l1_chain_id 11155111"),
            "{err}"
        );

        // A dev chain has no pin, so a zero rollup version fails closed.
        let mut config = valid_config();
        config.rollup_version = 0;
        let err = config.validate().unwrap_err();
        assert!(
            err.to_string()
                .contains("aztec:sandbox has no pinned rollup"),
            "{err}"
        );
    }

    #[test]
    fn public_networks_bind_their_pinned_outbox() {
        // The V5 Outbox under v6 is a different rollup's Outbox, so it fails
        // closed, as does any unrelated address.
        let v5_outbox = pinned_rollup("mainnet", AztecProtocolVersion::V5)
            .unwrap()
            .outbox_address;
        let mut config = mainnet_config();
        config.outbox_address = v5_outbox;
        let err = config.validate().unwrap_err();
        assert!(
            err.to_string().contains(
                "aztec:mainnet v6 pins outbox_address \
                 0xfd2a12658a82d7156da56c7a8d49a69fc966c8d1, \
                 got 0x5b062ab5fd3a66bc7e73b04ced38587673b6a2d7"
            ),
            "{err}"
        );

        let mut config = mainnet_config();
        config.outbox_address = [0x22u8; 20];
        let err = config.validate().unwrap_err();
        assert!(err.to_string().contains("pins outbox_address"), "{err}");

        // A dev chain has no pin, so any non-zero Outbox stays valid.
        valid_config().validate().unwrap();
    }

    #[test]
    fn every_public_aztec_chain_is_pinned_for_both_protocols() {
        let registry = zka_registry::Registry::embedded();
        for reference in ["mainnet", "alpha-testnet"] {
            let chain = registry
                .settlement_chain("aztec", reference, "aztec")
                .unwrap();
            assert_ne!(chain.tier, "dev", "{reference}");
            for protocol in [AztecProtocolVersion::V5, AztecProtocolVersion::V6] {
                let pin = pinned_rollup(reference, protocol).unwrap();
                registry.eip155_chain(pin.l1_chain_id).unwrap();
            }
        }
        assert!(pinned_rollup("sandbox", AztecProtocolVersion::V6).is_none());
    }

    #[test]
    fn pinned_addresses_decode_exactly_and_never_repeat() {
        let pin = pinned_rollup("mainnet", AztecProtocolVersion::V6).unwrap();
        assert_eq!(
            pin.outbox_address,
            parse_eth_address("pin", "0xFD2a12658A82d7156DA56c7A8d49A69fC966c8D1").unwrap()
        );

        let mut seen = std::collections::HashSet::new();
        for pin in PINNED_ROLLUPS {
            for address in [pin.rollup_address, pin.inbox_address, pin.outbox_address] {
                assert_ne!(address, [0u8; 20], "{pin:?}");
                assert!(
                    seen.insert(address),
                    "{pin:?} repeats 0x{}",
                    hex::encode(address)
                );
            }
        }
    }

    #[test]
    fn config_validation_rejects_unregistered_chains() {
        // Unknown Aztec reference fails closed against the registry.
        let mut config = valid_config();
        config.reference = "devnet9".into();
        let err = config.validate().unwrap_err();
        assert!(
            err.to_string().contains("unknown chain `aztec:devnet9`"),
            "{err}"
        );

        // Unknown L1 anchor chain id fails closed.
        let mut config = valid_config();
        config.l1_chain_id = 999_999;
        let err = config.validate().unwrap_err();
        assert!(err.to_string().contains("unknown chain"), "{err}");

        // A registered chain owned by a different adapter fails closed.
        let registry = zka_registry::Registry::embedded();
        assert!(matches!(
            registry.settlement_chain("aztec", "sandbox", "ethereum"),
            Err(zka_registry::RegistryError::AdapterMismatch { .. })
        ));
    }

    #[test]
    fn config_finality_depth_tighten_not_loosen() {
        // Below the mainnet floor (64) fails closed.
        let mut config = mainnet_config();
        config.finality_depth = 12;
        let err = config.validate().unwrap_err();
        assert!(err.to_string().contains("policy"), "{err}");

        // Tightening above the floor passes.
        let mut config = mainnet_config();
        config.confirmations = 4;
        config.finality_depth = 128;
        config.validate().unwrap();

        // Confirmations below the floor fail closed too.
        let mut config = mainnet_config();
        config.confirmations = 1;
        config.finality_depth = 64;
        assert!(config.validate().is_err());
    }

    #[test]
    fn config_validation_rejects_bad_shapes() {
        let mut config = valid_config();
        config.l2_node_url = "ftp://nope".into();
        assert!(config.validate().is_err());

        let mut config = valid_config();
        config.l1_rpc_url = "".into();
        assert!(config.validate().is_err());

        let mut config = valid_config();
        config.portal_address = [0u8; 20];
        assert!(config.validate().is_err());

        let mut config = valid_config();
        config.outbox_address = [0u8; 20];
        assert!(config.validate().is_err());

        let mut config = valid_config();
        config.l2_bridge = [0u8; 32];
        assert!(config.validate().is_err());

        let mut config = valid_config();
        config.protocol_version = AztecProtocolVersion::V5;
        config.rollup_version = 4;
        let err = config.validate().unwrap_err();
        assert!(err.to_string().contains("v5"), "{err}");

        let mut config = valid_config();
        config.protocol_version = AztecProtocolVersion::V6;
        config.rollup_version = 5;
        let err = config.validate().unwrap_err();
        assert!(
            err.to_string().contains("v6 requires rollup_version >= 6"),
            "{err}"
        );

        let mut config = valid_config();
        config.protocol_version = AztecProtocolVersion::V6;
        config.rollup_version = 6;
        config.validate().unwrap();
    }

    #[test]
    fn protocol_version_serde_is_closed() {
        let v6: AztecProtocolVersion = serde_json::from_str("\"v6\"").unwrap();
        assert_eq!(v6, AztecProtocolVersion::V6);
        assert_eq!(serde_json::to_string(&v6).unwrap(), "\"v6\"");
        assert!(serde_json::from_str::<AztecProtocolVersion>("\"v4\"").is_err());
        assert!(serde_json::from_str::<AztecProtocolVersion>("\"v7\"").is_err());
    }

    #[test]
    fn address_parsing_round_trips() {
        let addr =
            parse_eth_address("portal", "0x00000000000000000000000000000000DeaDBeef").unwrap();
        assert_eq!(addr[16..], [0xde, 0xad, 0xbe, 0xef]);
        assert!(parse_eth_address("portal", "0x1234").is_err());
        assert!(parse_eth_address("portal", "zz").is_err());
        let word = parse_bytes32("l2_bridge", &format!("0x{}", "33".repeat(32))).unwrap();
        assert_eq!(word, [0x33u8; 32]);
        assert!(parse_bytes32("l2_bridge", "0x33").is_err());
    }
}
