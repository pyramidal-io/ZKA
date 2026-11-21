// Copyright 2026 ZKA Contributors
// SPDX-License-Identifier: Apache-2.0

//! Canonical ZKA chain / asset / verifier / public-input encoding registry.
//!
//! The registry data lives in `registry/chains.json` and `registry/assets.json`
//! at the repository root and is compiled into this crate (`include_str!`), so
//! every adapter binary carries the same canonical encodings. All lookups are
//! **fail-closed**: an unregistered chain, asset, circuit, or a public-input
//! order that drifts from the registry is a structured error, never a guess.
//!
//! Canonical forms (see `docs/sdd/sdd_registry_encodings.md` for the annex):
//!
//! - **Chain ids** are CAIP-2-style `namespace:reference` strings
//!   (`eip155:1`, `aztec:sandbox`). Adapters address chains by namespace +
//!   the native reference they already hold (an EVM numeric chain id, an
//!   Aztec network reference).
//! - **Asset ids** are CAIP-19-style `<chainId>/<namespace>:<reference>`
//!   strings; per-chain `encodings` define how an asset projects into the
//!   in-circuit asset domain (e.g. the ADR 0003 keccak-248 projection).
//! - **Verifier ids** are `zka:verifier:<target>:<scheme>:<circuit>` and map
//!   1:1 onto `artifacts/manifest.json` circuit entries.
//! - **Public-input order** per circuit is pinned by name, mirroring the
//!   manifest and `schemas/public-inputs/*.json` (cross-checked in CI by
//!   `scripts/validate_registry.py`).

pub mod transport;

pub use transport::{
    redact_endpoint, PlaintextPolicy, RpcEndpoint, RpcScheme, TransportPolicyError,
    TransportProfile, TransportResult,
};

use serde::Deserialize;
use std::collections::BTreeMap;
use std::sync::OnceLock;
use thiserror::Error;

/// Supported registry schema version.
pub const REGISTRY_VERSION: &str = "zka:registry:v1";

/// Asset-risk profiles recognized by this registry version.
pub const ASSET_RISK_PROFILES: [&str; 3] = [
    "zka:asset-risk:s3-hard:v1",
    "zka:asset-risk:governance-residual:v1",
    "zka:asset-risk:issuer-controlled:v1",
];

const CHAINS_JSON: &str = include_str!("../../../registry/chains.json");
const ASSETS_JSON: &str = include_str!("../../../registry/assets.json");

/// Structured, fail-closed registry errors.
#[derive(Debug, Error)]
pub enum RegistryError {
    /// The chain is not registered; settlement is allowlisted to registry entries.
    #[error("unknown chain `{0}`: not in registry/chains.json (settlement is fail-closed to registered chains)")]
    UnknownChain(String),
    /// The chain is registered, but for a different settlement adapter.
    #[error(
        "chain `{chain_id}` is registered for settlement adapter `{expected}`, not `{actual}`"
    )]
    AdapterMismatch {
        chain_id: String,
        expected: String,
        actual: String,
    },
    /// The asset is not registered.
    #[error("unknown asset `{0}`: not in registry/assets.json")]
    UnknownAsset(String),
    /// The chain has no registered asset with the given denom/role.
    #[error("chain `{chain_id}` has no registered native asset with denom `{denom}` (registered: {registered:?})")]
    NativeDenomMismatch {
        chain_id: String,
        denom: String,
        registered: Vec<String>,
    },
    /// The circuit is not registered.
    #[error("unknown circuit `{0}`: not in the registry circuits section")]
    UnknownCircuit(String),
    /// The proving scheme drifted from the registry.
    #[error("scheme mismatch for circuit `{circuit}`: registry pins `{expected}`, got `{actual}`")]
    SchemeMismatch {
        circuit: String,
        expected: String,
        actual: String,
    },
    /// Configured finality/confirmation depths sit BELOW the chain's
    /// policy floor (config may tighten but never loosen).
    #[error("chain `{chain_id}` finality policy violation: {detail} (configuration may tighten but never loosen below policy minimums)")]
    PolicyViolation { chain_id: String, detail: String },
    /// The public-input order drifted from the registry.
    #[error("public-input order mismatch for circuit `{circuit}`: registry pins [{expected}], got [{actual}]")]
    PublicInputOrderMismatch {
        circuit: String,
        expected: String,
        actual: String,
    },
    /// The registry data itself is malformed (should be unreachable for the
    /// embedded registry — it is gated by unit tests and CI validation).
    #[error("invalid registry data: {0}")]
    Invalid(String),
}

pub type Result<T> = std::result::Result<T, RegistryError>;

/// Per-chain finality + reorg policy: the ENFORCEABLE floor for adapter
/// configuration. See docs/security/finality_and_bridge_security_policy.md
/// for the full per-chain assumptions (reorg handling, trust model,
/// failure modes) behind these numbers.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FinalityPolicy {
    /// `instant` (BFT: committed = final), `probabilistic` (depth-based),
    /// or `oracle-attested` (committee attests finality).
    pub finality_class: String,
    /// Floor for receipt confirmations before an effect is `Confirmed`.
    pub min_confirmations: u64,
    /// Floor for buried-block depth before an effect is `Finalized`.
    pub min_finality_depth: u64,
    /// Upper bound on expected reorg depth; accepted-root windows and
    /// indexer cursor safety margins must cover at least this.
    pub max_reorg_depth: u64,
}

impl FinalityPolicy {
    /// Enforce tighten-not-loosen on configured depths: values may EXCEED
    /// the policy floor but never sit below it.
    pub fn require_depths(
        &self,
        chain_id: &str,
        confirmations: u64,
        finality_depth: u64,
    ) -> Result<()> {
        if confirmations < self.min_confirmations {
            return Err(RegistryError::PolicyViolation {
                chain_id: chain_id.to_string(),
                detail: format!(
                    "confirmations {confirmations} < policy minimum {}",
                    self.min_confirmations
                ),
            });
        }
        if finality_depth < self.min_finality_depth {
            return Err(RegistryError::PolicyViolation {
                chain_id: chain_id.to_string(),
                detail: format!(
                    "finality_depth {finality_depth} < policy minimum {}",
                    self.min_finality_depth
                ),
            });
        }
        Ok(())
    }

    /// Minimum accepted-root window / indexer cursor safety margin implied
    /// by the policy's reorg bound.
    pub fn min_root_window(&self) -> usize {
        self.max_reorg_depth.max(1) as usize
    }

    /// Enforce that an accepted-root window covers the reorg bound.
    pub fn require_root_window(&self, chain_id: &str, window: usize) -> Result<()> {
        if window < self.min_root_window() {
            return Err(RegistryError::PolicyViolation {
                chain_id: chain_id.to_string(),
                detail: format!(
                    "root window {window} < policy minimum {} (maxReorgDepth)",
                    self.min_root_window()
                ),
            });
        }
        Ok(())
    }
}

/// One registered chain.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ChainEntry {
    /// Canonical chain id (`namespace:reference`).
    pub chain_id: String,
    pub namespace: String,
    pub reference: String,
    pub display_name: String,
    /// `main`, `test`, or `dev`.
    pub tier: String,
    /// Which settlement adapter owns this chain (`ethereum`, `aztec`).
    pub settlement_adapter: String,
    /// Bridge-domain derivation rule id (see `bridgeDomainRules`).
    pub bridge_domain_rule: String,
    /// Asset-id encoding rule id (see `registry/assets.json` `encodings`).
    pub asset_encoding: String,
    /// Verifier set used when settling on this chain (`null` for chains that
    /// settle through another chain's verifiers).
    pub verifier_set: Option<String>,
    /// Enforceable finality/reorg floor (REQUIRED: a chain without a policy
    /// fails registry load, so settlement on it is impossible).
    pub finality_policy: FinalityPolicy,
}

/// One registered circuit with its pinned public-input order.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CircuitEntry {
    pub name: String,
    /// Versioned circuit identity when the constraint system is migration-bound.
    #[serde(default)]
    pub circuit_id: Option<String>,
    /// Versioned artifact identity. Present when proof compatibility depends on
    /// semantics beyond the circuit's package name.
    pub artifact_id: Option<String>,
    /// Named derivation profile bound to the artifact identity.
    pub derivation_profile: Option<String>,
    pub scheme: String,
    /// Closed proof targets published for this circuit (`offchain` and/or `evm`).
    pub verifier_targets: Vec<String>,
    /// Public inputs in canonical (circuit ABI / manifest) order.
    pub public_inputs: Vec<String>,
    /// Repo-relative path of the public-input encoder schema.
    pub encoder: String,
    /// Repo-relative path of the EVM verifier contract (None = off-chain only).
    pub evm_verifier_contract: Option<String>,
}

/// One registered asset.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AssetEntry {
    /// Canonical asset id (`<chainId>/<namespace>:<reference>`).
    pub asset_id: String,
    pub chain_id: String,
    pub symbol: String,
    #[serde(default)]
    pub decimals: Option<u32>,
    #[serde(default)]
    pub denom: Option<String>,
    /// `native` or `erc20`.
    pub role: String,
    /// Encoding rule id (must exist in `encodings`).
    pub encoding: String,
    /// For `l1-erc20-keccak248` assets: the pinned in-circuit field value
    /// (32-byte big-endian hex, top byte 0x00).
    #[serde(default)]
    pub field_be: Option<String>,
    /// Optional machine-readable asset-risk profile. Unknown identifiers fail
    /// registry validation rather than silently degrading policy.
    #[serde(default)]
    pub risk_profile: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ChainsFile {
    version: String,
    #[allow(dead_code)]
    description: String,
    bridge_domain_rules: BTreeMap<String, serde_json::Value>,
    chains: Vec<ChainEntry>,
    verifier_sets: BTreeMap<String, Vec<String>>,
    circuits: Vec<CircuitEntry>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AssetsFile {
    version: String,
    #[allow(dead_code)]
    description: String,
    encodings: BTreeMap<String, serde_json::Value>,
    assets: Vec<AssetEntry>,
}

/// The loaded, validated registry.
#[derive(Debug, Clone)]
pub struct Registry {
    chains: Vec<ChainEntry>,
    circuits: Vec<CircuitEntry>,
    verifier_sets: BTreeMap<String, Vec<String>>,
    assets: Vec<AssetEntry>,
}

impl Registry {
    /// The embedded canonical registry (compiled in from `registry/*.json`).
    ///
    /// Panics only if the *embedded* data is invalid, which is a build defect
    /// gated by this crate's tests and the CI registry validation script —
    /// runtime inputs can never trigger it.
    pub fn embedded() -> &'static Registry {
        static REGISTRY: OnceLock<Registry> = OnceLock::new();
        REGISTRY.get_or_init(|| {
            Registry::from_json(CHAINS_JSON, ASSETS_JSON)
                .expect("embedded registry/chains.json + registry/assets.json must be valid")
        })
    }

    /// Parse + validate registry data from JSON strings.
    pub fn from_json(chains_json: &str, assets_json: &str) -> Result<Registry> {
        let chains_file: ChainsFile = serde_json::from_str(chains_json)
            .map_err(|e| RegistryError::Invalid(format!("chains.json: {e}")))?;
        let assets_file: AssetsFile = serde_json::from_str(assets_json)
            .map_err(|e| RegistryError::Invalid(format!("assets.json: {e}")))?;

        if chains_file.version != REGISTRY_VERSION {
            return Err(RegistryError::Invalid(format!(
                "chains.json version `{}` (expected `{REGISTRY_VERSION}`)",
                chains_file.version
            )));
        }
        if assets_file.version != REGISTRY_VERSION {
            return Err(RegistryError::Invalid(format!(
                "assets.json version `{}` (expected `{REGISTRY_VERSION}`)",
                assets_file.version
            )));
        }

        let registry = Registry {
            chains: chains_file.chains,
            circuits: chains_file.circuits,
            verifier_sets: chains_file.verifier_sets,
            assets: assets_file.assets,
        };
        registry.validate(&chains_file.bridge_domain_rules, &assets_file.encodings)?;
        Ok(registry)
    }

    /// Internal consistency validation (fail-closed at load).
    fn validate(
        &self,
        domain_rules: &BTreeMap<String, serde_json::Value>,
        encodings: &BTreeMap<String, serde_json::Value>,
    ) -> Result<()> {
        let invalid = |msg: String| Err(RegistryError::Invalid(msg));

        // Chains: unique ids, id == namespace:reference, rule/encoding/set refs resolve.
        for (i, chain) in self.chains.iter().enumerate() {
            if chain.chain_id != format!("{}:{}", chain.namespace, chain.reference) {
                return invalid(format!(
                    "chain `{}`: chainId must equal `namespace:reference`",
                    chain.chain_id
                ));
            }
            if self.chains[..i]
                .iter()
                .any(|c| c.chain_id == chain.chain_id)
            {
                return invalid(format!("duplicate chain id `{}`", chain.chain_id));
            }
            if !matches!(chain.tier.as_str(), "main" | "test" | "dev") {
                return invalid(format!(
                    "chain `{}`: unknown tier `{}`",
                    chain.chain_id, chain.tier
                ));
            }
            if !domain_rules.contains_key(&chain.bridge_domain_rule) {
                return invalid(format!(
                    "chain `{}`: unknown bridgeDomainRule `{}`",
                    chain.chain_id, chain.bridge_domain_rule
                ));
            }
            if !encodings.contains_key(&chain.asset_encoding) {
                return invalid(format!(
                    "chain `{}`: unknown assetEncoding `{}`",
                    chain.chain_id, chain.asset_encoding
                ));
            }
            if let Some(set) = &chain.verifier_set {
                if !self.verifier_sets.contains_key(set) {
                    return invalid(format!(
                        "chain `{}`: unknown verifierSet `{}`",
                        chain.chain_id, set
                    ));
                }
            }
            // Finality policy shape: known class, sane floors, and class
            // consistency (instant finality has no reorgs by definition).
            let policy = &chain.finality_policy;
            if !matches!(
                policy.finality_class.as_str(),
                "instant" | "probabilistic" | "oracle-attested"
            ) {
                return invalid(format!(
                    "chain `{}`: unknown finalityClass `{}`",
                    chain.chain_id, policy.finality_class
                ));
            }
            if policy.min_confirmations == 0 || policy.min_finality_depth == 0 {
                return invalid(format!(
                    "chain `{}`: finality policy floors must be >= 1",
                    chain.chain_id
                ));
            }
            if policy.min_finality_depth < policy.min_confirmations {
                return invalid(format!(
                    "chain `{}`: minFinalityDepth must be >= minConfirmations",
                    chain.chain_id
                ));
            }
            if policy.finality_class == "instant" && policy.max_reorg_depth != 0 {
                return invalid(format!(
                    "chain `{}`: instant finality implies maxReorgDepth = 0",
                    chain.chain_id
                ));
            }
        }

        // Circuits: unique names and fail-closed version/profile pairing.
        for (i, circuit) in self.circuits.iter().enumerate() {
            if self.circuits[..i].iter().any(|c| c.name == circuit.name) {
                return invalid(format!("duplicate circuit `{}`", circuit.name));
            }
            match (&circuit.artifact_id, &circuit.derivation_profile) {
                (Some(artifact_id), Some(profile)) => {
                    if artifact_id.is_empty()
                        || profile.is_empty()
                        || !artifact_id.starts_with(&format!("{}:", circuit.name))
                    {
                        return invalid(format!(
                            "circuit `{}` has invalid artifactId/derivationProfile identity",
                            circuit.name
                        ));
                    }
                    if self.circuits[..i]
                        .iter()
                        .any(|other| other.artifact_id.as_ref() == Some(artifact_id))
                    {
                        return invalid(format!("duplicate artifact id `{artifact_id}`"));
                    }
                }
                (None, None) => {}
                _ => {
                    return invalid(format!(
                        "circuit `{}` must declare artifactId and derivationProfile together",
                        circuit.name
                    ));
                }
            }
        }

        // Verifier ids: `zka:verifier:<target>:<scheme>:<circuit>`, circuit
        // must exist with the same scheme; evm-target ids require an EVM
        // verifier contract binding on the circuit.
        for (set_name, ids) in &self.verifier_sets {
            for id in ids {
                let parts: Vec<&str> = id.split(':').collect();
                let [zka, verifier, target, scheme, circuit_name] = parts.as_slice() else {
                    return invalid(format!(
                        "verifier id `{id}` in set `{set_name}` is malformed"
                    ));
                };
                if *zka != "zka" || *verifier != "verifier" {
                    return invalid(format!(
                        "verifier id `{id}` in set `{set_name}` is malformed"
                    ));
                }
                let Some(circuit) = self.circuits.iter().find(|c| c.name == *circuit_name) else {
                    return invalid(format!(
                        "verifier id `{id}` references unknown circuit `{circuit_name}`"
                    ));
                };
                if circuit.scheme != *scheme {
                    return invalid(format!(
                        "verifier id `{id}` scheme `{scheme}` != circuit scheme `{}`",
                        circuit.scheme
                    ));
                }
                if *target == "evm" && circuit.evm_verifier_contract.is_none() {
                    return invalid(format!(
                        "verifier id `{id}` targets evm but circuit `{circuit_name}` has no evmVerifierContract"
                    ));
                }
            }
        }

        // Assets: unique ids, chain refs resolve, encoding refs resolve,
        // asset id is prefixed by its chain id, keccak248 field shape.
        for (i, asset) in self.assets.iter().enumerate() {
            if self.assets[..i]
                .iter()
                .any(|a| a.asset_id == asset.asset_id)
            {
                return invalid(format!("duplicate asset id `{}`", asset.asset_id));
            }
            if !asset.asset_id.starts_with(&format!("{}/", asset.chain_id)) {
                return invalid(format!(
                    "asset `{}`: assetId must be prefixed by its chainId `{}`",
                    asset.asset_id, asset.chain_id
                ));
            }
            if !self.chains.iter().any(|c| c.chain_id == asset.chain_id) {
                return invalid(format!(
                    "asset `{}` references unknown chain `{}`",
                    asset.asset_id, asset.chain_id
                ));
            }
            if !encodings.contains_key(&asset.encoding) {
                return invalid(format!(
                    "asset `{}`: unknown encoding `{}`",
                    asset.asset_id, asset.encoding
                ));
            }
            if !matches!(asset.role.as_str(), "native" | "erc20") {
                return invalid(format!(
                    "asset `{}`: unknown role `{}`",
                    asset.asset_id, asset.role
                ));
            }
            if let Some(risk_profile) = &asset.risk_profile {
                if !ASSET_RISK_PROFILES.contains(&risk_profile.as_str()) {
                    return invalid(format!(
                        "asset `{}`: unknown riskProfile `{risk_profile}`",
                        asset.asset_id
                    ));
                }
            }
            if let Some(field_be) = &asset.field_be {
                let hex = field_be.strip_prefix("0x").unwrap_or(field_be);
                if hex.len() != 64 || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
                    return invalid(format!(
                        "asset `{}`: fieldBe must be 0x-prefixed 32-byte hex",
                        asset.asset_id
                    ));
                }
                if !hex.starts_with("00") {
                    return invalid(format!(
                        "asset `{}`: fieldBe top byte must be 0x00 (< 2^248 projection)",
                        asset.asset_id
                    ));
                }
            }
        }

        Ok(())
    }

    // ------------------------------------------------------------------
    // Chain lookups (fail-closed)
    // ------------------------------------------------------------------

    /// Look up a chain by canonical id (`namespace:reference`).
    pub fn chain(&self, chain_id: &str) -> Result<&ChainEntry> {
        self.chains
            .iter()
            .find(|c| c.chain_id == chain_id)
            .ok_or_else(|| RegistryError::UnknownChain(chain_id.to_string()))
    }

    /// Look up a chain by namespace + native reference.
    pub fn chain_in_namespace(&self, namespace: &str, reference: &str) -> Result<&ChainEntry> {
        self.chains
            .iter()
            .find(|c| c.namespace == namespace && c.reference == reference)
            .ok_or_else(|| RegistryError::UnknownChain(format!("{namespace}:{reference}")))
    }

    /// Look up a chain by namespace + reference AND require it to belong to
    /// the given settlement adapter. This is the adapter-boundary check:
    /// "is this a chain I am allowed to settle on?"
    pub fn settlement_chain(
        &self,
        namespace: &str,
        reference: &str,
        adapter: &str,
    ) -> Result<&ChainEntry> {
        let chain = self.chain_in_namespace(namespace, reference)?;
        if chain.settlement_adapter != adapter {
            return Err(RegistryError::AdapterMismatch {
                chain_id: chain.chain_id.clone(),
                expected: chain.settlement_adapter.clone(),
                actual: adapter.to_string(),
            });
        }
        Ok(chain)
    }

    /// Convenience: look up an EVM chain by numeric chain id for the
    /// `ethereum` adapter.
    pub fn eip155_chain(&self, chain_id: u64) -> Result<&ChainEntry> {
        self.settlement_chain("eip155", &chain_id.to_string(), "ethereum")
    }

    /// All registered chains.
    pub fn chains(&self) -> &[ChainEntry] {
        &self.chains
    }

    // ------------------------------------------------------------------
    // Asset lookups (fail-closed)
    // ------------------------------------------------------------------

    /// Look up an asset by canonical id.
    pub fn asset(&self, asset_id: &str) -> Result<&AssetEntry> {
        self.assets
            .iter()
            .find(|a| a.asset_id == asset_id)
            .ok_or_else(|| RegistryError::UnknownAsset(asset_id.to_string()))
    }

    /// All assets registered for a chain.
    pub fn assets_for_chain(&self, chain_id: &str) -> Vec<&AssetEntry> {
        self.assets
            .iter()
            .filter(|a| a.chain_id == chain_id)
            .collect()
    }

    /// Require that `denom` is the registered native denom of the chain.
    /// Fails closed when the chain has no registered native asset or the
    /// denom differs.
    pub fn require_native_denom(&self, chain_id: &str, denom: &str) -> Result<&AssetEntry> {
        let natives: Vec<&AssetEntry> = self
            .assets
            .iter()
            .filter(|a| a.chain_id == chain_id && a.role == "native")
            .collect();
        natives
            .iter()
            .find(|a| a.denom.as_deref() == Some(denom))
            .copied()
            .ok_or_else(|| RegistryError::NativeDenomMismatch {
                chain_id: chain_id.to_string(),
                denom: denom.to_string(),
                registered: natives.iter().filter_map(|a| a.denom.clone()).collect(),
            })
    }

    // ------------------------------------------------------------------
    // Circuit / verifier lookups (fail-closed)
    // ------------------------------------------------------------------

    /// Look up a circuit by manifest name.
    pub fn circuit(&self, name: &str) -> Result<&CircuitEntry> {
        self.circuits
            .iter()
            .find(|c| c.name == name)
            .ok_or_else(|| RegistryError::UnknownCircuit(name.to_string()))
    }

    /// All registered circuits.
    pub fn circuits(&self) -> &[CircuitEntry] {
        &self.circuits
    }

    /// Verifier ids in a verifier set.
    pub fn verifier_set(&self, name: &str) -> Result<&[String]> {
        self.verifier_sets
            .get(name)
            .map(|v| v.as_slice())
            .ok_or_else(|| RegistryError::Invalid(format!("unknown verifier set `{name}`")))
    }

    /// Verify that a circuit's scheme and public-input order (by name) match
    /// the registry exactly. This is the metadata gate adapters run against
    /// any runtime-loaded artifact manifest: order drift fails closed.
    pub fn verify_circuit_public_inputs(
        &self,
        name: &str,
        scheme: &str,
        public_inputs: &[&str],
    ) -> Result<&CircuitEntry> {
        let circuit = self.circuit(name)?;
        if circuit.scheme != scheme {
            return Err(RegistryError::SchemeMismatch {
                circuit: name.to_string(),
                expected: circuit.scheme.clone(),
                actual: scheme.to_string(),
            });
        }
        if circuit.public_inputs.len() != public_inputs.len()
            || circuit
                .public_inputs
                .iter()
                .zip(public_inputs.iter())
                .any(|(a, b)| a != b)
        {
            return Err(RegistryError::PublicInputOrderMismatch {
                circuit: name.to_string(),
                expected: circuit.public_inputs.join(", "),
                actual: public_inputs.join(", "),
            });
        }
        Ok(circuit)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_registry_is_valid() {
        let registry = Registry::embedded();
        assert!(!registry.chains().is_empty());
        assert!(!registry.circuits().is_empty());
    }

    #[test]
    fn chain_lookups_resolve_registered_chains() {
        let r = Registry::embedded();
        assert_eq!(r.chain("eip155:1").unwrap().settlement_adapter, "ethereum");
        assert_eq!(r.eip155_chain(31337).unwrap().tier, "dev");
        assert_eq!(
            r.settlement_chain("aztec", "sandbox", "aztec")
                .unwrap()
                .tier,
            "dev"
        );
        assert_eq!(
            r.settlement_chain("aztec", "mainnet", "aztec")
                .unwrap()
                .bridge_domain_rule,
            "aztec-portal-evm-binding"
        );
    }

    #[test]
    fn aztec_asset_projects_to_the_same_l1_field_as_its_underlying() {
        // The Aztec portal is one-per-asset and escrows the L1 ERC-20, so an
        // Aztec-settled asset MUST project to the identical ADR 0003 field as
        // its eip155 underlying (the digest binds the L1 chain id + token,
        // not the settlement venue). Pinned here so the two entries cannot
        // drift apart.
        let r = Registry::embedded();
        let l1 = r
            .asset("eip155:1/erc20:0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48")
            .unwrap();
        let aztec = r
            .asset("aztec:mainnet/erc20:0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48")
            .unwrap();
        assert_eq!(aztec.field_be, l1.field_be);
        assert_eq!(aztec.encoding, "l1-erc20-keccak248");
    }

    #[test]
    fn base_weth9_is_registered_for_s3_hard_pool() {
        let r = Registry::embedded();
        let asset = r
            .asset("eip155:8453/erc20:0x4200000000000000000000000000000000000006")
            .unwrap();
        assert_eq!(asset.symbol, "WETH");
        assert_eq!(asset.decimals, Some(18));
        assert_eq!(
            asset.field_be.as_deref(),
            Some("0x00b79d5775fbebcc217e3aeda900f052bb68fc41d2f46b2fd7f4aac08f600530")
        );
        assert_eq!(
            asset.risk_profile.as_deref(),
            Some("zka:asset-risk:s3-hard:v1")
        );
    }

    #[test]
    fn unknown_chain_fails_closed() {
        let r = Registry::embedded();
        assert!(matches!(
            r.chain("eip155:999999"),
            Err(RegistryError::UnknownChain(_))
        ));
        assert!(matches!(
            r.eip155_chain(999_999),
            Err(RegistryError::UnknownChain(_))
        ));
        assert!(matches!(
            r.settlement_chain("aztec", "nope", "aztec"),
            Err(RegistryError::UnknownChain(_))
        ));
    }

    #[test]
    fn adapter_mismatch_fails_closed() {
        let r = Registry::embedded();
        // eip155:1 is registered, but it is NOT an aztec settlement chain.
        assert!(matches!(
            r.settlement_chain("eip155", "1", "aztec"),
            Err(RegistryError::AdapterMismatch { .. })
        ));
    }

    #[test]
    fn asset_lookups_and_native_denom() {
        let r = Registry::embedded();
        let usdc = r
            .asset("eip155:1/erc20:0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48")
            .unwrap();
        assert_eq!(usdc.symbol, "USDC");
        assert!(usdc.field_be.as_deref().unwrap().starts_with("0x00"));

        // No registered chain carries a native-role asset, so every native
        // denom lookup fails closed.
        assert!(matches!(
            r.require_native_denom("eip155:1", "eth"),
            Err(RegistryError::NativeDenomMismatch { ref registered, .. }) if registered.is_empty()
        ));
        assert!(matches!(
            r.asset("eip155:1/erc20:0xdeadbeef"),
            Err(RegistryError::UnknownAsset(_))
        ));
    }

    #[test]
    fn circuit_public_input_order_is_pinned() {
        let r = Registry::embedded();
        r.verify_circuit_public_inputs(
            "zka_withdrawal",
            "ultra_honk",
            &[
                "nullifier",
                "merkle_root",
                "withdrawal_amount",
                "asset_commitment",
                "external_recipient",
                "context",
            ],
        )
        .unwrap();

        // Reordered inputs fail closed.
        assert!(matches!(
            r.verify_circuit_public_inputs(
                "zka_withdrawal",
                "ultra_honk",
                &[
                    "merkle_root",
                    "nullifier",
                    "withdrawal_amount",
                    "asset_commitment",
                    "external_recipient",
                    "context",
                ],
            ),
            Err(RegistryError::PublicInputOrderMismatch { .. })
        ));
        // Wrong scheme fails closed.
        assert!(matches!(
            r.verify_circuit_public_inputs("zka_withdrawal", "plonk", &[]),
            Err(RegistryError::SchemeMismatch { .. })
        ));
        // Unknown circuit fails closed.
        assert!(matches!(
            r.verify_circuit_public_inputs("not_a_circuit", "ultra_honk", &[]),
            Err(RegistryError::UnknownCircuit(_))
        ));
    }

    #[test]
    fn afp_kdc_artifact_identity_is_pinned() {
        let r = Registry::embedded();

        let credential = r.circuit("zka_credential").unwrap();
        assert_eq!(
            credential.artifact_id.as_deref(),
            Some("zka_credential:afp-kdc-v1.0.1")
        );
        assert_eq!(
            credential.derivation_profile.as_deref(),
            Some("afp-kdc-v1.0.1")
        );

        let binding = r.circuit("zka_transfer_binding").unwrap();
        assert_eq!(
            binding.artifact_id.as_deref(),
            Some("zka_transfer_binding:afp-kdc-v1.0.1")
        );
        assert_eq!(
            binding.derivation_profile.as_deref(),
            Some("afp-kdc-v1.0.1")
        );
    }

    #[test]
    fn malformed_or_duplicate_artifact_identities_are_rejected() {
        let assets = r#"{"version":"zka:registry:v1","description":"","encodings":{},"assets":[]}"#;
        let circuit = |name: &str, identity: &str| {
            format!(
                r#"{{"name":"{name}",{identity}"scheme":"ultra_honk","verifierTargets":["offchain"],"publicInputs":[],"encoder":"registry/public_inputs/{name}.json","evmVerifierContract":null}}"#
            )
        };
        let chains = |circuits: String| {
            format!(
                r#"{{"version":"zka:registry:v1","description":"","bridgeDomainRules":{{}},"chains":[],"verifierSets":{{}},"circuits":[{circuits}]}}"#
            )
        };

        for invalid in [
            circuit("zka_test", r#""artifactId":"zka_test:v1","#),
            circuit("zka_test", r#""derivationProfile":"v1","#),
            circuit("zka_test", r#""artifactId":"","derivationProfile":"v1","#),
            circuit(
                "zka_test",
                r#""artifactId":"other:v1","derivationProfile":"v1","#,
            ),
        ] {
            assert!(matches!(
                Registry::from_json(&chains(invalid), assets),
                Err(RegistryError::Invalid(_))
            ));
        }

        let duplicate = format!(
            "{},{}",
            circuit(
                "zka_first",
                r#""artifactId":"zka_first:v1","derivationProfile":"v1","#,
            ),
            circuit(
                "zka_second",
                r#""artifactId":"zka_first:v1","derivationProfile":"v1","#,
            )
        );
        assert!(matches!(
            Registry::from_json(&chains(duplicate), assets),
            Err(RegistryError::Invalid(_))
        ));
    }

    #[test]
    fn legacy_coord_v1_is_absent() {
        let registry = Registry::embedded();
        let legacy_name = ["zka", "coordination"].join("_");
        let legacy_recursive_name = format!("{legacy_name}_recursive");
        assert!(registry.circuit(&legacy_name).is_err());
        assert!(registry.circuit(&legacy_recursive_name).is_err());
    }

    #[test]
    fn verifier_sets_resolve() {
        let r = Registry::embedded();
        let evm = r.verifier_set("evm-ultra-honk-v1").unwrap();
        assert_eq!(
            evm,
            vec![
                "zka:verifier:evm:ultra_honk:zka_pay_batch".to_string(),
                "zka:verifier:evm:ultra_honk:zka_pay_deposit".to_string(),
                "zka:verifier:evm:ultra_honk:zka_pay_withdrawal".to_string(),
                "zka:verifier:evm:ultra_honk:zka_credential".to_string(),
                "zka:verifier:evm:ultra_honk:zka_root_update".to_string(),
                "zka:verifier:evm:ultra_honk:zka_transfer".to_string(),
                "zka:verifier:evm:ultra_honk:zka_transfer_binding".to_string(),
                "zka:verifier:evm:ultra_honk:zka_transfer_binding_v2".to_string(),
                "zka:verifier:evm:ultra_honk:zka_withdrawal".to_string(),
            ]
        );
        let offchain = r.verifier_set("offchain-ultra-honk-v1").unwrap();
        assert_eq!(
            offchain,
            vec![
                "zka:verifier:offchain:ultra_honk:zka_balance".to_string(),
                "zka:verifier:offchain:ultra_honk:zka_coordination_v2".to_string(),
                "zka:verifier:offchain:ultra_honk:zka_coordination_v2_profile".to_string(),
                "zka:verifier:offchain:ultra_honk:zka_coordination_v2_recursive".to_string(),
                "zka:verifier:offchain:ultra_honk:zka_coord_v2_sample_application".to_string(),
                "zka:verifier:offchain:ultra_honk:zka_coord_reconciliation".to_string(),
                "zka:verifier:offchain:ultra_honk:zka_coord_reciprocal_compute".to_string(),
                "zka:verifier:offchain:ultra_honk:zka_coord_reciprocal_ack".to_string(),
                "zka:verifier:offchain:ultra_honk:zka_credential".to_string(),
                "zka:verifier:offchain:ultra_honk:zka_pay_transition".to_string(),
                "zka:verifier:offchain:ultra_honk:zka_recursive".to_string(),
                "zka:verifier:offchain:ultra_honk:zka_reputation".to_string(),
                "zka:verifier:offchain:ultra_honk:zka_root_update".to_string(),
                "zka:verifier:offchain:ultra_honk:zka_transfer".to_string(),
                "zka:verifier:offchain:ultra_honk:zka_transfer_binding".to_string(),
                "zka:verifier:offchain:ultra_honk:zka_transfer_binding_v2".to_string(),
                "zka:verifier:offchain:ultra_honk:zka_transfer_multi".to_string(),
                "zka:verifier:offchain:ultra_honk:zka_withdrawal".to_string(),
            ]
        );
    }

    #[test]
    fn finality_policies_load_per_class() {
        let r = Registry::embedded();
        let mainnet = &r.chain("eip155:1").unwrap().finality_policy;
        assert_eq!(mainnet.finality_class, "probabilistic");
        assert_eq!(mainnet.min_confirmations, 2);
        assert_eq!(mainnet.min_finality_depth, 64);
        assert_eq!(mainnet.min_root_window(), 64);

        let anvil = &r.chain("eip155:31337").unwrap().finality_policy;
        assert_eq!(anvil.finality_class, "instant");
        assert_eq!(anvil.max_reorg_depth, 0);
        assert_eq!(anvil.min_root_window(), 1);
    }

    #[test]
    fn finality_policy_tighten_not_loosen() {
        let r = Registry::embedded();
        let policy = &r.chain("eip155:1").unwrap().finality_policy;

        // Meeting / tightening the floor passes.
        policy.require_depths("eip155:1", 2, 64).unwrap();
        policy.require_depths("eip155:1", 12, 256).unwrap();
        policy.require_root_window("eip155:1", 64).unwrap();
        policy.require_root_window("eip155:1", 512).unwrap();

        // Loosening below the floor fails closed.
        assert!(matches!(
            policy.require_depths("eip155:1", 1, 64),
            Err(RegistryError::PolicyViolation { .. })
        ));
        assert!(matches!(
            policy.require_depths("eip155:1", 2, 12),
            Err(RegistryError::PolicyViolation { .. })
        ));
        assert!(matches!(
            policy.require_root_window("eip155:1", 8),
            Err(RegistryError::PolicyViolation { .. })
        ));
    }

    #[test]
    fn chains_without_or_with_malformed_policy_are_rejected() {
        // A chain entry MISSING finalityPolicy fails registry load entirely
        // (required field => fail closed; settlement on it is impossible).
        let chains = r#"{"version":"zka:registry:v1","description":"","bridgeDomainRules":{"r":{}},
            "chains":[{"chainId":"eip155:1","namespace":"eip155","reference":"1","displayName":"x",
            "tier":"main","settlementAdapter":"ethereum","bridgeDomainRule":"r","assetEncoding":"e",
            "verifierSet":null}],"verifierSets":{},"circuits":[]}"#;
        let assets =
            r#"{"version":"zka:registry:v1","description":"","encodings":{"e":{}},"assets":[]}"#;
        assert!(matches!(
            Registry::from_json(chains, assets),
            Err(RegistryError::Invalid(_))
        ));

        // An instant-finality chain claiming a non-zero reorg depth is
        // internally inconsistent and rejected.
        let chains = r#"{"version":"zka:registry:v1","description":"","bridgeDomainRules":{"r":{}},
            "chains":[{"chainId":"eip155:1","namespace":"eip155","reference":"1","displayName":"x",
            "tier":"main","settlementAdapter":"ethereum","bridgeDomainRule":"r","assetEncoding":"e",
            "verifierSet":null,
            "finalityPolicy":{"finalityClass":"instant","minConfirmations":1,"minFinalityDepth":1,"maxReorgDepth":5}}],
            "verifierSets":{},"circuits":[]}"#;
        assert!(matches!(
            Registry::from_json(chains, assets),
            Err(RegistryError::Invalid(_))
        ));
    }

    #[test]
    fn invalid_registry_data_is_rejected() {
        // Wrong version.
        let err = Registry::from_json(
            r#"{"version":"zka:registry:v0","description":"","bridgeDomainRules":{},"chains":[],"verifierSets":{},"circuits":[]}"#,
            r#"{"version":"zka:registry:v1","description":"","encodings":{},"assets":[]}"#,
        )
        .unwrap_err();
        assert!(matches!(err, RegistryError::Invalid(_)));

        // Asset referencing an unknown chain.
        let err = Registry::from_json(
            r#"{"version":"zka:registry:v1","description":"","bridgeDomainRules":{},"chains":[],"verifierSets":{},"circuits":[]}"#,
            r#"{"version":"zka:registry:v1","description":"","encodings":{"e":{}},"assets":[{"assetId":"eip155:1/erc20:0xaa","chainId":"eip155:1","symbol":"X","role":"erc20","encoding":"e"}]}"#,
        )
        .unwrap_err();
        assert!(matches!(err, RegistryError::Invalid(_)));

        // Unknown risk-profile identifiers fail closed.
        let chains = r#"{"version":"zka:registry:v1","description":"","bridgeDomainRules":{"r":{}},
            "chains":[{"chainId":"eip155:1","namespace":"eip155","reference":"1","displayName":"x",
            "tier":"main","settlementAdapter":"ethereum","bridgeDomainRule":"r","assetEncoding":"e",
            "verifierSet":null,
            "finalityPolicy":{"finalityClass":"instant","minConfirmations":1,"minFinalityDepth":1,"maxReorgDepth":0}}],
            "verifierSets":{},"circuits":[]}"#;
        let assets = r#"{"version":"zka:registry:v1","description":"","encodings":{"e":{}},
            "assets":[{"assetId":"eip155:1/erc20:0xaa","chainId":"eip155:1","symbol":"X",
            "role":"erc20","encoding":"e","riskProfile":"zka:asset-risk:unknown:v1"}]}"#;
        let err = Registry::from_json(chains, assets).unwrap_err();
        assert!(matches!(err, RegistryError::Invalid(_)));
    }
}
