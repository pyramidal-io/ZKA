# Per-Chain Finality and Bridge Security Policy

Status: Live (v1) Enforced by: `FinalityPolicy` in `registry/chains.json` → `zka-registry` → adapter config validation (fail-closed, tighten-not-loosen) Related: `docs/sdd/sdd_registry_encodings.md`, `docs/sdd/sdd_bridge_ethereum.md`

## 1. Purpose

Every settlement adapter makes finality, reorg, and trust assumptions. Before this policy they lived implicitly in adapter defaults (`confirmations: 1`, `finality_depth: 12`, `finality_depth: 24`, root-window sizes) where an operator could silently weaken them. This document makes the assumptions **explicit per chain**, and the enforceable floor is **machine-checked**: each registry chain entry carries a typed `finalityPolicy`, adapter configuration is validated against it at construction, and a config that sits *below* the floor is rejected (`RegistryError::PolicyViolation`). Configuration may **tighten** (deeper confirmations, larger windows) but never **loosen**.

```json
"finalityPolicy": {
  "finalityClass": "probabilistic | instant | oracle-attested",
  "minConfirmations": <floor for receipt confirmations>,
  "minFinalityDepth": <floor for blocks-buried before Final>,
  "maxReorgDepth":    <upper bound the indexer windows must cover>
}
```

A chain without a policy cannot be loaded at all (the registry rejects the entry), and a chain absent from the registry cannot be configured into any adapter — both fail closed.

## 2. Per-chain policies

### 2.1 Ethereum (`eip155:1`, `eip155:11155111`, `eip155:31337`)

| Chain | Class | minConfirmations | minFinalityDepth | maxReorgDepth |
|-------|-------|------------------|------------------|---------------|
| `eip155:1` mainnet | probabilistic | 2 | 64 | 64 |
| `eip155:11155111` Sepolia | probabilistic | 1 | 32 | 64 |
| `eip155:31337` Anvil | instant | 1 | 1 | 0 |

- **Finality definition.** Gasper finality: a block is *final* after two
  justified epochs (~64 slots, ≈13 min). The bridge treats a submission as
  `Confirmed` after `confirmations` receipts and `Finalized` after
  `finality_depth` blocks (`EthereumBridgeConfig`, consumed by the
  `submission.rs` receipt tracker). The mainnet floor of 64 approximates
  2 epochs in block depth; Sepolia accepts 32 (test tier); Anvil is a
  single-node devnet with no reorgs.
- **Reorg handling.** The `EventIndexer` reconstructs the accepted-root
  window + nullifier set from logs; `root_window_size` must cover at least
  `maxReorgDepth` (policy-checked) so a reorged-out root cannot linger as
  the only accepted anchor. On a detected re-org deeper than the window,
  the operator MUST re-index from the contract deployment block
  (`indexer_start_block`), not patch the cursor forward.
- **Trust assumptions.** No oracle and no light client: the adapter trusts
  its **own JSON-RPC endpoint** for chain id (verified at connect), logs,
  and receipts. The submission signer is gas-only (non-custodial posture,
  spec §1.6); value movement is authorized exclusively by proofs.
- **Failure modes / operator guidance.** RPC endpoint lying about logs ⇒
  divergent reconstruction — run `zka-settlement-ops consistency-check`
  against an independent RPC provider; structured divergence output is the
  alarm. Deep reorg beyond `maxReorgDepth` ⇒ halt submissions, re-index,
  re-run consistency check before resuming.

### 2.4 Aztec (`aztec:mainnet`, `aztec:alpha-testnet`, `aztec:sandbox`)

| Chain | Class | minConfirmations | minFinalityDepth | maxReorgDepth |
|-------|-------|------------------|------------------|---------------|
| `aztec:mainnet` | probabilistic | 2 | 64 | 64 |
| `aztec:alpha-testnet` | probabilistic | 1 | 32 | 64 |
| `aztec:sandbox` | instant | 1 | 1 | 0 |

- **Finality definition.** Two-stage, both machine-gated. (1) **L2 proven
  gate**: an outbox entry is consumable only once its containing L2 block
  is *proven* (rollup proof settled on L1) — `enforce_proven` in
  `zka-bridge-aztec` rejects settlement against any block above the node's
  proven head, and there is no depth knob to loosen it. (2) **L1 anchor
  depth**: the numbers above are in **L1 anchor blocks** — `finality_depth`
  is how deep the rollup proof must be buried on the anchor before the
  entry is treated as final (an anchor reorg can un-prove an L2 block);
  `confirmations` gates the consume-tx receipt. Floors are enforced in
  `AztecBridgeConfig::validate` (tighten-not-loosen). The sandbox is a
  single-node Anvil-anchored devnet: instant, no reorgs.
- **Reorg handling.** Aztec L2 has no independent reorg surface (sequenced
  blocks are pinned by the rollup contract); the reorg surface is the **L1
  anchor**, so `maxReorgDepth` mirrors the anchor's bound. An anchor reorg
  deeper than the bound ⇒ halt submissions, re-index the portal events from
  a pre-reorg cursor, re-run the consistency check before resuming.
- **Trust assumptions.** **Proof-anchored** (no committee, no oracle): the
  rollup proves every L2 transaction, the L1 Outbox enforces strict
  once-only consumption, and the portal is immutable / ownerless /
  per-asset with no admin path (Safeguards 3 & 5; `ZKAAztecPortal.sol`).
  The adapter trusts its **own Aztec-node JSON-RPC endpoint** for
  proven/latest heights and membership witnesses, and its **L1 JSON-RPC
  endpoint** for portal events — a lying node degrades liveness, never
  safety (a fabricated witness fails Outbox inclusion on-chain; an
  under-reported proven head only delays settlement). Consumption is
  permissionless and the L1 submission signer is gas-only.
- **Failure modes / operator guidance.** Rollup proving stalled ⇒ proven
  head freezes and entries stop becoming consumable — liveness only,
  fail-closed by construction; escalate to the rollup operator. Node lying
  about the proven head upward cannot mint (the Outbox checks inclusion
  against settled roots); lying downward delays settlement — pin
  independent endpoints and compare via `doctor`. Portal events missing ⇒
  the EVM indexer recovery procedures apply
  (`docs/operations/aztec_outbox.md`).

## 3. Enforcement map (what is machine-checked today)

| Adapter surface | Enforced floor |
|-----------------|----------------|
| `zka-registry` load | every chain entry MUST carry a well-formed policy (class-specific shape checks; `instant` ⇒ `maxReorgDepth = 0`) |
| `EthereumBridgeConfig::validate` | `confirmations ≥ minConfirmations`, `finality_depth ≥ minFinalityDepth`, `root_window_size ≥ max(maxReorgDepth, 1)`, plus the RPC transport policy of §3c |
| `zka_registry::transport::RpcEndpoint` | every settlement endpoint (Ethereum/APLBridge, Aztec): profile scheme allowlist, TLS off loopback, no URL-embedded credentials (§3c) |
| `AztecBridgeConfig::validate` | `confirmations ≥ minConfirmations`, `finality_depth ≥ minFinalityDepth` of the `aztec:<reference>` chain, plus a registered eip155 anchor and the §3c transport policy on both endpoints; the proven gate (`enforce_proven`) has no loosening knob |
| `zka-settlement-ops OpsConfig::validate` | per configured chain: `root_window ≥ max(maxReorgDepth, 1)` (indexer window/cursor safety margin); every configured endpoint additionally satisfies §3c |

Tighten-not-loosen is tested in each crate (a config above the floor passes; below the floor is a structured `PolicyViolation` rejection).

## 3b. Timeout and retry behavior (declared per adapter)

Timeouts are adapter-configuration, not consensus policy — they affect liveness, never safety (a timed-out read/submission is retried or surfaced, and value movement remains proof-authorized regardless):

| Adapter | Declared behavior |
|---------|-------------------|
| Ethereum | `RetryPolicy` (bounded attempts, exponential backoff, default 4 × 250 ms base) for gas estimation and transient RPC ops; `poll_interval` (default 2 s) for receipt tracking; all submissions fail with structured errors after the retry budget — never silently. |
| Aztec | `AztecBridgeConfig.timeout` (default 15 s) per JSON-RPC call (node + L1); the proven gate re-checks the proven head at preparation time, so a stalled node can only delay consumption, never settle an unproven entry. |

A timeout therefore degrades to **no action** (fail closed): nothing is attested, submitted, or marked final on the basis of a missing response.

## 3c. RPC transport policy (all settlement endpoints)

Finality depth only means something if the answers it is computed from came
from the endpoint the operator pinned. Every adapter client stack accepts any
URL it can parse, including a cleartext `http` / `ws` scheme to an arbitrary
remote host; on such a channel an on-path attacker can withhold or fabricate
event and log history, replay a stale root window, serve a forged chain id or
deployment code hash, or lie about confirmations so a submission looks final
when it is not — and submission paths push signed transactions across the same
channel.

`zka_registry::transport::RpcEndpoint` is therefore the single gate in front of
every adapter's client construction. It lives in the registry, beside these
finality floors, so every adapter shares one policy without taking on another
adapter's dependency tree (notably, the Aztec crate enforces it without
pulling in the Alloy provider stack). It fails closed:

| Endpoint | Verdict |
|----------|---------|
| encrypted scheme (`https`, and `wss` where the profile allows it), any host | accepted |
| cleartext scheme (`http`, and `ws` where allowed) on an explicit loopback authority (`127.0.0.0/8`, `[::1]`, `localhost`) | accepted — devnet only |
| cleartext scheme on any other host | rejected |
| a scheme outside the adapter's profile (see below) | rejected |
| any other scheme (`ftp`, `file`, `grpc`, `ipc`, …) | rejected |
| credentials embedded in the URL authority (username, password, or both) | rejected |

**Transport profiles.** The scheme allowlist is a capability statement, not a
preference: an adapter must reject an endpoint it could never dial.

| Profile | Schemes | Adapters |
|---------|---------|----------|
| `TransportProfile::Http` | `https`, `http` (loopback) | every adapter: the Alloy HTTP provider stack (`zka-bridge-ethereum`, and through it the settlement-ops `doctor`/indexer, the holder adapter and the SDK local-e2e harness); Aztec node API and its L1 execution JSON-RPC; the settlement-ops `aztec` config section |
| `TransportProfile::HttpOrWebSocket` | `https`, `wss`, `http` / `ws` (loopback) | none at present — retained for an adapter that actually dials a WebSocket |

The Alloy integration was on `HttpOrWebSocket` until the claim was measured
against the code. Every provider behind the policy gate is built through
`ProviderBuilder::connect_reqwest`; no caller invokes `connect_ws` or
constructs a `WsConnect`. Accepting `wss://` therefore let an operator write an
endpoint that passed configuration validation and then failed at connect —
precisely the deferred failure the profile split exists to prevent. Alloy's
`provider-ws` feature is now off: widening the profile and re-enabling that
feature must happen together with a real WebSocket caller.

Like the finality floors, the policy is tighten-not-loosen: a caller that
declares itself non-local selects `PlaintextPolicy::Forbidden`, which rejects
cleartext on loopback too. The holder adapter binds that choice to the same
flag that governs its inbound listener — with `local_integration = false` its
pinned RPC endpoint MUST be TLS.

A validated endpoint renders (`Display`/`Debug`/`redacted()`) as
`scheme://host[:port]` only, so a provider API key carried in the endpoint's
path or query cannot leak through an error, a log line, or `doctor` health
output. The Aztec `HttpJsonRpcTransport`, which holds endpoints, deliberately
does not derive `Debug` for the same reason.

**Enforcement points.**

| Adapter | Gate |
|---------|------|
| Ethereum / APLBridge | `EthereumBridge::new`, `EthereumBridgeConfig::validate` (hence `connect_live`), the settlement-ops `doctor` and indexer providers, the holder adapter's `no_redirect_provider`, the SDK local-e2e Anvil harness |
| Aztec | `HttpJsonRpcTransport::new` (node + L1) and `AztecBridgeConfig::validate` (`l2_node_url`, `l1_rpc_url`) |
| settlement-ops | `OpsConfig::validate` for the `ethereum` and `aplbridge` sections; the `aztec` section inherits the policy through `AztecBridgeConfig::validate` |

**Operator migration.** This tightening is breaking for a deployment that
reached a *remote* Aztec node over cleartext (for example an `http://` Aztec
node / L1 endpoint on a private or container network). Such endpoints are now rejected at config load. Either
terminate TLS in front of the node and use `https://`, or co-locate the
adapter and address the node on loopback. The
[Aztec outbox](../operations/aztec_outbox.md) runbook carries the same note.

Every settlement transport in this tree is now covered. The Aztec L1 endpoint
is worth calling out: it speaks Ethereum JSON-RPC, but it is dialled by the
Aztec crate's own HTTP poster rather than the Alloy provider stack, so it takes
`TransportProfile::Http` — a `wss://` L1 endpoint is rejected there even
though it is also rejected by `zka-bridge-ethereum`.

## 4. Changing a policy

Policy changes are registry data changes: edit `registry/chains.json`, update this document, and let CI re-validate with `cargo test --manifest-path src/zka-registry/Cargo.toml`; the crate tests pin the floors. Loosening a floor is a security-relevant change and MUST be called out in the PR.
