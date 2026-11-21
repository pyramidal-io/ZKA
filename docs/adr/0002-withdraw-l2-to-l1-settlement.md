# ADR 0002 — Withdraw L2→L1 settlement for the Aztec deployment

- **Status:** Accepted (A1 + B1 + C1) — 2026-05-29; **Implemented** (in-repo)
- **Date:** 2026-05-29
- **Deciders:** ZKA protocol owner (Michael)
- **Decision:** Adopt A1 (immutable `PublicImmutable` portal address, never admin-settable — the Safeguard-3 crux), B1 (one portal per asset for v1), and C1 (a new ownerless, non-upgradeable Outbox-consuming `ZKAAztecPortal.sol`).
- **Implementation status:**
  - L2 side — **DONE**: `ZKATransfer` immutable portal config + `_process_withdrawal` emitting `message_portal` with the canonical sha256 content encoding + `src/withdrawal.nr` encoding-lock unit tests + TXE tests.
  - L1 side — **DONE**: `contracts/ethereum/ZKAAztecPortal.sol` (ownerless/non-upgradeable, one-per-asset; v5 `outbox.consume` → `safeTransfer`) + `IAztecOutbox.sol` (vendored v5/AZUP-2 Outbox iface) + `test/ZKAAztecPortal.t.sol` (10 Forge tests, incl. the cross-env content-hash match against the L2 golden and AZUP-2 partial-root replay).
  - Remaining (ops acceptance): run the env-gated live smoke against a real Aztec v5 endpoint/deployment and record the deployed portal/Outbox pairing.
- **Related:**
  - Scope: Aztec L2-to-L1 withdrawal settlement
  - Spec: ZKA v0.6.0 §1.6 Safeguard 5 (unconditional exit), §8.2 (Ethereum bridge / withdrawal)
  - Code: `aztec/zka_transfer_aztec/src/main.nr` (`withdraw` / `_process_withdrawal`), `contracts/ethereum/ZKAAztecPortal.sol`
  - API basis: aztec-packages v5/AZUP-2 `message_portal` / `Outbox` (see "API reference" below)

## Context

`ZKATransfer.withdraw(amount, asset_commitment, external_recipient)` burns the sender's notes in the private phase (value-conserving `_spend` + `_return_change`) and enqueues a public `_process_withdrawal(external_recipient, amount)`. Today `_process_withdrawal` is a **documented stub** — it asserts non-zero inputs and carries a `TODO(phase>2)` to emit the L2→L1 message. So a ZKA note can be burned on L2 but the underlying asset is never released on L1. This ADR specifies how the burn is settled to L1.

Two settlement models exist in the repo and must not be conflated:

1. **Standalone-proof settlement** — `contracts/ethereum/ZKAEthPool.sol`. This is **verifier-based**: it authenticates proof-bound ZKA/Pay deposits, batch transitions, and withdrawals on L1. The former multi-asset `ZKABridgeEthereum` model is permanently retired because its deposit admission and withdrawal public-input encoding were unsafe.
2. **Aztec rollup deployment** — `ZKATransfer` runs *inside* the Aztec rollup, which already proves every transaction. An Aztec contract does **not** submit a proof to L1; it emits an **L2→L1 message** to the Aztec **Outbox**, and an L1 **portal** consumes that message (with a Merkle inclusion proof against the rollup's settled output root) to release the asset. There is **no UltraVerifier on this path** — the rollup is the prover.

This ADR is about model (2): the Aztec deployment's withdrawal settlement. It is **orthogonal** to the standalone-proof pool (model 1).

### Safeguard 5 (and 3) framing — the binding constraint

§1.6 Safeguard 5: *"Unshielding/withdrawal MUST be unconditional — no compliance proof may gate exit."* And Safeguard 3: no admin/governance key may invalidate, freeze, **redirect**, or force-transfer a note; no pausable/upgradeable/admin paths over note validity. The §1.6 custody audit already confirmed `withdraw` takes no compliance/credential/admin input. This ADR MUST preserve that: the settlement mechanism it adds must not introduce any admin-controlled surface that can **redirect, gate, freeze, or block** a withdrawal.

## API reference (aztec-packages v5 / AZUP-2)

- **L2 emit:** `context.message_portal(recipient: EthAddress, content: Field)` on `PublicContext` (and `PrivateContext`). `content` is a single Field; the canonical encoding is `sha256_to_field(selector ++ args_be)` where `selector` is `keccak256("withdraw(address,uint256)")[0..4]` and each arg is 32-byte big-endian. (Per the reference `token_portal_content_hash_lib`.)
- **Portal binding:** the L1 portal `EthAddress` is **contract state**, set at deploy time (the canonical TokenBridge stores it in immutable config populated by the constructor).
- **L1 consume:** `IOutbox.consume(DataStructures.L2ToL1Msg msg, Epoch epoch, uint256 numCheckpointsInEpoch, uint256 leafIndex, bytes32[] path)`. The portal reconstructs `L2ToL1Msg{ sender: L2Actor(l2Address, version), recipient: L1Actor(address(this), chainId), content: Hash.sha256ToField(abi.encodeWithSignature("withdraw(address,uint256)", recipient, amount)) }`, calls `consume`, then `safeTransfer`s. AZUP-2 allows multiple roots per epoch: the root is selected by `numCheckpointsInEpoch`, and the Outbox enforces **once-only** consumption by stable `(epoch, leafId)`, where `leafId = 2^path.length + leafIndex`.
- **Hash:** both sides use **SHA-256** truncated to a field (prepend a zero byte), NOT keccak, for the message content.

## Decision drivers

1. **Safeguard 5 / 3 — no admin surface over exit.** The portal binding and the
   settlement path must contain no admin-mutable, pausable, or gating element.
2. **Unconditional, atomic burn.** The L2 burn already reverts atomically on any
   failure (sender keeps notes). The L2→L1 message must be emitted in the same tx
   as the burn so a successful withdraw always produces a claimable message.
3. **L2→L1 bridges are inherently "burn-on-L2, claim-on-L1."** Once the message
   is emitted and the rollup settles, the L1 release is permissionless (anyone can
   relay the inclusion proof; funds go to the encoded `recipient`). The trust
   assumption is **deploy-time correctness of the portal pairing**, which is
   standard and is NOT an ongoing admin power.
4. **Asset ↔ L1 token mapping.** A ZKA note carries an `asset_commitment`; the L1
   release needs to know which underlying token to transfer.
5. **Match the canonical Aztec portal pattern** (TokenBridge/TokenPortal) so the
   design is auditable against a known-good reference and TXE/e2e-testable.

## Considered options

### Portal binding: how `ZKATransfer` learns its L1 portal address

- **A1 — `PublicImmutable<EthAddress>` set in the constructor. [Recommended]** The portal is fixed at deploy and can never change. No admin path can redirect exit (Safeguard 3/5 preserved). Matches the canonical TokenBridge `Config`.
- **A2 — `PublicMutable<EthAddress>` with an admin setter.** Rejected: an admin who can change the portal can **redirect** every future withdrawal to an attacker-controlled L1 contract — a direct Safeguard-3 violation ("no admin key may redirect a note's value"). Even "admin can only set once" is worse than an immutable: it adds a privileged surface for no benefit.
- **A3 — portal passed per-`withdraw` call by the caller.** Rejected: lets a griefer/relayer specify a wrong portal and strand the user's burned funds; and it isn't a property of the protocol contract. The portal is a protocol invariant, not a per-call parameter.

### Asset ↔ L1 token mapping

- **B1 — one portal per asset (escrow model). [Recommended for v1]** Each `(ZKATransfer, asset)` pairs 1:1 with an L1 portal that escrows exactly one underlying ERC-20, exactly like the canonical `TokenPortal`. Simplest, matches the reference, smallest content payload (`withdraw(address recipient, uint256 amount)`). Multi-asset is handled by deploying one portal per asset and binding the asset in the message is unnecessary.
- **B2 — single multi-asset portal; carry `asset_commitment` in the message.** `withdraw(address recipient, uint256 amount, bytes32 asset)` and the portal maps `asset → ERC-20`. More flexible but the asset→token registry on L1 becomes a governed surface (which token a commitment maps to) — keep it immutable/registry -append-only if chosen, and note the added audit surface. Defer to a later ADR.

### Settlement contract

- **C1 — new `ZKAAztecPortal.sol` (Outbox-consuming). [Recommended]** A minimal portal: immutable `(outbox, l2Bridge, rollupVersion, underlying)`; `withdraw(recipient, amount, epoch, numCheckpointsInEpoch, leafIndex, path)` reconstructs the message, `outbox.consume(...)`, `safeTransfer`. No owner, no pause, no upgrade.
- **C2 — extend the former `ZKABridgeEthereum.sol`.** Rejected: bolting Outbox consumption onto the verifier-based model conflates two settlement models and enlarges a security-critical contract. That legacy implementation is now retired; keep the models separate.

## Decision (proposed)

Adopt **A1 + B1 + C1**:

1. **L2 (`ZKATransfer`)** — add `portal: EthAddress` to the contract config as a `PublicImmutable`, set in the constructor (alongside `admin`). Implement `_process_withdrawal` to emit `self.context.message_portal(portal, content)` where `content = sha256_to_field(selector("withdraw(address,uint256)") ++ recipient_be ++ amount_be)` and `recipient` is `external_recipient` interpreted as a 20-byte L1 address. `withdraw` itself is unchanged (still no compliance/credential/admin input).
2. **L1** — a new minimal, ownerless, non-upgradeable `ZKAAztecPortal.sol` per asset that consumes the Outbox message and releases the ERC-20. (Implemented + deployed out-of-repo / in a follow-up; this ADR fixes its interface + the content encoding so L2 and L1 agree.)
3. **Trust model** — deploy-time-correct, immutable portal pairing; **no admin recovery path** (an override would itself violate Safeguard 3). This is the standard, audited L2→L1 model.

## Consequences

- **Preserves Safeguard 5 & 3:** withdraw stays unconditional; the only new state is an *immutable* portal address — no admin can redirect/gate/freeze exit.
- **The L2 change is implementable now** in `zka_transfer_aztec` (constructor arg + `_process_withdrawal` body using `message_portal`). The TXE can assert the message is *emitted* (recipient + content) on a successful withdraw and that withdraw still succeeds with no compliance/credential input; **full L1 consumption requires an Outbox + a deployed portal and is an e2e/sandbox test**, not a TXE unit test.
- **Deployment follow-up:** record the deployed `ZKAAztecPortal.sol` and `(outbox, l2Bridge, rollupVersion, underlying)` wiring for each target Aztec v5 network, then run the env-gated live acceptance smoke.
- **Asset model is v1-limited** to one-portal-per-asset (B1); multi-asset is a later ADR (B2) with an explicit note on the L1 asset-registry surface.
- **`external_recipient` semantics tighten:** it must be a valid 20-byte L1 address (the content encodes it as `address`); document this at the `withdraw` boundary (currently it is just an asserted-non-zero Field).

## Accepted answers

1. **A1 (immutable portal)** is accepted over any admin-settable variant.
2. **B1 (one portal per asset)** is accepted for v1; multi-asset L1 portal design is deferred.
3. The L2, L1, adapter, and ops surfaces now live in-repo; remaining acceptance is deployment-specific live/sandbox execution against an operator-supplied v5 endpoint.
