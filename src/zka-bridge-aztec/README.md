# zka-bridge-aztec

ZKA settlement adapter boundary for the Aztec deployment: the Rust half of the L2→L1 withdrawal pipeline between `aztec/zka_transfer_aztec` (L2) and `contracts/ethereum/ZKAAztecPortal.sol` (L1).

## Settlement model

The Aztec rollup proves every L2 transaction, so withdrawals carry **no ZKA proof on L1**. `ZKATransfer.withdraw` burns the holder's notes on L2 and emits an L2→L1 message to the immutable, ownerless, per-asset portal. Once the containing L2 block is **proven** (rollup proof settled on L1), anyone may consume the message from the rollup Outbox — strict once-only — and the portal releases the underlying ERC-20 to the recipient bound in the message content.

```
L2 withdraw (notes burned)            L1
ZKATransfer ──L2→L1 msg──► Outbox ──consume(msg, epoch, numCheckpoints, leaf, path)──► ZKAAztecPortal ──ERC-20──► recipient
                           (proven blocks only, once-only)             (immutable, permissionless)
```

## Wire protocols (documented honestly)

* **Aztec node** — JSON-RPC 2.0 over HTTP (the AZUP-2/v5 node API; the same surface `createAztecNodeClient` speaks): `aztec_getBlockNumber` with `{tag: "latest" | "proven"}` and `aztec_getL2ToL1MembershipWitness`. The PXE is deliberately NOT used: this adapter only reads public rollup state — no Aztec-side viewing/spending keys ever touch the ops boundary.
* **L1 anchor** — standard Ethereum execution JSON-RPC (`eth_blockNumber`, `eth_getLogs` over the portal's `Withdrawn` events).

Both live behind the typed `AztecTransport` trait (`HttpJsonRpcTransport` live; mocked byte-for-byte in CI).

## Fail-closed boundaries

* **Registry**: configuration must resolve `aztec:<reference>` for the `aztec` adapter AND a registered eip155 anchor chain; unregistered chains are structured errors (`registry/chains.json` is the allowlist).
* **Finality policy**: configured `confirmations`/`finality_depth` must satisfy the chain's registry floor (tighten-not-loosen).
* **Proven gate**: an outbox entry is only consumable once its L2 block is proven (`enforce_proven`); never settles against unproven state.
* **Replay gate**: `OutboxState` mirrors the v5 Outbox's once-only rule keyed `(epoch_number, leaf_id)`; a duplicate consumption in a reconstructed stream is corrupt/replayed — hard error.
* **Submission**: `UnconfiguredSubmitter` is the default — every submission path errors before any network traffic until an operator wires a `PortalSubmitter` (L1 signer reference only, the EVM `SignerSource` convention).

## Cross-environment lock

`withdraw_content_hash(recipient, amount)` = `sha256_to_field(selector ++ recipient_be(32) ++ amount_be(32))` is pinned byte-for-byte against the Noir L2 implementation and the Solidity portal via the `(0xbeef, 1000)` golden `0x002c54ccb6af0251a12093d39b5dd48465cf1061ebf84a15c54cb7839261ef99` (`content_hash_matches_l2_and_l1_golden` here, `test_ContentHashMatchesL2Golden` in `test/ZKAAztecPortal.t.sol`).

## Operations

The `[aztec]` section of `zka-settlement-ops` drives this adapter for indexing (proven-height finality view + portal `Withdrawn` reconstruction) and health checks. Runbook: `docs/operations/aztec_outbox.md`.
