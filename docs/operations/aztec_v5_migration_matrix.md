# Aztec v5 / AZUP-2 Migration Matrix

Last reviewed: 2026-07-02.

This note records the upstream impact audit behind the ZKA-Aztec v5 migration. It is intentionally narrow: the migration preserves ZKA/ZKC semantics and only updates the Aztec protocol surface, Outbox witness shape, replay key, tooling pins, and operator docs.

## Sources reviewed

| Source | Signal used |
|--------|-------------|
| [Aztec v5 node migration guide](https://forum.aztec.network/t/v5-node-migration-guide/8596) | v4 and v5 nodes are incompatible; v5 nodes use `aztec_*` JSON-RPC methods; legacy `node_*` aliases are transitional only. |
| [AZUP-2 ready for proposal](https://forum.aztec.network/t/azup-2-is-ready-for-proposal/8605) | AZUP-2 bundles the v5 protocol changes and deploys from `v5-next`. |
| [AZUP-2 governance issue](https://github.com/AztecProtocol/governance/issues/32) | AZIP-14 is part of AZUP-2. |
| [AZIP-14](https://github.com/AztecProtocol/governance/blob/main/AZIPs/azip-14.md) | Multiple roots per epoch are the intended replay/Outbox model change. |
| [`IOutbox.sol` on `v5.1.0`](https://github.com/AztecProtocol/aztec-packages/blob/v5.1.0/l1-contracts/src/core/interfaces/messagebridge/IOutbox.sol) | Current interface: `consume(message, epoch, numCheckpointsInEpoch, leafIndex, path)`, `RootAdded(epoch, numCheckpointsInEpoch, root)`, `MessageConsumed(..., numCheckpointsInEpoch)`. |
| [`Outbox.sol` on `v5.1.0`](https://github.com/AztecProtocol/aztec-packages/blob/v5.1.0/l1-contracts/src/core/messagebridge/Outbox.sol) | Current replay key: epoch-level nullifier bitmap over `leafId = 2^path.length + leafIndex`; roots are stored by `numCheckpointsInEpoch`. |
| [`l2_to_l1_membership.ts` on `v5.1.0`](https://github.com/AztecProtocol/aztec-packages/blob/v5.1.0/yarn-project/stdlib/src/messaging/l2_to_l1_membership.ts) | Node witness shape includes `epochNumber`, `numCheckpointsInEpoch`, `root`, `leafIndex`, and `siblingPath`. |

## Migration decisions

| Surface | v4 assumption removed | v5 / AZUP-2 decision |
|---------|-----------------------|----------------------|
| Protocol config | Rollup version defaulted to `1`, and any `>=1` value passed. | Adapter and ops config default to protocol `v5` and `rollup_version = 5`; values below 5 fail closed. |
| Node RPC | `node_getBlockNumber`, `node_getProvenBlockNumber`, `node_getL2ToL1MessageMembershipWitness`. | `aztec_getBlockNumber` with `{tag: "latest" | "proven"}` and `aztec_getL2ToL1MembershipWitness(messageLeaf, txHash)`. No legacy aliases are used. |
| Membership witness | Witness carried only `leafIndex` and `siblingPath`, keyed by L2 block. | Witness carries `epochNumber`, `numCheckpointsInEpoch`, `root`, `leafIndex`, and `siblingPath`, keyed by L2 tx hash. |
| L1 Outbox ABI | `consume(message, epoch, leafIndex, path)`. | `consume(message, epoch, numCheckpointsInEpoch, leafIndex, path)`, plus root lookup by `(epoch, numCheckpointsInEpoch)`. |
| Replay key | `(l2_block_number, leaf_index)` in Rust, bare `leafIndex` in ops state. | Stable v5 key `(epoch, leafId)`, where `leafId = 2^path.length + leafIndex`; ops persists withdrawals under `epoch:leafId`. |
| Partial roots | Not represented. | Duplicate `leafId` in the same epoch is rejected even when observed through a different `numCheckpointsInEpoch`; the Forge mock and invariant vector cover this. |
| Content hash | `withdraw(address,uint256)` SHA-256-to-field. | Unchanged. This migration does not alter ZKA withdrawal semantics. |
| L1 portal safety | Ownerless portal with immutable bindings. | Preserved. Constructor now rejects stale rollup versions `< 5`; no owner/admin/recovery path added. |
| Tooling | Aztec.nr dependencies pinned to v4.3.0. | Aztec.nr packages pin `aztec-packages` `v5.1.0`; TXE helper requires a v5-compatible Aztec toolchain. |
| Live acceptance | Env-gated smoke existed but spoke v4 wire shapes. | Mock smoke now speaks v5 wire shapes. Real v5 live/sandbox acceptance remains env-gated and should be run once endpoints are supplied. |

## Notes

- AZIP-14 describes the multiple-root concept; current `v5.1.0` code uses `numCheckpointsInEpoch` as the root selector. ZKA follows the implementation used by the current v5 stable release.
- The adapter intentionally does not retain a v4 compatibility mode. A v4 deployment must stay on a v4-specific adapter/config because the RPC and Outbox witness shapes are materially different.
