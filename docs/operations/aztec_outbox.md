# Runbook: Aztec Outbox

**Public snapshot adapter status: `experimental` (see `certification/aztec.json`).** The source is a complete reference integration, but its public certification remains experimental because live public-network acceptance is deferred. `zka-bridge-aztec` ships the reference components — `NodeAztecClient` (Aztec node JSON-RPC + L1 `eth_*`), the proven-block finality gate (`enforce_proven`), the once-only outbox consumption tracker (`OutboxState`), and `WithdrawalFlow` (gate-then-plan), with `withdraw_content_hash` cross-locked byte-for-byte against the L2 Noir and L1 Solidity values. The slice is wired into `zka-settlement-ops` via the **`[aztec]` section in `ops.toml`**: the proven view is polled from the L2 node into the store's finality view, and the portal's settled `Withdrawn` consumptions are indexed from the L1 anchor. (Contracts: `aztec/` workspace on L2, `contracts/ethereum/ZKAAztecPortal.sol` on L1.)

For the AZUP-2/v5 impact audit and source matrix, see [`aztec_v5_migration_matrix.md`](aztec_v5_migration_matrix.md).

## What the surface does

Aztec settlement follows the L1↔L2 message-portal model:

- **L2 → L1 (outbox)**: `ZKATransfer.withdraw` burns the holder's notes on
  L2 and inserts an L2→L1 message into the rollup's **outbox** on L1. After
  the containing L2 block is **proven** the entry becomes consumable; anyone
  may call `ZKAAztecPortal.withdraw(recipient, amount, epoch,
  numCheckpointsInEpoch, leafIndex, path)` — the portal reconstructs the exact
  message, consumes it from the
  Outbox (strict once-only), and releases the underlying ERC-20. No ZKA
  proof appears on L1: the rollup proves every L2 transaction.
- **L1 → L2 (inbox)**: deposits insert into the rollup inbox; the L2 side
  claims them. Indexing-wise this surfaces as portal contract events on L1.

Replay protection is layered: the Outbox enforces once-only consumption on-chain; `OutboxState` mirrors it adapter-side (a replayed consumption never reaches submission); the ops fold rejects duplicate `(epoch, leafId)` streams as corrupt/replayed; and the ZKA nullifier set remains the L2-level gate.

## Configure (`[aztec]` in `ops.toml`)

> **Transport policy (breaking).** Both endpoints are validated against the
> canonical fail-closed transport policy
> ([§3c](../security/finality_and_bridge_security_policy.md#3c-rpc-transport-policy-all-settlement-endpoints)):
> a non-loopback host MUST use `https://`, cleartext `http://` is accepted only
> for an explicit loopback authority (`127.0.0.0/8`, `[::1]`, `localhost`), and
> credentials must not be embedded in the URL. `wss://` is rejected for
> `l1_rpc_url`, as it now is for the `[ethereum]` section too: no adapter in the
> tree dials a WebSocket. A deployment that previously reached a remote node over
> cleartext must terminate TLS in front of it or co-locate and use loopback.
> The sandbox values below are loopback and remain valid.

```toml
[aztec]
l2_node_url = "http://localhost:8080"        # Aztec node JSON-RPC (aztec_* methods); https:// off loopback
reference = "sandbox"                        # registered aztec:<reference>
l1_rpc_url = "http://localhost:8545"         # L1 anchor JSON-RPC (eth_* methods); https:// off loopback
l1_chain_id = 31337                          # registered eip155 anchor
portal_address = "0x..."                     # deployed ZKAAztecPortal
outbox_address = "0x..."                     # the rollup's L1 Outbox; public: must be the pin
l2_bridge = "0x..."                          # L2 ZKATransfer address (32-byte)
rollup_version = 0                           # sandbox: REPLACE with node_getNodeInfo rollupVersion; public: 0 = pinned rollup
# protocol_version = "v6"                    # default; "v5" only until the V5 rollup sunsets
# start_l1_block = 0                         # portal deployment block
# confirmations = 0                          # 0 = registry-policy floor
# finality_depth = 0                         # 0 = registry-policy floor (L1 anchor blocks)
```

The section validates through the adapter's own config (`AztecBridgeConfig::validate`, fail-closed): registry membership for BOTH `aztec:<reference>` (under the `aztec` adapter) and the eip155 anchor, finality-policy floors tighten-not-loosen (`docs/security/finality_and_bridge_security_policy.md` §2.5), non-zero deployment bindings, and the pinned rollup below. An unregistered chain cannot be configured at all.

The rollup version is the L2→L1 message `sender.version`, so a wrong value reconstructs messages the Outbox never holds. Each public network is therefore pinned per protocol version (`zka_bridge_aztec::PINNED_ROLLUPS`, versions from the network's `node_getNodeInfo`, addresses from its L1 `Registry` and rollup). A public section must use the pinned L1 chain and pinned `outbox_address`, and either omit `rollup_version` (0 resolves to the pin) or set exactly the pinned value; anything else fails closed. A public `aztec` chain without a pin for its protocol fails closed too. The sandbox has no pin and must set `rollup_version` to its node's `rollupVersion`.

| `reference` | Protocol | `rollup_version` | L1 anchor | Rollup | Inbox | Outbox |
|-------------|----------|------------------|-----------|--------|-------|--------|
| `mainnet` | `v6` (default) | `2070860440` | `eip155:1` | `0xE37A2663Cc9c119BA41572C40fAb0bbb23a5402f` | `0x603B06cEcC1d537Aad83f1d46651e32014c5B6aD` | `0xFD2a12658A82d7156DA56c7A8d49A69fC966c8D1` |
| `alpha-testnet` | `v6` (default) | `679261766` | `eip155:11155111` | `0x1f435a7F2dA358caF887A470FAeEE7d5D5f4eFBA` | `0x7cdC32Dd7d008870A95f1837Ffd7229ef676EF8A` | `0xA5A0f7a7BDAf280964a1922A68C83462E5F6E15b` |
| `mainnet` | `v5` (until the V5 rollup sunsets) | `4248422647` | `eip155:1` | `0x91fF8bbD8Ebb07893010D50A48A1609e5EBd8E34` | `0x7d4Ef0676c2032bbCC09227501D34d86641ab8cA` | `0x5B062aB5fD3A66BC7e73b04CeD38587673b6A2D7` |
| `alpha-testnet` | `v5` (until the V5 rollup sunsets) | `1821665230` | `eip155:11155111` | `0xD73A91bdcF6891C7642F3e460036e1ef2CC23178` | `0x3047dBF2b7dd9f58AC41113525480F94745a4f7C` | `0x905f80009bBef9d9426675B45009922971eD42fF` |

The `alpha-testnet` registry reference is the public Aztec testnet on Sepolia; its V6 node is `https://aztec-testnet.drpc.org`. A V6 deployment needs a portal constructed against the V6 rollup's Inbox, Outbox and `rollupVersion`, since `ZKAAztecPortal` fixes all three at construction. The constructor reverts unless the Outbox and Inbox report one non-zero `ROLLUP()` and both report that `rollupVersion` as `VERSION()`: a portal paired across rollups would accept deposits it can never release.

| Piece | Live behavior |
|-------|---------------|
| Indexing | `sync_aztec`: L2 latest/proven heads → the store's finality view (`finalized_height` = the **proven** head, fail-closed on regression); portal `Withdrawn` events via `eth_getLogs` → the store's withdrawal ledger (keyed by `epoch:leafId`) |
| Cursor semantics | L1 blocks (identical to the Ethereum indexer: `cursor` = next L1 block to index); L2 heights live in the finality view, never in the cursor |
| Replay protection | Outbox once-only on L1 (rollup-enforced) + adapter `OutboxState` replay gate + duplicate `(epoch, leafId)` fold rejection |
| Relaying | `WithdrawalFlow::prepare` (proven gate → membership witness → replay gate) behind `PortalSubmitter`; the default `UnconfiguredSubmitter` fails closed |

## Health checks

`zka-settlement-ops doctor` probes per the table; alert on non-zero exit.

| Probe | Healthy | Unhealthy signature |
|-------|---------|---------------------|
| `l2_node` | node reachable, `proven <= latest` | unreachable: the proven gate fails closed (liveness only); `proven > latest`: inconsistent node — do not trust its finality |
| `finality_view` | live proven head at/above the stored view | live proven BELOW the stored view = **fail** (a regressed proven head can fabricate finality — fix the endpoint before trusting consumability); stored view a proving-window behind = warn (re-run `index`) |
| `l1_rpc` | reachable, head + cursor reported | unreachable: portal-event indexing stalls (see [evm_indexer.md](evm_indexer.md)) |
| Proven head frozen | proven advances across `index` passes | frozen proven head: rollup proving stalled → outbox entries stop becoming consumable (liveness, not safety) |

## Failure modes

| Symptom | Cause | Recovery |
|---------|-------|----------|
| Outbox entry never consumable | Rollup proving stalled (proven head frozen) | Wait/escalate to the rollup operator; fail-closed by construction |
| `NotProven` from flow preparation | The withdrawal's L2 block is above the proven head | Expected — retry after the proof settles; never override |
| Consumption tx reverts | Entry already consumed (duplicate relayer) or wrong root/leaf proof | Idempotent: once-only is enforced on L1; check the withdrawal ledger, fix the `epoch`/`numCheckpointsInEpoch`/leaf source |
| `doctor` `finality_view` **fail** | L2 endpoint regressed / swapped to a stale node | Fix/pin the endpoint; do not trust consumability until the live proven head is at/above the stored view |
| Duplicate `(epoch, leafId)` error from `index` | Corrupt or replayed portal event stream | Treat as an incident: verify the L1 endpoint, re-index from `start_l1_block` against an independent provider, compare via `check` |
| Portal events missing | Wrong portal address / L1 reorg | EVM indexer recovery procedures apply ([evm_indexer.md](evm_indexer.md)) |

## Key / secret handling

Relayer-side only: the L1 submission key via `SignerSource::EnvHex` (the EVM standard, [README.md](README.md)). **No Aztec-side viewing/spending keys ever touch the ops surface** — the adapter reads only public rollup state (block numbers, outbox membership witnesses); the PXE is deliberately not on the transport.

## Live smoke status

The public snapshot does not export an operator live-smoke harness and makes no live public-network claim. The source now targets Aztec V6. Endpoint/finality and strict withdrawal acceptance still require exact-artifact public-network evidence; complete lifecycle qualification, independent audit and explicit production activation remain separate gates. The machine-readable certification therefore records `live_smoke` as `partial`, based only on local portal and recorded-wire coverage.

## CI coverage

Public CI runs the exported adapter and registry tests, focused L1 portal tests, Aztec.nr compilation and pure tests, TXE transition tests, and the real cross-environment proof with the pinned Aztec v6 toolchain (`aztec`/`aztec-nargo`, not plain `nargo`). These local and recorded-wire tests do not constitute live public-network acceptance.
