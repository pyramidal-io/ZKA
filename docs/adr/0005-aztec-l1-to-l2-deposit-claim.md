# ADR 0005: Authenticated Aztec L1-to-L2 deposit claims

**Status:** Accepted and implemented (2026-08-19)
**Scope:** authenticated Aztec L1-to-L2 deposit claim
**Refs:** `docs/design/aztec_native_pay_profile.md` §§3.2–3.3; ADR 0002; ZKA §1.6 Safeguards 3 and 5

## Context

ADR 0002 completed the Aztec withdrawal leg, but entry remained unsafe: `ZKAAztecPortal` could release escrow on withdrawal while `ZKATransfer.mint` allowed any caller to create an arbitrary note without proving that matching L1 collateral had been escrowed. Adding escrow without replacing that mint would make the portal drainable.

An L1-to-L2 deposit has four security requirements:

1. The message must bind the asset, amount, and beneficiary.
2. A claim must prove knowledge of the secret committed on L1.
3. Each Inbox message must be consumed once.
4. A caller who observes or submits another user's claim must not redirect or capture its note.

The portal must retain ADR 0002's deploy-time-only trust model: one immutable portal per asset, with no owner, upgrade, pause, setter, recovery, or sweep path.

## Decision

Adopt the Aztec TokenPortal/TokenBridge pattern, strengthened by binding the beneficiary and asset in the application content.

### L1 portal

`ZKAAztecPortal` receives immutable `(outbox, inbox, l2Bridge, rollupVersion, underlying, assetCommitment)` configuration. `depositToAztec(amount, beneficiary, claimSecretHash)`:

1. rejects zero or non-field claim inputs, values above `u128::MAX`, and beneficiaries that fail the pinned Aztec V6 point-validity predicate;
2. transfers exactly the declared ERC-20 amount into portal escrow;
3. sends an Inbox message to immutable `L2Actor(l2Bridge, rollupVersion)`; and
4. returns the Inbox message key and compact cumulative insertion index.

Before depositing, the caller generates a field secret and derives `claimSecretHash` with the Aztec V6 SDK's `computeSecretHash(secret)` helper (`poseidon2HashWithSeparator([secret], DomainSeparator.SECRET_HASH)`). The secret preimage must be retained until the claim succeeds. Keccak-256, SHA-256, and raw secrets are not compatible; because the portal is intentionally ownerless and has no recovery path, an incorrect hash or lost preimage locks that deposit. The pinned fixture is:

```text
input  = 0x123456
output = 0x1e3cf2b3d167833b6e447285a470612b27e13f01739b5325d9821594f54cda04
```

The ERC-20 transfer and Inbox insertion are atomic in one EVM transaction. An Inbox revert therefore rolls the escrow transfer back.

The beneficiary check runs before any token or Inbox call. It matches
`AztecAddress::is_valid()`: for the canonical field-valued address `x`, a field
element `y` must exist with `y² = x³ − 17`. The portal evaluates the quadratic
residue predicate through the EVM modular-exponentiation precompile and fails
closed if that call fails or returns malformed data. This establishes address
well-formedness only; it does not establish key ownership, wallet availability,
or that the caller selected the intended recipient. Message encoding and the
content-hash function remain unchanged.

The content is:

```text
sha256_to_field(
  selector("claim_private(bytes32,bytes32,uint256)")
  || beneficiary_be(32)
  || assetCommitment_be(32)
  || amount_be(32)
)
```

The Inbox envelope additionally binds the L1 sender (this portal), L2 recipient, rollup version, and `claimSecretHash`. The complete message therefore binds `(portal, L2 bridge, rollup version, asset, amount, beneficiary, secret hash)`.

### V6 Fast Inbox clients

Aztec 6.0.0 (AZIP-22 Fast Inbox) keeps the `sendL2Message` call signature. Its
`MessageSent` event is now `(bytes32 indexed hash, bytes32 inboxRollingHash,
uint256 bucketSeq, L1ToL2Msg message)`. The envelope contains sender/chain ID,
recipient/rollup version, content, secret hash and compact insertion index. The
message hash authenticates all seven ABI words; the rolling hash is bytes32.
The benchmark helpers validate the full envelope against the portal receipt and
requested deposit, using the [pinned V6 Inbox implementation](https://github.com/AztecProtocol/aztec-packages/blob/0219f11d8133970df3974fe5ae65e006bf8c193a/l1-contracts/src/core/messagebridge/Inbox.sol).

The returned insertion index identifies the message before it is consumable.
Blocks stream messages in Inbox order into consecutive leaves, so the committed
leaf index has the same numeric value. Clients MUST wait for inclusion at the
PXE's anchor tip and request
`getL1ToL2MessageMembershipWitness('checkpointed', messageKey)`; they MUST reject
a missing witness or an index that differs from the receipt. An L1 receipt or
`getL1ToL2MessageIndex` result alone does not prove L2 inclusion. The benchmark's
`resolveMessageLeafIndex` enforces this before exposing claim inputs.

Each rollup requires its own portal instance: Inbox, Outbox, L2 bridge and rollup
version are constructor immutables. ZKA has no V5 deployment to migrate. V6
local/testnet work does not qualify a production deployment; the activation gates
in [ADR 0010](0010-aztec-flagship-and-production-gates.md) remain applicable.

### L2 claim

`ZKATransfer` stores `portal` and `asset_commitment` as `PublicImmutable` values. Its private `claim_private(beneficiary, amount, claim_secret, message_leaf_index)` reconstructs the content from the immutable asset, consumes the message using `PrivateContext.consume_l1_to_l2_message`, and only then inserts `ZKANote(asset_commitment, amount)` for `beneficiary`.

Aztec's consume operation checks the secret preimage and Inbox-tree membership and emits the protocol L1-to-L2 message nullifier. The nullifier makes the claim once-only. The beneficiary is part of the consumed content and is also the note owner, so another caller cannot substitute themselves. Even a caller with the claim arguments can only cause the intended beneficiary's note to be delivered; they receive no value.

The unauthenticated `mint` entrypoint is removed. Tests seed the real TXE Inbox message tree and claim through the production path; no test-only mint remains.

Both `ZKATransfer.claim_private` and `ZKAPay.claim_private` enforce the same
constrained point-validity predicate before consuming the Inbox message.
`ZKATransfer.transfer`, `transfer_from`, and `transfer_with_compliance`,
`ZKAPay.transfer` and `pay`, and `ZKACredential.disclose_to` enforce it before
spending or loading credentials for recipient delivery. Existing value,
zero-address, context, and authwit checks retain their precedence. L1 withdrawal
addresses and the sender's change-note path are outside this recipient guard.

### Value and asset model

The deposit leg accepts `1..u128::MAX`, matching the lossless note-value bound already enforced by the spend path. Each deployment represents one immutable asset commitment and one immutable underlying ERC-20. Multi-asset portals and mutable asset registries are out of scope.

## Rejected alternatives

- **Keep `mint` behind an admin role.** Rejected because it creates a privileged unbacked-mint/escrow-drain capability and violates the ownerless posture.
- **Bind only amount, like the minimal reference private bridge.** Rejected because it permits beneficiary substitution and does not bind the ZKA asset.
- **Use the secret as the note owner.** Rejected because learning the secret would make a pending claim capturable. The secret authorizes consumption; the separately bound beneficiary owns the output.
- **Mutable Inbox, portal, or asset configuration.** Rejected because a setter could redirect deposits or break deposit/withdraw solvency after deployment.
- **Portal-local replay tracking.** Rejected as redundant and easier to diverge from protocol state. The Aztec message nullifier is the canonical once-only mechanism.

## Security invariants and verification

- Forge pins the L1/L2 content-hash golden and proves each tuple component changes the content.
- Forge proves escrow plus Inbox insertion and atomic rollback on Inbox failure.
- Forge and constrained Noir tests share point-validity fixtures, including field-edge values. Portal tests require invalid beneficiaries to fail before external calls; TXE tests require specific invalid-address errors before message lookup, spending, or credential loading. These tests establish behavior, not complete diagnostic or app/kernel proof qualification.
- TXE proves wrong secret, amount, beneficiary, asset, or L1 sender messages cannot claim.
- TXE proves a second consumption fails through the protocol nullifier.
- TXE proves a front-running caller receives no note while the bound beneficiary receives the full amount.
- Constructor immutability tests cover all settlement endpoints and the asset; no owner/pause/upgrade/sweep surface is introduced.

## Consequences

- Every ZKA note introduced through the Aztec deployment is backed by a consumed message from the immutable portal's ERC-20 escrow.
- Portal deployment now requires the matching Inbox and asset commitment in addition to ADR 0002's withdrawal configuration.
- Existing integrations must replace direct `mint` calls with an L1 deposit, message synchronization, and private claim.
- End-to-end gas/mana measurement remains a separate dependent requirement; this ADR establishes the production path that measurement must exercise.
