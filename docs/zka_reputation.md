# ZKA/Reputation: bounded bilateral AFP history proof

**Version:** 0.1.0-draft
**Status:** bounded reference prototype; not an operational AFP Introduction Tier
**Circuit ID:** `zka:reputation:ultrahonk:bn254:v1`
**Proof system:** UltraHonk over BN254, using the repository-pinned Noir and Barretenberg versions
**Consumes:** AFP v0.3.14-draft §12.6.1 (`docs/afp_specification.md`) and AFP Introduction Profile §14.6 (`docs/afp_introduction_profile.md`), both in AFP.dev

This document specifies the ZKA-family circuit primitive used by AFP's bilateral
Introduction Tier reputation mechanism. It proves that one party knows a bounded,
clean history of finally settled interactions whose exact count and cumulative
value match public values. The statement is scoped to one agreement, one
counterparty, one value domain, one authenticated history head, and one proof
request.

The proof is deliberately not a global or portable positive-reputation score. It
does not expose a stable holder commitment, ZKA address, spending key, proof key,
or cross-agreement subject identifier. AFP defines no portable record of a default
(AFP Introduction Profile §14.7), and this circuit creates none.

## 1. Security boundary

Circuit validity establishes consistency with the public `history_root`, last
commitment reference, and counter. It does **not** establish that those values are
the parties' real or latest AFP state. A root or counter supplied only by the
prover is not reputation evidence.

### 1.1 Unspecified AFP adapter seam

This ZKA artifact deliberately does **not** define an AFP wire-level reputation
adapter. AFP v0.3.14-draft §12.6.1 leaves each profile's `outcome_root` preimage
profile-defined, while the signed `reputation_state` in AFP Introduction
Profile §14.4 does not carry this circuit's root, roles, value scope,
pseudonym, or counter. Neither specification currently defines:

- a versioned reputation-state attachment, its canonical bytes, the exact
  signature payload, or its relationship to `AfpCommitmentAtom.outcome_root`;
- the eligible AFP atom/profile kinds and the deterministic applicability,
  value, finality, slash/default, reference, uniqueness, and ordering rules that
  project an AFP chain into this circuit's record leaves; or
- cross-language attachment and projection KATs.

Those are AFP-owned integration semantics and require a separately versioned,
jointly reviewed AFP adapter profile. Until that profile exists, no deployment
can authenticate this circuit's public root interoperably, no proof from this
prototype may authorize an AFP limit adjustment, and no implementation may
describe it as an operational `afp:reputation-proof`. The remaining conditions
in this section are necessary requirements for that future adapter, not a
complete or presently implementable AFP wire protocol.

A future adapter MUST authenticate the exact public state as the latest state
accepted by both parties under the §12.6.1 bilateral, KEL-anchored signature and
chaining rules, and MUST fail closed unless all of the following hold:

1. Both party signatures over the state attachment and its containing
   `AfpCommitmentAtom` are valid at the pinned KEL key states. One signature, an
   operator signature, or an arbiter signature cannot substitute for either
   party.
2. The attachment binds the exact circuit ID, public `history_root`, agreement
   identifier, ordered presenter and counterparty roles, value scope,
   `relationship_pseudonym`, last commitment reference, and reputation counter.
3. The referenced §12.6.1 commitment chain is gap-free and the advertised head
   is the verifier's latest accepted reputation head for that agreement and AID
   pair. The adapter MUST reject a stale or repeated counter and serialize each
   compare-and-store update atomically. Reputation-record sequence numbers need
   only increase: unrelated records in the same per-AID-pair chain may occupy the
   intervening sequence numbers.
4. The authenticated `history_root` MUST be the complete, ordered projection of
   **every** interaction applicable to this agreement, ordered presenter/
   counterparty pair, and value scope through the advertised head. The adapter
   MUST derive that projection from the gap-free signed chain and MUST NOT permit
   either party to omit a late, unsettled, slashed, defaulted, zero-value, or
   otherwise adverse applicable event. If the complete projection contains more
   than eight events, this bounded v1 circuit is out of capacity and the adapter
   MUST reject it; selecting a favorable eight-event window is non-conforming.
5. Every applicable record has reached the finality threshold signed for its
   settlement profile. The circuit treats `settled_flags` as witness data; it
   cannot observe settlement finality or authenticate KERI signatures itself.
   The verifier MUST also require the bilaterally signed cumulative
   reputation state from AFP Introduction Profile §14.4, including its slash
   count, to agree with the complete projection and the public count and total.
6. Every public input equals the authenticated proof request or signed state.
   Caller- or prover-selected substitutes are never authoritative.

A valid proof only permits the presenter to propose an
`afp:limit-adjustment:v1`. Both parties still have to sign that adjustment. A
rejected, stale, malformed, slashed, or default-bearing proof yields no
adjustment and MUST NOT freeze, claw back, redirect, delay, or invalidate any
note, custody right, transfer, withdrawal, collateral, agreement exit, or other
tenant state.

## 2. Canonical encodings

`agreement_id`, `counterparty_aid`, and every active AFP commitment reference
are encoded as two unsigned 128-bit limbs. For a non-empty string `s`, first
require that `s` is already Unicode NFC, then compute:

```text
digest = SHA-256(u32be(byte_length(UTF8(s))) || UTF8(s))
hi     = uint128_be(digest[0..16])
lo     = uint128_be(digest[16..32])
```

The verifier MUST reject an empty, non-NFC, or otherwise non-canonical source
string and MUST recompute the limbs. This is the AFP string-to-limbs mapping;
SHA-256 here is an encoding hash and does not add a Poseidon2 domain.

`value_scope` prevents summing incomparable assets or denominations. It is the
high/low limb split of SHA-256 over RFC 8785 JCS bytes for exactly this object:

```json
{
  "asset_id": "<the exact canonical asset identifier signed in the agreement>",
  "decimals": 6,
  "kind": "zka:reputation-value-scope:v1",
  "unit": "atomic"
}
```

`asset_id` MUST be one non-empty NFC string present in the signed AFP policy;
`decimals` MUST be the asset's signed integer decimal precision in `[0, 255]`;
and `unit` MUST equal the literal `atomic`. Each `settled_value` and
`cumulative_settled_value` is therefore an integer count of that asset's atomic
unit. A v1 proof MUST NOT mix assets, denominations, exchange rates, or valuation
timestamps. A different value-scope object produces a different relationship
scope and pseudonym.

`context` is a separate, non-zero public field supplied from the authenticated
AFP proof request. When the proof is carried in an AFP session, the verifier MUST
first recompute the exact §5.2 string `"X_" || lowercase_hex(session_digest)`,
require its payload to be exactly 32 bytes, and then apply AFP §15.4's existing
field reading:

```text
r = 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001
context = big_endian_uint256(session_digest) mod r
```

A malformed source, fallback mapping, truncation, hashing of the `X_` string, or
zero result is invalid. This is a reading of the same session context, not a
parallel context. It is not folded into the history root: UltraHonk binds it as
a co-equal public input. A static context permits same-context replay, so the
verifier MUST use a fresh request/session context and MUST compare it exactly.

## 3. Public statement

The public input order is normative and is also recorded in
`schemas/public-inputs/zka_reputation.json`.

| Index | Name | Noir type | Meaning |
|---:|---|---|---|
| 0 | `agreement_id_hi` | `u128` | High limb of the agreement-id digest. |
| 1 | `agreement_id_lo` | `u128` | Low limb of the agreement-id digest. |
| 2 | `counterparty_aid_hi` | `u128` | High limb of the verifier/counterparty AID digest. |
| 3 | `counterparty_aid_lo` | `u128` | Low limb of the verifier/counterparty AID digest. |
| 4 | `value_scope_hi` | `u128` | High limb of the single-asset value-scope digest. |
| 5 | `value_scope_lo` | `u128` | Low limb of the single-asset value-scope digest. |
| 6 | `relationship_pseudonym` | `Field` | KDC-derived handle scoped to the preceding six limbs. |
| 7 | `history_root` | `Field` | Fixed-width Poseidon2 commitment authenticated outside the circuit. |
| 8 | `last_commitment_ref_hi` | `u128` | High limb of the final active AFP commitment reference. |
| 9 | `last_commitment_ref_lo` | `u128` | Low limb of the final active AFP commitment reference. |
| 10 | `reputation_counter` | `u64` | Sequence number of the authenticated history head. |
| 11 | `settled_interactions` | `u32` | Exact active record count, in `[1, 8]`. |
| 12 | `cumulative_settled_value` | `u128` | Exact sum of the active records in the value scope. |
| 13 | `context` | `Field` | Fresh, non-zero AFP request/session replay context. |

The statement discloses the exact count and total. A future threshold-hiding or
recursive profile needs a new circuit ID and verification key; it MUST NOT be
silently interpreted as v1.

## 4. Private witness

The witness contains the AFP-KDC seed field plus eight fixed record slots:

```text
master_seed: Field
record_refs_hi, record_refs_lo: [u128; 8]
sequence_numbers:                [u64; 8]
settled_values:                  [u128; 8]
settled_flags:                   [bool; 8]
slash_flags:                     [bool; 8]
default_flags:                   [bool; 8]
```

Under AFP entity identity, `master_seed` is the big-endian BN254 reduction of
the per-entity sub-seed `M'` from AFP-KDC v1.0.3 §A.5, not the tenant root
seed. It remains private. Standalone ZKA deployments may use their standalone
KDC seed under the same §A.6 interface.

The active records are the prefix `[0, settled_interactions)`. For a valid proof
this prefix is the complete applicable projection described in §1, not a
prover-selected sample or rolling window. Each active record MUST have a non-zero
reference, a non-zero value, `settled = true`, `slashed = false`, and
`defaulted = false`. Active sequence numbers MUST be strictly increasing but
need not be contiguous because the underlying §12.6.1 counter is per AID pair.
Every member of every inactive slot MUST be the canonical zero/false value;
alternative padding is rejected.

## 5. Poseidon2 transcript

Let `Hn(x...)` be the repository's length-bound Poseidon2 BN254 t=4/rate=3
hash, let `D` be the registered AFP-KDC field for `zka/commitment`, and let the
circuit-local transcript type codes be:

```text
RELATIONSHIP_SCOPE = 1
REPUTATION_EVENT   = 2
HISTORY_SEED       = 3
HISTORY_FOLD       = 4
```

These numeric codes are typed sub-transcripts under the already registered
`zka/commitment` domain. They are not new string domains or fixed-byte tags.

```text
scope = H8(D, 1,
           agreement_id_hi, agreement_id_lo,
           counterparty_aid_hi, counterparty_aid_lo,
           value_scope_hi, value_scope_lo)

cbk = H2(DOMAIN_ZKC_CREDENTIAL, master_seed)
relationship_pseudonym =
    H3(DOMAIN_ZKC_PRESENTATION_SCOPE, cbk, scope)

leaf[i] = H9(D, 2,
             sequence_numbers[i],
             record_refs_hi[i], record_refs_lo[i],
             settled_values[i],
             settled_flags[i], slash_flags[i], default_flags[i])

state[0] = H10(D, 3,
               agreement_id_hi, agreement_id_lo,
               counterparty_aid_hi, counterparty_aid_lo,
               value_scope_hi, value_scope_lo,
               relationship_pseudonym, settled_interactions)

state[i + 1] = H5(D, 4, state[i], leaf[i], active[i])  for i = 0..7
history_root = state[8]
```

The circuit constrains `relationship_pseudonym` and `history_root` to these
values. It also constrains the final active sequence/reference to the public
head and constrains the Field-domain sum of active values to the public `u128`
total. At most eight `u128` addends sum to less than `2^131`, far below the
BN254 scalar modulus, so the internal Field accumulator cannot wrap before the
public `u128` comparison. Totals larger than `2^128 - 1` are not representable
by this profile and are rejected.

## 6. Circuit verifier and blocked AFP acceptance

The following algorithm verifies the ZKA circuit statement. It is sufficient for
test and interoperability work on the proof itself, but it is **not** an AFP
acceptance algorithm while the adapter seam in §1.1 is unspecified. For circuit
ID `zka:reputation:ultrahonk:bn254:v1`, a circuit verifier MUST:

1. Select the exact registry-pinned UltraHonk verification key and 14-field
   public-input encoder. A proof or vector for another circuit ID is invalid.
2. Receive the expected agreement, ordered counterparty, value-scope,
   relationship-pseudonym, history-root, head-reference, and counter values from
   a trusted test fixture or, eventually, the versioned AFP adapter described in
   §1.1. Copying them from the proof request is not authentication.
3. Require `settled_interactions` and `cumulative_settled_value` to satisfy the
   negotiated growth-curve request. Because v1 publishes exact values, the
   ordinary comparison is `proved >= requested` within the same value scope.
4. Require `context` to equal the fresh authenticated AFP request/session value.
5. Atomically reject a stale/repeated `reputation_counter`, verify the proof,
   then record the accepted counter before emitting an acceptance receipt. A
   circuit-valid proof does not itself consume a nullifier or update this state.
6. On cryptographic success, return only that the circuit statement was
   satisfied. Until §1.1 is closed, this result MUST NOT be interpreted as AFP
   reputation acceptance. After that seam is standardized, any limit change
   still remains the separately bilaterally signed handshake in AFP
   Introduction Profile §14.6.

The future AFP adapter profile MUST pin the relationship pseudonym in the
bilaterally signed agreement or its first reputation-state attachment. It MUST
NOT accept a new pseudonym for an existing agreement without an explicit,
bilaterally signed rotation/rebind procedure. This prototype defines neither
the attachment nor that procedure and therefore cannot support KDC-seed
rotation.

## 7. Known-answer and negative vectors

`noir/zka_reputation/Prover.toml` is the canonical three-record witness. The
executable `canonical_three_record_kat_is_valid` test pins both derived outputs:

```text
relationship_pseudonym =
  0x304e967727812b6019e734655f6036ef63a8cc4771d1d1d1715f6c542be29fc4
history_root =
  0x074ade4e5df8fbc1e3361e8503a6f446e7fa98e9a3054cd655914baed5ae2c29
session_context =
  X_eddb6ad038bd9a1a79c6c1d29ebd7461da0383948b7e6c13dadd6553b97e4a7f
context =
  0x2c4a3104b3f719739885aaf898b812ed3933e272a498a9cecb558f03f97e4a7b
settled_interactions = 3
cumulative_settled_value = 10000
reputation_counter = 11
```

The same Noir module contains executable rejection vectors for zero identifiers,
root, pseudonym and context; the wrong seed or relationship scope; zero,
unsettled, slashed or defaulted active records; duplicate or decreasing
sequences; non-canonical inactive slots; a wrong total, head, counter or root;
and a two-maximum-`u128` overflow attempt. The canonical KAT's gaps demonstrate
that selected records need not have adjacent per-AID-pair sequence numbers. The
circuit alone cannot distinguish a legitimate gap from omission of an
applicable adverse event; only the future, versioned complete-projection adapter
described in §1.1 can provide that guarantee. One- and eight-record boundary
cases and the maximum single-record `u128` value are accepted.

## 8. Prototype limits and deployment status

This v1 reference is intentionally bounded to a complete history of at most
eight applicable interactions and rebuilds the complete fixed-width root. It
does not provide rolling-window reputation or recursive/unbounded history,
KERI or Ed25519 verification in-circuit, chain-finality verification,
cross-asset valuation, third-party positive-reputation transfer, automatic
growth-curve enforcement, a persistent replay store, or key-rotation continuity.

Consequently this deliverable realizes only the bounded ZKA circuit seam and its
public contract. It does not make the AFP Introduction Profile (§14)
operational, and the missing adapter contract is a hard blocker rather than
an implementation detail. A deployment MUST NOT use this proof for an AFP
limit adjustment until AFP publishes the versioned attachment/projection
contract and cross-language KATs identified in §1.1, and the adapter,
current-head store, proof/VK registry, request/receipt path, audited production
capacity profile, and the other lower layers in AFP Introduction Profile
§14.9 are implemented and reviewed.
