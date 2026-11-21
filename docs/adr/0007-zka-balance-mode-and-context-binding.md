# ADR 0007: `zka_balance` mode and context binding

**Status:** Accepted (2026-08-26)
**Requirements:** pre-publication security punch-list items P6-b (bind the balance proof mode to the request), P6-c (add replay binding to `zka_balance`), and P6-d (mode-aware threshold ordering)
**Refs:** `noir/zka_balance/src/main.nr`; `schemas/public-inputs/zka_balance.json`; `src/zka-sdk/src/proofs/balance_noir.rs`; ADR 0001; ZKA §5.2, §5.4.1, §6.1, Safeguard 6

## Context

The `zka_balance` circuit proves a note's value lies in a caller-published interval without consuming the note.
Before this change the circuit's four public inputs (`merkle_root`, `asset_commitment`, `threshold_or_lower`, `upper_bound`) said nothing about which comparison mode (`>=`, `<=`, range) produced them, and carried no replay-protection context at all.
A `zka-sdk` verifier that checked only the bounds could be handed a proof honestly generated for a *different* mode — for example a `<=` proof whose bounds happen to also satisfy a requested `>=` check — and accept it as though the requested claim had been proven.
The same proof could also be replayed against any verifier or session, since nothing in the public inputs was bound to who asked or when.

This ADR settles three things together, because they interact: how the comparison mode is disclosed, how replay protection is bound, and what "non-zero context" means as a MUST, not a SHOULD.

**Context is a MUST, anchored to machinery the spec already mandates.**
The requirement text this ADR discharges described context uniqueness as a bare SHOULD.
That is insufficient: ZKA already mandates an authenticated-request/receipt mechanism for exactly this purpose (Safeguard 6), and already mandates, in the ZKC v2 payment-binding circuit and in §5.4.1's ZKM settlement-context check, that `context` is (a) non-zero, (b) a separate co-equal public input never folded into the claim binding (ADR-0001 Option A), and (c) a value the verifier itself derives, never a caller-supplied one.
`zka_balance` is not a new context-binding design; it is the same shape already normative elsewhere in the spec, applied to a circuit that had not yet adopted it.
Given that the machinery already exists and is already mandatory for cross-referenced circuits, treating `zka_balance`'s context as a SHOULD would be an unexplained downgrade, not a conservative default.
Accordingly the decision below states, and ZKA §6.1 now states normatively, that `context` MUST be non-zero, MUST be a separate co-equal public input never folded into the claim binding, and MUST equal a value the verifier itself derived — mirroring §5.4.1's "a caller-supplied context is never authoritative" verbatim in style — and that `context` MUST bind the replay-protection context of the authenticated proof request (Safeguard 6). When carried by `afp:envelope:v1`, the field equals AFP's canonical nonzero BN254 `session_context_field` projection of the authenticated raw `X_...` session identifier, mirroring the existing `zka_transfer_binding` wording as clarified by protocol-family epoch `2026-09-04.1`.
Per-session uniqueness of the *value chosen for* context remains a RECOMMENDED operational practice, not a circuit-checkable property (see Consequences); the MUST is on the binding shape, which the circuit can and does enforce via `assert(context != 0)` plus the verifier-side equality check in `verify_balance_proof`.

## Decision

`proof_type` is disclosed as public input index [4]; `context` is a separate co-equal public input at index [5] with `assert(context != 0, "context must be non-zero")`, per ADR-0001 Option A.
Claims are canonicalized to saturating u64 intervals so that every mode publishes a genuine `[low, high]` interval: proof type 0 (`>= T`) publishes `[T, 2^64 - 1]`; proof type 1 (`<= T`) publishes `[0, T]`; proof type 2 (range) publishes `[lower, upper]` with both bounds free.
The SDK verifier (`verify_balance_proof`) checks, in this load-bearing order, that the circuit is `Balance`, the target is `NoirRecursive` (the offchain flavor), the expected statement is well-formed (`validate()`), the public-input count is 6, index [4] equals the requested mode, and index [5] equals the expected context. It then compares the root and asset identity exactly and applies P6d's same-mode monotone interval predicate before invoking the backend: a proved `>= T` satisfies a request for `>= R` when `T >= R`; a proved `<= T` satisfies a request for `<= R` when `T <= R`; and a proved range `[lo, hi]` satisfies a requested range `[L, H]` when `lo >= L` and `hi <= H`. Equality is accepted in every mode.

**Mode-hiding is deliberately and irreversibly abandoned.**
The requirement's own stated ground for rejecting per-mode verification keys — "VK identity leaks the mode to a ledger observer" — applies verbatim to a public `proof_type`: either way, an observer with proof/VK access learns the mode.
What actually survives as a reason to prefer a shared VK with a public `proof_type` field over per-mode VKs is artifact multiplication (three VKs, three manifest entries, three artifact-pipeline instantiations for one circuit). A shared VK also leaves any future cross-mode subsumption policy on one verifier path instead of requiring dispatch and policy coordination across three artifacts. P6d itself retains exact mode matching.
The leak this decision gives up was already near-total before this change: `upper_bound == 0` disclosed "this is not a range proof" by API convention even under the old four-input ABI, so at most roughly one bit of mode information was ever actually hidden.
`zka_balance` also has no on-chain verifier — `artifacts/manifest.json` publishes `evm: null` for it, and `registry/chains.json` lists `verifierTargets: ["offchain"]` with `evmVerifierContract: null` — and it emits no nullifier, so there is no deployed ledger-observer path for this leak to reach in the first place.

## Rejected alternatives

**Per-mode verification keys.** Three separate circuits/VKs for `>=`, `<=`, and range would hide the mode from anyone without the VK, but at the cost of artifact multiplication (three manifest entries and three artifact pipelines for one logical circuit). They would also make any future cross-mode subsumption policy coordinate verification across multiple VKs instead of applying one request policy after one shared verifier path. P6d does not enable that optional cross-mode policy.

**`statement_binding` hash with sealed thresholds.** Hashing `(proof_type, threshold_or_lower, upper_bound)` into one opaque public commitment, never revealing the triple, is the literal alternative named in the requirement text. It forecloses P6d outright: a verifier could only test statements it already knows in full, and testing an unknown threshold against a committed statement means a roughly `2^64` preimage search over the threshold domain. This is recorded as a design constraint discovered during this work, not a softened trade-off.

**`statement_binding` with public thresholds and a secret nonce.** Keeping the thresholds public but folding a secret nonce into the mode commitment buys back roughly one bit of mode-hiding, at the cost of a confidential out-of-band nonce-distribution channel in a protocol whose premise is that verification requires no secrets, a new domain separator to pin and audit, an unpinned Poseidon2 arity choice, and an entropy requirement that no CI gate can enforce. A nonce-less version of the same binding is equivalent to a three-entry Poseidon2 lookup table, since the mode space has exactly three elements — it adds a hash computation without adding security.

**Dropping index [4] and shipping 5 public inputs.** Inferring the mode from which saturating bound is present (`upper_bound == 2^64 - 1` implies mode 0, `threshold_or_lower == 0` implies mode 1) is security-equivalent to publishing `proof_type` explicitly, since the canonical encoding already makes the bounds determine the mode. It was rejected anyway because it forces P6d to re-derive the mode from a magic saturating constant instead of reading a field, and it forces any consumer that reads only the manifest's public-input names — without also knowing the saturating-encoding convention — to get the mode wrong.

## Soundness findings

Reproduced under the pinned toolchain (nargo 1.0.0-beta.22) against the pre-P6b circuit, before the fixes in this change landed:

1. The pre-P6b circuit accepted `threshold_or_lower = p - 1` together with `note_value = 1000` under proof type 0 (`>=`): the difference `note_value - threshold_or_lower` wraps in the scalar field to `1001`, which satisfied the circuit's (unwidth-checked) comparison.
2. The pre-P6b circuit accepted a `note_value` near `p` under proof type 1 (`<=`): `note_value` itself had no width constraint anywhere in the circuit, so a field element just below the modulus satisfied `value <= 500` by wraparound.

Both are closed by the same four-check design: `assert_fits_u64(threshold_or_lower)`, `assert_fits_u64(upper_bound)`, `assert_fits_u64(note_value - threshold_or_lower)`, `assert_fits_u64(upper_bound - note_value)`.
Completeness of that four-check set: writing `d_lo = note_value - threshold_or_lower` and `d_hi = upper_bound - note_value`, `d_lo + d_hi === upper_bound - threshold_or_lower (mod p)`.
The left-hand side is bounded below `2^65` by the two range checks on `d_lo` and `d_hi`, so an inverted interval — whose right-hand side would be `p - (threshold_or_lower - upper_bound) > 2^254` — is unsatisfiable.
Hence `upper_bound >= threshold_or_lower`, the modular equation holds as an exact integer equation, and `note_value = threshold_or_lower + d_lo <= upper_bound < 2^64` is forced.
No separate range check on `note_value` or on `upper_bound - threshold_or_lower` is needed; both are derived properties, pinned by tests rather than by redundant constraints.

## P6d ordering and forward scope

P6d resolves threshold semantics as an ordering, not equality, while retaining the exact mode-equality conjunct: a proof whose disclosed mode differs from the requested mode MUST be rejected. Within one mode, the verifier uses the monotone containment predicate — `lo_proven >= lo_requested AND hi_proven <= hi_requested` — specialized through the canonical encodings above. Thus a stronger `>=` proof, a stricter `<=` proof, or a contained range can satisfy the request; a weaker proof cannot. Equality remains an accepted containment case.

Cross-mode subsumption remains optional future scope. For example, a mode-2 range proof over `[T, 2^64-1]` could be allowed to satisfy a mode-0 `>= T` request, because both the mode and raw bounds are legible on the wire under this ABI. Such a relaxation would replace the exact mode-equality rule but would not change the public-input ABI fixed by this ADR; it is deliberately not part of P6d.

## Consequences

`zka_balance`'s public-input count grows from 4 to 6 in ABI order (`merkle_root, asset_commitment, threshold_or_lower, upper_bound, proof_type, context`), with `proof_type` promoted to public in place and `context` appended — no parameter reordering.
This is a manifest-breaking, artifact-regenerating, fixture-regenerating change, tracked through the full cascade in the P6b/P6c implementation steps (schema, registry, SDK, live tests, artifact manifest, proof fixtures, benchmarks).
Per-session uniqueness of the context *value* remains the caller's operational responsibility: the circuit enforces the binding shape (non-zero, co-equal, verifier-derived-and-checked) but cannot enforce that a given verifier mints a fresh context per session rather than reusing one fixed value, and it cannot detect the difference between the two from the proof alone — see the non-normative warning added to ZKA §6.1.
