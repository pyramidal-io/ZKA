# ADR 0001 — Canonical §5.2 disclosure context-binding shape (cross-environment)

- **Status:** Accepted (Option A) — 2026-05-29
- **Date:** 2026-05-29
- **Deciders:** ZKA protocol owner (Michael)
- **Decision:** Option A — conform to the normative §5.2 model: `context` is a separate, co-equal binding (public input on EVM; separate note field / return component on Aztec), never folded into the disclosure hash. The earlier Aztec fold is reconciled back toward the spec; the standalone circuit's dead `_context_binding` is removed.
- **Related:**
  - Scope: Aztec vs. standalone disclosure-binding alignment
  - Spec: ZKA v0.6.0 §5.2 (Identity Binding Circuit) — normative
  - Code: `noir/zka_credential/src/main.nr`, `aztec/zka_credential_aztec/src/main.nr`, `aztec/zka_aztec_lib/src/lib.nr`, `aztec/zka_cross_env_tests/src/lib.nr`
  - Prior work: Aztec §5.2 context binding and the §1.6 custody audit

## Context

ZKA's §5.2 disclosure proofs must bind their output to a caller-supplied session **context** = `H(verifierId, sessionId, timestamp)` so a proof made for one verifier/session/time cannot be replayed against another. The protocol is implemented in two environments that are required to be cross-verifiable (the "interoperability guarantee" in `aztec/README.md` — a disclosure proven in one environment is recognizable in the other). Today the two environments bind context **differently**:

### Standalone Noir circuit (`noir/zka_credential/src/main.nr`)

```
Public inputs: [credential_commitment, disclosed_attribute_hash, context]
  disclosed_attribute_hash = fold(credential_data, attributes, mask)   // context-INDEPENDENT
  assert(context != 0)
```

- Replay protection comes from `context` being a **public input**: the SNARK binds it to the proof, so a proof generated with `context_A` will not verify against `context_B`. This is the standard SNARK replay pattern.
- Line 117 — `let _context_binding = poseidon3(credential_commitment, credential_data, context)` — is **dead-code-eliminated** (unused `_`-prefixed local) and therefore constrains nothing. Its comment ("bind credential to context") is misleading: the real binding is the public input, not this line.
- EVM verifier interface (asserted by `zka_cross_env_tests::test_evm_verifier_public_inputs_match`): `[cc, raw_disclosed_hash, context]` — three public inputs.

### Aztec contract (`aztec/zka_credential_aztec/src/main.nr`)

```
prove_disclosure(mask, context) -> poseidon3(DOMAIN_DISCLOSURE_BIND, raw_disclosed_hash, context)
```

- Returns a **single context-FOLDED value**; `context` is not exposed separately. The fold uses a provisional domain separator `DOMAIN_DISCLOSURE_BIND = 0x2ddd…` (`aztec/zka_aztec_lib/src/lib.nr`).
- `disclose_to` writes this folded hash into the recipient note's `credential_data` slot.

### The divergence

The **raw** disclosed hash is already byte-identical across environments (`test_evm_verifier_public_inputs_match` / `test_evm_verifier_public_inputs_all_masks` pass — they compare the library-level `compute_disclosed_hash`). The divergence is purely in **where the context binding lives**:

| | Standalone / EVM | Aztec |
|---|---|---|
| Disclosure artifact | `raw_disclosed_hash` (context-independent) | `poseidon3(DOMAIN, raw, context)` (context-folded) |
| Context exposure | separate public input | folded into the artifact, not exposed separately |
| Replay protection via | context public input bound to proof | folded value differs per context |

A relayer/verifier cannot use one interface for both, so cross-chain verification of a disclosure proof is not yet possible.

## Decision drivers

1. **The spec is normative and already picks a model.** ZKA v0.6.0 §5.2 lists `context: Hash` as a **separate public input** and specifies replay protection as *"context bound into the proof"* (constraint 4), with a `MUST` that it follow the ZKC v0.2.2 `claimBinding`/context model (`context = H(verifierId, sessionId, timestamp)`). The spec does **not** fold context into the disclosure/holder hash.
2. **Cross-spec consistency with ZKC v0.2.2.** The ZKA↔ZKC reconciliation (Appendix C.1) records agreement on "the `claimBinding`/context replay model." Keeping context a separate binding element aligns ZKA with ZKC; folding it into the disclosure hash would diverge from both.
3. **Cross-environment byte-equality.** The raw disclosed hash is already identical in both environments — the smallest change that achieves full cross-env equality of the *exposed* artifact is to stop folding on the Aztec side, not to start folding on the standalone side.
4. **EVM verifier interface stability.** Verifiers are per-circuit and non-upgradeable (Safeguard 3). There is **no committed Solidity consumer** of the credential/disclosure verifier today (`contracts/ethereum/` wires only the transfer/withdrawal verifier), so changing the interface is cheap *now* — but the spec-conformant shape already matches the existing `[cc, raw_disclosed_hash, context]` interface, so no change is even needed.
5. **Aztec consumption modes (the one real subtlety).** Synchronous same-tx composition binds a returned value to its `context` argument via the call proof, so no fold is needed there. **Asynchronous** consumption (`disclose_to` stores a note the recipient checks in a *later* tx) needs the context to travel *with* the note — either folded into one field (the earlier design) or carried as a **separate note field** alongside the raw hash.

## Options considered

### Option A — Context as a separate, co-equal binding (conform to §5.2). **[Recommended]**

The canonical disclosure artifact is the **raw** `disclosed_attribute_hash`; `context` is always carried as a **separate** public input (standalone/EVM) or **separate note field / return component** (Aztec). Context is never folded into the disclosure hash. This is the model the normative spec already specifies.

- **Standalone:** already conformant. Remove the dead `_context_binding` line and fix its misleading comment (replay protection is the `context` public input). No public-input change.
- **Aztec:** stop folding. `prove_disclosure(mask, context)` returns the raw hash; the `(mask, context, raw_hash)` correspondence is guaranteed by the call proof for same-tx consumers. For `disclose_to`, store **both** `raw_hash` and `context` as separate `CredNote` fields so a later-tx recipient can verify the session. Remove `DOMAIN_DISCLOSURE_BIND` and `compute_disclosure_binding` (no fold ⇒ no domain separator needed; supersedes the earlier folded design).
- **Cross-env:** both environments expose `[cc, raw_disclosed_hash, context]`; add a regression test asserting full triple-equality.
- **Pros:** spec-conformant; ZKC-aligned; preserves the existing EVM verifier interface; clean separation of "what was disclosed" vs "when/to-whom"; minimal-disclosure-friendly (the raw commitment is the disclosure, context is metadata).
- **Cons:** partially reverts the earlier Aztec fold; `disclose_to` notes grow one field; the Aztec tests that assert "return value differs per context" must be rewritten to assert the binding-via-argument model (zero-context rejected; correspondence enforced by the call / the stored context field).

### Option B — Context folded into the hash (canonical = `poseidon3(DOMAIN, raw, context)`).

Make both environments expose the folded bound hash; change the standalone public-input vector to `[cc, bound_disclosed_hash, context]` (or drop the separate context input).

- **Pros:** one self-contained artifact that is intrinsically context-specific, convenient for asynchronous/stored consumption without a second field; domain-separated by construction (the I-2 defense).
- **Cons:** **diverges from the normative §5.2 spec** (which mandates context as a separate public input) and from the ZKC `claimBinding` model — adopting it would require a **spec amendment** (ZKA §5.2 + ZKC re-alignment), not just a code change; conflates disclosure content with session metadata; requires a new credential EVM verifier deployment if/when the interface is changed.

### Option C — Expose both (raw + folded).

Carry `raw`, `context`, and the folded `bound` together. Maximum flexibility, but adds a public input / note field for no benefit Option A doesn't already provide, and still has to answer "which one is canonical for cross-env equality." Rejected as over-engineered.

## Decision (proposed)

**Adopt Option A — conform to the normative §5.2 model: `context` is a separate, co-equal binding (public input on EVM; separate note field / return component on Aztec), never folded into the disclosure hash.** This makes the exposed disclosure artifact byte-identical across environments (the raw hash, already equal) and keeps ZKA aligned with its own spec and with ZKC v0.2.2.

Choosing Option B would be a deliberate **spec change**; if that is preferred for the asynchronous-note ergonomics, it should be escalated as a ZKA §5.2 + ZKC amendment rather than landed as an implementation detail.

## Consequences / implementation plan (if Option A is accepted)

1. **Standalone** (`noir/zka_credential/src/main.nr`): delete the dead `_context_binding` line (117); replace the comment with an accurate statement that replay protection is the `context` public input. (No interface change.)
2. **Aztec** (`zka_credential_aztec`, `zka_aztec_lib`):
   - `prove_disclosure` / `prove_kyc` / `prove_jurisdiction` / `prove_source_of_funds` / `aggregate_disclosures` return the **raw** disclosed hash; keep `assert(context != 0)`.
   - `disclose_to`: store `raw_disclosed_hash` and `context` as **separate** `CredNote` fields (add a `context` field) instead of folding; update the WIRE CONTRACT header + `CredNote` doc accordingly.
   - Remove `DOMAIN_DISCLOSURE_BIND` + `compute_disclosure_binding` (and the provisional `0x2ddd…` literal). No Blake2b domain canonicalization is then required for disclosure binding.
3. **Cross-env tests** (`zka_cross_env_tests`): add a test asserting `[cc, raw_disclosed_hash, context]` equality across environments (extends the existing EVM-verifier tests to the full triple).
4. **Aztec TXE tests** (`zka_credential_aztec/src/test.nr`): rewrite the "different context ⇒ different return value" tests to the Option-A model (zero-context rejected; `disclose_to` note carries the matching `context` field; same raw hash for same mask).
5. **Docs:** update `aztec/README.md` "Cross-Environment Testing" row and the §5.2 header comments to describe the separate-context model; mark this ADR `Accepted`.

If Option B is chosen instead, the plan inverts (fold on the standalone side, regenerate the credential EVM verifier, amend the spec) — captured here for completeness but **not recommended**.

## Open question for the decider

Confirm **Option A** (conform to §5.2 — context as a separate binding, no fold), or elect **Option B** (fold; requires a spec/ZKC amendment). On confirmation of Option A, the implementation above is straightforward and can proceed under the disclosure-binding alignment review, after which the real cross-environment proof test is unblocked.
