# zka_recursive

`zka_recursive` verifies Barretenberg UltraHonk proofs inside an outer Noir
proof via `std::verify_proof_with_type` (bb's `recursive_aggregation`
opcode), proving up to `MAX_RECURSIVE_DEPTH = 4` inner proofs valid with a
single outer proof. It is proven end-to-end with the pinned toolchain
(`.noir-version`: nargo 1.0.0-beta.25 + bb 5.0.0) and has
committed proof fixtures gated by CI like every other core circuit.

## Inner proof class (sizing decision, 2026-06-11)

bb's recursive gadget requires the public-input count passed to
`verify_proof_with_type` to EXACTLY match the inner circuit's public-input
count. Zero-padding a smaller inner PI vector to a larger fixed size was
tested empirically against the pinned bb: the outer proof is *produced* but
**fails verification** ("verification failed at reduction step") — i.e. a
padding convention is fail-closed but unusable. A single instantiation
therefore aggregates exactly one inner PI-count class:

| This instantiation | `PUBLIC_INPUT_SIZE = 5` |
|---|---|
| Aggregatable inner circuits | `zka_transfer` (5 PIs) |
| Other classes | need their own instantiation of this source with `PUBLIC_INPUT_SIZE` adjusted: `zka_credential` = 4, `zka_balance`/`zka_withdrawal` = 6, `zka_transfer_multi` = 15 |
| Coord v2 | uses the dedicated `zka_coordination_v2_recursive` 33-field final receipt circuit, not this generic aggregator |
| Excluded | `zka_root_update` (22 PIs) — an EVM-verified singleton, intentionally not part of aggregation plans |

## Witness preparation (real inner proofs only)

The witness needs real Barretenberg recursive proof material — all-zero mock
proofs in *active* slots are not valid witnesses. Per inner-proof slot:

- `verification_keys`: UltraHonk VK as `[Field; 115]`
- `proofs`: zero-knowledge UltraHonk proof as `[Field; 458]` (the ZK Honk
  proof size of the pinned bb)
- `proof_public_inputs`: the inner circuit's public inputs, `[Field; 5]`
- `key_hashes`: the VK key hash

Inner proofs MUST be generated with bb's recursion flavor
(`-t noir-recursive`: poseidon2 transcript + ZK Honk, matching
`PROOF_TYPE_HONK_ZK = 6`); EVM-flavor (keccak) proofs are not recursively
verifiable. *Inactive* slots (index >= `num_proofs`) are zero-filled — the
`num_proofs` multiplexer predicates the `verify_proof` calls, so inactive
slots never reach bb's gadget (verified empirically).

The toolchain for all of this is in-repo:

1. `bb write_vk / bb prove` with `-t noir-recursive --output_format json`
   emit the VK (115 fields + key hash), proof (458 fields), and inner public
   inputs directly as field arrays.
2. `src/zka-crypto/examples/prepare_recursive_witness.rs` consumes those
   JSON files for 1..=4 inner proofs, computes the Poseidon2
   `aggregation_commitment` with the KAT-locked canonical primitives, and
   emits `Prover.toml`.
3. `scripts/generate_proof_fixtures.py --only zka_recursive` orchestrates
   the whole cycle: proves the donor circuit (`zka_transfer`) twice,
   regenerates the committed `Prover.toml` here, proves + verifies the outer
   circuit, and writes the committed fixtures under
   `tests/fixtures/proofs/zka_recursive/` — the positive aggregation of two
   real transfer proofs, the standard tampered-public-input and
   corrupted-proof negatives, and a recursive-only negative
   (`negative_inner_proof.json`): an outer proof built over a tampered inner
   proof, which bb MUST reject at outer verification.

The committed `Prover.toml` embeds real inner proofs. Run
`scripts/generate_proof_fixtures.py --only zka_recursive` whenever circuits or
the toolchain change to regenerate and validate the committed fixtures.
