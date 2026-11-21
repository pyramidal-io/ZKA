// =============================================================================
// ZKA Recursive Proof Aggregation Circuit (Noir / BN254)
//
// Spec Reference: ZKA v0.4.0
//
// Aggregates multiple ZKA proofs into a single proof using recursive
// verification. Given N inner proofs (up to MAX_RECURSIVE_DEPTH = 4), the
// circuit verifies each one and produces a single aggregated proof.
//
// This acts as a proof-of-proofs: the verifier only needs to check the
// aggregated proof to be convinced that all inner proofs are valid.
//
// Domain Separators (recursive-specific):
//   DOMAIN_RECURSIVE_SEED   - Initial seed for the aggregation hash chain
//   DOMAIN_RECURSIVE_VERIFY - Commits verified proof material into the aggregate
//
// Public Inputs (3):
//   [0] aggregation_commitment - Hash of all verified proof public inputs
//   [1] num_proofs             - Number of proofs being aggregated (1-4)
//   [2] context                - Replay protection (epoch/chain/app binding)
//
// Private Inputs:
//   verification_keys    - Verification key for each inner proof (4 slots)
//   proofs               - Proof bytes for each inner proof (4 slots)
//   proof_public_inputs  - Public inputs of each inner proof (4 slots)
//   key_hashes           - VK key hash per inner proof (4 slots)
//
// Inner public-input sizing (fixed-size zero-padding does NOT work):
//   bb's recursive-verification gadget requires the public-input count passed
//   to std::verify_proof_with_type to EXACTLY match the inner circuit's
//   public-input count. Zero-padding a smaller inner PI vector to a larger
//   fixed size was tested empirically against bb
//   5.0.0-nightly.20260324: the outer proof is produced but FAILS
//   verification (fail-closed, but unusable). A single circuit therefore
//   aggregates exactly one inner PI-count class, and ZKA uses per-class
//   recursive instantiations instead of a padding convention.
//
//   THIS instantiation is the 5-field class: it aggregates `zka_transfer`
//   (5 public inputs) proofs.
//   Other classes (zka_credential=4,
//   zka_balance/zka_withdrawal=6, zka_transfer_multi=15,
//   zka_root_update=22) need their own instantiation of this same source
//   with PUBLIC_INPUT_SIZE adjusted; zka_root_update (22) is intentionally
//   excluded from aggregation plans (it is an EVM-verified singleton).
//   Coord v2 instead uses its dedicated `zka_coordination_v2_recursive`
//   33-field final receipt circuit, not this generic aggregator.
// =============================================================================

use zka_lib::{poseidon2, poseidon4};

/// Maximum number of inner proofs that can be aggregated in a single recursion
global MAX_RECURSIVE_DEPTH: u32 = 4;

/// Barretenberg UltraHonk verification key size when converted to field elements.
global VK_SIZE: u32 = 115;

/// Barretenberg UltraHonk ZK proof size when converted to field elements.
/// Ground truth for the pinned toolchain (bb 5.0.0, see
/// .noir-version): `bb prove -s ultra_honk -t noir-recursive` emits a
/// 14656-byte proof = 458 fields. bb's recursive-verification gadget asserts
/// this size when building the VK, so a stale value makes `bb write_vk` fail
/// for this circuit (the previous 500 dated from an older bb).
global PROOF_SIZE: u32 = 458;

/// Barretenberg proof type identifier for zero-knowledge UltraHonk proofs.
global PROOF_TYPE_HONK_ZK: u32 = 6;

/// Size of each inner proof's public-input vector (field elements).
///
/// MUST exactly match the inner circuit class being aggregated: bb's
/// recursive gadget rejects (at outer-proof verification) any witness whose
/// PI count differs from the inner VK's -- zero-padding does NOT work (tested
/// against bb 5.0.0-nightly.20260324). This instantiation aggregates the
/// 5-field class: `zka_transfer`.
global PUBLIC_INPUT_SIZE: u32 = 5;

/// Domain separator for the aggregation hash chain seed
global DOMAIN_RECURSIVE_SEED: Field =
    0x1a33333333333333333333333333333333333333333333333333333333333333;

/// Domain separator for inner proof verification hashing
global DOMAIN_RECURSIVE_VERIFY: Field =
    0x1a44444444444444444444444444444444444444444444444444444444444444;

// =============================================================================
// Inner Proof Verification
//
// The foreign call emits Barretenberg's recursive aggregation opcode. Noir
// witness execution alone cannot prove validity; invalid inner proofs are
// rejected by the proving backend when it attempts to create the outer proof.
// =============================================================================

fn verify_inner_proof(
    verification_key: [Field; 115],
    proof: [Field; 458],
    proof_public_inputs: [Field; 5],
    key_hash: Field,
) -> Field {
    std::verify_proof_with_type(
        verification_key,
        proof,
        proof_public_inputs,
        key_hash,
        PROOF_TYPE_HONK_ZK,
    );

    // Hash the verification key into a single commitment
    let mut vk_acc = DOMAIN_RECURSIVE_VERIFY;
    for i in 0..VK_SIZE {
        vk_acc = poseidon2(vk_acc, verification_key[i]);
    }

    // Hash the proof into a single commitment
    let mut proof_acc = DOMAIN_RECURSIVE_VERIFY;
    for i in 0..PROOF_SIZE {
        proof_acc = poseidon2(proof_acc, proof[i]);
    }

    // Hash the public inputs into a single commitment
    let mut pi_acc = DOMAIN_RECURSIVE_VERIFY;
    for i in 0..PUBLIC_INPUT_SIZE {
        pi_acc = poseidon2(pi_acc, proof_public_inputs[i]);
    }

    // Combine all components with the VK key hash into a binding commitment.
    poseidon4(vk_acc, proof_acc, pi_acc, key_hash)
}

fn main(
    // === Public Inputs ===
    aggregation_commitment: pub Field,
    num_proofs: pub Field,
    context: pub Field,
    // === Private Inputs ===
    verification_keys: [[Field; 115]; 4],
    proofs: [[Field; 458]; 4],
    proof_public_inputs: [[Field; 5]; 4],
    key_hashes: [Field; 4],
) {
    // =========================================================================
    // 1. INPUT VALIDATION
    //
    // num_proofs must be in {1, 2, 3, 4}. Zero proofs would produce a
    // vacuously true aggregation, and more than MAX_RECURSIVE_DEPTH is
    // unsupported by the fixed circuit layout.
    // =========================================================================
    assert(num_proofs as u32 >= 1, "num_proofs must be at least 1");
    assert(
        num_proofs as u32 <= MAX_RECURSIVE_DEPTH,
        "num_proofs must be at most MAX_RECURSIVE_DEPTH (4)",
    );

    // =========================================================================
    // 2. CONTEXT BINDING
    //
    // The context must be non-zero to prevent replay attacks. It encodes
    // epoch, chain_id, and application_id from the outer protocol.
    // =========================================================================
    assert(context != 0, "Context must be non-zero for replay protection");

    // =========================================================================
    // 3. INNER PROOF VERIFICATION AND AGGREGATION
    //
    // For each proof slot, compute the verification hash. Active slots
    // (i < num_proofs) contribute their full verification hash to the
    // aggregation chain. Inactive slots contribute zero.
    //
    // The aggregation uses a chained Poseidon2 hash:
    //   acc = H(DOMAIN_RECURSIVE_SEED, context)   [initial seed]
    //   acc = H(acc, proof_hash_0)                 [first proof]
    //   acc = H(acc, proof_hash_1)                 [second proof]
    //   ...
    //   aggregation_commitment = acc
    //
    // The context is mixed into the seed to bind the aggregation to a
    // specific execution context.
    // =========================================================================
    let mut agg_acc = poseidon2(DOMAIN_RECURSIVE_SEED, context);

    for i in 0..MAX_RECURSIVE_DEPTH {
        // A slot is active if its index is less than num_proofs.
        // Since Noir doesn't support < on Field directly, we check whether
        // the index equals or exceeds num_proofs by testing against each
        // possible boundary value. Once we hit or pass num_proofs, the
        // slot is inactive.
        let idx = i as Field;
        let mut slot_active = true;
        if idx == num_proofs {
            slot_active = false;
        }
        if idx == num_proofs + 1 {
            slot_active = false;
        }
        if idx == num_proofs + 2 {
            slot_active = false;
        }
        if idx == num_proofs + 3 {
            slot_active = false;
        }

        let contribution = if slot_active {
            verify_inner_proof(
                verification_keys[i],
                proofs[i],
                proof_public_inputs[i],
                key_hashes[i],
            )
        } else {
            0
        };
        agg_acc = poseidon2(agg_acc, contribution);
    }

    // =========================================================================
    // 4. AGGREGATION COMMITMENT VERIFICATION
    //
    // The computed aggregation must match the public input. This binds the
    // prover to the exact set of inner proofs they claimed to aggregate.
    // =========================================================================
    assert(
        agg_acc == aggregation_commitment,
        "Aggregation commitment mismatch: computed aggregation does not match public input",
    );
}

// =============================================================================
// Tests
// =============================================================================

#[test(should_fail_with = "num_proofs must be at least 1")]
fn test_num_proofs_zero_fails() {
    let context: Field = 0xdeadbeef;
    let num_proofs: Field = 0;

    let verification_keys = [[0; 115]; 4];
    let proofs = [[0; 458]; 4];
    let proof_public_inputs = [[0; 5]; 4];
    let key_hashes: [Field; 4] = [0; 4];

    // Aggregation commitment doesn't matter since num_proofs check fails first
    main(
        0,
        num_proofs,
        context,
        verification_keys,
        proofs,
        proof_public_inputs,
        key_hashes,
    );
}

#[test(should_fail_with = "Context must be non-zero")]
fn test_context_zero_fails() {
    let context: Field = 0; // zero context
    let num_proofs: Field = 1;

    let verification_keys = [[0; 115]; 4];
    let proofs = [[0; 458]; 4];
    let proof_public_inputs = [[0; 5]; 4];
    let key_hashes: [Field; 4] = [0; 4];

    main(
        0,
        num_proofs,
        context,
        verification_keys,
        proofs,
        proof_public_inputs,
        key_hashes,
    );
}

#[test]
fn test_domain_separators_are_distinct() {
    assert(
        DOMAIN_RECURSIVE_SEED != DOMAIN_RECURSIVE_VERIFY,
        "Recursive domain separators must be distinct",
    );
    assert(DOMAIN_RECURSIVE_SEED != 0, "DOMAIN_RECURSIVE_SEED must be non-zero");
    assert(DOMAIN_RECURSIVE_VERIFY != 0, "DOMAIN_RECURSIVE_VERIFY must be non-zero");
}
