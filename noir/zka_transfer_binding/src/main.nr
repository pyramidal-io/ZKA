// =============================================================================
// ZKA Combined Transfer + Binding Circuit (Noir / BN254)
//
// Spec Reference: ZKA v0.6.4-draft, Section 5.3 ("Combined Transfer + Binding
// Circuit"). Cross-references Section 5.2 (Identity Binding) and Section 5.4 (Compliance
// Bundle, the `binding` member).
//
// Proves a private single-asset transfer AND, in the SAME proof, that the
// spending key behind the transfer also owns a ZKC credential whose canonical
// `holderCommitment` is the public input `holder_commitment`. This is the
// single-proof, selective-disclosure-compliant settlement primitive that the
// R3 vertical depends on: the bundle `binding` member (Section 5.4) and the payment
// `transaction` member collapse into one UltraHonk proof, so a verifier learns
// "this transfer was made by the holder of credential C" without two separate
// proofs and without revealing the spending key.
//
// Constraints (transfer Section 3.2 + binding Section 5.2):
//   1. Input note commitment validity
//   2. Merkle membership of input note
//   3. Nullifier correctness (double-spend prevention)
//   4. Ownership verification (spending key -> address)
//   5. Output note commitment validity
//   6. Value conservation (input == output)
//   7. Input value non-zero (context binding is via the public input)
//   8. AFP-KDC CREDENTIAL BINDING:
//        sk = H(DOMAIN_ZKA_SPENDING, master_seed)
//        holder_commitment == H(DOMAIN_ZKC_BINDING,
//                               H(DOMAIN_ZKC_CREDENTIAL, master_seed))
//      The shared private seed independently derives spending authority and
//      the credential identity in one proof.
//
// Public Inputs (5) -- order is normative (Section 5.3):
//   [0] nullifier          - Prevents double-spending
//   [1] output_commitment  - New note entering the system
//   [2] merkle_root        - State anchor
//   [3] context            - Replay protection (epoch/chain/app/session)
//   [4] holder_commitment  - Canonical ZKC holderCommitment for compliance
//                            binding (= zka_credential's credential_commitment)
//
// Relationship to Section 5.3 pseudocode and the implemented codebase
// -----------------------------------------------------------
// This is AFP-KDC v1.0.2 §A.6 exactly. `cbk` is a sibling of `sk`, not a
// descendant, so knowing a spending key cannot derive the credential anchor.
// The combined proof's `holder_commitment` remains byte-identical to the
// standalone credential proof and SDK/ZKC anchor. (asset_commitment is a
// PRIVATE input here: Section 5.3's public-input set is
// the 5 listed above; the asset type is not disclosed by the combined proof.)
// =============================================================================

use zka_lib::{
    compute_merkle_root, compute_note_commitment, compute_nullifier, derive_address,
    derive_credential_binding_key, derive_credential_commitment,
    derive_spending_key_from_master_seed, MERKLE_DEPTH,
};

fn main(
    // === Public Inputs ===
    nullifier: pub Field,
    output_commitment: pub Field,
    merkle_root: pub Field,
    context: pub Field,
    holder_commitment: pub Field,
    // === Private Inputs: Asset ===
    asset_commitment: Field,
    // === Private Inputs: Input Note ===
    input_value: Field,
    input_recipient: Field,
    input_randomness: Field,
    // === Private Inputs: Merkle Path ===
    merkle_siblings: [Field; 32],
    merkle_path_index: Field,
    // === Private Inputs: AFP-KDC master seed field ===
    master_seed: Field,
    // === Private Inputs: Output Note ===
    output_value: Field,
    output_recipient: Field,
    output_randomness: Field,
) {
    assert(output_randomness != 0, "Output randomness must be non-zero");
    assert(
        output_randomness != input_randomness,
        "Output randomness must not reuse input randomness",
    );
    // AFP-KDC v1.0.2 §A.6 spending path. The prover boundary is responsible
    // for reducing the 32-byte seed as one unsigned big-endian integer.
    let spending_key = derive_spending_key_from_master_seed(master_seed);

    // ------------------------------------------------------------------ TRANSFER
    // 1. INPUT NOTE COMMITMENT
    let input_commitment = compute_note_commitment(
        asset_commitment,
        input_value,
        input_recipient,
        input_randomness,
    );

    // 2. MERKLE MEMBERSHIP
    let computed_root = compute_merkle_root(input_commitment, merkle_path_index, merkle_siblings);
    assert(computed_root == merkle_root, "Merkle root mismatch: input note not in state tree");

    // 3. NULLIFIER CORRECTNESS
    let expected_nullifier = compute_nullifier(input_commitment, spending_key);
    assert(expected_nullifier == nullifier, "Nullifier mismatch");

    // 4. OWNERSHIP VERIFICATION
    let derived_address = derive_address(spending_key);
    assert(derived_address == input_recipient, "Ownership verification failed");

    // 5. OUTPUT NOTE COMMITMENT
    let expected_output = compute_note_commitment(
        asset_commitment,
        output_value,
        output_recipient,
        output_randomness,
    );
    assert(expected_output == output_commitment, "Output commitment mismatch");

    // 6. VALUE CONSERVATION
    assert(input_value == output_value, "Value conservation violated");

    // 7. INPUT VALUE NON-ZERO (context binding is via the public input below)
    assert(input_value != 0, "Input value must be non-zero");

    // ------------------------------------------------------------------- BINDING
    // 8. CREDENTIAL BINDING (Section 5.2 / Section 5.3)
    //
    // Derive the credential sibling from the SAME master seed that produced
    // the spending key above. The paths share only the private seed.
    let cbk = derive_credential_binding_key(master_seed);
    let expected_holder_commitment = derive_credential_commitment(cbk);
    assert(
        expected_holder_commitment == holder_commitment,
        "Credential binding mismatch: derived holderCommitment != public holder_commitment",
    );

    // 9. CONTEXT BINDING (Section 5.2 constraint 4)
    //
    // `context` is a PUBLIC INPUT, so the proof is cryptographically bound to
    // it (a proof for one context does not verify against another). The only
    // in-circuit constraint is non-zero, matching zka_transfer / zka_credential.
    assert(context != 0, "Context must be non-zero for replay protection");

    // Suppress the unused MERKLE_DEPTH import warning while keeping the
    // canonical depth visible at the call site (compute_merkle_root fixes 32).
    assert(MERKLE_DEPTH == 32, "MERKLE_DEPTH must be 32");
}

// =============================================================================
// Tests
// =============================================================================

/// AFP-KDC v1.0.2 holderCommitment from the seed sibling path.
fn holder_commitment_of(master_seed: Field) -> Field {
    let cbk = derive_credential_binding_key(master_seed);
    derive_credential_commitment(cbk)
}

#[test]
fn test_valid_transfer_binding() {
    let master_seed = 0x42;
    let spending_key = derive_spending_key_from_master_seed(master_seed);
    let recipient = derive_address(spending_key);
    let asset_commitment = zka_lib::compute_asset_commitment(0x01);
    let value: Field = 1000;
    let input_randomness = 0xaabb;
    let output_randomness = 0xccdd;
    let output_recipient = 0xdeadbeef;

    let input_commitment =
        compute_note_commitment(asset_commitment, value, recipient, input_randomness);
    let exp_output =
        compute_note_commitment(asset_commitment, value, output_recipient, output_randomness);
    let nf = compute_nullifier(input_commitment, spending_key);
    let hc = holder_commitment_of(master_seed);

    let siblings: [Field; 32] = [0; 32];
    let expected_root = compute_merkle_root(input_commitment, 0, siblings);

    main(
        nf,
        exp_output,
        expected_root,
        0x12345678,
        hc,
        asset_commitment,
        value,
        recipient,
        input_randomness,
        siblings,
        0,
        master_seed,
        value,
        output_recipient,
        output_randomness,
    );
}

#[test(should_fail_with = "Credential binding mismatch")]
fn test_wrong_credential_holder_fails() {
    // A valid transfer, but holder_commitment is derived from a DIFFERENT
    // spending key than the one authorizing the transfer => binding must fail.
    let master_seed = 0x42;
    let other_seed = 0x99;
    let spending_key = derive_spending_key_from_master_seed(master_seed);
    let recipient = derive_address(spending_key);
    let asset_commitment = zka_lib::compute_asset_commitment(0x01);
    let value: Field = 1000;

    let input_commitment = compute_note_commitment(asset_commitment, value, recipient, 0xaa);
    let exp_output = compute_note_commitment(asset_commitment, value, 0xcc, 0xbb);
    let nf = compute_nullifier(input_commitment, spending_key);
    // holderCommitment for the WRONG key.
    let wrong_hc = holder_commitment_of(other_seed);
    let siblings: [Field; 32] = [0; 32];
    let root = compute_merkle_root(input_commitment, 0, siblings);

    main(
        nf,
        exp_output,
        root,
        0x55,
        wrong_hc,
        asset_commitment,
        value,
        recipient,
        0xaa,
        siblings,
        0,
        master_seed,
        value,
        0xcc,
        0xbb,
    );
}

#[test(should_fail_with = "Value conservation violated")]
fn test_value_mismatch_fails() {
    let master_seed = 0x42;
    let spending_key = derive_spending_key_from_master_seed(master_seed);
    let recipient = derive_address(spending_key);
    let asset_commitment = zka_lib::compute_asset_commitment(0x01);

    let input_commitment = compute_note_commitment(asset_commitment, 1000, recipient, 0xaa);
    let exp_output = compute_note_commitment(asset_commitment, 500, 0xcc, 0xbb);
    let nf = compute_nullifier(input_commitment, spending_key);
    let hc = holder_commitment_of(master_seed);
    let siblings: [Field; 32] = [0; 32];
    let root = compute_merkle_root(input_commitment, 0, siblings);

    main(
        nf,
        exp_output,
        root,
        0x55,
        hc,
        asset_commitment,
        1000,
        recipient,
        0xaa,
        siblings,
        0,
        master_seed,
        500,
        0xcc,
        0xbb,
    );
}

#[test(should_fail_with = "Ownership verification failed")]
fn test_wrong_spending_key_fails() {
    let real_seed = 0x42;
    let wrong_seed = 0x99;
    let real_key = derive_spending_key_from_master_seed(real_seed);
    let wrong_key = derive_spending_key_from_master_seed(wrong_seed);
    let recipient = derive_address(real_key);
    let asset_commitment = zka_lib::compute_asset_commitment(0x01);

    let input_commitment = compute_note_commitment(asset_commitment, 500, recipient, 0xaa);
    let exp_output = compute_note_commitment(asset_commitment, 500, 0xcc, 0xbb);
    let nf = compute_nullifier(input_commitment, wrong_key);
    // holderCommitment computed for the wrong key so binding would pass; the
    // OWNERSHIP check (constraint 4) must fail first.
    let hc = holder_commitment_of(wrong_seed);
    let siblings: [Field; 32] = [0; 32];
    let root = compute_merkle_root(input_commitment, 0, siblings);

    main(
        nf,
        exp_output,
        root,
        0x55,
        hc,
        asset_commitment,
        500,
        recipient,
        0xaa,
        siblings,
        0,
        wrong_seed,
        500,
        0xcc,
        0xbb,
    );
}

#[test(should_fail_with = "Merkle root mismatch")]
fn test_wrong_merkle_root_fails() {
    let master_seed = 0x42;
    let spending_key = derive_spending_key_from_master_seed(master_seed);
    let recipient = derive_address(spending_key);
    let asset_commitment = zka_lib::compute_asset_commitment(0x01);

    let input_commitment = compute_note_commitment(asset_commitment, 1000, recipient, 0xaa);
    let exp_output = compute_note_commitment(asset_commitment, 1000, 0xcc, 0xbb);
    let nf = compute_nullifier(input_commitment, spending_key);
    let hc = holder_commitment_of(master_seed);
    let siblings: [Field; 32] = [0; 32];

    main(
        nf,
        exp_output,
        0xBAD000,
        0x55,
        hc,
        asset_commitment,
        1000,
        recipient,
        0xaa,
        siblings,
        0,
        master_seed,
        1000,
        0xcc,
        0xbb,
    );
}

#[test(should_fail_with = "Nullifier mismatch")]
fn test_wrong_nullifier_fails() {
    let master_seed = 0x42;
    let spending_key = derive_spending_key_from_master_seed(master_seed);
    let recipient = derive_address(spending_key);
    let asset_commitment = zka_lib::compute_asset_commitment(0x01);

    let input_commitment = compute_note_commitment(asset_commitment, 1000, recipient, 0xaa);
    let exp_output = compute_note_commitment(asset_commitment, 1000, 0xcc, 0xbb);
    let hc = holder_commitment_of(master_seed);
    let siblings: [Field; 32] = [0; 32];
    let root = compute_merkle_root(input_commitment, 0, siblings);

    main(
        0xBAD111,
        exp_output,
        root,
        0x55,
        hc,
        asset_commitment,
        1000,
        recipient,
        0xaa,
        siblings,
        0,
        master_seed,
        1000,
        0xcc,
        0xbb,
    );
}

#[test(should_fail_with = "Context must be non-zero")]
fn test_zero_context_fails() {
    let master_seed = 0x42;
    let spending_key = derive_spending_key_from_master_seed(master_seed);
    let recipient = derive_address(spending_key);
    let asset_commitment = zka_lib::compute_asset_commitment(0x01);
    let value: Field = 1000;

    let input_commitment = compute_note_commitment(asset_commitment, value, recipient, 0xaa);
    let exp_output = compute_note_commitment(asset_commitment, value, 0xcc, 0xbb);
    let nf = compute_nullifier(input_commitment, spending_key);
    let hc = holder_commitment_of(master_seed);
    let siblings: [Field; 32] = [0; 32];
    let root = compute_merkle_root(input_commitment, 0, siblings);

    main(
        nf,
        exp_output,
        root,
        0, // zero context
        hc,
        asset_commitment,
        value,
        recipient,
        0xaa,
        siblings,
        0,
        master_seed,
        value,
        0xcc,
        0xbb,
    );
}

#[test]
fn test_holder_commitment_matches_credential_circuit_derivation() {
    // The combined circuit's holderCommitment derivation MUST equal the
    // standalone credential commitment derivation (zka_credential), so a
    // bundle's binding.holderCommitment lines up across legs.
    let master_seed = 0x1234;
    let cbk = derive_credential_binding_key(master_seed);
    let cc = derive_credential_commitment(cbk);
    assert(holder_commitment_of(master_seed) == cc, "holderCommitment derivation drift");
}
