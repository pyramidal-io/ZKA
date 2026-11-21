// =============================================================================
// ZKA Transfer Circuit (Noir / BN254)
//
// Spec Reference: ZKA specification §3.1
//
// Proves a private single-asset transfer with 7 constraints:
//   1. Input note commitment validity
//   2. Merkle membership of input note
//   3. Nullifier correctness (double-spend prevention)
//   4. Ownership verification (spending key -> address)
//   5. Output note commitment validity
//   6. Value conservation (input == output) in the u64 balance domain
//   7. Context binding: a non-zero public context whose expected value the
//      verifier derives from its own authenticated state (§3.1 constraint 7)
//
// Asset conservation is implicit: the same asset_commitment (public input)
// is used in both input and output commitment computations.
//
// Public Inputs (5):
//   [0] nullifier          - Prevents double-spending
//   [1] output_commitment  - New note entering the system
//   [2] merkle_root        - State anchor
//   [3] context            - Replay protection, supplied by the verifier
//   [4] asset_commitment   - Identifies asset type
// =============================================================================

use zka_lib::{
    assert_fits_u64, compute_merkle_root, compute_note_commitment, compute_nullifier,
    derive_address,
};

fn main(
    // === Public Inputs ===
    nullifier: pub Field,
    output_commitment: pub Field,
    merkle_root: pub Field,
    context: pub Field,
    asset_commitment: pub Field,
    // === Private Inputs: Input Note ===
    input_value: Field,
    input_recipient: Field,
    input_randomness: Field,
    // === Private Inputs: Merkle Path ===
    merkle_siblings: [Field; 32],
    merkle_path_index: Field,
    // === Private Inputs: Spending Key ===
    spending_key: Field,
    // === Private Inputs: Output Note ===
    output_value: Field,
    output_recipient: Field,
    output_randomness: Field,
) {
    // §2.3: note values live in the u64 balance domain.
    assert_fits_u64(input_value);
    assert_fits_u64(output_value);
    assert(output_randomness != 0, "Output randomness must be non-zero");
    assert(
        output_randomness != input_randomness,
        "Output randomness must not reuse input randomness",
    );
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
    assert(input_value != 0, "Input value must be non-zero");

    // 7. CONTEXT BINDING
    // The deployment profile defines the context derivation; the verifier
    // supplies the expected value and never takes it from transaction data.
    assert(context != 0, "Context must be non-zero for replay protection");
}

// =============================================================================
// Tests
// =============================================================================

global TEST_CONTEXT: Field = 0x0f41a62ef72b7a3d01f5d2c40b47e2fe49aba08981dd4ba261163f8e5e13f6c9;

fn transfer_with(
    context: Field,
    input_value: Field,
    output_value: Field,
    output_randomness: Field,
) {
    let spending_key = 0x42;
    let recipient = derive_address(spending_key);
    let asset_commitment = zka_lib::compute_asset_commitment(0x01);
    let input_randomness = 0xaabb;
    let output_recipient = 0xdeadbeef;
    let input_commitment =
        compute_note_commitment(asset_commitment, input_value, recipient, input_randomness);
    let siblings: [Field; 32] = [0; 32];
    main(
        compute_nullifier(input_commitment, spending_key),
        compute_note_commitment(
            asset_commitment,
            output_value,
            output_recipient,
            output_randomness,
        ),
        compute_merkle_root(input_commitment, 0, siblings),
        context,
        asset_commitment,
        input_value,
        recipient,
        input_randomness,
        siblings,
        0,
        spending_key,
        output_value,
        output_recipient,
        output_randomness,
    );
}

#[test]
fn test_valid_transfer() {
    transfer_with(TEST_CONTEXT, 1000, 1000, 0xccdd);
}

#[test]
fn test_maximum_u64_value_transfers() {
    transfer_with(TEST_CONTEXT, 0xffffffffffffffff, 0xffffffffffffffff, 0xccdd);
}

#[test(should_fail_with = "call to assert_max_bit_size")]
fn test_value_above_u64_domain_fails() {
    transfer_with(
        TEST_CONTEXT,
        0x10000000000000000,
        0x10000000000000000,
        0xccdd,
    );
}

#[test(should_fail_with = "call to assert_max_bit_size")]
fn test_field_wrapped_value_fails() {
    // p - 1 is congruent to -1: a wrapped "negative" balance must not pass.
    let wrapped: Field = 0 - 1;
    transfer_with(TEST_CONTEXT, wrapped, wrapped, 0xccdd);
}

#[test(should_fail_with = "Context must be non-zero for replay protection")]
fn test_zero_context_fails() {
    transfer_with(0, 1000, 1000, 0xccdd);
}

#[test(should_fail_with = "Input value must be non-zero")]
fn test_zero_value_fails() {
    transfer_with(TEST_CONTEXT, 0, 0, 0xccdd);
}

#[test(should_fail_with = "Output randomness must be non-zero")]
fn zero_output_randomness_fails() {
    transfer_with(TEST_CONTEXT, 1000, 1000, 0);
}

#[test(should_fail_with = "Output randomness must not reuse input randomness")]
fn reused_output_randomness_fails() {
    transfer_with(TEST_CONTEXT, 1000, 1000, 0xaabb);
}

#[test(should_fail_with = "Value conservation violated")]
fn test_value_mismatch_fails() {
    let spending_key = 0x42;
    let recipient = derive_address(spending_key);
    let asset_commitment = zka_lib::compute_asset_commitment(0x01);

    let input_commitment = compute_note_commitment(asset_commitment, 1000, recipient, 0xaa);
    let exp_output = compute_note_commitment(asset_commitment, 500, 0xcc, 0xbb);
    let nf = compute_nullifier(input_commitment, spending_key);
    let siblings: [Field; 32] = [0; 32];
    let root = compute_merkle_root(input_commitment, 0, siblings);

    main(
        nf,
        exp_output,
        root,
        TEST_CONTEXT,
        asset_commitment,
        1000,
        recipient,
        0xaa,
        siblings,
        0,
        spending_key,
        500,
        0xcc,
        0xbb,
    );
}

#[test(should_fail_with = "Ownership verification failed")]
fn test_wrong_spending_key_fails() {
    let real_key = 0x42;
    let wrong_key = 0x99;
    let recipient = derive_address(real_key);
    let asset_commitment = zka_lib::compute_asset_commitment(0x01);

    let input_commitment = compute_note_commitment(asset_commitment, 500, recipient, 0xaa);
    let exp_output = compute_note_commitment(asset_commitment, 500, 0xcc, 0xbb);
    let nf = compute_nullifier(input_commitment, wrong_key);
    let siblings: [Field; 32] = [0; 32];
    let root = compute_merkle_root(input_commitment, 0, siblings);

    main(
        nf,
        exp_output,
        root,
        TEST_CONTEXT,
        asset_commitment,
        500,
        recipient,
        0xaa,
        siblings,
        0,
        wrong_key,
        500,
        0xcc,
        0xbb,
    );
}

#[test(should_fail_with = "Merkle root mismatch")]
fn test_wrong_merkle_root_fails() {
    let spending_key = 0x42;
    let recipient = derive_address(spending_key);
    let asset_commitment = zka_lib::compute_asset_commitment(0x01);

    let input_commitment = compute_note_commitment(asset_commitment, 1000, recipient, 0xaa);
    let exp_output = compute_note_commitment(asset_commitment, 1000, 0xcc, 0xbb);
    let nf = compute_nullifier(input_commitment, spending_key);
    let siblings: [Field; 32] = [0; 32];

    main(
        nf,
        exp_output,
        0xBAD000,
        TEST_CONTEXT,
        asset_commitment,
        1000,
        recipient,
        0xaa,
        siblings,
        0,
        spending_key,
        1000,
        0xcc,
        0xbb,
    );
}

#[test(should_fail_with = "Nullifier mismatch")]
fn test_wrong_nullifier_fails() {
    let spending_key = 0x42;
    let recipient = derive_address(spending_key);
    let asset_commitment = zka_lib::compute_asset_commitment(0x01);

    let input_commitment = compute_note_commitment(asset_commitment, 1000, recipient, 0xaa);
    let exp_output = compute_note_commitment(asset_commitment, 1000, 0xcc, 0xbb);
    let siblings: [Field; 32] = [0; 32];
    let root = compute_merkle_root(input_commitment, 0, siblings);

    main(
        0xBAD111,
        exp_output,
        root,
        TEST_CONTEXT,
        asset_commitment,
        1000,
        recipient,
        0xaa,
        siblings,
        0,
        spending_key,
        1000,
        0xcc,
        0xbb,
    );
}
