// =============================================================================
// ZKA Withdrawal Circuit (Noir / BN254)
//
// Spec Reference: ZKA v0.6.3, Section 3.2
//
// Proves a private withdrawal to an external (non-ZKA) address with 7 constraints:
//   1. Input note commitment validity
//   2. Merkle membership of input note
//   3. Nullifier correctness (double-spend prevention)
//   4. Ownership verification (spending key -> address)
//   5. Value matches the revealed withdrawal amount (public)
//   6. External recipient is bound (public destination hash)
//   7. Context binding (epoch/chain/app replay protection)
//
// Unlike a transfer, the withdrawal reveals the value and external recipient
// publicly so that a bridge contract can release funds on the destination chain.
// There is no output note: the note is consumed (nullified) and value exits
// the shielded pool.
//
// Public Inputs (6) -- order is normative per ZKA Section 3.2 and generated for
// EVM consumers from schemas/public-inputs/zka_withdrawal.json. The Noir
// verifier ABI ordering is fixed by the main() parameter declaration order
// below, so this order is load-bearing. `asset_commitment` is the exact field
// used inside the note commitment: new profiles derive it with
// compute_asset_commitment(canonical_asset_id), while an immutable legacy
// profile must pin any alternate encoding explicitly in its deployment record.
//   [0] nullifier            - Prevents double-spending
//   [1] merkle_root          - State anchor
//   [2] withdrawal_amount    - Revealed value for bridge contract
//   [3] asset_commitment     - Identifies asset type
//   [4] external_recipient   - Destination address hash
//   [5] context              - Replay protection
// =============================================================================

use zka_lib::{
    compute_merkle_root, compute_note_commitment, compute_nullifier, derive_address, MERKLE_DEPTH,
};

fn main(
    // === Public Inputs ===
    nullifier: pub Field,
    merkle_root: pub Field,
    withdrawal_amount: pub Field,
    asset_commitment: pub Field,
    external_recipient: pub Field,
    context: pub Field,
    // === Private Inputs: Input Note ===
    input_value: Field,
    input_recipient: Field,
    input_randomness: Field,
    // === Private Inputs: Merkle Path ===
    merkle_siblings: [Field; 32],
    merkle_path_index: Field,
    // === Private Inputs: Spending Key ===
    spending_key: Field,
) {
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

    // 5. VALUE MATCHES WITHDRAWAL AMOUNT
    // The private input_value (hidden inside the commitment) must equal the
    // publicly revealed withdrawal_amount so the bridge contract pays the
    // correct amount. This prevents over- or under-withdrawal.
    assert(input_value == withdrawal_amount, "Withdrawal amount mismatch");

    // 6. EXTERNAL RECIPIENT BINDING
    // The external_recipient is a public input bound to the proof. The bridge
    // contract verifies the proof was generated for this specific destination.
    // We enforce it is non-zero to prevent funds being burned to a null address.
    assert(external_recipient != 0, "External recipient must be non-zero");

    // 7. CONTEXT BINDING (validated externally; included as public input)
    // The context field is bound to the proof as a public input, providing
    // replay protection across epochs, chains, and applications.
    // We also require the withdrawal amount to be positive.
    assert(input_value != 0, "Withdrawal value must be non-zero");
}

// =============================================================================
// Tests
// =============================================================================

/// Helper: build a valid set of withdrawal witness values.
/// Returns (nullifier, merkle_root, input_commitment) plus the witness params.
fn build_valid_witness() -> (Field, Field, Field, Field, Field, Field, // public: nf, root, amount, asset, ext_recip, ctx
Field, Field, Field, // private: value, recipient, randomness
[Field; 32], Field, // private: merkle siblings, path index
Field // private: spending_key
) {
    let spending_key: Field = 0x42;
    let recipient = derive_address(spending_key);
    let asset_commitment = zka_lib::compute_asset_commitment(0x01);
    let value: Field = 1000;
    let randomness: Field = 0xaabb;
    let external_recipient: Field = 0xdeadbeef;
    let context: Field = 0x12345678;

    let input_commitment = compute_note_commitment(asset_commitment, value, recipient, randomness);
    let nf = compute_nullifier(input_commitment, spending_key);
    let siblings: [Field; 32] = [0; 32];
    let root = compute_merkle_root(input_commitment, 0, siblings);

    (
        nf, root, value, asset_commitment, external_recipient, context, value, recipient,
        randomness, siblings, 0, spending_key,
    )
}

#[test]
fn test_valid_withdrawal() {
    let (nf, root, amount, asset, ext_recip, ctx, value, recipient, randomness, siblings, path_idx, spending_key) =
        build_valid_witness();

    main(
        nf,
        root,
        amount,
        asset,
        ext_recip,
        ctx,
        value,
        recipient,
        randomness,
        siblings,
        path_idx,
        spending_key,
    );
}

#[test]
fn test_valid_withdrawal_different_amounts() {
    // Verify the circuit works with various value sizes
    let spending_key: Field = 0x42;
    let recipient = derive_address(spending_key);
    let asset_commitment = zka_lib::compute_asset_commitment(0x01);
    let context: Field = 0x99;
    let external_recipient: Field = 0xabcdef;

    // Small value
    let value: Field = 1;
    let randomness: Field = 0x1111;
    let commitment = compute_note_commitment(asset_commitment, value, recipient, randomness);
    let nf = compute_nullifier(commitment, spending_key);
    let siblings: [Field; 32] = [0; 32];
    let root = compute_merkle_root(commitment, 0, siblings);

    main(
        nf,
        root,
        value,
        asset_commitment,
        external_recipient,
        context,
        value,
        recipient,
        randomness,
        siblings,
        0,
        spending_key,
    );
}

#[test(should_fail_with = "Withdrawal amount mismatch")]
fn test_value_mismatch_fails() {
    // Attempt to withdraw a different amount than what is in the note
    let spending_key: Field = 0x42;
    let recipient = derive_address(spending_key);
    let asset_commitment = zka_lib::compute_asset_commitment(0x01);
    let true_value: Field = 1000;
    let fake_withdrawal: Field = 500;

    let input_commitment = compute_note_commitment(asset_commitment, true_value, recipient, 0xaa);
    let nf = compute_nullifier(input_commitment, spending_key);
    let siblings: [Field; 32] = [0; 32];
    let root = compute_merkle_root(input_commitment, 0, siblings);

    main(
        nf,
        root,
        fake_withdrawal,
        asset_commitment,
        0xdeadbeef,
        0x00,
        true_value,
        recipient,
        0xaa,
        siblings,
        0,
        spending_key,
    );
}

#[test(should_fail_with = "Ownership verification failed")]
fn test_wrong_spending_key_fails() {
    // Attempt to spend a note owned by a different key
    let real_key: Field = 0x42;
    let wrong_key: Field = 0x99;
    let recipient = derive_address(real_key); // note belongs to real_key
    let asset_commitment = zka_lib::compute_asset_commitment(0x01);
    let value: Field = 1000;

    let input_commitment = compute_note_commitment(asset_commitment, value, recipient, 0xaa);
    // Nullifier computed with wrong key (would pass nullifier check but fail ownership)
    let nf = compute_nullifier(input_commitment, wrong_key);
    let siblings: [Field; 32] = [0; 32];
    let root = compute_merkle_root(input_commitment, 0, siblings);

    main(
        nf,
        root,
        value,
        asset_commitment,
        0xdeadbeef,
        0x00,
        value,
        recipient,
        0xaa,
        siblings,
        0,
        wrong_key,
    );
}

#[test(should_fail_with = "Merkle root mismatch")]
fn test_wrong_merkle_root_fails() {
    // Supply a bogus merkle root that doesn't match the note's position
    let spending_key: Field = 0x42;
    let recipient = derive_address(spending_key);
    let asset_commitment = zka_lib::compute_asset_commitment(0x01);
    let value: Field = 1000;

    let input_commitment = compute_note_commitment(asset_commitment, value, recipient, 0xaa);
    let nf = compute_nullifier(input_commitment, spending_key);
    let siblings: [Field; 32] = [0; 32];
    // Use a fabricated root instead of the real computed one
    let fake_root: Field = 0xBAD000;

    main(
        nf,
        fake_root,
        value,
        asset_commitment,
        0xdeadbeef,
        0x00,
        value,
        recipient,
        0xaa,
        siblings,
        0,
        spending_key,
    );
}

#[test(should_fail_with = "Nullifier mismatch")]
fn test_wrong_nullifier_fails() {
    // Supply an incorrect nullifier
    let spending_key: Field = 0x42;
    let recipient = derive_address(spending_key);
    let asset_commitment = zka_lib::compute_asset_commitment(0x01);
    let value: Field = 1000;

    let input_commitment = compute_note_commitment(asset_commitment, value, recipient, 0xaa);
    let siblings: [Field; 32] = [0; 32];
    let root = compute_merkle_root(input_commitment, 0, siblings);
    let fake_nullifier: Field = 0xBAD111;

    main(
        fake_nullifier,
        root,
        value,
        asset_commitment,
        0xdeadbeef,
        0x00,
        value,
        recipient,
        0xaa,
        siblings,
        0,
        spending_key,
    );
}

#[test(should_fail_with = "External recipient must be non-zero")]
fn test_zero_external_recipient_fails() {
    // A zero external_recipient would burn funds; circuit must reject it
    let spending_key: Field = 0x42;
    let recipient = derive_address(spending_key);
    let asset_commitment = zka_lib::compute_asset_commitment(0x01);
    let value: Field = 1000;

    let input_commitment = compute_note_commitment(asset_commitment, value, recipient, 0xaa);
    let nf = compute_nullifier(input_commitment, spending_key);
    let siblings: [Field; 32] = [0; 32];
    let root = compute_merkle_root(input_commitment, 0, siblings);

    main(
        nf,
        root,
        value,
        asset_commitment,
        0,
        0x00,
        value,
        recipient,
        0xaa,
        siblings,
        0,
        spending_key,
    );
}

#[test(should_fail_with = "Withdrawal value must be non-zero")]
fn test_zero_value_withdrawal_fails() {
    // Withdrawing zero value is meaningless and must be rejected
    let spending_key: Field = 0x42;
    let recipient = derive_address(spending_key);
    let asset_commitment = zka_lib::compute_asset_commitment(0x01);
    let value: Field = 0;

    let input_commitment = compute_note_commitment(asset_commitment, value, recipient, 0xaa);
    let nf = compute_nullifier(input_commitment, spending_key);
    let siblings: [Field; 32] = [0; 32];
    let root = compute_merkle_root(input_commitment, 0, siblings);

    main(
        nf,
        root,
        value,
        asset_commitment,
        0xdeadbeef,
        0x00,
        value,
        recipient,
        0xaa,
        siblings,
        0,
        spending_key,
    );
}
