use zka_lib::{
    compute_asset_commitment, compute_merkle_root, compute_note_commitment, compute_nullifier,
    derive_address, derive_presentation_pseudonym, derive_spending_key_from_master_seed,
    derive_zkc_v04_credential_binding_key,
};

/// Prove that a payment subject is the same ZKC v0.4 scoped presentation
/// subject without exposing the stable holderCommitment.
fn assert_payment_subject_binding(
    master_seed: Field,
    scope_id: Field,
    presentation_pseudonym: Field,
) {
    assert(scope_id != 0, "payment binding requires a scoped ZKC v2 presentation");
    let cbk = derive_zkc_v04_credential_binding_key(master_seed);
    assert(
        derive_presentation_pseudonym(cbk, scope_id) == presentation_pseudonym,
        "payment subject does not match ZKC presentation",
    );
}

fn main(
    // Public transfer inputs.
    nullifier: pub Field,
    output_commitment: pub Field,
    merkle_root: pub Field,
    context: pub Field,
    // Public ZKC v0.4 scoped-presentation inputs.
    presentation_pseudonym: pub Field,
    scope_id: pub Field,
    // Private asset/input note.
    asset_commitment: Field,
    input_value: Field,
    input_recipient: Field,
    input_randomness: Field,
    merkle_siblings: [Field; 32],
    merkle_path_index: Field,
    // The common principal secret. The spending key and v0.4 cbk are both
    // derived in-circuit, so the note owner and credential subject cannot
    // diverge without making the witness unsatisfiable.
    master_seed: Field,
    // Private output note.
    output_value: Field,
    output_recipient: Field,
    output_randomness: Field,
) {
    assert(output_randomness != 0, "Output randomness must be non-zero");
    assert(
        output_randomness != input_randomness,
        "Output randomness must not reuse input randomness",
    );
    let spending_key = derive_spending_key_from_master_seed(master_seed);
    let input_commitment = compute_note_commitment(
        asset_commitment,
        input_value,
        input_recipient,
        input_randomness,
    );
    let computed_root = compute_merkle_root(input_commitment, merkle_path_index, merkle_siblings);
    assert(computed_root == merkle_root, "Merkle root mismatch: input note not in state tree");
    assert(compute_nullifier(input_commitment, spending_key) == nullifier, "Nullifier mismatch");
    assert(derive_address(spending_key) == input_recipient, "Ownership verification failed");

    let expected_output = compute_note_commitment(
        asset_commitment,
        output_value,
        output_recipient,
        output_randomness,
    );
    assert(expected_output == output_commitment, "Output commitment mismatch");
    assert(input_value == output_value, "Value conservation violated");
    assert(input_value != 0, "Input value must be non-zero");
    assert(context != 0, "Context must be non-zero for replay protection");

    assert_payment_subject_binding(master_seed, scope_id, presentation_pseudonym);
}

#[test]
fn valid_scoped_subject_binding_matches_zkc_v04() {
    let master_seed: Field = 42;
    let scope_id: Field = 0x2632aaf1e51423d6eab07aa448f245c91490f34a5b3e6744e47f584fab96c4d5;
    let cbk = derive_zkc_v04_credential_binding_key(master_seed);
    let pseudonym = derive_presentation_pseudonym(cbk, scope_id);

    assert_payment_subject_binding(master_seed, scope_id, pseudonym);
}

#[test(should_fail_with = "payment binding requires a scoped ZKC v2 presentation")]
fn anonymous_payment_binding_is_rejected() {
    assert_payment_subject_binding(42, 0, 0);
}

#[test(should_fail_with = "payment subject does not match ZKC presentation")]
fn mismatched_note_and_credential_subject_is_rejected() {
    let other_cbk = derive_zkc_v04_credential_binding_key(99);
    let other_pseudonym = derive_presentation_pseudonym(other_cbk, 7);
    assert_payment_subject_binding(42, 7, other_pseudonym);
}

#[test]
fn valid_payment_proves_note_owner_controls_scoped_credential() {
    let master_seed: Field = 42;
    let spending_key = derive_spending_key_from_master_seed(master_seed);
    let recipient = derive_address(spending_key);
    let asset = compute_asset_commitment(1);
    let value: Field = 1000;
    let input_commitment = compute_note_commitment(asset, value, recipient, 0xaa);
    let siblings: [Field; 32] = [0; 32];
    let root = compute_merkle_root(input_commitment, 0, siblings);
    let nullifier = compute_nullifier(input_commitment, spending_key);
    let output = compute_note_commitment(asset, value, 0xbeef, 0xbb);
    let scope_id: Field = 7;
    let cbk = derive_zkc_v04_credential_binding_key(master_seed);
    let pseudonym = derive_presentation_pseudonym(cbk, scope_id);

    main(
        nullifier,
        output,
        root,
        0x1234,
        pseudonym,
        scope_id,
        asset,
        value,
        recipient,
        0xaa,
        siblings,
        0,
        master_seed,
        value,
        0xbeef,
        0xbb,
    );
}

#[test(should_fail_with = "payment subject does not match ZKC presentation")]
fn payment_rejects_credential_subject_from_another_master_seed() {
    let master_seed: Field = 42;
    let spending_key = derive_spending_key_from_master_seed(master_seed);
    let recipient = derive_address(spending_key);
    let asset = compute_asset_commitment(1);
    let value: Field = 1000;
    let input_commitment = compute_note_commitment(asset, value, recipient, 0xaa);
    let siblings: [Field; 32] = [0; 32];
    let root = compute_merkle_root(input_commitment, 0, siblings);
    let nullifier = compute_nullifier(input_commitment, spending_key);
    let output = compute_note_commitment(asset, value, 0xbeef, 0xbb);
    let scope_id: Field = 7;
    let wrong_cbk = derive_zkc_v04_credential_binding_key(99);
    let wrong_pseudonym = derive_presentation_pseudonym(wrong_cbk, scope_id);

    main(
        nullifier,
        output,
        root,
        0x1234,
        wrong_pseudonym,
        scope_id,
        asset,
        value,
        recipient,
        0xaa,
        siblings,
        0,
        master_seed,
        value,
        0xbeef,
        0xbb,
    );
}
