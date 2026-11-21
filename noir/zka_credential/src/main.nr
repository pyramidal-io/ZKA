// ZKA note/credential identity binding (ZKA specification section 5.2).
//
// This circuit proves only the conjunction owned by ZKA: one private master
// seed controls both a committed ZKA note and a ZKC holder anchor. Credential
// issuance, predicates, selective disclosure, and revocation remain in ZKC.

use zka_lib::{
    compute_merkle_root, compute_note_commitment, derive_address,
    derive_spending_key_from_master_seed, derive_zkc_holder_commitment,
    derive_zkc_v04_credential_binding_key,
};

fn main(
    // Normative public statement, in declaration order.
    note_commitment: pub Field,
    holder_commitment: pub Field,
    merkle_root: pub Field,
    context: pub Field,
    // Private KDC root and note opening.
    master_seed: Field,
    asset_commitment: Field,
    note_value: Field,
    note_recipient: Field,
    note_randomness: Field,
    // Private depth-32 membership witness.
    merkle_siblings: [Field; 32],
    merkle_path_index: Field,
) {
    let spending_key = derive_spending_key_from_master_seed(master_seed);
    let expected_recipient = derive_address(spending_key);
    assert(note_recipient == expected_recipient, "note recipient is not owned by master seed");

    let expected_note = compute_note_commitment(
        asset_commitment,
        note_value,
        note_recipient,
        note_randomness,
    );
    assert(expected_note == note_commitment, "note commitment mismatch");

    let expected_root = compute_merkle_root(note_commitment, merkle_path_index, merkle_siblings);
    assert(expected_root == merkle_root, "note is not a member of the committed tree");

    let cbk = derive_zkc_v04_credential_binding_key(master_seed);
    let expected_holder = derive_zkc_holder_commitment(cbk);
    assert(expected_holder == holder_commitment, "holder commitment mismatch");

    assert(context != 0, "context must be non-zero");
}

fn valid_inputs() -> (Field, Field, Field, Field, Field, Field, Field, [Field; 32]) {
    let master_seed: Field = 42;
    let asset_commitment: Field = 7;
    let note_value: Field = 1000;
    let note_randomness: Field = 0xaaaa;
    let spending_key = derive_spending_key_from_master_seed(master_seed);
    let note_recipient = derive_address(spending_key);
    let note_commitment = compute_note_commitment(
        asset_commitment,
        note_value,
        note_recipient,
        note_randomness,
    );
    let siblings: [Field; 32] = [0; 32];
    let cbk = derive_zkc_v04_credential_binding_key(master_seed);
    let holder_commitment = derive_zkc_holder_commitment(cbk);
    (
        master_seed, asset_commitment, note_value, note_recipient, note_randomness, note_commitment,
        holder_commitment, siblings,
    )
}

#[test]
fn valid_identity_binding() {
    let (master_seed, asset_commitment, note_value, note_recipient, note_randomness, note_commitment, holder_commitment, siblings) =
        valid_inputs();
    let merkle_root = compute_merkle_root(note_commitment, 0, siblings);
    main(
        note_commitment,
        holder_commitment,
        merkle_root,
        0x1234,
        master_seed,
        asset_commitment,
        note_value,
        note_recipient,
        note_randomness,
        siblings,
        0,
    );
}

#[test]
fn valid_identity_binding_with_asymmetric_nonzero_path() {
    let (master_seed, asset_commitment, note_value, note_recipient, note_randomness, note_commitment, holder_commitment, _) =
        valid_inputs();
    let mut siblings: [Field; 32] = [0; 32];
    siblings[0] = 11;
    siblings[1] = 23;
    siblings[7] = 37;
    siblings[31] = 47;
    // Index 5 exercises both left- and right-child branches in the path.
    let merkle_root = compute_merkle_root(note_commitment, 5, siblings);
    main(
        note_commitment,
        holder_commitment,
        merkle_root,
        0x1234,
        master_seed,
        asset_commitment,
        note_value,
        note_recipient,
        note_randomness,
        siblings,
        5,
    );
}

#[test(should_fail_with = "note recipient is not owned by master seed")]
fn wrong_seed_fails() {
    let (_, asset, value, recipient, randomness, note, holder, siblings) = valid_inputs();
    let root = compute_merkle_root(note, 0, siblings);
    main(
        note,
        holder,
        root,
        1,
        99,
        asset,
        value,
        recipient,
        randomness,
        siblings,
        0,
    );
}

#[test(should_fail_with = "note commitment mismatch")]
fn wrong_note_opening_fails() {
    let (seed, asset, value, recipient, randomness, note, holder, siblings) = valid_inputs();
    let root = compute_merkle_root(note, 0, siblings);
    main(
        note,
        holder,
        root,
        1,
        seed,
        asset,
        value + 1,
        recipient,
        randomness,
        siblings,
        0,
    );
}

#[test(should_fail_with = "note is not a member of the committed tree")]
fn wrong_merkle_path_fails() {
    let (seed, asset, value, recipient, randomness, note, holder, siblings) = valid_inputs();
    let root = compute_merkle_root(note, 0, siblings);
    let mut wrong_siblings = siblings;
    wrong_siblings[0] = 1;
    main(
        note,
        holder,
        root,
        1,
        seed,
        asset,
        value,
        recipient,
        randomness,
        wrong_siblings,
        0,
    );
}

#[test(should_fail_with = "holder commitment mismatch")]
fn wrong_holder_commitment_fails() {
    let (seed, asset, value, recipient, randomness, note, holder, siblings) = valid_inputs();
    let root = compute_merkle_root(note, 0, siblings);
    main(
        note,
        holder + 1,
        root,
        1,
        seed,
        asset,
        value,
        recipient,
        randomness,
        siblings,
        0,
    );
}

#[test(should_fail_with = "context must be non-zero")]
fn zero_context_fails() {
    let (seed, asset, value, recipient, randomness, note, holder, siblings) = valid_inputs();
    let root = compute_merkle_root(note, 0, siblings);
    main(
        note,
        holder,
        root,
        0,
        seed,
        asset,
        value,
        recipient,
        randomness,
        siblings,
        0,
    );
}
