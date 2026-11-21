use zka_lib::compute_note_commitment;

global MAX_NOTE_VALUE_WEI: u128 = 0xffffffffffffffffffffffffffffff;

fn main(
    note_commitment: pub Field,
    amount: pub u128,
    asset_commitment: pub Field,
    pool_context: pub Field,
    recipient: Field,
    randomness: Field,
) {
    assert(amount > 0, "deposit amount must be non-zero");
    assert(amount <= MAX_NOTE_VALUE_WEI, "deposit amount exceeds launch bound");
    assert(pool_context != 0, "pool context must be non-zero");
    assert(randomness != 0, "deposit randomness must be non-zero");

    let expected =
        compute_note_commitment(asset_commitment, amount as Field, recipient, randomness);
    assert(expected == note_commitment, "deposit commitment mismatch");
}

#[test]
fn test_valid_deposit() {
    let amount: u128 = 1000;
    let asset_commitment: Field = 0x1234;
    let pool_context: Field = 0x5678;
    let recipient: Field = 0x9abc;
    let randomness: Field = 0xdef0;
    let note_commitment =
        compute_note_commitment(asset_commitment, amount as Field, recipient, randomness);

    main(
        note_commitment,
        amount,
        asset_commitment,
        pool_context,
        recipient,
        randomness,
    );
}

#[test(should_fail_with = "deposit randomness must be non-zero")]
fn test_zero_randomness_fails() {
    let amount: u128 = 1000;
    let asset_commitment: Field = 0x1234;
    let pool_context: Field = 0x5678;
    let recipient: Field = 0x9abc;
    let randomness: Field = 0;
    let note_commitment =
        compute_note_commitment(asset_commitment, amount as Field, recipient, randomness);

    main(
        note_commitment,
        amount,
        asset_commitment,
        pool_context,
        recipient,
        randomness,
    );
}

#[test(should_fail_with = "deposit commitment mismatch")]
fn test_wrong_amount_fails() {
    let committed_amount: u128 = 1000;
    let public_amount: u128 = 999;
    let asset_commitment: Field = 0x1234;
    let recipient: Field = 0x9abc;
    let randomness: Field = 0xdef0;
    let note_commitment = compute_note_commitment(
        asset_commitment,
        committed_amount as Field,
        recipient,
        randomness,
    );

    main(
        note_commitment,
        public_amount,
        asset_commitment,
        0x5678,
        recipient,
        randomness,
    );
}

#[test(should_fail_with = "deposit commitment mismatch")]
fn test_wrong_asset_fails() {
    let amount: u128 = 1000;
    let committed_asset: Field = 0x1234;
    let public_asset: Field = 0x1235;
    let recipient: Field = 0x9abc;
    let randomness: Field = 0xdef0;
    let note_commitment =
        compute_note_commitment(committed_asset, amount as Field, recipient, randomness);

    main(
        note_commitment,
        amount,
        public_asset,
        0x5678,
        recipient,
        randomness,
    );
}

#[test(should_fail_with = "deposit commitment mismatch")]
fn test_wrong_commitment_fails() {
    let amount: u128 = 1000;
    let asset_commitment: Field = 0x1234;
    let recipient: Field = 0x9abc;
    let randomness: Field = 0xdef0;
    let note_commitment =
        compute_note_commitment(asset_commitment, amount as Field, recipient, randomness);

    main(
        note_commitment + 1,
        amount,
        asset_commitment,
        0x5678,
        recipient,
        randomness,
    );
}

#[test(should_fail_with = "deposit amount must be non-zero")]
fn test_zero_amount_fails() {
    let amount: u128 = 0;
    let asset_commitment: Field = 0x1234;
    let recipient: Field = 0x9abc;
    let randomness: Field = 0xdef0;
    let note_commitment =
        compute_note_commitment(asset_commitment, amount as Field, recipient, randomness);

    main(
        note_commitment,
        amount,
        asset_commitment,
        0x5678,
        recipient,
        randomness,
    );
}

#[test(should_fail_with = "deposit amount exceeds launch bound")]
fn test_amount_above_max_fails() {
    let amount: u128 = 0x1000000000000000000000000000000;
    let asset_commitment: Field = 0x1234;
    let recipient: Field = 0x9abc;
    let randomness: Field = 0xdef0;
    let note_commitment =
        compute_note_commitment(asset_commitment, amount as Field, recipient, randomness);

    main(
        note_commitment,
        amount,
        asset_commitment,
        0x5678,
        recipient,
        randomness,
    );
}

#[test(should_fail_with = "pool context must be non-zero")]
fn test_zero_context_fails() {
    let amount: u128 = 1000;
    let asset_commitment: Field = 0x1234;
    let recipient: Field = 0x9abc;
    let randomness: Field = 0xdef0;
    let note_commitment =
        compute_note_commitment(asset_commitment, amount as Field, recipient, randomness);

    main(
        note_commitment,
        amount,
        asset_commitment,
        0,
        recipient,
        randomness,
    );
}
