use zka_lib::{
    compute_merkle_root, compute_note_commitment, compute_nullifier, derive_address, poseidon2,
    verify_nullifier_absent_and_insert,
};

global MAX_NOTE_VALUE_WEI: u128 = 0xffffffffffffffffffffffffffffff;

fn main(
    commitment_root: pub Field,
    old_nullifier_root: pub Field,
    new_nullifier_root: pub Field,
    nullifier: pub Field,
    amount: pub u128,
    external_recipient: pub Field,
    asset_commitment: pub Field,
    pool_context: pub Field,
    note_recipient: Field,
    note_randomness: Field,
    note_path: [Field; 32],
    note_index: Field,
    spending_key: Field,
    nullifier_path: [Field; 128],
) {
    assert(amount > 0, "withdrawal amount must be non-zero");
    assert(amount <= MAX_NOTE_VALUE_WEI, "withdrawal amount exceeds launch bound");
    assert(external_recipient != 0, "external recipient must be non-zero");
    // A recipient must fit in a 20-byte L1 address. ZKAEthPool settles to an
    // `address` parameter, so today's calldata cannot express a wider value --
    // this states the encoding's bound in the circuit itself rather than
    // inheriting it from a contract's parameter type.
    zka_lib::assert_fits_u160(external_recipient);
    assert(pool_context != 0, "pool context must be non-zero");

    let note_commitment = compute_note_commitment(
        asset_commitment,
        amount as Field,
        note_recipient,
        note_randomness,
    );
    assert(
        compute_merkle_root(note_commitment, note_index, note_path) == commitment_root,
        "withdrawal note is not in commitment tree",
    );
    assert(derive_address(spending_key) == note_recipient, "withdrawal note owner mismatch");
    assert(
        compute_nullifier(note_commitment, spending_key) == nullifier,
        "withdrawal nullifier mismatch",
    );

    let expected_new_nullifier_root =
        verify_nullifier_absent_and_insert(old_nullifier_root, nullifier, nullifier_path);
    assert(
        expected_new_nullifier_root == new_nullifier_root,
        "withdrawal successor nullifier root mismatch",
    );
}

struct WithdrawalFixture {
    commitment_root: Field,
    old_nullifier_root: Field,
    new_nullifier_root: Field,
    nullifier: Field,
    amount: u128,
    external_recipient: Field,
    asset_commitment: Field,
    pool_context: Field,
    note_recipient: Field,
    note_randomness: Field,
    note_path: [Field; 32],
    note_index: Field,
    spending_key: Field,
    nullifier_path: [Field; 128],
}

fn execute(fixture: WithdrawalFixture) {
    main(
        fixture.commitment_root,
        fixture.old_nullifier_root,
        fixture.new_nullifier_root,
        fixture.nullifier,
        fixture.amount,
        fixture.external_recipient,
        fixture.asset_commitment,
        fixture.pool_context,
        fixture.note_recipient,
        fixture.note_randomness,
        fixture.note_path,
        fixture.note_index,
        fixture.spending_key,
        fixture.nullifier_path,
    );
}

fn empty_nullifier_path() -> [Field; 128] {
    let mut siblings: [Field; 128] = [0; 128];
    let mut empty: Field = 0;
    for depth in 0..128 {
        siblings[depth] = empty;
        empty = poseidon2(empty, empty);
    }
    siblings
}

fn fixture_for_amount(amount: u128) -> WithdrawalFixture {
    let spending_key: Field = 0x42;
    let note_recipient = derive_address(spending_key);
    let asset_commitment = zka_lib::compute_asset_commitment(1);
    let note_randomness: Field = 0xaabb;
    let note_commitment = compute_note_commitment(
        asset_commitment,
        amount as Field,
        note_recipient,
        note_randomness,
    );
    let note_path: [Field; 32] = [0; 32];
    let note_index: Field = 0;
    let commitment_root = compute_merkle_root(note_commitment, note_index, note_path);
    let nullifier = compute_nullifier(note_commitment, spending_key);
    let nullifier_path = empty_nullifier_path();
    let old_nullifier_root: Field =
        0x2413c3e2b026ffff5628832762082690520fc5a22f825e3af1a86cc435901981;
    let new_nullifier_root =
        verify_nullifier_absent_and_insert(old_nullifier_root, nullifier, nullifier_path);

    WithdrawalFixture {
        commitment_root,
        old_nullifier_root,
        new_nullifier_root,
        nullifier,
        amount,
        external_recipient: 0xdeadbeef,
        asset_commitment,
        pool_context: 0xc001,
        note_recipient,
        note_randomness,
        note_path,
        note_index,
        spending_key,
        nullifier_path,
    }
}

fn valid_fixture() -> WithdrawalFixture {
    fixture_for_amount(1000)
}

#[test]
fn valid_withdrawal_advances_nullifier_root() {
    execute(valid_fixture());
}

#[test]
fn maximum_amount_is_accepted() {
    execute(fixture_for_amount(MAX_NOTE_VALUE_WEI));
}

#[test(should_fail_with = "withdrawal note owner mismatch")]
fn wrong_owner_is_rejected() {
    let mut fixture = valid_fixture();
    fixture.spending_key = 0x43;
    execute(fixture);
}

#[test(should_fail_with = "withdrawal note is not in commitment tree")]
fn wrong_note_path_is_rejected() {
    let mut fixture = valid_fixture();
    fixture.note_path[0] += 1;
    execute(fixture);
}

#[test(should_fail_with = "withdrawal nullifier mismatch")]
fn wrong_nullifier_is_rejected() {
    let mut fixture = valid_fixture();
    fixture.nullifier += 1;
    execute(fixture);
}

#[test(should_fail_with = "nullifier is present or path is invalid")]
fn wrong_nullifier_path_is_rejected() {
    let mut fixture = valid_fixture();
    fixture.nullifier_path[0] += 1;
    execute(fixture);
}

#[test(should_fail_with = "nullifier is present or path is invalid")]
fn wrong_old_nullifier_root_is_rejected() {
    let mut fixture = valid_fixture();
    fixture.old_nullifier_root += 1;
    execute(fixture);
}

#[test(should_fail_with = "withdrawal successor nullifier root mismatch")]
fn wrong_successor_nullifier_root_is_rejected() {
    let mut fixture = valid_fixture();
    fixture.new_nullifier_root += 1;
    execute(fixture);
}

#[test(should_fail_with = "withdrawal note is not in commitment tree")]
fn wrong_amount_is_rejected() {
    let mut fixture = valid_fixture();
    fixture.amount -= 1;
    execute(fixture);
}

#[test(should_fail_with = "external recipient must be non-zero")]
fn zero_external_recipient_is_rejected() {
    let mut fixture = valid_fixture();
    fixture.external_recipient = 0;
    execute(fixture);
}

// A recipient wider than 20 bytes has no valid L1 encoding: ZKAEthPool settles
// to an `address`, which occupies only the low 20 bytes of the public input.
// The circuit states that bound itself rather than inheriting it from the
// contract's parameter type -- defense in depth, and it keeps the circuit
// meaningful for any future caller that does not go through that type.
#[test(should_fail_with = "call to assert_max_bit_size")]
fn oversized_external_recipient_is_rejected() {
    let mut fixture = valid_fixture();
    fixture.external_recipient = zka_lib::TWO_POW_160;
    execute(fixture);
}

// The largest real L1 address (2^160 - 1) must still be accepted, proving the
// bound rejects only genuinely unrepresentable recipients.
#[test]
fn maximum_external_recipient_is_accepted() {
    let mut fixture = valid_fixture();
    fixture.external_recipient = zka_lib::TWO_POW_160 - 1;
    execute(fixture);
}

#[test(should_fail_with = "withdrawal note is not in commitment tree")]
fn wrong_asset_is_rejected() {
    let mut fixture = valid_fixture();
    fixture.asset_commitment += 1;
    execute(fixture);
}

#[test(should_fail_with = "pool context must be non-zero")]
fn zero_pool_context_is_rejected() {
    let mut fixture = valid_fixture();
    fixture.pool_context = 0;
    execute(fixture);
}

#[test(should_fail_with = "withdrawal amount must be non-zero")]
fn zero_amount_is_rejected() {
    let mut fixture = valid_fixture();
    fixture.amount = 0;
    execute(fixture);
}

#[test(should_fail_with = "withdrawal amount exceeds launch bound")]
fn amount_above_maximum_is_rejected() {
    let mut fixture = valid_fixture();
    fixture.amount = 0x1000000000000000000000000000000;
    execute(fixture);
}

#[test(should_fail_with = "nullifier is present or path is invalid")]
fn replay_against_successor_root_is_rejected() {
    let mut fixture = valid_fixture();
    fixture.old_nullifier_root = fixture.new_nullifier_root;
    execute(fixture);
}
