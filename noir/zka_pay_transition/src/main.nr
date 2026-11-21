use zka_lib::{compute_merkle_root, compute_note_commitment, compute_nullifier, derive_address};

global MAX_NOTE_VALUE_WEI: u128 = 0xffffffffffffffffffffffffffffff;

fn main(
    nullifiers: pub [Field; 2],
    output_commitments: pub [Field; 3],
    commitment_root: pub Field,
    pool_context: pub Field,
    interaction_context: pub Field,
    announcement_bundle_hash_hi: pub u128,
    announcement_bundle_hash_lo: pub u128,
    fee_recipient: pub Field,
    asset_commitment: pub Field,
    num_inputs: pub u32,
    has_change: pub bool,
    has_fee: pub bool,
    input_values: [u128; 2],
    input_recipients: [Field; 2],
    input_randomness: [Field; 2],
    input_paths: [[Field; 32]; 2],
    input_indices: [Field; 2],
    spending_key: Field,
    output_values: [u128; 3],
    output_recipients: [Field; 3],
    output_randomness: [Field; 3],
) {
    assert((num_inputs == 1) | (num_inputs == 2), "num_inputs must be 1 or 2");
    assert(pool_context != 0, "pool context must be non-zero");
    assert(interaction_context != 0, "interaction context must be non-zero");

    // These public limbs are intentionally opaque to the client circuit. Their
    // u128 types provide canonical limb range constraints; later circuits bind
    // and recompute the exact announcement-bundle digest.
    let _announcement_bundle_hash_hi_field = announcement_bundle_hash_hi as Field;
    let _announcement_bundle_hash_lo_field = announcement_bundle_hash_lo as Field;

    let owner = derive_address(spending_key);
    let mut input_commitments: [Field; 2] = [0; 2];
    let mut input_total: Field = 0;

    for i in 0..2 {
        if i < num_inputs {
            assert(input_values[i] > 0, "active input value must be non-zero");
            assert(
                input_values[i] <= MAX_NOTE_VALUE_WEI,
                "active input value exceeds launch bound",
            );

            let commitment = compute_note_commitment(
                asset_commitment,
                input_values[i] as Field,
                input_recipients[i],
                input_randomness[i],
            );
            input_commitments[i] = commitment;
            assert(
                compute_merkle_root(commitment, input_indices[i], input_paths[i])
                    == commitment_root,
                "payment input is not in commitment tree",
            );

            let expected_nullifier = compute_nullifier(commitment, spending_key);
            assert(expected_nullifier == nullifiers[i], "payment nullifier mismatch");
            assert(expected_nullifier != 0, "active nullifier must be non-zero");
            assert(input_recipients[i] == owner, "payment input owner mismatch");

            // The u128 value is range-checked above before entering Field
            // arithmetic, so the bounded totals cannot wrap the BN254 field.
            input_total += input_values[i] as Field;
        } else {
            assert(input_values[i] == 0, "inactive input value must be zero");
            assert(input_recipients[i] == 0, "inactive input recipient must be zero");
            assert(input_randomness[i] == 0, "inactive input randomness must be zero");
            for depth in 0..32 {
                assert(input_paths[i][depth] == 0, "inactive input path must be zero");
            }
            assert(input_indices[i] == 0, "inactive input index must be zero");
            assert(nullifiers[i] == 0, "inactive nullifier must be zero");
        }
    }

    if num_inputs == 2 {
        assert(
            input_commitments[0] != input_commitments[1],
            "active input commitments must be distinct",
        );
        assert(nullifiers[0] != nullifiers[1], "active nullifiers must be distinct");
    }

    let mut output_total: Field = 0;
    for i in 0..3 {
        let is_active = if i == 0 {
            true
        } else if i == 1 {
            has_change
        } else {
            has_fee
        };

        if is_active {
            assert(output_randomness[i] != 0, "active output randomness must be non-zero");
            for input_index in 0..2 {
                if input_index < num_inputs {
                    assert(
                        output_randomness[i] != input_randomness[input_index],
                        "active output randomness must not reuse input randomness",
                    );
                }
            }
            for output_index in 0..3 {
                let prior_is_active = if output_index == 0 {
                    true
                } else if output_index == 1 {
                    has_change
                } else {
                    has_fee
                };
                if (output_index < i) & prior_is_active {
                    assert(
                        output_randomness[i] != output_randomness[output_index],
                        "active output randomness must be distinct",
                    );
                }
            }
            if i == 0 {
                assert(output_values[i] > 0, "recipient output value must be non-zero");
            } else {
                assert(output_values[i] > 0, "active output value must be non-zero");
            }
            assert(
                output_values[i] <= MAX_NOTE_VALUE_WEI,
                "active output value exceeds launch bound",
            );
            let expected_commitment = compute_note_commitment(
                asset_commitment,
                output_values[i] as Field,
                output_recipients[i],
                output_randomness[i],
            );
            assert(expected_commitment == output_commitments[i], "output commitment mismatch");

            // As above, only an already range-checked u128 reaches Field
            // accumulation.
            output_total += output_values[i] as Field;
        } else {
            assert(output_values[i] == 0, "inactive output value must be zero");
            assert(output_recipients[i] == 0, "inactive output recipient must be zero");
            assert(output_randomness[i] == 0, "inactive output randomness must be zero");
            assert(output_commitments[i] == 0, "inactive output commitment must be zero");
        }
    }

    if has_fee {
        assert(fee_recipient != 0, "fee recipient must be non-zero with a fee");
        assert(
            fee_recipient == output_recipients[2],
            "fee recipient must match fee output recipient",
        );
    } else {
        assert(fee_recipient == 0, "fee recipient must be zero without a fee");
    }

    assert(input_total == output_total, "payment value conservation violated");
}

struct PaymentFixture {
    nullifiers: [Field; 2],
    output_commitments: [Field; 3],
    commitment_root: Field,
    pool_context: Field,
    interaction_context: Field,
    announcement_bundle_hash_hi: u128,
    announcement_bundle_hash_lo: u128,
    fee_recipient: Field,
    asset_commitment: Field,
    num_inputs: u32,
    has_change: bool,
    has_fee: bool,
    input_values: [u128; 2],
    input_recipients: [Field; 2],
    input_randomness: [Field; 2],
    input_paths: [[Field; 32]; 2],
    input_indices: [Field; 2],
    spending_key: Field,
    output_values: [u128; 3],
    output_recipients: [Field; 3],
    output_randomness: [Field; 3],
}

fn execute(fixture: PaymentFixture) {
    main(
        fixture.nullifiers,
        fixture.output_commitments,
        fixture.commitment_root,
        fixture.pool_context,
        fixture.interaction_context,
        fixture.announcement_bundle_hash_hi,
        fixture.announcement_bundle_hash_lo,
        fixture.fee_recipient,
        fixture.asset_commitment,
        fixture.num_inputs,
        fixture.has_change,
        fixture.has_fee,
        fixture.input_values,
        fixture.input_recipients,
        fixture.input_randomness,
        fixture.input_paths,
        fixture.input_indices,
        fixture.spending_key,
        fixture.output_values,
        fixture.output_recipients,
        fixture.output_randomness,
    );
}

fn one_input_no_change_no_fee() -> PaymentFixture {
    let spending_key: Field = 0x42;
    let owner = derive_address(spending_key);
    let asset_commitment = zka_lib::compute_asset_commitment(1);
    let input_value: u128 = 1000;
    let input_randomness: Field = 0xaa;
    let input_commitment = compute_note_commitment(
        asset_commitment,
        input_value as Field,
        owner,
        input_randomness,
    );
    let input_path: [Field; 32] = [0; 32];
    let commitment_root = compute_merkle_root(input_commitment, 0, input_path);
    let output_value: u128 = 1000;
    let output_recipient: Field = 0x1111;
    let output_randomness: Field = 0xbb;

    PaymentFixture {
        nullifiers: [compute_nullifier(input_commitment, spending_key), 0],
        output_commitments: [
            compute_note_commitment(
                asset_commitment,
                output_value as Field,
                output_recipient,
                output_randomness,
            ),
            0,
            0,
        ],
        commitment_root,
        pool_context: 0x1234,
        interaction_context: 0x5678,
        announcement_bundle_hash_hi: 0x11112222333344445555666677778888,
        announcement_bundle_hash_lo: 0x9999aaaabbbbccccddddeeeeffff0000,
        fee_recipient: 0,
        asset_commitment,
        num_inputs: 1,
        has_change: false,
        has_fee: false,
        input_values: [input_value, 0],
        input_recipients: [owner, 0],
        input_randomness: [input_randomness, 0],
        input_paths: [input_path, [0; 32]],
        input_indices: [0, 0],
        spending_key,
        output_values: [output_value, 0, 0],
        output_recipients: [output_recipient, 0, 0],
        output_randomness: [output_randomness, 0, 0],
    }
}

fn one_input_change_fee() -> PaymentFixture {
    let mut fixture = one_input_no_change_no_fee();
    fixture.has_change = true;
    fixture.has_fee = true;
    fixture.fee_recipient = 0xfefe;
    fixture.output_values = [700, 250, 50];
    fixture.output_recipients = [0x1111, fixture.input_recipients[0], fixture.fee_recipient];
    fixture.output_randomness = [0xbb, 0xcc, 0xdd];
    for i in 0..3 {
        fixture.output_commitments[i] = compute_note_commitment(
            fixture.asset_commitment,
            fixture.output_values[i] as Field,
            fixture.output_recipients[i],
            fixture.output_randomness[i],
        );
    }
    fixture
}

fn two_input_change_fee() -> PaymentFixture {
    let mut fixture = one_input_change_fee();
    let owner = fixture.input_recipients[0];
    fixture.num_inputs = 2;
    fixture.input_values = [600, 400];
    fixture.input_recipients = [owner, owner];
    fixture.input_randomness = [0xaa, 0xab];

    let commitments = [
        compute_note_commitment(fixture.asset_commitment, 600, owner, 0xaa),
        compute_note_commitment(fixture.asset_commitment, 400, owner, 0xab),
    ];
    let mut path_0: [Field; 32] = [0; 32];
    path_0[0] = commitments[1];
    let mut path_1: [Field; 32] = [0; 32];
    path_1[0] = commitments[0];
    fixture.input_paths = [path_0, path_1];
    fixture.input_indices = [0, 1];
    fixture.commitment_root = compute_merkle_root(commitments[0], 0, path_0);
    fixture.nullifiers = [
        compute_nullifier(commitments[0], fixture.spending_key),
        compute_nullifier(commitments[1], fixture.spending_key),
    ];
    fixture
}

#[test]
fn one_input_no_change_no_fee_is_valid() {
    execute(one_input_no_change_no_fee());
}

#[test]
fn one_input_change_and_fee_is_valid() {
    execute(one_input_change_fee());
}

#[test]
fn two_inputs_change_and_fee_are_valid() {
    execute(two_input_change_fee());
}

#[test]
fn opaque_nonzero_public_context_and_hash_values_are_valid() {
    let mut fixture = one_input_no_change_no_fee();
    fixture.pool_context = 0x9999;
    fixture.interaction_context = 0xaaaa;
    fixture.announcement_bundle_hash_hi = 7;
    fixture.announcement_bundle_hash_lo = 8;
    execute(fixture);
}

#[test(should_fail_with = "payment input owner mismatch")]
fn wrong_owner_fails() {
    let mut fixture = one_input_no_change_no_fee();
    fixture.spending_key = 0x99;
    let input_commitment = compute_note_commitment(
        fixture.asset_commitment,
        fixture.input_values[0] as Field,
        fixture.input_recipients[0],
        fixture.input_randomness[0],
    );
    fixture.nullifiers[0] = compute_nullifier(input_commitment, fixture.spending_key);
    execute(fixture);
}

#[test(should_fail_with = "payment input is not in commitment tree")]
fn wrong_merkle_path_fails() {
    let mut fixture = one_input_no_change_no_fee();
    fixture.input_paths[0][0] = 1;
    execute(fixture);
}

#[test(should_fail_with = "active input commitments must be distinct")]
fn duplicate_inputs_fail() {
    let mut fixture = two_input_change_fee();
    fixture.input_values[1] = fixture.input_values[0];
    fixture.input_recipients[1] = fixture.input_recipients[0];
    fixture.input_randomness[1] = fixture.input_randomness[0];
    fixture.input_paths[1] = fixture.input_paths[0];
    fixture.input_indices[1] = fixture.input_indices[0];
    fixture.nullifiers[1] = fixture.nullifiers[0];
    execute(fixture);
}

#[test(should_fail_with = "inactive input value must be zero")]
fn inactive_input_value_fails() {
    let mut fixture = one_input_no_change_no_fee();
    fixture.input_values[1] = 1;
    execute(fixture);
}

#[test(should_fail_with = "inactive input recipient must be zero")]
fn inactive_input_recipient_fails() {
    let mut fixture = one_input_no_change_no_fee();
    fixture.input_recipients[1] = 1;
    execute(fixture);
}

#[test(should_fail_with = "inactive input randomness must be zero")]
fn inactive_input_randomness_fails() {
    let mut fixture = one_input_no_change_no_fee();
    fixture.input_randomness[1] = 1;
    execute(fixture);
}

#[test(should_fail_with = "inactive input path must be zero")]
fn inactive_input_path_fails() {
    let mut fixture = one_input_no_change_no_fee();
    fixture.input_paths[1][31] = 1;
    execute(fixture);
}

#[test(should_fail_with = "inactive input index must be zero")]
fn inactive_input_index_fails() {
    let mut fixture = one_input_no_change_no_fee();
    fixture.input_indices[1] = 1;
    execute(fixture);
}

#[test(should_fail_with = "inactive nullifier must be zero")]
fn inactive_nullifier_fails() {
    let mut fixture = one_input_no_change_no_fee();
    fixture.nullifiers[1] = 1;
    execute(fixture);
}

#[test(should_fail_with = "inactive output value must be zero")]
fn inactive_change_value_fails() {
    let mut fixture = one_input_no_change_no_fee();
    fixture.output_values[1] = 1;
    execute(fixture);
}

#[test(should_fail_with = "inactive output recipient must be zero")]
fn inactive_fee_recipient_witness_fails() {
    let mut fixture = one_input_no_change_no_fee();
    fixture.output_recipients[2] = 1;
    execute(fixture);
}

#[test(should_fail_with = "inactive output randomness must be zero")]
fn inactive_change_randomness_fails() {
    let mut fixture = one_input_no_change_no_fee();
    fixture.output_randomness[1] = 1;
    execute(fixture);
}

#[test(should_fail_with = "inactive output commitment must be zero")]
fn inactive_fee_commitment_fails() {
    let mut fixture = one_input_no_change_no_fee();
    fixture.output_commitments[2] = 1;
    execute(fixture);
}

#[test(should_fail_with = "active output randomness must be non-zero")]
fn zero_active_output_randomness_fails() {
    let mut fixture = one_input_no_change_no_fee();
    fixture.output_randomness[0] = 0;
    fixture.output_commitments[0] = compute_note_commitment(
        fixture.asset_commitment,
        fixture.output_values[0] as Field,
        fixture.output_recipients[0],
        0,
    );
    execute(fixture);
}

#[test(should_fail_with = "active output randomness must not reuse input randomness")]
fn output_randomness_reused_from_input_fails() {
    let mut fixture = one_input_no_change_no_fee();
    fixture.output_randomness[0] = fixture.input_randomness[0];
    fixture.output_commitments[0] = compute_note_commitment(
        fixture.asset_commitment,
        fixture.output_values[0] as Field,
        fixture.output_recipients[0],
        fixture.output_randomness[0],
    );
    execute(fixture);
}

#[test(should_fail_with = "active output randomness must be distinct")]
fn repeated_active_output_randomness_fails() {
    let mut fixture = one_input_change_fee();
    fixture.output_randomness[1] = fixture.output_randomness[0];
    fixture.output_commitments[1] = compute_note_commitment(
        fixture.asset_commitment,
        fixture.output_values[1] as Field,
        fixture.output_recipients[1],
        fixture.output_randomness[1],
    );
    execute(fixture);
}

#[test(should_fail_with = "recipient output value must be non-zero")]
fn missing_recipient_output_fails() {
    let mut fixture = one_input_no_change_no_fee();
    fixture.output_values[0] = 0;
    fixture.output_commitments[0] = compute_note_commitment(
        fixture.asset_commitment,
        0,
        fixture.output_recipients[0],
        fixture.output_randomness[0],
    );
    execute(fixture);
}

#[test(should_fail_with = "active input value must be non-zero")]
fn zero_active_input_value_fails() {
    let mut fixture = one_input_no_change_no_fee();
    fixture.input_values[0] = 0;
    let commitment = compute_note_commitment(
        fixture.asset_commitment,
        0,
        fixture.input_recipients[0],
        fixture.input_randomness[0],
    );
    fixture.commitment_root =
        compute_merkle_root(commitment, fixture.input_indices[0], fixture.input_paths[0]);
    fixture.nullifiers[0] = compute_nullifier(commitment, fixture.spending_key);
    execute(fixture);
}

#[test(should_fail_with = "active input value exceeds launch bound")]
fn overflow_bound_input_value_fails() {
    let mut fixture = one_input_no_change_no_fee();
    let overflow: u128 = 0x1000000000000000000000000000000;
    fixture.input_values[0] = overflow;
    let commitment = compute_note_commitment(
        fixture.asset_commitment,
        overflow as Field,
        fixture.input_recipients[0],
        fixture.input_randomness[0],
    );
    fixture.commitment_root =
        compute_merkle_root(commitment, fixture.input_indices[0], fixture.input_paths[0]);
    fixture.nullifiers[0] = compute_nullifier(commitment, fixture.spending_key);
    execute(fixture);
}

#[test(should_fail_with = "output commitment mismatch")]
fn wrong_output_commitment_fails() {
    let mut fixture = one_input_no_change_no_fee();
    fixture.output_commitments[0] += 1;
    execute(fixture);
}

#[test(should_fail_with = "payment value conservation violated")]
fn conservation_failure_fails() {
    let mut fixture = one_input_no_change_no_fee();
    fixture.output_values[0] = 999;
    fixture.output_commitments[0] = compute_note_commitment(
        fixture.asset_commitment,
        999,
        fixture.output_recipients[0],
        fixture.output_randomness[0],
    );
    execute(fixture);
}

#[test(should_fail_with = "pool context must be non-zero")]
fn zero_pool_context_fails() {
    let mut fixture = one_input_no_change_no_fee();
    fixture.pool_context = 0;
    execute(fixture);
}

#[test(should_fail_with = "interaction context must be non-zero")]
fn zero_interaction_context_fails() {
    let mut fixture = one_input_no_change_no_fee();
    fixture.interaction_context = 0;
    execute(fixture);
}

#[test(should_fail_with = "fee recipient must match fee output recipient")]
fn incorrect_fee_recipient_fails() {
    let mut fixture = one_input_change_fee();
    fixture.fee_recipient = 0xfefd;
    execute(fixture);
}

#[test(should_fail_with = "fee recipient must be zero without a fee")]
fn nonzero_fee_recipient_without_fee_fails() {
    let mut fixture = one_input_no_change_no_fee();
    fixture.fee_recipient = 1;
    execute(fixture);
}

#[test(should_fail_with = "num_inputs must be 1 or 2")]
fn zero_inputs_fails() {
    let mut fixture = one_input_no_change_no_fee();
    fixture.num_inputs = 0;
    execute(fixture);
}

#[test(should_fail_with = "num_inputs must be 1 or 2")]
fn three_inputs_fails() {
    let mut fixture = two_input_change_fee();
    fixture.num_inputs = 3;
    execute(fixture);
}
