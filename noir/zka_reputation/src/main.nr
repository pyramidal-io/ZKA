use zka_lib::{
    derive_credential_binding_key, derive_presentation_pseudonym, DOMAIN_ZKA_COMMITMENT,
    poseidon_hash,
};

global MAX_HISTORY_RECORDS: u32 = 8;

// These are circuit-local type discriminators under the registered
// DOMAIN_ZKA_COMMITMENT domain. They are not new protocol domain tags.
global TYPE_RELATIONSHIP_SCOPE: Field = 1;
global TYPE_REPUTATION_EVENT: Field = 2;
global TYPE_HISTORY_SEED: Field = 3;
global TYPE_HISTORY_FOLD: Field = 4;

global KAT_RELATIONSHIP_PSEUDONYM: Field =
    0x304e967727812b6019e734655f6036ef63a8cc4771d1d1d1715f6c542be29fc4;
global KAT_HISTORY_ROOT: Field = 0x074ade4e5df8fbc1e3361e8503a6f446e7fa98e9a3054cd655914baed5ae2c29;
// AFP v0.3.10-draft §5.2's session-context KAT, interpreted as a
// canonical BN254 field by the reduction specified in AFP §15.4.
global KAT_SESSION_CONTEXT_FIELD: Field =
    0x2c4a3104b3f719739885aaf898b812ed3933e272a498a9cecb558f03f97e4a7b;

fn flag_as_field(flag: bool) -> Field {
    if flag {
        1
    } else {
        0
    }
}

fn compute_relationship_scope(
    agreement_id_hi: u128,
    agreement_id_lo: u128,
    counterparty_aid_hi: u128,
    counterparty_aid_lo: u128,
    value_scope_hi: u128,
    value_scope_lo: u128,
) -> Field {
    poseidon_hash([
        DOMAIN_ZKA_COMMITMENT,
        TYPE_RELATIONSHIP_SCOPE,
        agreement_id_hi as Field,
        agreement_id_lo as Field,
        counterparty_aid_hi as Field,
        counterparty_aid_lo as Field,
        value_scope_hi as Field,
        value_scope_lo as Field,
    ])
}

fn compute_record_commitment(
    record_ref_hi: u128,
    record_ref_lo: u128,
    sequence_number: u64,
    settled_value: u128,
    settled: bool,
    slashed: bool,
    defaulted: bool,
) -> Field {
    poseidon_hash([
        DOMAIN_ZKA_COMMITMENT,
        TYPE_REPUTATION_EVENT,
        sequence_number as Field,
        record_ref_hi as Field,
        record_ref_lo as Field,
        settled_value as Field,
        flag_as_field(settled),
        flag_as_field(slashed),
        flag_as_field(defaulted),
    ])
}

fn compute_history_root(
    agreement_id_hi: u128,
    agreement_id_lo: u128,
    counterparty_aid_hi: u128,
    counterparty_aid_lo: u128,
    value_scope_hi: u128,
    value_scope_lo: u128,
    relationship_pseudonym: Field,
    settled_interactions: u32,
    record_refs_hi: [u128; MAX_HISTORY_RECORDS],
    record_refs_lo: [u128; MAX_HISTORY_RECORDS],
    sequence_numbers: [u64; MAX_HISTORY_RECORDS],
    settled_values: [u128; MAX_HISTORY_RECORDS],
    settled_flags: [bool; MAX_HISTORY_RECORDS],
    slash_flags: [bool; MAX_HISTORY_RECORDS],
    default_flags: [bool; MAX_HISTORY_RECORDS],
) -> Field {
    let mut state = poseidon_hash([
        DOMAIN_ZKA_COMMITMENT,
        TYPE_HISTORY_SEED,
        agreement_id_hi as Field,
        agreement_id_lo as Field,
        counterparty_aid_hi as Field,
        counterparty_aid_lo as Field,
        value_scope_hi as Field,
        value_scope_lo as Field,
        relationship_pseudonym,
        settled_interactions as Field,
    ]);

    // Always commit all eight slots. The active bit makes the fixed-width
    // padding explicit, while the main predicate requires canonical zero
    // values for every inactive slot.
    for slot in 0..MAX_HISTORY_RECORDS {
        let active = slot < settled_interactions;
        let leaf = compute_record_commitment(
            record_refs_hi[slot],
            record_refs_lo[slot],
            sequence_numbers[slot],
            settled_values[slot],
            settled_flags[slot],
            slash_flags[slot],
            default_flags[slot],
        );
        state = poseidon_hash([
            DOMAIN_ZKA_COMMITMENT,
            TYPE_HISTORY_FOLD,
            state,
            leaf,
            flag_as_field(active),
        ]);
    }
    state
}

fn main(
    agreement_id_hi: pub u128,
    agreement_id_lo: pub u128,
    counterparty_aid_hi: pub u128,
    counterparty_aid_lo: pub u128,
    value_scope_hi: pub u128,
    value_scope_lo: pub u128,
    relationship_pseudonym: pub Field,
    history_root: pub Field,
    last_commitment_ref_hi: pub u128,
    last_commitment_ref_lo: pub u128,
    reputation_counter: pub u64,
    settled_interactions: pub u32,
    cumulative_settled_value: pub u128,
    context: pub Field,
    master_seed: Field,
    record_refs_hi: [u128; MAX_HISTORY_RECORDS],
    record_refs_lo: [u128; MAX_HISTORY_RECORDS],
    sequence_numbers: [u64; MAX_HISTORY_RECORDS],
    settled_values: [u128; MAX_HISTORY_RECORDS],
    settled_flags: [bool; MAX_HISTORY_RECORDS],
    slash_flags: [bool; MAX_HISTORY_RECORDS],
    default_flags: [bool; MAX_HISTORY_RECORDS],
) {
    assert(
        (agreement_id_hi != 0) | (agreement_id_lo != 0),
        "agreement identifier must be non-zero",
    );
    assert(
        (counterparty_aid_hi != 0) | (counterparty_aid_lo != 0),
        "counterparty AID must be non-zero",
    );
    assert((value_scope_hi != 0) | (value_scope_lo != 0), "value scope must be non-zero");
    assert(relationship_pseudonym != 0, "relationship pseudonym must be non-zero");
    assert(history_root != 0, "history root must be non-zero");
    assert(context != 0, "context must be non-zero");
    assert(
        (settled_interactions >= 1) & (settled_interactions <= MAX_HISTORY_RECORDS),
        "settled interaction count must be between one and eight",
    );

    let relationship_scope = compute_relationship_scope(
        agreement_id_hi,
        agreement_id_lo,
        counterparty_aid_hi,
        counterparty_aid_lo,
        value_scope_hi,
        value_scope_lo,
    );
    assert(relationship_scope != 0, "derived relationship scope must be non-zero");
    let credential_binding_key = derive_credential_binding_key(master_seed);
    assert(
        derive_presentation_pseudonym(credential_binding_key, relationship_scope)
            == relationship_pseudonym,
        "relationship pseudonym does not match master seed and scope",
    );

    let mut cumulative_value: Field = 0;
    let mut last_sequence: u64 = 0;
    let mut last_ref_hi: u128 = 0;
    let mut last_ref_lo: u128 = 0;

    for slot in 0..MAX_HISTORY_RECORDS {
        let active = slot < settled_interactions;
        if active {
            assert(
                (record_refs_hi[slot] != 0) | (record_refs_lo[slot] != 0),
                "active record reference must be non-zero",
            );
            assert(settled_values[slot] != 0, "active settled value must be non-zero");
            assert(settled_flags[slot], "active record must be settled");
            assert(!slash_flags[slot], "active record must not be slashed");
            assert(!default_flags[slot], "active record must not be defaulted");
            if slot > 0 {
                assert(
                    sequence_numbers[slot - 1] < sequence_numbers[slot],
                    "active record sequence numbers must strictly increase",
                );
            }

            // Every addend is a range-constrained u128. With at most eight
            // active records, the mathematical sum is below 2^131, far below
            // the BN254 scalar-field modulus (>2^253), so this Field-domain
            // accumulator cannot wrap before comparison to the public u128.
            cumulative_value += settled_values[slot] as Field;
            last_sequence = sequence_numbers[slot];
            last_ref_hi = record_refs_hi[slot];
            last_ref_lo = record_refs_lo[slot];
        } else {
            assert(record_refs_hi[slot] == 0, "inactive record reference hi must be zero");
            assert(record_refs_lo[slot] == 0, "inactive record reference lo must be zero");
            assert(sequence_numbers[slot] == 0, "inactive sequence number must be zero");
            assert(settled_values[slot] == 0, "inactive settled value must be zero");
            assert(!settled_flags[slot], "inactive settled flag must be false");
            assert(!slash_flags[slot], "inactive slash flag must be false");
            assert(!default_flags[slot], "inactive default flag must be false");
        }
    }

    assert(
        cumulative_value == cumulative_settled_value as Field,
        "cumulative settled value mismatch",
    );
    assert(last_sequence == reputation_counter, "reputation counter mismatch");
    assert(last_ref_hi == last_commitment_ref_hi, "last commitment reference hi mismatch");
    assert(last_ref_lo == last_commitment_ref_lo, "last commitment reference lo mismatch");

    let computed_history_root = compute_history_root(
        agreement_id_hi,
        agreement_id_lo,
        counterparty_aid_hi,
        counterparty_aid_lo,
        value_scope_hi,
        value_scope_lo,
        relationship_pseudonym,
        settled_interactions,
        record_refs_hi,
        record_refs_lo,
        sequence_numbers,
        settled_values,
        settled_flags,
        slash_flags,
        default_flags,
    );
    assert(computed_history_root == history_root, "reputation history root mismatch");
}

struct ReputationFixture {
    agreement_id_hi: u128,
    agreement_id_lo: u128,
    counterparty_aid_hi: u128,
    counterparty_aid_lo: u128,
    value_scope_hi: u128,
    value_scope_lo: u128,
    relationship_pseudonym: Field,
    history_root: Field,
    last_commitment_ref_hi: u128,
    last_commitment_ref_lo: u128,
    reputation_counter: u64,
    settled_interactions: u32,
    cumulative_settled_value: u128,
    context: Field,
    master_seed: Field,
    record_refs_hi: [u128; MAX_HISTORY_RECORDS],
    record_refs_lo: [u128; MAX_HISTORY_RECORDS],
    sequence_numbers: [u64; MAX_HISTORY_RECORDS],
    settled_values: [u128; MAX_HISTORY_RECORDS],
    settled_flags: [bool; MAX_HISTORY_RECORDS],
    slash_flags: [bool; MAX_HISTORY_RECORDS],
    default_flags: [bool; MAX_HISTORY_RECORDS],
}

fn execute(fixture: ReputationFixture) {
    main(
        fixture.agreement_id_hi,
        fixture.agreement_id_lo,
        fixture.counterparty_aid_hi,
        fixture.counterparty_aid_lo,
        fixture.value_scope_hi,
        fixture.value_scope_lo,
        fixture.relationship_pseudonym,
        fixture.history_root,
        fixture.last_commitment_ref_hi,
        fixture.last_commitment_ref_lo,
        fixture.reputation_counter,
        fixture.settled_interactions,
        fixture.cumulative_settled_value,
        fixture.context,
        fixture.master_seed,
        fixture.record_refs_hi,
        fixture.record_refs_lo,
        fixture.sequence_numbers,
        fixture.settled_values,
        fixture.settled_flags,
        fixture.slash_flags,
        fixture.default_flags,
    );
}

fn canonical_fixture() -> ReputationFixture {
    ReputationFixture {
        agreement_id_hi: 0x0123456789abcdeffedcba9876543210,
        agreement_id_lo: 0x00112233445566778899aabbccddeeff,
        counterparty_aid_hi: 0x102132435465768798a9bacbdcedfe0f,
        counterparty_aid_lo: 0xffeeddccbbaa99887766554433221100,
        value_scope_hi: 0x0f0e0d0c0b0a09080706050403020100,
        value_scope_lo: 0x112233445566778899aabbccddeeff00,
        relationship_pseudonym: KAT_RELATIONSHIP_PSEUDONYM,
        history_root: KAT_HISTORY_ROOT,
        last_commitment_ref_hi: 0x30000000000000000000000000000003,
        last_commitment_ref_lo: 0xcccccccccccccccccccccccccccccccc,
        reputation_counter: 11,
        settled_interactions: 3,
        cumulative_settled_value: 10000,
        context: KAT_SESSION_CONTEXT_FIELD,
        master_seed: 0x123456789abcdef,
        record_refs_hi: [
            0x10000000000000000000000000000001,
            0x20000000000000000000000000000002,
            0x30000000000000000000000000000003,
            0,
            0,
            0,
            0,
            0,
        ],
        record_refs_lo: [
            0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa,
            0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb,
            0xcccccccccccccccccccccccccccccccc,
            0,
            0,
            0,
            0,
            0,
        ],
        sequence_numbers: [4, 7, 11, 0, 0, 0, 0, 0],
        settled_values: [1000, 2500, 6500, 0, 0, 0, 0, 0],
        settled_flags: [true, true, true, false, false, false, false, false],
        slash_flags: [false; MAX_HISTORY_RECORDS],
        default_flags: [false; MAX_HISTORY_RECORDS],
    }
}

fn refresh_history_root(mut fixture: ReputationFixture) -> ReputationFixture {
    fixture.history_root = compute_history_root(
        fixture.agreement_id_hi,
        fixture.agreement_id_lo,
        fixture.counterparty_aid_hi,
        fixture.counterparty_aid_lo,
        fixture.value_scope_hi,
        fixture.value_scope_lo,
        fixture.relationship_pseudonym,
        fixture.settled_interactions,
        fixture.record_refs_hi,
        fixture.record_refs_lo,
        fixture.sequence_numbers,
        fixture.settled_values,
        fixture.settled_flags,
        fixture.slash_flags,
        fixture.default_flags,
    );
    fixture
}

#[test]
fn canonical_three_record_kat_is_valid() {
    let fixture = canonical_fixture();
    assert(fixture.context == KAT_SESSION_CONTEXT_FIELD);
    let scope = compute_relationship_scope(
        fixture.agreement_id_hi,
        fixture.agreement_id_lo,
        fixture.counterparty_aid_hi,
        fixture.counterparty_aid_lo,
        fixture.value_scope_hi,
        fixture.value_scope_lo,
    );
    let pseudonym =
        derive_presentation_pseudonym(derive_credential_binding_key(fixture.master_seed), scope);
    let root = compute_history_root(
        fixture.agreement_id_hi,
        fixture.agreement_id_lo,
        fixture.counterparty_aid_hi,
        fixture.counterparty_aid_lo,
        fixture.value_scope_hi,
        fixture.value_scope_lo,
        pseudonym,
        fixture.settled_interactions,
        fixture.record_refs_hi,
        fixture.record_refs_lo,
        fixture.sequence_numbers,
        fixture.settled_values,
        fixture.settled_flags,
        fixture.slash_flags,
        fixture.default_flags,
    );
    assert(pseudonym == KAT_RELATIONSHIP_PSEUDONYM);
    assert(root == KAT_HISTORY_ROOT);
    execute(fixture);
}

#[test]
fn one_record_history_is_valid() {
    let mut fixture = canonical_fixture();
    fixture.settled_interactions = 1;
    fixture.record_refs_hi = [fixture.record_refs_hi[0], 0, 0, 0, 0, 0, 0, 0];
    fixture.record_refs_lo = [fixture.record_refs_lo[0], 0, 0, 0, 0, 0, 0, 0];
    fixture.sequence_numbers = [4, 0, 0, 0, 0, 0, 0, 0];
    fixture.settled_values = [1000, 0, 0, 0, 0, 0, 0, 0];
    fixture.settled_flags = [true, false, false, false, false, false, false, false];
    fixture.last_commitment_ref_hi = fixture.record_refs_hi[0];
    fixture.last_commitment_ref_lo = fixture.record_refs_lo[0];
    fixture.reputation_counter = 4;
    fixture.cumulative_settled_value = 1000;
    execute(refresh_history_root(fixture));
}

#[test]
fn eight_record_history_is_valid() {
    let mut fixture = canonical_fixture();
    fixture.settled_interactions = MAX_HISTORY_RECORDS;
    fixture.record_refs_hi[3] = 4;
    fixture.record_refs_hi[4] = 5;
    fixture.record_refs_hi[5] = 6;
    fixture.record_refs_hi[6] = 7;
    fixture.record_refs_hi[7] = 8;
    fixture.sequence_numbers = [4, 7, 11, 12, 13, 14, 15, 16];
    fixture.settled_values = [1000, 2500, 6500, 4, 5, 6, 7, 8];
    fixture.settled_flags = [true; MAX_HISTORY_RECORDS];
    fixture.last_commitment_ref_hi = 8;
    fixture.last_commitment_ref_lo = 0;
    fixture.reputation_counter = 16;
    fixture.cumulative_settled_value = 10030;
    execute(refresh_history_root(fixture));
}

#[test]
fn maximum_u128_single_record_value_is_valid() {
    let mut fixture = canonical_fixture();
    fixture.settled_interactions = 1;
    fixture.record_refs_hi = [fixture.record_refs_hi[0], 0, 0, 0, 0, 0, 0, 0];
    fixture.record_refs_lo = [fixture.record_refs_lo[0], 0, 0, 0, 0, 0, 0, 0];
    fixture.sequence_numbers = [4, 0, 0, 0, 0, 0, 0, 0];
    fixture.settled_values = [0xffffffffffffffffffffffffffffffff, 0, 0, 0, 0, 0, 0, 0];
    fixture.settled_flags = [true, false, false, false, false, false, false, false];
    fixture.last_commitment_ref_hi = fixture.record_refs_hi[0];
    fixture.last_commitment_ref_lo = fixture.record_refs_lo[0];
    fixture.reputation_counter = 4;
    fixture.cumulative_settled_value = 0xffffffffffffffffffffffffffffffff;
    execute(refresh_history_root(fixture));
}

#[test(should_fail_with = "settled interaction count must be between one and eight")]
fn zero_record_history_is_rejected() {
    let mut fixture = canonical_fixture();
    fixture.settled_interactions = 0;
    execute(fixture);
}

#[test(should_fail_with = "settled interaction count must be between one and eight")]
fn more_than_eight_records_is_rejected() {
    let mut fixture = canonical_fixture();
    fixture.settled_interactions = 9;
    execute(fixture);
}

#[test(should_fail_with = "agreement identifier must be non-zero")]
fn zero_agreement_identifier_is_rejected() {
    let mut fixture = canonical_fixture();
    fixture.agreement_id_hi = 0;
    fixture.agreement_id_lo = 0;
    execute(fixture);
}

#[test(should_fail_with = "counterparty AID must be non-zero")]
fn zero_counterparty_aid_is_rejected() {
    let mut fixture = canonical_fixture();
    fixture.counterparty_aid_hi = 0;
    fixture.counterparty_aid_lo = 0;
    execute(fixture);
}

#[test(should_fail_with = "value scope must be non-zero")]
fn zero_value_scope_is_rejected() {
    let mut fixture = canonical_fixture();
    fixture.value_scope_hi = 0;
    fixture.value_scope_lo = 0;
    execute(fixture);
}

#[test(should_fail_with = "relationship pseudonym must be non-zero")]
fn zero_relationship_pseudonym_is_rejected() {
    let mut fixture = canonical_fixture();
    fixture.relationship_pseudonym = 0;
    execute(fixture);
}

#[test(should_fail_with = "history root must be non-zero")]
fn zero_history_root_is_rejected() {
    let mut fixture = canonical_fixture();
    fixture.history_root = 0;
    execute(fixture);
}

#[test(should_fail_with = "context must be non-zero")]
fn zero_context_is_rejected() {
    let mut fixture = canonical_fixture();
    fixture.context = 0;
    execute(fixture);
}

#[test(should_fail_with = "relationship pseudonym does not match master seed and scope")]
fn another_master_seed_cannot_use_the_relationship_pseudonym() {
    let mut fixture = canonical_fixture();
    fixture.master_seed += 1;
    execute(fixture);
}

#[test(should_fail_with = "relationship pseudonym does not match master seed and scope")]
fn relationship_pseudonym_is_bound_to_agreement_id_hi() {
    let mut fixture = canonical_fixture();
    fixture.agreement_id_hi += 1;
    execute(fixture);
}

#[test(should_fail_with = "relationship pseudonym does not match master seed and scope")]
fn relationship_pseudonym_is_bound_to_agreement_id_lo() {
    let mut fixture = canonical_fixture();
    fixture.agreement_id_lo += 1;
    execute(fixture);
}

#[test(should_fail_with = "relationship pseudonym does not match master seed and scope")]
fn relationship_pseudonym_is_bound_to_counterparty_aid_hi() {
    let mut fixture = canonical_fixture();
    fixture.counterparty_aid_hi += 1;
    execute(fixture);
}

#[test(should_fail_with = "relationship pseudonym does not match master seed and scope")]
fn relationship_pseudonym_is_bound_to_counterparty_aid_lo() {
    let mut fixture = canonical_fixture();
    fixture.counterparty_aid_lo += 1;
    execute(fixture);
}

#[test(should_fail_with = "relationship pseudonym does not match master seed and scope")]
fn relationship_pseudonym_is_bound_to_value_scope_hi() {
    let mut fixture = canonical_fixture();
    fixture.value_scope_hi += 1;
    execute(fixture);
}

#[test(should_fail_with = "relationship pseudonym does not match master seed and scope")]
fn relationship_pseudonym_is_bound_to_value_scope_lo() {
    let mut fixture = canonical_fixture();
    fixture.value_scope_lo += 1;
    execute(fixture);
}

#[test(should_fail_with = "active record reference must be non-zero")]
fn zero_active_record_reference_is_rejected() {
    let mut fixture = canonical_fixture();
    fixture.record_refs_hi[1] = 0;
    fixture.record_refs_lo[1] = 0;
    execute(fixture);
}

#[test(should_fail_with = "active settled value must be non-zero")]
fn zero_active_settled_value_is_rejected() {
    let mut fixture = canonical_fixture();
    fixture.settled_values[1] = 0;
    execute(fixture);
}

#[test(should_fail_with = "active record must be settled")]
fn unsettled_active_record_is_rejected() {
    let mut fixture = canonical_fixture();
    fixture.settled_flags[1] = false;
    execute(fixture);
}

#[test(should_fail_with = "active record must not be slashed")]
fn slashed_active_record_is_rejected() {
    let mut fixture = canonical_fixture();
    fixture.slash_flags[1] = true;
    execute(fixture);
}

#[test(should_fail_with = "active record must not be defaulted")]
fn defaulted_active_record_is_rejected() {
    let mut fixture = canonical_fixture();
    fixture.default_flags[1] = true;
    execute(fixture);
}

#[test(should_fail_with = "active record sequence numbers must strictly increase")]
fn duplicate_sequence_number_is_rejected() {
    let mut fixture = canonical_fixture();
    fixture.sequence_numbers[1] = fixture.sequence_numbers[0];
    execute(fixture);
}

#[test(should_fail_with = "active record sequence numbers must strictly increase")]
fn decreasing_sequence_number_is_rejected() {
    let mut fixture = canonical_fixture();
    fixture.sequence_numbers[1] = fixture.sequence_numbers[0] - 1;
    execute(fixture);
}

#[test(should_fail_with = "inactive record reference hi must be zero")]
fn inactive_record_reference_hi_is_rejected() {
    let mut fixture = canonical_fixture();
    fixture.record_refs_hi[3] = 1;
    execute(fixture);
}

#[test(should_fail_with = "inactive record reference lo must be zero")]
fn inactive_record_reference_lo_is_rejected() {
    let mut fixture = canonical_fixture();
    fixture.record_refs_lo[3] = 1;
    execute(fixture);
}

#[test(should_fail_with = "inactive sequence number must be zero")]
fn inactive_sequence_number_is_rejected() {
    let mut fixture = canonical_fixture();
    fixture.sequence_numbers[3] = 1;
    execute(fixture);
}

#[test(should_fail_with = "inactive settled value must be zero")]
fn inactive_settled_value_is_rejected() {
    let mut fixture = canonical_fixture();
    fixture.settled_values[3] = 1;
    execute(fixture);
}

#[test(should_fail_with = "inactive settled flag must be false")]
fn inactive_settled_flag_is_rejected() {
    let mut fixture = canonical_fixture();
    fixture.settled_flags[3] = true;
    execute(fixture);
}

#[test(should_fail_with = "inactive slash flag must be false")]
fn inactive_slash_flag_is_rejected() {
    let mut fixture = canonical_fixture();
    fixture.slash_flags[3] = true;
    execute(fixture);
}

#[test(should_fail_with = "inactive default flag must be false")]
fn inactive_default_flag_is_rejected() {
    let mut fixture = canonical_fixture();
    fixture.default_flags[3] = true;
    execute(fixture);
}

#[test(should_fail_with = "cumulative settled value mismatch")]
fn wrong_cumulative_value_is_rejected() {
    let mut fixture = canonical_fixture();
    fixture.cumulative_settled_value -= 1;
    execute(fixture);
}

#[test(should_fail_with = "cumulative settled value mismatch")]
fn field_accumulator_does_not_wrap_at_u128() {
    let mut fixture = canonical_fixture();
    fixture.settled_interactions = 2;
    fixture.record_refs_hi =
        [fixture.record_refs_hi[0], fixture.record_refs_hi[1], 0, 0, 0, 0, 0, 0];
    fixture.record_refs_lo =
        [fixture.record_refs_lo[0], fixture.record_refs_lo[1], 0, 0, 0, 0, 0, 0];
    fixture.sequence_numbers = [4, 7, 0, 0, 0, 0, 0, 0];
    fixture.settled_values =
        [0xffffffffffffffffffffffffffffffff, 0xffffffffffffffffffffffffffffffff, 0, 0, 0, 0, 0, 0];
    fixture.settled_flags = [true, true, false, false, false, false, false, false];
    fixture.last_commitment_ref_hi = fixture.record_refs_hi[1];
    fixture.last_commitment_ref_lo = fixture.record_refs_lo[1];
    fixture.reputation_counter = 7;
    fixture.cumulative_settled_value = 0xffffffffffffffffffffffffffffffff;
    execute(refresh_history_root(fixture));
}

#[test(should_fail_with = "reputation counter mismatch")]
fn wrong_reputation_counter_is_rejected() {
    let mut fixture = canonical_fixture();
    fixture.reputation_counter -= 1;
    execute(fixture);
}

#[test(should_fail_with = "last commitment reference hi mismatch")]
fn wrong_last_commitment_reference_hi_is_rejected() {
    let mut fixture = canonical_fixture();
    fixture.last_commitment_ref_hi += 1;
    execute(fixture);
}

#[test(should_fail_with = "last commitment reference lo mismatch")]
fn wrong_last_commitment_reference_lo_is_rejected() {
    let mut fixture = canonical_fixture();
    fixture.last_commitment_ref_lo += 1;
    execute(fixture);
}

#[test(should_fail_with = "reputation history root mismatch")]
fn stale_history_root_after_record_change_is_rejected() {
    let mut fixture = canonical_fixture();
    fixture.settled_values[1] += 1;
    fixture.cumulative_settled_value += 1;
    execute(fixture);
}

#[test(should_fail_with = "reputation history root mismatch")]
fn wrong_history_root_is_rejected() {
    let mut fixture = canonical_fixture();
    fixture.history_root += 1;
    execute(fixture);
}
