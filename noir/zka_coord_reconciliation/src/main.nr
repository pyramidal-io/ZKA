use zka_coord_v2::{compute_state_input_commitment, CoordReceiptV2, validate_receipt};
use zka_lib::poseidon2;

global DOMAIN_RECONCILIATION_SOURCE: Field =
    0x0000000000007a6b612f636f6f72642f7265636f6e63696c652f736f75726365;
global DOMAIN_RECONCILIATION_OUTPUT: Field =
    0x0000000000007a6b612f636f6f72642f7265636f6e63696c652f6f7574707574;
global DOMAIN_RECONCILIATION_DATA_AVAILABILITY: Field =
    0x000000000000000000007a6b612f636f6f72642f7265636f6e63696c652f6461;
global RECONCILIATION_PROFILE_ID: Field =
    0x147446fe0f34833135f89bc9d7aa756cb778f8e8fbd77e570996ff1a8df752e1;

fn compute_source_commitment(
    source_id: u32,
    record_count: u8,
    keys: [u64; 4],
    values: [u64; 4],
    exception_codes: [u8; 4],
) -> Field {
    let mut state = poseidon2(DOMAIN_RECONCILIATION_SOURCE, 14);
    state = poseidon2(state, source_id as Field);
    state = poseidon2(state, record_count as Field);
    for slot in 0..4 {
        state = poseidon2(state, keys[slot] as Field);
        state = poseidon2(state, values[slot] as Field);
        state = poseidon2(state, exception_codes[slot] as Field);
    }
    state
}

fn compute_output_commitment(
    output_count: u8,
    output_keys: [u64; 16],
    output_values: [u64; 16],
) -> Field {
    let mut state = poseidon2(DOMAIN_RECONCILIATION_OUTPUT, 33);
    state = poseidon2(state, output_count as Field);
    for output in 0..16 {
        state = poseidon2(state, output_keys[output] as Field);
        state = poseidon2(state, output_values[output] as Field);
    }
    state
}

fn compute_data_availability_commitment(
    predecessor_count: u8,
    input_commitments: [Field; 4],
    availability_references: [Field; 4],
) -> Field {
    let mut state = poseidon2(DOMAIN_RECONCILIATION_DATA_AVAILABILITY, 9);
    state = poseidon2(state, predecessor_count as Field);
    for source in 0..4 {
        state = poseidon2(state, input_commitments[source]);
        state = poseidon2(state, availability_references[source]);
    }
    state
}

fn validate_reconciliation_receipt_binding(
    profile_id: Field,
    profile_version: u32,
    assurance_class: u8,
    predecessor_count: u8,
    input_commitments: [Field; 4],
    pre_state_commitment: Field,
    output_commitment: Field,
    post_state_commitment: Field,
    external_fact_commitment: Field,
    data_availability_commitment: Field,
    output_count: u8,
    output_keys: [u64; 16],
    output_values: [u64; 16],
    availability_references: [Field; 4],
) {
    assert(profile_id == RECONCILIATION_PROFILE_ID, "Wrong reconciliation profile id");
    assert(profile_version == 1, "Wrong reconciliation profile version");
    assert(assurance_class == 1, "Reconciliation profile requires ZK-native assurance");
    assert(
        predecessor_count >= 2 & predecessor_count <= 4,
        "Reconciliation receipt requires two to four predecessors",
    );
    assert(
        pre_state_commitment
            == compute_state_input_commitment(predecessor_count, input_commitments),
        "Reconciliation pre-state must bind all authenticated source roots",
    );

    let expected_output = compute_output_commitment(output_count, output_keys, output_values);
    assert(output_commitment == expected_output, "Reconciliation output commitment mismatch");
    assert(
        post_state_commitment == expected_output,
        "Reconciliation post-state must equal the reconciled output root",
    );
    assert(
        external_fact_commitment == 0,
        "Reconciliation uses profile-local exceptions, not external facts",
    );

    for source in 0..4 {
        if source < predecessor_count as u32 {
            assert(
                availability_references[source] != 0,
                "Active source requires a data-availability reference commitment",
            );
        } else {
            assert(
                availability_references[source] == 0,
                "Inactive availability reference slots must be zero",
            );
        }
    }
    assert(
        data_availability_commitment
            == compute_data_availability_commitment(
                predecessor_count,
                input_commitments,
                availability_references,
            ),
        "Data-availability commitment mismatch",
    );
}

fn validate_authenticated_inputs(
    predecessor_count: u8,
    input_commitments: [Field; 4],
    source_ids: [u32; 4],
    source_counts: [u8; 4],
    input_keys: [u64; 16],
    input_values: [u64; 16],
    exception_codes: [u8; 16],
) {
    for source in 0..4 {
        let offset = source * 4;
        if source < predecessor_count as u32 {
            assert(source_ids[source] != 0, "Active source identity must be non-zero");
            for previous in 0..4 {
                if previous < source {
                    assert(
                        source_ids[source] != source_ids[previous],
                        "Active source identities must be distinct",
                    );
                }
            }
            let expected = compute_source_commitment(
                source_ids[source],
                source_counts[source],
                [
                    input_keys[offset],
                    input_keys[offset + 1],
                    input_keys[offset + 2],
                    input_keys[offset + 3],
                ],
                [
                    input_values[offset],
                    input_values[offset + 1],
                    input_values[offset + 2],
                    input_values[offset + 3],
                ],
                [
                    exception_codes[offset],
                    exception_codes[offset + 1],
                    exception_codes[offset + 2],
                    exception_codes[offset + 3],
                ],
            );
            assert(
                input_commitments[source] == expected,
                "Source records do not match authenticated Coord input commitment",
            );
        } else {
            assert(
                (source_ids[source] == 0)
                    & (source_counts[source] == 0)
                    & (input_commitments[source] == 0),
                "Inactive source metadata and commitment must be zero",
            );
        }
    }
}

fn validate_reconciliation_claim(
    source_count: u8,
    source_counts: [u8; 4],
    input_keys: [u64; 16],
    input_values: [u64; 16],
    exception_codes: [u8; 16],
    output_count: u8,
    output_keys: [u64; 16],
    output_values: [u64; 16],
) {
    assert(source_count >= 2 & source_count <= 4, "Reconciliation requires two to four sources");
    assert(output_count <= 16, "Reconciliation output count is out of bounds");

    let mut total_input_value: Field = 0;
    let mut total_exception_value: Field = 0;
    let mut active_input_count: u32 = 0;
    let mut exception_count: u32 = 0;

    for source in 0..4 {
        let active_source = source < source_count as u32;
        if active_source {
            assert(
                source_counts[source] > 0 & source_counts[source] <= 4,
                "Active source record count is out of bounds",
            );
        } else {
            assert(source_counts[source] == 0, "Inactive source count must be zero");
        }

        for slot in 0..4 {
            let index = source * 4 + slot;
            let active_record = active_source & slot < source_counts[source] as u32;
            if active_record {
                assert(input_keys[index] != 0, "Active input record key must be non-zero");
                assert(input_values[index] != 0, "Active input record value must be non-zero");
                assert(exception_codes[index] <= 3, "Unknown reconciliation exception code");
                if slot + 1 < source_counts[source] as u32 {
                    assert(
                        input_keys[index] < input_keys[index + 1],
                        "Source records must use canonical unique key order",
                    );
                }
                total_input_value = total_input_value + input_values[index] as Field;
                active_input_count = active_input_count + 1;
                if exception_codes[index] != 0 {
                    total_exception_value = total_exception_value + input_values[index] as Field;
                    exception_count = exception_count + 1;
                } else {
                    let mut match_count: Field = 0;
                    for output in 0..16 {
                        if (output < output_count as u32)
                            & (output_keys[output] == input_keys[index]) {
                            match_count = match_count + 1;
                        }
                    }
                    assert(match_count == 1, "Every non-exception input must match one output");
                }
            } else {
                assert(
                    (input_keys[index] == 0)
                        & (input_values[index] == 0)
                        & (exception_codes[index] == 0),
                    "Inactive input record slots must be zero",
                );
            }
        }
    }

    let mut total_output_value: Field = 0;
    for output in 0..16 {
        if output < output_count as u32 {
            assert(output_keys[output] != 0, "Active output key must be non-zero");
            assert(output_values[output] != 0, "Active output value must be non-zero");
            if output + 1 < output_count as u32 {
                assert(
                    output_keys[output] < output_keys[output + 1],
                    "Output records must use canonical unique key order",
                );
            }

            let mut expected_value: Field = 0;
            for input in 0..16 {
                if (input_keys[input] == output_keys[output]) & (exception_codes[input] == 0) {
                    expected_value = expected_value + input_values[input] as Field;
                }
            }
            assert(
                expected_value == output_values[output] as Field,
                "Output value does not equal matched input aggregate",
            );
            total_output_value = total_output_value + output_values[output] as Field;
        } else {
            assert(
                (output_keys[output] == 0) & (output_values[output] == 0),
                "Inactive output record slots must be zero",
            );
        }
    }

    assert(
        total_input_value == total_output_value + total_exception_value,
        "Reconciliation value conservation violated",
    );
    assert(
        active_input_count >= exception_count + output_count as u32,
        "Reconciliation count conservation violated",
    );
}

fn validate_source_ingress_claim(
    predecessor_count: u8,
    initial_state_commitment: Field,
    input_commitments: [Field; 4],
    pre_state_commitment: Field,
    output_commitment: Field,
    post_state_commitment: Field,
    external_fact_commitment: Field,
    data_availability_commitment: Field,
    source_ids: [u32; 4],
    source_counts: [u8; 4],
    input_keys: [u64; 16],
    input_values: [u64; 16],
    exception_codes: [u8; 16],
    availability_references: [Field; 4],
) {
    assert(predecessor_count <= 1, "Source ingress accepts at most one workflow predecessor");
    if predecessor_count == 0 {
        assert(
            pre_state_commitment == initial_state_commitment,
            "Genesis source ingress pre-state must equal initial state",
        );
    } else {
        assert(
            pre_state_commitment
                == compute_state_input_commitment(predecessor_count, input_commitments),
            "Sequenced source ingress pre-state must bind its workflow predecessor",
        );
    }
    assert(source_ids[0] != 0, "Source ingress identity must be non-zero");
    assert(
        source_counts[0] > 0 & source_counts[0] <= 4,
        "Source ingress record count is out of bounds",
    );
    for source in 1..4 {
        assert(
            (source_ids[source] == 0)
                & (source_counts[source] == 0)
                & (availability_references[source] == 0),
            "Inactive source ingress metadata must be zero",
        );
    }
    for input in 0..16 {
        if input < source_counts[0] as u32 {
            assert(input_keys[input] != 0, "Active input record key must be non-zero");
            assert(input_values[input] != 0, "Active input record value must be non-zero");
            assert(exception_codes[input] <= 3, "Unknown reconciliation exception code");
            if input + 1 < source_counts[0] as u32 {
                assert(
                    input_keys[input] < input_keys[input + 1],
                    "Source records must use canonical unique key order",
                );
            }
        } else {
            assert(
                (input_keys[input] == 0)
                    & (input_values[input] == 0)
                    & (exception_codes[input] == 0),
                "Inactive input record slots must be zero",
            );
        }
    }
    let expected_source = compute_source_commitment(
        source_ids[0],
        source_counts[0],
        [input_keys[0], input_keys[1], input_keys[2], input_keys[3]],
        [input_values[0], input_values[1], input_values[2], input_values[3]],
        [exception_codes[0], exception_codes[1], exception_codes[2], exception_codes[3]],
    );
    assert(output_commitment == expected_source, "Source ingress commitment mismatch");
    assert(
        post_state_commitment == expected_source,
        "Source ingress post-state must equal its record-set root",
    );
    assert(
        external_fact_commitment == 0,
        "Source ingress uses profile-local exceptions, not external facts",
    );
    assert(
        availability_references[0] != 0,
        "Source ingress requires a data-availability reference commitment",
    );
    assert(
        data_availability_commitment
            == compute_data_availability_commitment(
                1,
                [expected_source, 0, 0, 0],
                availability_references,
            ),
        "Data-availability commitment mismatch",
    );
}

fn main(
    protocol_version: pub u8,
    workflow_definition_hash: pub Field,
    workflow_instance_id: pub Field,
    context: pub Field,
    initial_state_commitment: pub Field,
    profile_id: pub Field,
    profile_version: pub u32,
    profile_manifest_hash: pub Field,
    profile_vk_hash: pub Field,
    verifier_policy_root: pub Field,
    assurance_class: pub u8,
    step_id: pub Field,
    step_index: pub u32,
    predecessor_count: pub u8,
    predecessor_step_ids: pub [Field; 4],
    input_commitments: pub [Field; 4],
    input_set_commitment: pub Field,
    pre_state_commitment: pub Field,
    output_commitment: pub Field,
    post_state_commitment: pub Field,
    external_fact_commitment: pub Field,
    data_availability_commitment: pub Field,
    topology_commitment: pub Field,
    receipt_commitment: pub Field,
    workflow_path: [Field; 32],
    source_ids: [u32; 4],
    source_counts: [u8; 4],
    input_keys: [u64; 16],
    input_values: [u64; 16],
    exception_codes: [u8; 16],
    output_count: u8,
    output_keys: [u64; 16],
    output_values: [u64; 16],
    availability_references: [Field; 4],
) {
    let receipt = CoordReceiptV2 {
        protocol_version,
        workflow_definition_hash,
        workflow_instance_id,
        context,
        initial_state_commitment,
        profile_id,
        profile_version,
        profile_manifest_hash,
        profile_vk_hash,
        verifier_policy_root,
        assurance_class,
        step_id,
        step_index,
        predecessor_count,
        predecessor_step_ids,
        input_commitments,
        input_set_commitment,
        pre_state_commitment,
        output_commitment,
        post_state_commitment,
        external_fact_commitment,
        data_availability_commitment,
        topology_commitment,
        receipt_commitment,
    };
    validate_receipt(receipt, workflow_path);
    if predecessor_count <= 1 {
        assert(profile_id == RECONCILIATION_PROFILE_ID, "Wrong reconciliation profile id");
        assert(profile_version == 1, "Wrong reconciliation profile version");
        assert(assurance_class == 1, "Reconciliation profile requires ZK-native assurance");
        assert(output_count == 0, "Source ingress must not carry reconciled output records");
        for output in 0..16 {
            assert(
                (output_keys[output] == 0) & (output_values[output] == 0),
                "Source ingress output record slots must be zero",
            );
        }
        validate_source_ingress_claim(
            predecessor_count,
            initial_state_commitment,
            input_commitments,
            pre_state_commitment,
            output_commitment,
            post_state_commitment,
            external_fact_commitment,
            data_availability_commitment,
            source_ids,
            source_counts,
            input_keys,
            input_values,
            exception_codes,
            availability_references,
        );
    } else {
        validate_authenticated_inputs(
            predecessor_count,
            input_commitments,
            source_ids,
            source_counts,
            input_keys,
            input_values,
            exception_codes,
        );
        validate_reconciliation_claim(
            predecessor_count,
            source_counts,
            input_keys,
            input_values,
            exception_codes,
            output_count,
            output_keys,
            output_values,
        );
        validate_reconciliation_receipt_binding(
            profile_id,
            profile_version,
            assurance_class,
            predecessor_count,
            input_commitments,
            pre_state_commitment,
            output_commitment,
            post_state_commitment,
            external_fact_commitment,
            data_availability_commitment,
            output_count,
            output_keys,
            output_values,
            availability_references,
        );
    }
}

#[test]
fn accepts_two_source_fan_in_with_duplicate_key_aggregation() {
    let source_counts: [u8; 4] = [2, 2, 0, 0];
    let input_keys: [u64; 16] = [10, 20, 0, 0, 10, 30, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    let input_values: [u64; 16] = [7, 5, 0, 0, 11, 13, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    let exception_codes: [u8; 16] = [0; 16];
    let output_keys: [u64; 16] = [10, 20, 30, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    let output_values: [u64; 16] = [18, 5, 13, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

    validate_reconciliation_claim(
        2,
        source_counts,
        input_keys,
        input_values,
        exception_codes,
        3,
        output_keys,
        output_values,
    );
}

#[test]
fn source_commitment_binds_order_values_and_exceptions() {
    let keys: [u64; 4] = [10, 20, 0, 0];
    let values: [u64; 4] = [7, 5, 0, 0];
    let exceptions: [u8; 4] = [0, 2, 0, 0];
    let commitment = compute_source_commitment(17, 2, keys, values, exceptions);
    assert(commitment == 0x0affcd8efdb78c471d6100974340cbec71b3231f1aa3d2e959282cdcf96360c6);

    assert(compute_source_commitment(18, 2, keys, values, exceptions) != commitment);
    assert(
        compute_source_commitment(17, 2, [20, 10, 0, 0], [5, 7, 0, 0], [2, 0, 0, 0]) != commitment,
    );
    assert(compute_source_commitment(17, 2, keys, [7, 6, 0, 0], exceptions) != commitment);
    assert(compute_source_commitment(17, 2, keys, values, [0, 3, 0, 0]) != commitment);
}

#[test]
fn accepts_canonical_genesis_source_ingress() {
    let source_commitment = compute_source_commitment(17, 2, [10, 20, 0, 0], [7, 5, 0, 0], [0; 4]);
    validate_source_ingress_claim(
        0,
        4,
        [0; 4],
        4,
        source_commitment,
        source_commitment,
        0,
        compute_data_availability_commitment(1, [source_commitment, 0, 0, 0], [21, 0, 0, 0]),
        [17, 0, 0, 0],
        [2, 0, 0, 0],
        [10, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        [7, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        [0; 16],
        [21, 0, 0, 0],
    );
}

#[test]
fn accepts_sequenced_source_ingress() {
    let source_commitment =
        compute_source_commitment(18, 2, [10, 30, 0, 0], [11, 13, 0, 0], [0; 4]);
    validate_source_ingress_claim(
        1,
        4,
        [99, 0, 0, 0],
        compute_state_input_commitment(1, [99, 0, 0, 0]),
        source_commitment,
        source_commitment,
        0,
        compute_data_availability_commitment(1, [source_commitment, 0, 0, 0], [22, 0, 0, 0]),
        [18, 0, 0, 0],
        [2, 0, 0, 0],
        [10, 30, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        [11, 13, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        [0; 16],
        [22, 0, 0, 0],
    );
}

#[test]
fn authenticates_each_active_source_against_coord_inputs() {
    let source_ids: [u32; 4] = [17, 18, 0, 0];
    let source_counts: [u8; 4] = [2, 2, 0, 0];
    let input_keys: [u64; 16] = [10, 20, 0, 0, 10, 30, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    let input_values: [u64; 16] = [7, 5, 0, 0, 11, 13, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    let exceptions: [u8; 16] = [0; 16];
    let commitments: [Field; 4] = [
        compute_source_commitment(17, 2, [10, 20, 0, 0], [7, 5, 0, 0], [0; 4]),
        compute_source_commitment(18, 2, [10, 30, 0, 0], [11, 13, 0, 0], [0; 4]),
        0,
        0,
    ];

    validate_authenticated_inputs(
        2,
        commitments,
        source_ids,
        source_counts,
        input_keys,
        input_values,
        exceptions,
    );
}

#[test]
fn output_commitment_binds_count_order_keys_and_values() {
    let keys: [u64; 16] = [10, 20, 30, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    let values: [u64; 16] = [18, 5, 13, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    let commitment = compute_output_commitment(3, keys, values);
    assert(commitment == 0x1934ead544def182b3175dd219f2049fd191ab21e13e84418191a9c893f10bf6);

    assert(compute_output_commitment(2, keys, values) != commitment);
    assert(
        compute_output_commitment(
            3,
            [20, 10, 30, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            [5, 18, 13, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        )
            != commitment,
    );
    assert(
        compute_output_commitment(3, keys, [19, 5, 13, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
            != commitment,
    );
}

#[test]
fn data_availability_commitment_binds_active_sources_and_references() {
    let inputs: [Field; 4] = [11, 12, 0, 0];
    let references: [Field; 4] = [21, 22, 0, 0];
    let commitment = compute_data_availability_commitment(2, inputs, references);
    assert(commitment == 0x25212bcbd5f2c833f0cf4f7521fd00c623a2afc71b64c7e60df5f3c3521643fd);

    assert(compute_data_availability_commitment(1, inputs, references) != commitment);
    assert(compute_data_availability_commitment(2, [12, 11, 0, 0], references) != commitment);
    assert(compute_data_availability_commitment(2, inputs, [22, 21, 0, 0]) != commitment);
}

#[test]
fn binds_reconciliation_claim_to_coord_receipt_state_and_evidence() {
    let input_commitments: [Field; 4] = [11, 12, 0, 0];
    let availability_references: [Field; 4] = [21, 22, 0, 0];
    let output_keys: [u64; 16] = [10, 20, 30, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    let output_values: [u64; 16] = [18, 5, 13, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    let output = compute_output_commitment(3, output_keys, output_values);

    validate_reconciliation_receipt_binding(
        0x147446fe0f34833135f89bc9d7aa756cb778f8e8fbd77e570996ff1a8df752e1,
        1,
        1,
        2,
        input_commitments,
        compute_state_input_commitment(2, input_commitments),
        output,
        output,
        0,
        compute_data_availability_commitment(2, input_commitments, availability_references),
        3,
        output_keys,
        output_values,
        availability_references,
    );
}

#[test]
fn accepts_declared_exception_with_value_conservation() {
    validate_reconciliation_claim(
        2,
        [2, 2, 0, 0],
        [10, 20, 0, 0, 10, 30, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        [7, 5, 0, 0, 11, 13, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        [0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        2,
        [10, 30, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        [18, 13, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    );
}

#[test]
fn accepts_all_records_as_declared_exceptions() {
    validate_reconciliation_claim(
        2,
        [1, 1, 0, 0],
        [10, 0, 0, 0, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        [7, 0, 0, 0, 11, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        [1, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        0,
        [0; 16],
        [0; 16],
    );
}

#[test(should_fail_with = "Active source identities must be distinct")]
fn rejects_duplicate_active_source_identities() {
    let commitments: [Field; 4] = [
        compute_source_commitment(17, 1, [10, 0, 0, 0], [7, 0, 0, 0], [0; 4]),
        compute_source_commitment(17, 1, [20, 0, 0, 0], [11, 0, 0, 0], [0; 4]),
        0,
        0,
    ];
    validate_authenticated_inputs(
        2,
        commitments,
        [17, 17, 0, 0],
        [1, 1, 0, 0],
        [10, 0, 0, 0, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        [7, 0, 0, 0, 11, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        [0; 16],
    );
}

#[test(should_fail_with = "Output value does not equal matched input aggregate")]
fn rejects_broken_value_aggregation() {
    validate_reconciliation_claim(
        2,
        [1, 1, 0, 0],
        [10, 0, 0, 0, 10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        [7, 0, 0, 0, 11, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        [0; 16],
        1,
        [10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        [17, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    );
}

#[test(should_fail_with = "Source records must use canonical unique key order")]
fn rejects_duplicate_or_reordered_source_records() {
    validate_reconciliation_claim(
        2,
        [2, 1, 0, 0],
        [10, 10, 0, 0, 10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        [7, 5, 0, 0, 11, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        [0; 16],
        1,
        [10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        [23, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    );
}

#[test(should_fail_with = "Every non-exception input must match one output")]
fn rejects_undeclared_dropped_record() {
    validate_reconciliation_claim(
        2,
        [1, 1, 0, 0],
        [10, 0, 0, 0, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        [7, 0, 0, 0, 11, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        [0; 16],
        1,
        [10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        [7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    );
}

#[test(should_fail_with = "Source records do not match authenticated Coord input commitment")]
fn rejects_authenticated_source_substitution() {
    validate_authenticated_inputs(
        2,
        [11, 12, 0, 0],
        [17, 18, 0, 0],
        [1, 1, 0, 0],
        [10, 0, 0, 0, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        [7, 0, 0, 0, 11, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        [0; 16],
    );
}

#[test(should_fail_with = "Reconciliation post-state must equal the reconciled output root")]
fn rejects_post_state_substitution() {
    let keys: [u64; 16] = [10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    let values: [u64; 16] = [7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    let output = compute_output_commitment(1, keys, values);
    validate_reconciliation_receipt_binding(
        RECONCILIATION_PROFILE_ID,
        1,
        1,
        2,
        [11, 12, 0, 0],
        compute_state_input_commitment(2, [11, 12, 0, 0]),
        output,
        output + 1,
        0,
        compute_data_availability_commitment(2, [11, 12, 0, 0], [21, 22, 0, 0]),
        1,
        keys,
        values,
        [21, 22, 0, 0],
    );
}

#[test(should_fail_with = "Reconciliation pre-state must bind all authenticated source roots")]
fn rejects_pre_state_source_omission() {
    let keys: [u64; 16] = [10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    let values: [u64; 16] = [7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    let output = compute_output_commitment(1, keys, values);
    validate_reconciliation_receipt_binding(
        RECONCILIATION_PROFILE_ID,
        1,
        1,
        2,
        [11, 12, 0, 0],
        compute_state_input_commitment(1, [11, 0, 0, 0]),
        output,
        output,
        0,
        compute_data_availability_commitment(2, [11, 12, 0, 0], [21, 22, 0, 0]),
        1,
        keys,
        values,
        [21, 22, 0, 0],
    );
}
