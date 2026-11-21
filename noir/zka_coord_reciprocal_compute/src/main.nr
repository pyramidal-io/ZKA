use zka_coord_v2::{
    compute_input_set_commitment, compute_receipt_commitment, compute_topology_commitment,
    CoordReceiptV2, validate_receipt,
};
use zka_lib::{compute_merkle_root, poseidon2};

global DOMAIN_RECIPROCAL_SETUP: Field =
    0x00000000000000000000007a6b612f636f6f72642f72782f73657475702f7631;
global DOMAIN_RECIPROCAL_CHUNKS: Field =
    0x000000000000000000007a6b612f636f6f72642f72782f6368756e6b732f7631;
global DOMAIN_RECIPROCAL_OUTPUT: Field =
    0x000000000000000000007a6b612f636f6f72642f72782f6f75747075742f7631;
global DOMAIN_RECIPROCAL_DATA_AVAILABILITY: Field =
    0x00000000000000000000000000007a6b612f636f6f72642f72782f64612f7631;
global DOMAIN_RECIPROCAL_CROSS_LINK: Field =
    0x00000000000000000000007a6b612f636f6f72642f72782f63726f73732f7631;
global RECIPROCAL_SIGNATURE_SCHEME_ID: Field =
    0x000000000000000000000000007a6b612f636f6f72642f72782f6b65792f7631;
global RECIPROCAL_COMPUTE_PROFILE_ID: Field =
    0x1aba8f8267027cdbd3e5ac25dc6767ffaf379e08541452dd1ea6b7a6f9710607;

struct ReciprocalSetup {
    version: u8,
    workflow_definition_hash: Field,
    workflow_instance_id: Field,
    context: Field,
    producer_role: u8,
    consumer_role: u8,
    producer_identity_key: [Field; 4],
    consumer_identity_key: [Field; 4],
    signature_scheme_id: Field,
    producer_ack_key: [Field; 4],
    consumer_ack_key: [Field; 4],
    initial_input_commitment: Field,
    leg1_sender_role: u8,
    leg1_recipient_role: u8,
    leg1_compute_profile_id: Field,
    leg1_transform_id: Field,
    leg1_multiplier: Field,
    leg1_offset: Field,
    leg2_sender_role: u8,
    leg2_recipient_role: u8,
    leg2_compute_profile_id: Field,
    leg2_transform_id: Field,
    leg2_multiplier: Field,
    leg2_offset: Field,
    active_chunks: u8,
    element_count: u8,
    chunk_width: u8,
    da_policy: Field,
    acknowledgement_deadline: u64,
    setup_expiry: u64,
    abort_channel_id: Field,
}

struct ReciprocalLeg {
    index: u32,
    sender_role: u8,
    recipient_role: u8,
    compute_profile_id: Field,
    transform_id: Field,
    multiplier: Field,
    offset: Field,
    prior_receipt_commitment: Field,
    prior_graph_commitment: Field,
}

struct ReciprocalDelivery {
    package_commitment: Field,
    retrieval_reference: Field,
    custodian_role: u8,
    retention_deadline: u64,
}

fn fold_key_limbs(mut state: Field, key: [Field; 4]) -> Field {
    for index in 0..4 {
        state = poseidon2(state, key[index]);
    }
    state
}

fn validate_key_limbs(key: [Field; 4]) {
    for index in 0..4 {
        key[index].assert_max_bit_size::<128>();
    }
}

fn validate_chunk_shape(active_chunks: u8, element_count: u8, values: [Field; 16]) {
    assert(
        active_chunks > 0 & active_chunks <= 4,
        "Reciprocal active chunk count is out of bounds",
    );
    assert(
        element_count > 0 & element_count <= active_chunks * 4,
        "Reciprocal element count is out of bounds",
    );
    for index in 0..16 {
        if index >= element_count as u32 {
            assert(values[index] == 0, "Inactive reciprocal chunk slots must be zero");
        }
    }
}

fn validate_affine_transform(
    active_chunks: u8,
    element_count: u8,
    inputs: [Field; 16],
    outputs: [Field; 16],
    multiplier: Field,
    offset: Field,
) {
    validate_chunk_shape(active_chunks, element_count, inputs);
    validate_chunk_shape(active_chunks, element_count, outputs);
    for index in 0..16 {
        if index < element_count as u32 {
            assert(
                outputs[index] == multiplier * inputs[index] + offset,
                "Reciprocal affine output mismatch",
            );
        }
    }
}

fn compute_reciprocal_chunk_commitment(
    active_chunks: u8,
    element_count: u8,
    values: [Field; 16],
) -> Field {
    validate_chunk_shape(active_chunks, element_count, values);
    let mut state = poseidon2(DOMAIN_RECIPROCAL_CHUNKS, 18);
    state = poseidon2(state, active_chunks as Field);
    state = poseidon2(state, element_count as Field);
    for index in 0..16 {
        state = poseidon2(state, values[index]);
    }
    state
}

fn compute_reciprocal_output_commitment(
    active_chunks: u8,
    element_count: u8,
    values: [Field; 16],
) -> Field {
    validate_chunk_shape(active_chunks, element_count, values);
    let mut state = poseidon2(DOMAIN_RECIPROCAL_OUTPUT, 18);
    state = poseidon2(state, active_chunks as Field);
    state = poseidon2(state, element_count as Field);
    for index in 0..16 {
        state = poseidon2(state, values[index]);
    }
    state
}

fn compute_reciprocal_data_availability_commitment(
    output_commitment: Field,
    package_commitment: Field,
    retrieval_reference: Field,
    custodian_role: u8,
    retention_deadline: u64,
    leg_index: u32,
) -> Field {
    let mut state = poseidon2(DOMAIN_RECIPROCAL_DATA_AVAILABILITY, 6);
    state = poseidon2(state, output_commitment);
    state = poseidon2(state, package_commitment);
    state = poseidon2(state, retrieval_reference);
    state = poseidon2(state, custodian_role as Field);
    state = poseidon2(state, retention_deadline as Field);
    poseidon2(state, leg_index as Field)
}

fn compute_reciprocal_setup_commitment(setup: ReciprocalSetup) -> Field {
    let mut state = poseidon2(DOMAIN_RECIPROCAL_SETUP, 43);
    state = poseidon2(state, setup.version as Field);
    state = poseidon2(state, setup.workflow_definition_hash);
    state = poseidon2(state, setup.workflow_instance_id);
    state = poseidon2(state, setup.context);
    state = poseidon2(state, setup.producer_role as Field);
    state = poseidon2(state, setup.consumer_role as Field);
    state = fold_key_limbs(state, setup.producer_identity_key);
    state = fold_key_limbs(state, setup.consumer_identity_key);
    state = poseidon2(state, setup.signature_scheme_id);
    state = fold_key_limbs(state, setup.producer_ack_key);
    state = fold_key_limbs(state, setup.consumer_ack_key);
    state = poseidon2(state, setup.initial_input_commitment);
    state = poseidon2(state, setup.leg1_sender_role as Field);
    state = poseidon2(state, setup.leg1_recipient_role as Field);
    state = poseidon2(state, setup.leg1_compute_profile_id);
    state = poseidon2(state, setup.leg1_transform_id);
    state = poseidon2(state, setup.leg1_multiplier);
    state = poseidon2(state, setup.leg1_offset);
    state = poseidon2(state, setup.leg2_sender_role as Field);
    state = poseidon2(state, setup.leg2_recipient_role as Field);
    state = poseidon2(state, setup.leg2_compute_profile_id);
    state = poseidon2(state, setup.leg2_transform_id);
    state = poseidon2(state, setup.leg2_multiplier);
    state = poseidon2(state, setup.leg2_offset);
    state = poseidon2(state, setup.active_chunks as Field);
    state = poseidon2(state, setup.element_count as Field);
    state = poseidon2(state, setup.chunk_width as Field);
    state = poseidon2(state, setup.da_policy);
    state = poseidon2(state, setup.acknowledgement_deadline as Field);
    state = poseidon2(state, setup.setup_expiry as Field);
    poseidon2(state, setup.abort_channel_id)
}

fn compute_reciprocal_cross_link(
    prior_receipt_commitment: Field,
    prior_graph_commitment: Field,
    setup_commitment: Field,
    leg_index: u32,
) -> Field {
    let mut state = poseidon2(DOMAIN_RECIPROCAL_CROSS_LINK, 4);
    state = poseidon2(state, prior_receipt_commitment);
    state = poseidon2(state, prior_graph_commitment);
    state = poseidon2(state, setup_commitment);
    poseidon2(state, leg_index as Field)
}

fn validate_setup(setup: ReciprocalSetup, receipt: CoordReceiptV2) {
    assert(setup.version == 1, "Wrong reciprocal setup version");
    assert(
        setup.workflow_instance_id == receipt.workflow_instance_id,
        "Reciprocal setup workflow instance mismatch",
    );
    assert(setup.context == receipt.context, "Reciprocal setup context mismatch");
    assert(
        (setup.producer_role != 0)
            & (setup.consumer_role != 0)
            & (setup.producer_role != setup.consumer_role),
        "Reciprocal setup roles are invalid",
    );
    assert(
        setup.signature_scheme_id == RECIPROCAL_SIGNATURE_SCHEME_ID,
        "Wrong reciprocal acknowledgement signature scheme",
    );
    assert(setup.chunk_width == 4, "Reciprocal chunk width must be four");
    assert(
        (setup.leg1_compute_profile_id == RECIPROCAL_COMPUTE_PROFILE_ID)
            & (setup.leg2_compute_profile_id == RECIPROCAL_COMPUTE_PROFILE_ID),
        "Wrong reciprocal compute profile id",
    );
    assert(setup.da_policy != 0, "Reciprocal data-availability policy must be non-zero");
    assert(
        setup.acknowledgement_deadline <= setup.setup_expiry,
        "Reciprocal setup expires before its acknowledgement deadline",
    );
    assert(setup.abort_channel_id != 0, "Reciprocal abort channel must be non-zero");
    validate_key_limbs(setup.producer_identity_key);
    validate_key_limbs(setup.consumer_identity_key);
    validate_key_limbs(setup.producer_ack_key);
    validate_key_limbs(setup.consumer_ack_key);
}

fn validate_leg_matches_setup(setup: ReciprocalSetup, leg: ReciprocalLeg) {
    assert((leg.index == 1) | (leg.index == 2), "Reciprocal leg index is out of bounds");
    if leg.index == 1 {
        assert(leg.sender_role == setup.leg1_sender_role, "Reciprocal leg sender mismatch");
        assert(
            leg.recipient_role == setup.leg1_recipient_role,
            "Reciprocal leg recipient mismatch",
        );
        assert(
            leg.compute_profile_id == setup.leg1_compute_profile_id,
            "Reciprocal compute profile does not match setup",
        );
        assert(
            leg.transform_id == setup.leg1_transform_id,
            "Reciprocal transform id does not match setup",
        );
        assert(
            leg.multiplier == setup.leg1_multiplier,
            "Reciprocal multiplier does not match setup",
        );
        assert(leg.offset == setup.leg1_offset, "Reciprocal offset does not match setup");
    } else {
        assert(leg.sender_role == setup.leg2_sender_role, "Reciprocal leg sender mismatch");
        assert(
            leg.recipient_role == setup.leg2_recipient_role,
            "Reciprocal leg recipient mismatch",
        );
        assert(
            leg.compute_profile_id == setup.leg2_compute_profile_id,
            "Reciprocal compute profile does not match setup",
        );
        assert(
            leg.transform_id == setup.leg2_transform_id,
            "Reciprocal transform id does not match setup",
        );
        assert(
            leg.multiplier == setup.leg2_multiplier,
            "Reciprocal multiplier does not match setup",
        );
        assert(leg.offset == setup.leg2_offset, "Reciprocal offset does not match setup");
    }
}

fn validate_reciprocal_compute_receipt(
    receipt: CoordReceiptV2,
    workflow_path: [Field; 32],
    setup: ReciprocalSetup,
    leg: ReciprocalLeg,
    input_values: [Field; 16],
    output_values: [Field; 16],
    delivery: ReciprocalDelivery,
) {
    validate_receipt(receipt, workflow_path);
    validate_setup(setup, receipt);
    validate_leg_matches_setup(setup, leg);
    assert(
        receipt.profile_id == RECIPROCAL_COMPUTE_PROFILE_ID,
        "Wrong reciprocal compute profile id",
    );
    assert(receipt.profile_version == 1, "Wrong reciprocal compute profile version");
    assert(receipt.assurance_class == 1, "Reciprocal compute requires ZK-native assurance");
    assert(
        receipt.external_fact_commitment == 0,
        "Reciprocal compute does not authenticate external facts",
    );
    assert(
        receipt.data_availability_commitment != 0,
        "Reciprocal compute requires retained delivery material",
    );
    assert(delivery.package_commitment != 0, "Reciprocal delivery package must be non-zero");
    assert(delivery.retrieval_reference != 0, "Reciprocal retrieval reference must be non-zero");
    assert(
        delivery.custodian_role == leg.recipient_role,
        "Reciprocal delivery custodian must be the recipient",
    );
    assert(delivery.retention_deadline > 0, "Reciprocal retention deadline must be non-zero");

    validate_affine_transform(
        setup.active_chunks,
        setup.element_count,
        input_values,
        output_values,
        leg.multiplier,
        leg.offset,
    );
    let setup_commitment = compute_reciprocal_setup_commitment(setup);
    let expected_input =
        compute_reciprocal_chunk_commitment(setup.active_chunks, setup.element_count, input_values);
    if leg.index == 1 {
        assert(receipt.step_index == 0, "First reciprocal leg must be workflow genesis");
        assert(receipt.predecessor_count == 0, "First reciprocal leg must not have predecessors");
        assert(
            receipt.initial_state_commitment == setup_commitment,
            "Reciprocal genesis setup commitment mismatch",
        );
        assert(
            expected_input == setup.initial_input_commitment,
            "Reciprocal genesis input does not match setup",
        );
        assert(
            (leg.prior_receipt_commitment == 0) & (leg.prior_graph_commitment == 0),
            "Reciprocal genesis must not carry prior-leg material",
        );
    } else {
        assert(receipt.step_index == 1, "Later reciprocal compute must follow acknowledgement");
        assert(
            receipt.predecessor_count == 1,
            "Later reciprocal compute requires one acknowledgement predecessor",
        );
        assert(
            receipt.input_commitments[0] == expected_input,
            "Reciprocal acknowledgement output does not match input chunks",
        );
        assert(
            (leg.prior_receipt_commitment != 0) & (leg.prior_graph_commitment != 0),
            "Later reciprocal compute requires prior-leg receipt and graph commitments",
        );
        let expected_cross_link = compute_reciprocal_cross_link(
            leg.prior_receipt_commitment,
            leg.prior_graph_commitment,
            setup_commitment,
            leg.index,
        );
        assert(
            receipt.initial_state_commitment == expected_cross_link,
            "Reciprocal prior-leg cross-link mismatch",
        );
        assert(
            receipt.pre_state_commitment != 0,
            "Reciprocal acknowledgement gate must be non-zero",
        );
    }

    let expected_output = compute_reciprocal_output_commitment(
        setup.active_chunks,
        setup.element_count,
        output_values,
    );
    assert(receipt.output_commitment == expected_output, "Reciprocal output commitment mismatch");
    assert(
        receipt.post_state_commitment == expected_output,
        "Reciprocal post-state must equal the output commitment",
    );
    let expected_da = compute_reciprocal_data_availability_commitment(
        expected_output,
        delivery.package_commitment,
        delivery.retrieval_reference,
        delivery.custodian_role,
        delivery.retention_deadline,
        leg.index,
    );
    assert(
        receipt.data_availability_commitment == expected_da,
        "Reciprocal data-availability commitment mismatch",
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
    setup: ReciprocalSetup,
    leg: ReciprocalLeg,
    input_values: [Field; 16],
    output_values: [Field; 16],
    delivery: ReciprocalDelivery,
) {
    validate_reciprocal_compute_receipt(
        CoordReceiptV2 {
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
        },
        workflow_path,
        setup,
        leg,
        input_values,
        output_values,
        delivery,
    );
}

fn kat_setup() -> ReciprocalSetup {
    ReciprocalSetup {
        version: 1,
        workflow_definition_hash: 1001,
        workflow_instance_id: 0x02cee4c0520193097ae2ed7cb1b1dad60aff4aeab979c2a1ef513d9f43333332,
        context: 1002,
        producer_role: 1,
        consumer_role: 2,
        producer_identity_key: [
            0x2ea8037b34671a773a9268aed54573a4,
            0xc966d84c12aec8c570103a6b2fc94c18,
            0xb31e4371ba5dd7f69c51be6ea3ab3445,
            0xeafaf1c8e9e9b73228b30f2d35628b6f,
        ],
        consumer_identity_key: [
            0xe4d67198d347ef83018dfb1f26d40a61,
            0xc8493a1a71f6948cde4c89072866b568,
            0x4d6324321d9846e24e46ecb27be5e06b,
            0xa47e2b85b9e056bd958e5da5294de25f,
        ],
        signature_scheme_id: RECIPROCAL_SIGNATURE_SCHEME_ID,
        producer_ack_key: [
            0x8f3e26a257e93d8e5fe899f148cda2c6,
            0xf324c267e34d285c9bf3e7ef1a9290bd,
            0xf7dfd636b29dbeb05d5fa47b9d487ed1,
            0xcef023c1bfd4c9714e4580a775356b47,
        ],
        consumer_ack_key: [
            0xb54e08c17f6497a23ddbcc1c6dfeacc1,
            0x3f80c0bf35db5c95a54a3abae438a482,
            0xe4eaf99fb98379403c569d8093a572d6,
            0x4e24931723cb445c09e013d578097e68,
        ],
        initial_input_commitment: 0x1bb70bcccf5938f1ee9bce3d9083f7dfca870b025db1374b1a1a489a3367b814,
        leg1_sender_role: 1,
        leg1_recipient_role: 2,
        leg1_compute_profile_id: RECIPROCAL_COMPUTE_PROFILE_ID,
        leg1_transform_id: 1101,
        leg1_multiplier: 3,
        leg1_offset: 7,
        leg2_sender_role: 2,
        leg2_recipient_role: 1,
        leg2_compute_profile_id: RECIPROCAL_COMPUTE_PROFILE_ID,
        leg2_transform_id: 1102,
        leg2_multiplier: 5,
        leg2_offset: 2,
        active_chunks: 2,
        element_count: 8,
        chunk_width: 4,
        da_policy: 1201,
        acknowledgement_deadline: 1800000000,
        setup_expiry: 1800003600,
        abort_channel_id: 1202,
    }
}

fn kat_leg1() -> ReciprocalLeg {
    ReciprocalLeg {
        index: 1,
        sender_role: 1,
        recipient_role: 2,
        compute_profile_id: RECIPROCAL_COMPUTE_PROFILE_ID,
        transform_id: 1101,
        multiplier: 3,
        offset: 7,
        prior_receipt_commitment: 0,
        prior_graph_commitment: 0,
    }
}

fn kat_leg2() -> ReciprocalLeg {
    ReciprocalLeg {
        index: 2,
        sender_role: 2,
        recipient_role: 1,
        compute_profile_id: RECIPROCAL_COMPUTE_PROFILE_ID,
        transform_id: 1102,
        multiplier: 5,
        offset: 2,
        prior_receipt_commitment: 0x01d05226588f6eef6099aed677e232311423952e39fccf6589c1bf635cd7a42d0,
        prior_graph_commitment: 0x01aafb211ec9765be37a8b067a6ead63b3cbc78d45cffcb8e9dbef4edf9296755,
    }
}

fn kat_leg1_inputs() -> [Field; 16] {
    [1, 2, 3, 4, 5, 6, 7, 8, 0, 0, 0, 0, 0, 0, 0, 0]
}

fn kat_leg1_outputs() -> [Field; 16] {
    [10, 13, 16, 19, 22, 25, 28, 31, 0, 0, 0, 0, 0, 0, 0, 0]
}

fn kat_leg2_inputs() -> [Field; 16] {
    [9, 10, 11, 12, 13, 14, 15, 16, 0, 0, 0, 0, 0, 0, 0, 0]
}

fn kat_leg2_outputs() -> [Field; 16] {
    [47, 52, 57, 62, 67, 72, 77, 82, 0, 0, 0, 0, 0, 0, 0, 0]
}

fn kat_delivery1() -> ReciprocalDelivery {
    ReciprocalDelivery {
        package_commitment: 1301,
        retrieval_reference: 1302,
        custodian_role: 2,
        retention_deadline: 1800086400,
    }
}

fn kat_delivery2() -> ReciprocalDelivery {
    ReciprocalDelivery {
        package_commitment: 2301,
        retrieval_reference: 2302,
        custodian_role: 1,
        retention_deadline: 1800086400,
    }
}

fn test_workflow_path() -> [Field; 32] {
    [0; 32]
}

fn finalize_test_receipt(
    mut receipt: CoordReceiptV2,
    workflow_path: [Field; 32],
) -> CoordReceiptV2 {
    receipt.input_set_commitment = compute_input_set_commitment(
        receipt.predecessor_count,
        receipt.predecessor_step_ids,
        receipt.input_commitments,
    );
    receipt.topology_commitment = compute_topology_commitment(receipt);
    receipt.workflow_definition_hash = compute_merkle_root(
        receipt.topology_commitment,
        (receipt.step_index + 1) as Field,
        workflow_path,
    );
    receipt.receipt_commitment = compute_receipt_commitment(receipt);
    receipt
}

// Unit receipts deliberately use a coherent synthetic manifest/VK snapshot. Embedding the live
// manifest hash here would create source.digest -> profile manifest hash -> source literal recursion.
// The shared Rust vector and live-proof gates separately pin production manifest/VK identities.
fn valid_genesis_receipt() -> CoordReceiptV2 {
    let setup = kat_setup();
    let outputs = kat_leg1_outputs();
    let output = compute_reciprocal_output_commitment(2, 8, outputs);
    let delivery = kat_delivery1();
    let initial_state = compute_reciprocal_setup_commitment(setup);
    finalize_test_receipt(
        CoordReceiptV2 {
            protocol_version: 2,
            workflow_definition_hash: 1,
            workflow_instance_id: setup.workflow_instance_id,
            context: setup.context,
            initial_state_commitment: initial_state,
            profile_id: RECIPROCAL_COMPUTE_PROFILE_ID,
            profile_version: 1,
            profile_manifest_hash: 4002,
            profile_vk_hash: 4003,
            verifier_policy_root: 5000,
            assurance_class: 1,
            step_id: 2101,
            step_index: 0,
            predecessor_count: 0,
            predecessor_step_ids: [0; 4],
            input_commitments: [0; 4],
            input_set_commitment: 0,
            pre_state_commitment: initial_state,
            output_commitment: output,
            post_state_commitment: output,
            external_fact_commitment: 0,
            data_availability_commitment: compute_reciprocal_data_availability_commitment(
                output,
                delivery.package_commitment,
                delivery.retrieval_reference,
                delivery.custodian_role,
                delivery.retention_deadline,
                1,
            ),
            topology_commitment: 0,
            receipt_commitment: 0,
        },
        test_workflow_path(),
    )
}

fn valid_later_receipt() -> CoordReceiptV2 {
    let setup = kat_setup();
    let leg = kat_leg2();
    let input = compute_reciprocal_chunk_commitment(2, 8, kat_leg2_inputs());
    let output = compute_reciprocal_output_commitment(2, 8, kat_leg2_outputs());
    let delivery = kat_delivery2();
    let initial_state = compute_reciprocal_cross_link(
        leg.prior_receipt_commitment,
        leg.prior_graph_commitment,
        compute_reciprocal_setup_commitment(setup),
        leg.index,
    );
    finalize_test_receipt(
        CoordReceiptV2 {
            protocol_version: 2,
            workflow_definition_hash: 1,
            workflow_instance_id: setup.workflow_instance_id,
            context: setup.context,
            initial_state_commitment: initial_state,
            profile_id: RECIPROCAL_COMPUTE_PROFILE_ID,
            profile_version: 1,
            profile_manifest_hash: 4002,
            profile_vk_hash: 4003,
            verifier_policy_root: 5000,
            assurance_class: 1,
            step_id: 3102,
            step_index: 1,
            predecessor_count: 1,
            predecessor_step_ids: [3101, 0, 0, 0],
            input_commitments: [input, 0, 0, 0],
            input_set_commitment: 0,
            pre_state_commitment: 0x03b91c70fabddd20eb2b0725d556e8583621af95b1873977e487bfa64bdb037c,
            output_commitment: output,
            post_state_commitment: output,
            external_fact_commitment: 0,
            data_availability_commitment: compute_reciprocal_data_availability_commitment(
                output,
                delivery.package_commitment,
                delivery.retrieval_reference,
                delivery.custodian_role,
                delivery.retention_deadline,
                2,
            ),
            topology_commitment: 0,
            receipt_commitment: 0,
        },
        test_workflow_path(),
    )
}

#[test]
fn affine_transform_accepts_two_canonical_chunks() {
    validate_affine_transform(2, 8, kat_leg1_inputs(), kat_leg1_outputs(), 3, 7);
    validate_affine_transform(2, 8, kat_leg2_inputs(), kat_leg2_outputs(), 5, 2);
}

#[test(should_fail_with = "Inactive reciprocal chunk slots must be zero")]
fn rejects_nonzero_inactive_chunk_slot() {
    validate_chunk_shape(1, 4, [1, 2, 3, 4, 9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
}

#[test(should_fail_with = "Reciprocal affine output mismatch")]
fn rejects_wrong_affine_output() {
    validate_affine_transform(
        1,
        4,
        [1, 2, 3, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        [10, 13, 16, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        3,
        7,
    );
}

#[test]
fn reciprocal_commitments_match_shared_kat() {
    let setup = kat_setup();
    assert(
        compute_reciprocal_chunk_commitment(2, 8, kat_leg1_inputs())
            == 0x1bb70bcccf5938f1ee9bce3d9083f7dfca870b025db1374b1a1a489a3367b814,
    );
    assert(
        compute_reciprocal_output_commitment(2, 8, kat_leg1_outputs())
            == 0x2ddf2f9c9ed64e876a8fdc232171afa1a70d1e34b9ce60879b10335c687c577a,
    );
    assert(
        compute_reciprocal_chunk_commitment(2, 8, kat_leg2_inputs())
            == 0x248bc4faa9fa81a24213442c5e764d411666e56877cffd5866026abfb9decbc3,
    );
    assert(
        compute_reciprocal_output_commitment(2, 8, kat_leg2_outputs())
            == 0x1bdd44a348f13928713a83875e212d8d7cffdc2057f31c131dfb6e67866a048d,
    );
    let setup_commitment = compute_reciprocal_setup_commitment(setup);
    assert(setup_commitment == 0x0a40ee17ca9278a52306b3d81a6551ad6ed023939aa00c49477639f07c895420);
    assert(
        compute_reciprocal_data_availability_commitment(
            0x2ddf2f9c9ed64e876a8fdc232171afa1a70d1e34b9ce60879b10335c687c577a,
            1301,
            1302,
            2,
            1800086400,
            1,
        )
            == 0x09abcc71d1196a58d229ec1d4dd0b618bae009e2cdcb8f23691a76ca89aebf52,
    );
    assert(
        compute_reciprocal_data_availability_commitment(
            0x1bdd44a348f13928713a83875e212d8d7cffdc2057f31c131dfb6e67866a048d,
            2301,
            2302,
            1,
            1800086400,
            2,
        )
            == 0x12d26415dff1976bd4bd7971d722add4b997b303518e604c5a22db1cf5615882,
    );
    assert(
        compute_reciprocal_cross_link(
            0x01d05226588f6eef6099aed677e232311423952e39fccf6589c1bf635cd7a42d0,
            0x01aafb211ec9765be37a8b067a6ead63b3cbc78d45cffcb8e9dbef4edf9296755,
            setup_commitment,
            2,
        )
            == 0x15b517d10fb37c267d41fe7c2dbd20534e735eeae8f38a24a735f9af54d98f35,
    );
}

#[test]
fn accepts_genesis_and_acknowledgement_gated_receipts() {
    validate_reciprocal_compute_receipt(
        valid_genesis_receipt(),
        test_workflow_path(),
        kat_setup(),
        kat_leg1(),
        kat_leg1_inputs(),
        kat_leg1_outputs(),
        kat_delivery1(),
    );
    validate_reciprocal_compute_receipt(
        valid_later_receipt(),
        test_workflow_path(),
        kat_setup(),
        kat_leg2(),
        kat_leg2_inputs(),
        kat_leg2_outputs(),
        kat_delivery2(),
    );
}

#[test(should_fail_with = "Wrong reciprocal compute profile id")]
fn rejects_wrong_profile_id() {
    let mut receipt = valid_genesis_receipt();
    receipt.profile_id += 1;
    receipt = finalize_test_receipt(receipt, test_workflow_path());
    validate_reciprocal_compute_receipt(
        receipt,
        test_workflow_path(),
        kat_setup(),
        kat_leg1(),
        kat_leg1_inputs(),
        kat_leg1_outputs(),
        kat_delivery1(),
    );
}

#[test(should_fail_with = "Wrong reciprocal compute profile id")]
fn rejects_coherent_synthetic_compute_profile_id() {
    let synthetic_profile_id: Field = 4001;
    let mut setup = kat_setup();
    setup.leg1_compute_profile_id = synthetic_profile_id;
    setup.leg2_compute_profile_id = synthetic_profile_id;

    let mut leg = kat_leg1();
    leg.compute_profile_id = synthetic_profile_id;

    let synthetic_setup_commitment = compute_reciprocal_setup_commitment(setup);
    let mut receipt = valid_genesis_receipt();
    receipt.profile_id = synthetic_profile_id;
    receipt.initial_state_commitment = synthetic_setup_commitment;
    receipt.pre_state_commitment = synthetic_setup_commitment;
    receipt = finalize_test_receipt(receipt, test_workflow_path());

    validate_reciprocal_compute_receipt(
        receipt,
        test_workflow_path(),
        setup,
        leg,
        kat_leg1_inputs(),
        kat_leg1_outputs(),
        kat_delivery1(),
    );
}

#[test(should_fail_with = "Wrong reciprocal compute profile version")]
fn rejects_wrong_profile_version() {
    let mut receipt = valid_genesis_receipt();
    receipt.profile_version = 2;
    receipt = finalize_test_receipt(receipt, test_workflow_path());
    validate_reciprocal_compute_receipt(
        receipt,
        test_workflow_path(),
        kat_setup(),
        kat_leg1(),
        kat_leg1_inputs(),
        kat_leg1_outputs(),
        kat_delivery1(),
    );
}

#[test(should_fail_with = "Reciprocal compute requires ZK-native assurance")]
fn rejects_wrong_assurance() {
    let mut receipt = valid_genesis_receipt();
    receipt.assurance_class = 2;
    receipt = finalize_test_receipt(receipt, test_workflow_path());
    validate_reciprocal_compute_receipt(
        receipt,
        test_workflow_path(),
        kat_setup(),
        kat_leg1(),
        kat_leg1_inputs(),
        kat_leg1_outputs(),
        kat_delivery1(),
    );
}

#[test(should_fail_with = "Reciprocal compute does not authenticate external facts")]
fn rejects_nonzero_external_fact() {
    let mut receipt = valid_genesis_receipt();
    receipt.external_fact_commitment = 1;
    receipt = finalize_test_receipt(receipt, test_workflow_path());
    validate_reciprocal_compute_receipt(
        receipt,
        test_workflow_path(),
        kat_setup(),
        kat_leg1(),
        kat_leg1_inputs(),
        kat_leg1_outputs(),
        kat_delivery1(),
    );
}

#[test(should_fail_with = "Reciprocal compute requires retained delivery material")]
fn rejects_zero_data_availability() {
    let mut receipt = valid_genesis_receipt();
    receipt.data_availability_commitment = 0;
    receipt = finalize_test_receipt(receipt, test_workflow_path());
    validate_reciprocal_compute_receipt(
        receipt,
        test_workflow_path(),
        kat_setup(),
        kat_leg1(),
        kat_leg1_inputs(),
        kat_leg1_outputs(),
        kat_delivery1(),
    );
}

#[test(should_fail_with = "Reciprocal genesis setup commitment mismatch")]
fn rejects_wrong_setup() {
    let mut setup = kat_setup();
    setup.abort_channel_id += 1;
    validate_reciprocal_compute_receipt(
        valid_genesis_receipt(),
        test_workflow_path(),
        setup,
        kat_leg1(),
        kat_leg1_inputs(),
        kat_leg1_outputs(),
        kat_delivery1(),
    );
}

#[test(should_fail_with = "Reciprocal acknowledgement output does not match input chunks")]
fn rejects_wrong_predecessor_input() {
    let mut receipt = valid_later_receipt();
    receipt.input_commitments[0] += 1;
    receipt = finalize_test_receipt(receipt, test_workflow_path());
    validate_reciprocal_compute_receipt(
        receipt,
        test_workflow_path(),
        kat_setup(),
        kat_leg2(),
        kat_leg2_inputs(),
        kat_leg2_outputs(),
        kat_delivery2(),
    );
}

#[test(should_fail_with = "Reciprocal prior-leg cross-link mismatch")]
fn rejects_changed_prior_receipt_commitment() {
    let mut leg = kat_leg2();
    leg.prior_receipt_commitment += 1;
    validate_reciprocal_compute_receipt(
        valid_later_receipt(),
        test_workflow_path(),
        kat_setup(),
        leg,
        kat_leg2_inputs(),
        kat_leg2_outputs(),
        kat_delivery2(),
    );
}

#[test(should_fail_with = "Reciprocal prior-leg cross-link mismatch")]
fn rejects_changed_prior_graph_commitment() {
    let mut leg = kat_leg2();
    leg.prior_graph_commitment += 1;
    validate_reciprocal_compute_receipt(
        valid_later_receipt(),
        test_workflow_path(),
        kat_setup(),
        leg,
        kat_leg2_inputs(),
        kat_leg2_outputs(),
        kat_delivery2(),
    );
}

#[test(should_fail_with = "Reciprocal multiplier does not match setup")]
fn rejects_changed_multiplier() {
    let mut leg = kat_leg1();
    leg.multiplier += 1;
    validate_reciprocal_compute_receipt(
        valid_genesis_receipt(),
        test_workflow_path(),
        kat_setup(),
        leg,
        kat_leg1_inputs(),
        kat_leg1_outputs(),
        kat_delivery1(),
    );
}

#[test(should_fail_with = "Reciprocal offset does not match setup")]
fn rejects_changed_offset() {
    let mut leg = kat_leg1();
    leg.offset += 1;
    validate_reciprocal_compute_receipt(
        valid_genesis_receipt(),
        test_workflow_path(),
        kat_setup(),
        leg,
        kat_leg1_inputs(),
        kat_leg1_outputs(),
        kat_delivery1(),
    );
}

#[test(should_fail_with = "Reciprocal leg recipient mismatch")]
fn rejects_changed_recipient() {
    let mut leg = kat_leg1();
    leg.recipient_role = 3;
    validate_reciprocal_compute_receipt(
        valid_genesis_receipt(),
        test_workflow_path(),
        kat_setup(),
        leg,
        kat_leg1_inputs(),
        kat_leg1_outputs(),
        kat_delivery1(),
    );
}

#[test(should_fail_with = "Reciprocal delivery custodian must be the recipient")]
fn rejects_changed_custodian_role() {
    let mut delivery = kat_delivery1();
    delivery.custodian_role = 1;
    validate_reciprocal_compute_receipt(
        valid_genesis_receipt(),
        test_workflow_path(),
        kat_setup(),
        kat_leg1(),
        kat_leg1_inputs(),
        kat_leg1_outputs(),
        delivery,
    );
}

#[test(should_fail_with = "Reciprocal data-availability commitment mismatch")]
fn rejects_changed_retention_deadline() {
    let mut delivery = kat_delivery1();
    delivery.retention_deadline += 1;
    validate_reciprocal_compute_receipt(
        valid_genesis_receipt(),
        test_workflow_path(),
        kat_setup(),
        kat_leg1(),
        kat_leg1_inputs(),
        kat_leg1_outputs(),
        delivery,
    );
}

#[test(should_fail_with = "Reciprocal data-availability commitment mismatch")]
fn rejects_changed_package_commitment() {
    let mut delivery = kat_delivery1();
    delivery.package_commitment += 1;
    validate_reciprocal_compute_receipt(
        valid_genesis_receipt(),
        test_workflow_path(),
        kat_setup(),
        kat_leg1(),
        kat_leg1_inputs(),
        kat_leg1_outputs(),
        delivery,
    );
}

#[test(should_fail_with = "Reciprocal data-availability commitment mismatch")]
fn rejects_changed_retrieval_reference() {
    let mut delivery = kat_delivery1();
    delivery.retrieval_reference += 1;
    validate_reciprocal_compute_receipt(
        valid_genesis_receipt(),
        test_workflow_path(),
        kat_setup(),
        kat_leg1(),
        kat_leg1_inputs(),
        kat_leg1_outputs(),
        delivery,
    );
}

#[test(should_fail_with = "Reciprocal output commitment mismatch")]
fn rejects_changed_output_commitment() {
    let mut receipt = valid_genesis_receipt();
    receipt.output_commitment += 1;
    receipt = finalize_test_receipt(receipt, test_workflow_path());
    validate_reciprocal_compute_receipt(
        receipt,
        test_workflow_path(),
        kat_setup(),
        kat_leg1(),
        kat_leg1_inputs(),
        kat_leg1_outputs(),
        kat_delivery1(),
    );
}

#[test(should_fail_with = "Reciprocal post-state must equal the output commitment")]
fn rejects_changed_post_state_commitment() {
    let mut receipt = valid_genesis_receipt();
    receipt.post_state_commitment += 1;
    receipt = finalize_test_receipt(receipt, test_workflow_path());
    validate_reciprocal_compute_receipt(
        receipt,
        test_workflow_path(),
        kat_setup(),
        kat_leg1(),
        kat_leg1_inputs(),
        kat_leg1_outputs(),
        kat_delivery1(),
    );
}

#[test(should_fail_with = "Reciprocal data-availability commitment mismatch")]
fn rejects_changed_data_availability_commitment() {
    let mut receipt = valid_genesis_receipt();
    receipt.data_availability_commitment += 1;
    receipt = finalize_test_receipt(receipt, test_workflow_path());
    validate_reciprocal_compute_receipt(
        receipt,
        test_workflow_path(),
        kat_setup(),
        kat_leg1(),
        kat_leg1_inputs(),
        kat_leg1_outputs(),
        kat_delivery1(),
    );
}

#[test(should_fail_with = "Receipt commitment mismatch")]
fn rejects_changed_receipt_commitment() {
    let mut receipt = valid_genesis_receipt();
    receipt.receipt_commitment += 1;
    validate_reciprocal_compute_receipt(
        receipt,
        test_workflow_path(),
        kat_setup(),
        kat_leg1(),
        kat_leg1_inputs(),
        kat_leg1_outputs(),
        kat_delivery1(),
    );
}
