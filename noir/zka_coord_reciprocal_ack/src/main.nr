use zka_coord_v2::{
    compute_input_set_commitment, compute_receipt_commitment, compute_topology_commitment,
    CoordReceiptV2, validate_receipt,
};
use zka_lib::{compute_merkle_root, poseidon2};

global DOMAIN_RECIPROCAL_SETUP: Field =
    0x00000000000000000000007a6b612f636f6f72642f72782f73657475702f7631;
global DOMAIN_RECIPROCAL_ACK: Field =
    0x000000000000000000000000007a6b612f636f6f72642f72782f61636b2f7631;
global DOMAIN_RECIPROCAL_CROSS_LINK: Field =
    0x00000000000000000000007a6b612f636f6f72642f72782f63726f73732f7631;
global DOMAIN_RECIPROCAL_TERMINAL: Field =
    0x00000000000000007a6b612f636f6f72642f72782f7465726d696e616c2f7631;
global RECIPROCAL_SIGNATURE_SCHEME_ID: Field =
    0x000000000000000000000000007a6b612f636f6f72642f72782f6b65792f7631;
global RECIPROCAL_ACK_PROFILE_ID: Field =
    0x23087cc4ad08d9dbc80318a7e7eb8df9618112319bca1c10f93fcd37073ebc6d;
global RECIPROCAL_COMPUTE_PROFILE_ID: Field =
    0x1aba8f8267027cdbd3e5ac25dc6767ffaf379e08541452dd1ea6b7a6f9710607;

global PINNED_PRODUCER_IDENTITY_KEY: [u8; 64] = [
    0x2e, 0xa8, 0x03, 0x7b, 0x34, 0x67, 0x1a, 0x77, 0x3a, 0x92, 0x68, 0xae, 0xd5, 0x45, 0x73, 0xa4,
    0xc9, 0x66, 0xd8, 0x4c, 0x12, 0xae, 0xc8, 0xc5, 0x70, 0x10, 0x3a, 0x6b, 0x2f, 0xc9, 0x4c, 0x18,
    0xb3, 0x1e, 0x43, 0x71, 0xba, 0x5d, 0xd7, 0xf6, 0x9c, 0x51, 0xbe, 0x6e, 0xa3, 0xab, 0x34, 0x45,
    0xea, 0xfa, 0xf1, 0xc8, 0xe9, 0xe9, 0xb7, 0x32, 0x28, 0xb3, 0x0f, 0x2d, 0x35, 0x62, 0x8b, 0x6f,
];
global PINNED_CONSUMER_IDENTITY_KEY: [u8; 64] = [
    0xe4, 0xd6, 0x71, 0x98, 0xd3, 0x47, 0xef, 0x83, 0x01, 0x8d, 0xfb, 0x1f, 0x26, 0xd4, 0x0a, 0x61,
    0xc8, 0x49, 0x3a, 0x1a, 0x71, 0xf6, 0x94, 0x8c, 0xde, 0x4c, 0x89, 0x07, 0x28, 0x66, 0xb5, 0x68,
    0x4d, 0x63, 0x24, 0x32, 0x1d, 0x98, 0x46, 0xe2, 0x4e, 0x46, 0xec, 0xb2, 0x7b, 0xe5, 0xe0, 0x6b,
    0xa4, 0x7e, 0x2b, 0x85, 0xb9, 0xe0, 0x56, 0xbd, 0x95, 0x8e, 0x5d, 0xa5, 0x29, 0x4d, 0xe2, 0x5f,
];

struct ReciprocalSetup {
    version: u8,
    workflow_definition_hash: Field,
    workflow_instance_id: Field,
    context: Field,
    producer_role: u8,
    consumer_role: u8,
    producer_identity_key: [u8; 64],
    consumer_identity_key: [u8; 64],
    signature_scheme_id: Field,
    producer_ack_key: [u8; 64],
    consumer_ack_key: [u8; 64],
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

struct ReciprocalAckStatement {
    version: u8,
    workflow_definition_hash: Field,
    workflow_instance_id: Field,
    context: Field,
    acknowledgement_step_id: Field,
    prior_receipt_commitment: Field,
    prior_graph_commitment: Field,
    prior_output_commitment: Field,
    delivery_package_commitment: Field,
    sender_role: u8,
    recipient_role: u8,
    sender_identity_key: [u8; 64],
    recipient_identity_key: [u8; 64],
    delegated_ack_key: [u8; 64],
    status: u8,
    issued_at: u64,
    deadline: u64,
    next_input_or_terminal: Field,
}

struct AckKat {
    setup: ReciprocalSetup,
    producer_setup_signature: [u8; 64],
    consumer_setup_signature: [u8; 64],
    ack_statement: ReciprocalAckStatement,
    recipient_ack_public_key: [u8; 64],
    other_ack_public_key: [u8; 64],
    ack_signature: [u8; 64],
}

fn fold_key_limbs(mut state: Field, key: [u8; 64]) -> Field {
    for limb_index in 0..4 {
        let mut limb: Field = 0;
        for byte_index in 0..16 {
            limb = limb * 256 + key[limb_index * 16 + byte_index] as Field;
        }
        state = poseidon2(state, limb);
    }
    state
}

fn fold_signature_limbs(mut state: Field, signature: [u8; 64]) -> Field {
    for limb_index in 0..4 {
        let mut limb: Field = 0;
        for byte_index in 0..16 {
            limb = limb * 256 + signature[limb_index * 16 + byte_index] as Field;
        }
        state = poseidon2(state, limb);
    }
    state
}

fn public_key_x(public_key: [u8; 64]) -> [u8; 32] {
    let mut x = [0; 32];
    for index in 0..32 {
        x[index] = public_key[index];
    }
    x
}

fn public_key_y(public_key: [u8; 64]) -> [u8; 32] {
    let mut y = [0; 32];
    for index in 0..32 {
        y[index] = public_key[index + 32];
    }
    y
}

/// Encodes a Field for the fixed-width secp256k1 signature-message ABI.
///
/// `bn254::decompose` constrains the value to its canonical representative;
/// the two 128-bit limbs are then emitted as high || low in big-endian order.
fn canonical_field_message(value: Field) -> [u8; 32] {
    let (low, high) = std::field::bn254::decompose(value);
    let high_bytes: [u8; 16] = high.to_be_bytes();
    let low_bytes: [u8; 16] = low.to_be_bytes();
    let mut message = [0; 32];
    for index in 0..16 {
        message[index] = high_bytes[index];
        message[index + 16] = low_bytes[index];
    }
    message
}

fn is_canonical_low_s(signature: [u8; 64]) -> bool {
    let maximum: [u8; 32] = [
        0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x5d, 0x57, 0x6e, 0x73, 0x57, 0xa4, 0x50, 0x1d, 0xdf, 0xe9, 0x2f, 0x46, 0x68, 0x1b,
        0x20, 0xa0,
    ];
    let mut equal = true;
    let mut less = false;
    for index in 0..32 {
        let byte = signature[index + 32];
        less = less | (equal & (byte < maximum[index]));
        equal = equal & (byte == maximum[index]);
    }
    less | equal
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

fn compute_reciprocal_ack_message(statement: ReciprocalAckStatement) -> Field {
    let mut state = poseidon2(DOMAIN_RECIPROCAL_ACK, 27);
    state = poseidon2(state, statement.version as Field);
    state = poseidon2(state, statement.workflow_definition_hash);
    state = poseidon2(state, statement.workflow_instance_id);
    state = poseidon2(state, statement.context);
    state = poseidon2(state, statement.acknowledgement_step_id);
    state = poseidon2(state, statement.prior_receipt_commitment);
    state = poseidon2(state, statement.prior_graph_commitment);
    state = poseidon2(state, statement.prior_output_commitment);
    state = poseidon2(state, statement.delivery_package_commitment);
    state = poseidon2(state, statement.sender_role as Field);
    state = poseidon2(state, statement.recipient_role as Field);
    state = fold_key_limbs(state, statement.sender_identity_key);
    state = fold_key_limbs(state, statement.recipient_identity_key);
    state = fold_key_limbs(state, statement.delegated_ack_key);
    state = poseidon2(state, statement.status as Field);
    state = poseidon2(state, statement.issued_at as Field);
    state = poseidon2(state, statement.deadline as Field);
    poseidon2(state, statement.next_input_or_terminal)
}

fn validate_setup_delegation(
    setup: ReciprocalSetup,
    producer_signature: [u8; 64],
    consumer_signature: [u8; 64],
) {
    assert(
        setup.producer_identity_key == PINNED_PRODUCER_IDENTITY_KEY,
        "Producer identity anchor mismatch",
    );
    assert(
        setup.consumer_identity_key == PINNED_CONSUMER_IDENTITY_KEY,
        "Consumer identity anchor mismatch",
    );
    assert(setup.version == 1, "Wrong reciprocal setup version");
    assert(
        (setup.producer_role != 0)
            & (setup.consumer_role != 0)
            & (setup.producer_role != setup.consumer_role),
        "Reciprocal setup roles are invalid",
    );
    assert(
        (setup.leg1_sender_role == setup.producer_role)
            & (setup.leg1_recipient_role == setup.consumer_role)
            & (setup.leg2_sender_role == setup.consumer_role)
            & (setup.leg2_recipient_role == setup.producer_role),
        "Reciprocal setup leg directions must be canonical",
    );
    assert(
        (setup.leg1_compute_profile_id == RECIPROCAL_COMPUTE_PROFILE_ID)
            & (setup.leg2_compute_profile_id == RECIPROCAL_COMPUTE_PROFILE_ID),
        "Reciprocal setup compute profiles must be canonical",
    );
    assert(
        setup.signature_scheme_id == RECIPROCAL_SIGNATURE_SCHEME_ID,
        "Wrong reciprocal acknowledgement signature scheme",
    );
    assert(setup.chunk_width == 4, "Reciprocal chunk width must be four");
    assert(
        (setup.active_chunks > 0) & (setup.active_chunks <= 4),
        "Reciprocal active chunk count is out of bounds",
    );
    assert(
        (setup.element_count > 0) & (setup.element_count <= setup.active_chunks * 4),
        "Reciprocal element count is out of bounds",
    );
    assert(setup.da_policy != 0, "Reciprocal data-availability policy must be non-zero");
    assert(
        setup.acknowledgement_deadline <= setup.setup_expiry,
        "Reciprocal setup expires before its acknowledgement deadline",
    );
    assert(setup.abort_channel_id != 0, "Reciprocal abort channel must be non-zero");
    assert(
        is_canonical_low_s(producer_signature),
        "Producer setup signature must use canonical low-s",
    );
    assert(
        is_canonical_low_s(consumer_signature),
        "Consumer setup signature must use canonical low-s",
    );

    let setup_commitment = compute_reciprocal_setup_commitment(setup);
    let producer_valid = std::ecdsa_secp256k1::verify_signature(
        public_key_x(setup.producer_identity_key),
        public_key_y(setup.producer_identity_key),
        producer_signature,
        canonical_field_message(setup_commitment),
    );
    assert(producer_valid, "Producer setup identity signature is invalid");
    let consumer_valid = std::ecdsa_secp256k1::verify_signature(
        public_key_x(setup.consumer_identity_key),
        public_key_y(setup.consumer_identity_key),
        consumer_signature,
        canonical_field_message(setup_commitment),
    );
    assert(consumer_valid, "Consumer setup identity signature is invalid");
}

fn validate_ack_signature(
    statement: ReciprocalAckStatement,
    public_key: [u8; 64],
    signature: [u8; 64],
) {
    assert(
        is_canonical_low_s(signature),
        "Recipient acknowledgement signature must use canonical low-s",
    );
    let message_commitment = compute_reciprocal_ack_message(statement);
    let valid = std::ecdsa_secp256k1::verify_signature(
        public_key_x(public_key),
        public_key_y(public_key),
        signature,
        canonical_field_message(message_commitment),
    );
    assert(valid, "Recipient acknowledgement signature is invalid");
}

fn compute_reciprocal_ack_evidence_commitment(
    setup_commitment: Field,
    message_commitment: Field,
    delegated_key: [u8; 64],
    signature: [u8; 64],
) -> Field {
    let mut state = poseidon2(DOMAIN_RECIPROCAL_ACK, 10);
    state = poseidon2(state, setup_commitment);
    state = poseidon2(state, message_commitment);
    state = fold_key_limbs(state, delegated_key);
    fold_signature_limbs(state, signature)
}

fn compute_reciprocal_cross_link(
    prior_receipt_commitment: Field,
    prior_graph_commitment: Field,
    setup_commitment: Field,
    next_leg_index: u32,
) -> Field {
    let mut state = poseidon2(DOMAIN_RECIPROCAL_CROSS_LINK, 4);
    state = poseidon2(state, prior_receipt_commitment);
    state = poseidon2(state, prior_graph_commitment);
    state = poseidon2(state, setup_commitment);
    poseidon2(state, next_leg_index as Field)
}

fn compute_reciprocal_terminal_commitment(
    setup_commitment: Field,
    prior_receipt_commitment: Field,
    prior_output_commitment: Field,
    prior_leg_index: u32,
) -> Field {
    let mut state = poseidon2(DOMAIN_RECIPROCAL_TERMINAL, 4);
    state = poseidon2(state, setup_commitment);
    state = poseidon2(state, prior_receipt_commitment);
    state = poseidon2(state, prior_output_commitment);
    poseidon2(state, prior_leg_index as Field)
}

fn validate_reciprocal_ack_receipt(
    receipt: CoordReceiptV2,
    workflow_path: [Field; 32],
    setup: ReciprocalSetup,
    producer_setup_signature: [u8; 64],
    consumer_setup_signature: [u8; 64],
    statement: ReciprocalAckStatement,
    acknowledgement_signature: [u8; 64],
    prior_leg_index: u32,
    terminal: bool,
) {
    validate_receipt(receipt, workflow_path);
    validate_setup_delegation(setup, producer_setup_signature, consumer_setup_signature);

    assert(
        receipt.profile_id == RECIPROCAL_ACK_PROFILE_ID,
        "Wrong canonical reciprocal acknowledgement profile id",
    );
    assert(receipt.profile_version == 1, "Wrong reciprocal acknowledgement profile version");
    assert(receipt.assurance_class == 3, "Reciprocal acknowledgement requires attested assurance");
    assert(
        receipt.data_availability_commitment == 0,
        "Acknowledgement does not claim data availability",
    );
    assert(receipt.step_index == 0, "Reciprocal acknowledgement must be workflow genesis");
    assert(
        receipt.predecessor_count == 0,
        "Reciprocal acknowledgement must not have Coord predecessors",
    );
    assert(
        receipt.workflow_instance_id == setup.workflow_instance_id,
        "Reciprocal acknowledgement receipt instance mismatch",
    );
    assert(receipt.context == setup.context, "Reciprocal acknowledgement receipt context mismatch");

    assert(statement.version == 1, "Wrong reciprocal acknowledgement encoding version");
    assert(
        statement.workflow_definition_hash == setup.workflow_definition_hash,
        "Reciprocal acknowledgement workflow definition mismatch",
    );
    assert(
        statement.workflow_instance_id == setup.workflow_instance_id,
        "Reciprocal acknowledgement workflow instance mismatch",
    );
    assert(statement.context == setup.context, "Reciprocal acknowledgement context mismatch");
    assert(
        statement.acknowledgement_step_id == receipt.step_id,
        "Reciprocal acknowledgement step mismatch",
    );
    assert(statement.status == 1, "Recipient acknowledgement status is not accepted");
    assert(
        statement.deadline == setup.acknowledgement_deadline,
        "Recipient acknowledgement deadline mismatch",
    );
    assert(
        statement.issued_at <= statement.deadline,
        "Recipient acknowledgement was issued after its deadline",
    );
    assert(
        (statement.prior_receipt_commitment != 0)
            & (statement.prior_graph_commitment != 0)
            & (statement.prior_output_commitment != 0)
            & (statement.delivery_package_commitment != 0),
        "Recipient acknowledgement prior-leg material must be non-zero",
    );

    assert(
        (prior_leg_index == 1) | (prior_leg_index == 2),
        "Reciprocal acknowledgement leg index is out of bounds",
    );
    let signed_parties_select_leg_one = (statement.sender_role == setup.leg1_sender_role)
        & (statement.recipient_role == setup.leg1_recipient_role);
    let signed_parties_select_leg_two = (statement.sender_role == setup.leg2_sender_role)
        & (statement.recipient_role == setup.leg2_recipient_role);
    assert(
        signed_parties_select_leg_one | signed_parties_select_leg_two,
        "Reciprocal acknowledgement parties do not select an authenticated leg",
    );
    let mut signed_leg_index: u32 = 1;
    if signed_parties_select_leg_two {
        signed_leg_index = 2;
    }
    assert(
        prior_leg_index == signed_leg_index,
        "Reciprocal acknowledgement leg index does not match signed parties",
    );
    assert(
        terminal == signed_parties_select_leg_two,
        "Reciprocal acknowledgement terminal mode mismatch",
    );
    let mut expected_sender_role = setup.leg1_sender_role;
    let mut expected_recipient_role = setup.leg1_recipient_role;
    if prior_leg_index == 2 {
        expected_sender_role = setup.leg2_sender_role;
        expected_recipient_role = setup.leg2_recipient_role;
    }
    assert(
        statement.sender_role == expected_sender_role,
        "Reciprocal acknowledgement sender mismatch",
    );
    assert(
        statement.recipient_role == expected_recipient_role,
        "Reciprocal acknowledgement recipient mismatch",
    );
    assert(
        (
            (statement.sender_role == setup.producer_role)
                | (statement.sender_role == setup.consumer_role)
        )
            & (
                (statement.recipient_role == setup.producer_role)
                    | (statement.recipient_role == setup.consumer_role)
            )
            & (statement.sender_role != statement.recipient_role),
        "Reciprocal acknowledgement parties must be distinct setup participants",
    );

    let mut expected_sender_identity = setup.producer_identity_key;
    let mut expected_recipient_identity = setup.consumer_identity_key;
    if statement.sender_role == setup.consumer_role {
        expected_sender_identity = setup.consumer_identity_key;
    }
    if statement.recipient_role == setup.producer_role {
        expected_recipient_identity = setup.producer_identity_key;
    }
    assert(
        statement.sender_identity_key == expected_sender_identity,
        "Reciprocal acknowledgement sender identity mismatch",
    );
    assert(
        statement.recipient_identity_key == expected_recipient_identity,
        "Reciprocal acknowledgement recipient identity mismatch",
    );

    let mut selected_ack_key = setup.consumer_ack_key;
    if statement.recipient_role == setup.producer_role {
        selected_ack_key = setup.producer_ack_key;
    }
    assert(
        statement.delegated_ack_key == selected_ack_key,
        "Reciprocal acknowledgement delegated key mismatch",
    );

    let setup_commitment = compute_reciprocal_setup_commitment(setup);
    let expected_cross_link = compute_reciprocal_cross_link(
        statement.prior_receipt_commitment,
        statement.prior_graph_commitment,
        setup_commitment,
        prior_leg_index + 1,
    );
    assert(
        receipt.initial_state_commitment == expected_cross_link,
        "Reciprocal prior-leg cross-link mismatch",
    );
    assert(
        receipt.pre_state_commitment == expected_cross_link,
        "Reciprocal acknowledgement pre-state mismatch",
    );
    assert(
        receipt.output_commitment == statement.next_input_or_terminal,
        "Reciprocal acknowledgement output mismatch",
    );
    if terminal {
        let expected_terminal = compute_reciprocal_terminal_commitment(
            setup_commitment,
            statement.prior_receipt_commitment,
            statement.prior_output_commitment,
            prior_leg_index,
        );
        assert(
            statement.next_input_or_terminal == expected_terminal,
            "Reciprocal terminal acknowledgement commitment mismatch",
        );
    } else {
        assert(
            statement.next_input_or_terminal != 0,
            "Reciprocal interior acknowledgement next input must be non-zero",
        );
    }

    let message_commitment = compute_reciprocal_ack_message(statement);
    assert(
        receipt.post_state_commitment == message_commitment,
        "Reciprocal acknowledgement gate state mismatch",
    );
    validate_ack_signature(statement, selected_ack_key, acknowledgement_signature);
    let expected_evidence = compute_reciprocal_ack_evidence_commitment(
        setup_commitment,
        message_commitment,
        selected_ack_key,
        acknowledgement_signature,
    );
    assert(
        receipt.external_fact_commitment == expected_evidence,
        "Reciprocal acknowledgement evidence mismatch",
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
    producer_setup_signature: [u8; 64],
    consumer_setup_signature: [u8; 64],
    statement: ReciprocalAckStatement,
    acknowledgement_signature: [u8; 64],
    prior_leg_index: u32,
    terminal: bool,
) {
    validate_reciprocal_ack_receipt(
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
        producer_setup_signature,
        consumer_setup_signature,
        statement,
        acknowledgement_signature,
        prior_leg_index,
        terminal,
    );
}

fn producer_ack_public_key() -> [u8; 64] {
    [
        0x8f, 0x3e, 0x26, 0xa2, 0x57, 0xe9, 0x3d, 0x8e, 0x5f, 0xe8, 0x99, 0xf1, 0x48, 0xcd, 0xa2,
        0xc6, 0xf3, 0x24, 0xc2, 0x67, 0xe3, 0x4d, 0x28, 0x5c, 0x9b, 0xf3, 0xe7, 0xef, 0x1a, 0x92,
        0x90, 0xbd, 0xf7, 0xdf, 0xd6, 0x36, 0xb2, 0x9d, 0xbe, 0xb0, 0x5d, 0x5f, 0xa4, 0x7b, 0x9d,
        0x48, 0x7e, 0xd1, 0xce, 0xf0, 0x23, 0xc1, 0xbf, 0xd4, 0xc9, 0x71, 0x4e, 0x45, 0x80, 0xa7,
        0x75, 0x35, 0x6b, 0x47,
    ]
}

fn consumer_ack_public_key() -> [u8; 64] {
    [
        0xb5, 0x4e, 0x08, 0xc1, 0x7f, 0x64, 0x97, 0xa2, 0x3d, 0xdb, 0xcc, 0x1c, 0x6d, 0xfe, 0xac,
        0xc1, 0x3f, 0x80, 0xc0, 0xbf, 0x35, 0xdb, 0x5c, 0x95, 0xa5, 0x4a, 0x3a, 0xba, 0xe4, 0x38,
        0xa4, 0x82, 0xe4, 0xea, 0xf9, 0x9f, 0xb9, 0x83, 0x79, 0x40, 0x3c, 0x56, 0x9d, 0x80, 0x93,
        0xa5, 0x72, 0xd6, 0x4e, 0x24, 0x93, 0x17, 0x23, 0xcb, 0x44, 0x5c, 0x09, 0xe0, 0x13, 0xd5,
        0x78, 0x09, 0x7e, 0x68,
    ]
}

fn kat_setup() -> ReciprocalSetup {
    ReciprocalSetup {
        version: 1,
        workflow_definition_hash: 1001,
        workflow_instance_id: 0x02cee4c0520193097ae2ed7cb1b1dad60aff4aeab979c2a1ef513d9f43333332,
        context: 1002,
        producer_role: 1,
        consumer_role: 2,
        producer_identity_key: PINNED_PRODUCER_IDENTITY_KEY,
        consumer_identity_key: PINNED_CONSUMER_IDENTITY_KEY,
        signature_scheme_id: RECIPROCAL_SIGNATURE_SCHEME_ID,
        producer_ack_key: producer_ack_public_key(),
        consumer_ack_key: consumer_ack_public_key(),
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

fn producer_setup_signature() -> [u8; 64] {
    [
        0xe3, 0xe3, 0xf5, 0xcd, 0xff, 0x6a, 0x01, 0xf1, 0x5b, 0xc1, 0x5c, 0xa4, 0x6b, 0xdb, 0xaa,
        0xfe, 0x35, 0x52, 0xae, 0xf9, 0x88, 0x82, 0xdd, 0x8d, 0x20, 0xde, 0x78, 0xb3, 0xc5, 0x95,
        0xd6, 0x68, 0x07, 0xdc, 0x69, 0x98, 0x3a, 0x3d, 0xed, 0xc9, 0xee, 0x01, 0xf2, 0xa7, 0x8a,
        0x6c, 0xbf, 0x01, 0x82, 0x35, 0x1b, 0x27, 0x0b, 0xc7, 0x19, 0x25, 0xce, 0x4d, 0x48, 0x11,
        0x58, 0xfa, 0x59, 0x30,
    ]
}

fn consumer_setup_signature() -> [u8; 64] {
    [
        0x76, 0x7f, 0x1c, 0xce, 0x4e, 0x6b, 0x09, 0xa6, 0x68, 0x3f, 0x78, 0x50, 0x3c, 0x43, 0x43,
        0x6d, 0xbd, 0xc7, 0x10, 0x7f, 0x40, 0x67, 0xdc, 0x80, 0x67, 0x42, 0xe3, 0x8a, 0x35, 0x3a,
        0xa3, 0x77, 0x46, 0xa7, 0xea, 0xbb, 0x2b, 0x09, 0x8e, 0x09, 0xf8, 0xfd, 0x9a, 0xcf, 0x39,
        0x9f, 0x28, 0x13, 0xef, 0xc3, 0xa3, 0xb7, 0x30, 0x10, 0xb5, 0x36, 0x65, 0xc1, 0x6c, 0x9c,
        0x55, 0x82, 0x92, 0x9b,
    ]
}

fn ack1_signature() -> [u8; 64] {
    [
        0x84, 0x43, 0xb5, 0xc8, 0x05, 0x2b, 0x4f, 0xec, 0xda, 0x2e, 0x76, 0x50, 0x19, 0x2e, 0xf9,
        0x59, 0x14, 0x46, 0x34, 0xcc, 0x7c, 0x93, 0xac, 0x05, 0xc6, 0x78, 0x56, 0xa3, 0x6e, 0x53,
        0x22, 0x30, 0x30, 0x83, 0x4b, 0xe9, 0x46, 0x9a, 0xdd, 0x85, 0x0e, 0x69, 0xb6, 0x71, 0x80,
        0x2d, 0x6a, 0xca, 0x6e, 0x6e, 0xad, 0x26, 0x66, 0x8c, 0x11, 0x26, 0x1e, 0x70, 0x2a, 0x03,
        0x3b, 0x2a, 0xec, 0x85,
    ]
}

fn ack_kat() -> AckKat {
    AckKat {
        setup: kat_setup(),
        producer_setup_signature: producer_setup_signature(),
        consumer_setup_signature: consumer_setup_signature(),
        ack_statement: ReciprocalAckStatement {
            version: 1,
            workflow_definition_hash: 1001,
            workflow_instance_id: 0x02cee4c0520193097ae2ed7cb1b1dad60aff4aeab979c2a1ef513d9f43333332,
            context: 1002,
            acknowledgement_step_id: 3101,
            prior_receipt_commitment: 0x1d05226588f6eef6099aed677e232311423952e39fccf6589c1bf635cd7a42d0,
            prior_graph_commitment: 0x1aafb211ec9765be37a8b067a6ead63b3cbc78d45cffcb8e9dbef4edf9296755,
            prior_output_commitment: 0x2ddf2f9c9ed64e876a8fdc232171afa1a70d1e34b9ce60879b10335c687c577a,
            delivery_package_commitment: 1301,
            sender_role: 1,
            recipient_role: 2,
            sender_identity_key: PINNED_PRODUCER_IDENTITY_KEY,
            recipient_identity_key: PINNED_CONSUMER_IDENTITY_KEY,
            delegated_ack_key: consumer_ack_public_key(),
            status: 1,
            issued_at: 1799999000,
            deadline: 1800000000,
            next_input_or_terminal: 0x248bc4faa9fa81a24213442c5e764d411666e56877cffd5866026abfb9decbc3,
        },
        recipient_ack_public_key: consumer_ack_public_key(),
        other_ack_public_key: producer_ack_public_key(),
        ack_signature: ack1_signature(),
    }
}

fn high_s_ack_kat() -> AckKat {
    let mut vector = ack_kat();
    vector.ack_signature = [
        0x84, 0x43, 0xb5, 0xc8, 0x05, 0x2b, 0x4f, 0xec, 0xda, 0x2e, 0x76, 0x50, 0x19, 0x2e, 0xf9,
        0x59, 0x14, 0x46, 0x34, 0xcc, 0x7c, 0x93, 0xac, 0x05, 0xc6, 0x78, 0x56, 0xa3, 0x6e, 0x53,
        0x22, 0x30, 0xcf, 0x7c, 0xb4, 0x16, 0xb9, 0x65, 0x22, 0x7a, 0xf1, 0x96, 0x49, 0x8e, 0x7f,
        0xd2, 0x95, 0x34, 0x4c, 0x40, 0x2f, 0xc0, 0x48, 0xbc, 0x8f, 0x15, 0xa1, 0x62, 0x34, 0x89,
        0x95, 0x0b, 0x54, 0xbc,
    ];
    vector
}

fn ack2_signature() -> [u8; 64] {
    [
        0xa6, 0x41, 0xf2, 0xb4, 0x3f, 0x34, 0x95, 0x37, 0x59, 0x29, 0x07, 0x26, 0x31, 0x5e, 0xa2,
        0x2a, 0x4e, 0xc4, 0xfa, 0xa2, 0xf3, 0x48, 0x2b, 0xcf, 0x39, 0xbf, 0xf7, 0x42, 0x4d, 0xf1,
        0x5f, 0x01, 0x7f, 0x58, 0xfd, 0xb5, 0xc3, 0xd2, 0x98, 0x55, 0x2a, 0x52, 0x91, 0xbf, 0x1c,
        0x7c, 0xd7, 0x07, 0xf9, 0x8b, 0x49, 0x13, 0xee, 0x05, 0x43, 0xdb, 0xc6, 0xa8, 0xb6, 0xc0,
        0xf2, 0x11, 0xa8, 0xa6,
    ]
}

fn terminal_ack_kat() -> AckKat {
    AckKat {
        setup: kat_setup(),
        producer_setup_signature: producer_setup_signature(),
        consumer_setup_signature: consumer_setup_signature(),
        ack_statement: ReciprocalAckStatement {
            version: 1,
            workflow_definition_hash: 1001,
            workflow_instance_id: 0x02cee4c0520193097ae2ed7cb1b1dad60aff4aeab979c2a1ef513d9f43333332,
            context: 1002,
            acknowledgement_step_id: 4101,
            prior_receipt_commitment: 0x11bf89661a9f14586b418cc089cc0dda8ff2d6ecc34ec50e6d68a5b0122edad5,
            prior_graph_commitment: 0x1e543147a9a51e1ef2981542eb2e7fa5d5e5e21a8153024673bbb09f8516e180,
            prior_output_commitment: 0x1bdd44a348f13928713a83875e212d8d7cffdc2057f31c131dfb6e67866a048d,
            delivery_package_commitment: 2301,
            sender_role: 2,
            recipient_role: 1,
            sender_identity_key: PINNED_CONSUMER_IDENTITY_KEY,
            recipient_identity_key: PINNED_PRODUCER_IDENTITY_KEY,
            delegated_ack_key: producer_ack_public_key(),
            status: 1,
            issued_at: 1799999100,
            deadline: 1800000000,
            next_input_or_terminal: 0x298006aebdbab39a37730cf2f84d2ed6965ac09bd33e0c52b315b940490cfdc1,
        },
        recipient_ack_public_key: producer_ack_public_key(),
        other_ack_public_key: consumer_ack_public_key(),
        ack_signature: ack2_signature(),
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
fn valid_ack_receipt(vector: AckKat, prior_leg_index: u32) -> CoordReceiptV2 {
    let setup_commitment = compute_reciprocal_setup_commitment(vector.setup);
    let message_commitment = compute_reciprocal_ack_message(vector.ack_statement);
    let cross_link = compute_reciprocal_cross_link(
        vector.ack_statement.prior_receipt_commitment,
        vector.ack_statement.prior_graph_commitment,
        setup_commitment,
        prior_leg_index + 1,
    );
    let evidence = compute_reciprocal_ack_evidence_commitment(
        setup_commitment,
        message_commitment,
        vector.recipient_ack_public_key,
        vector.ack_signature,
    );
    finalize_test_receipt(
        CoordReceiptV2 {
            protocol_version: 2,
            workflow_definition_hash: 1,
            workflow_instance_id: vector.setup.workflow_instance_id,
            context: vector.setup.context,
            initial_state_commitment: cross_link,
            profile_id: RECIPROCAL_ACK_PROFILE_ID,
            profile_version: 1,
            profile_manifest_hash: 5002,
            profile_vk_hash: 5003,
            verifier_policy_root: 4999,
            assurance_class: 3,
            step_id: vector.ack_statement.acknowledgement_step_id,
            step_index: 0,
            predecessor_count: 0,
            predecessor_step_ids: [0; 4],
            input_commitments: [0; 4],
            input_set_commitment: 0,
            pre_state_commitment: cross_link,
            output_commitment: vector.ack_statement.next_input_or_terminal,
            post_state_commitment: message_commitment,
            external_fact_commitment: evidence,
            data_availability_commitment: 0,
            topology_commitment: 0,
            receipt_commitment: 0,
        },
        test_workflow_path(),
    )
}

fn validate_kat_receipt(
    receipt: CoordReceiptV2,
    vector: AckKat,
    prior_leg_index: u32,
    terminal: bool,
) {
    validate_reciprocal_ack_receipt(
        receipt,
        test_workflow_path(),
        vector.setup,
        vector.producer_setup_signature,
        vector.consumer_setup_signature,
        vector.ack_statement,
        vector.ack_signature,
        prior_leg_index,
        terminal,
    );
}

#[test]
fn accepts_low_s_recipient_ack_vector() {
    let vector = ack_kat();
    validate_setup_delegation(
        vector.setup,
        vector.producer_setup_signature,
        vector.consumer_setup_signature,
    );
    validate_ack_signature(
        vector.ack_statement,
        vector.recipient_ack_public_key,
        vector.ack_signature,
    );
}

#[test]
fn canonical_field_message_encodes_bn254_limbs_high_then_low() {
    // p - 1, the largest canonical BN254 scalar-field element.  This pins both
    // the canonical-decomposition boundary and the existing 32-byte big-endian
    // signature-message ABI.
    let value: Field = 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000000;
    let expected: [u8; 32] = [
        0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29, 0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81, 0x58,
        0x5d, 0x28, 0x33, 0xe8, 0x48, 0x79, 0xb9, 0x70, 0x91, 0x43, 0xe1, 0xf5, 0x93, 0xf0, 0x00,
        0x00, 0x00,
    ];
    assert(
        canonical_field_message(value) == expected,
        "Canonical field message bytes must be high limb then low limb",
    );
}

#[test(should_fail_with = "Recipient acknowledgement signature is invalid")]
fn rejects_ack_signed_by_substituted_key() {
    let vector = ack_kat();
    validate_ack_signature(
        vector.ack_statement,
        vector.other_ack_public_key,
        vector.ack_signature,
    );
}

#[test(should_fail_with = "Recipient acknowledgement signature must use canonical low-s")]
fn rejects_high_s_ack_signature() {
    let vector = high_s_ack_kat();
    validate_ack_signature(
        vector.ack_statement,
        vector.recipient_ack_public_key,
        vector.ack_signature,
    );
}

#[test]
fn reciprocal_ack_commitments_match_shared_kat() {
    let interior = ack_kat();
    let terminal = terminal_ack_kat();
    let setup_commitment = compute_reciprocal_setup_commitment(interior.setup);
    assert(setup_commitment == 0x0a40ee17ca9278a52306b3d81a6551ad6ed023939aa00c49477639f07c895420);
    assert(
        compute_reciprocal_ack_message(interior.ack_statement)
            == 0x03b91c70fabddd20eb2b0725d556e8583621af95b1873977e487bfa64bdb037c,
    );
    assert(
        compute_reciprocal_ack_evidence_commitment(
            setup_commitment,
            compute_reciprocal_ack_message(interior.ack_statement),
            interior.recipient_ack_public_key,
            interior.ack_signature,
        )
            == 0x1857e9e34cb640197c48fe0e2be3d5c221e54b6ffca958290e6d98760770cb37,
    );
    assert(
        compute_reciprocal_cross_link(
            interior.ack_statement.prior_receipt_commitment,
            interior.ack_statement.prior_graph_commitment,
            setup_commitment,
            2,
        )
            == 0x15b517d10fb37c267d41fe7c2dbd20534e735eeae8f38a24a735f9af54d98f35,
    );
    assert(
        compute_reciprocal_ack_message(terminal.ack_statement)
            == 0x1e545c158fc545871c13e9b86282c7fefc4d36a1e7ca7375b61dc1813ee0c223,
    );
    assert(
        compute_reciprocal_terminal_commitment(
            setup_commitment,
            terminal.ack_statement.prior_receipt_commitment,
            terminal.ack_statement.prior_output_commitment,
            2,
        )
            == 0x298006aebdbab39a37730cf2f84d2ed6965ac09bd33e0c52b315b940490cfdc1,
    );
}

#[test]
fn accepts_interior_and_terminal_acknowledgement_receipts() {
    let interior = ack_kat();
    let interior_receipt = valid_ack_receipt(interior, 1);
    validate_kat_receipt(interior_receipt, interior, 1, false);
    let terminal = terminal_ack_kat();
    let terminal_receipt = valid_ack_receipt(terminal, 2);
    validate_kat_receipt(terminal_receipt, terminal, 2, true);
}

#[test(should_fail_with = "Producer setup identity signature is invalid")]
fn rejects_invalid_producer_setup_signature() {
    let mut vector = ack_kat();
    vector.producer_setup_signature[0] += 1;
    validate_setup_delegation(
        vector.setup,
        vector.producer_setup_signature,
        vector.consumer_setup_signature,
    );
}

#[test(should_fail_with = "Consumer setup identity signature is invalid")]
fn rejects_invalid_consumer_setup_signature() {
    let mut vector = ack_kat();
    vector.consumer_setup_signature[0] += 1;
    validate_setup_delegation(
        vector.setup,
        vector.producer_setup_signature,
        vector.consumer_setup_signature,
    );
}

#[test(should_fail_with = "Producer identity anchor mismatch")]
fn rejects_substituted_producer_identity() {
    let original = ack_kat();
    let receipt = valid_ack_receipt(original, 1);
    let mut changed = original;
    changed.setup.producer_identity_key[0] += 1;
    validate_kat_receipt(receipt, changed, 1, false);
}

#[test(should_fail_with = "Consumer identity anchor mismatch")]
fn rejects_substituted_consumer_identity() {
    let original = ack_kat();
    let receipt = valid_ack_receipt(original, 1);
    let mut changed = original;
    changed.setup.consumer_identity_key[0] -= 1;
    validate_kat_receipt(receipt, changed, 1, false);
}

#[test(should_fail_with = "Reciprocal acknowledgement delegated key mismatch")]
fn rejects_substituted_delegated_key() {
    let original = ack_kat();
    let receipt = valid_ack_receipt(original, 1);
    let mut changed = original;
    changed.ack_statement.delegated_ack_key = changed.other_ack_public_key;
    validate_kat_receipt(receipt, changed, 1, false);
}

#[test(should_fail_with = "Reciprocal acknowledgement workflow definition mismatch")]
fn rejects_changed_workflow_definition() {
    let original = ack_kat();
    let receipt = valid_ack_receipt(original, 1);
    let mut changed = original;
    changed.ack_statement.workflow_definition_hash += 1;
    validate_kat_receipt(receipt, changed, 1, false);
}

#[test(should_fail_with = "Reciprocal acknowledgement workflow instance mismatch")]
fn rejects_changed_workflow_instance() {
    let original = ack_kat();
    let receipt = valid_ack_receipt(original, 1);
    let mut changed = original;
    changed.ack_statement.workflow_instance_id += 1;
    validate_kat_receipt(receipt, changed, 1, false);
}

#[test(should_fail_with = "Reciprocal acknowledgement context mismatch")]
fn rejects_changed_context() {
    let original = ack_kat();
    let receipt = valid_ack_receipt(original, 1);
    let mut changed = original;
    changed.ack_statement.context += 1;
    validate_kat_receipt(receipt, changed, 1, false);
}

#[test(should_fail_with = "Reciprocal prior-leg cross-link mismatch")]
fn rejects_changed_prior_receipt() {
    let original = ack_kat();
    let receipt = valid_ack_receipt(original, 1);
    let mut changed = original;
    changed.ack_statement.prior_receipt_commitment += 1;
    validate_kat_receipt(receipt, changed, 1, false);
}

#[test(should_fail_with = "Reciprocal prior-leg cross-link mismatch")]
fn rejects_changed_prior_graph() {
    let original = ack_kat();
    let receipt = valid_ack_receipt(original, 1);
    let mut changed = original;
    changed.ack_statement.prior_graph_commitment += 1;
    validate_kat_receipt(receipt, changed, 1, false);
}

#[test(should_fail_with = "Recipient acknowledgement signature is invalid")]
fn rejects_changed_prior_output() {
    let mut vector = ack_kat();
    vector.ack_statement.prior_output_commitment += 1;
    validate_ack_signature(
        vector.ack_statement,
        vector.recipient_ack_public_key,
        vector.ack_signature,
    );
}

#[test(should_fail_with = "Recipient acknowledgement signature is invalid")]
fn rejects_changed_delivered_package() {
    let mut vector = ack_kat();
    vector.ack_statement.delivery_package_commitment += 1;
    validate_ack_signature(
        vector.ack_statement,
        vector.recipient_ack_public_key,
        vector.ack_signature,
    );
}

#[test(should_fail_with = "Reciprocal acknowledgement parties do not select an authenticated leg")]
fn rejects_changed_sender() {
    let original = ack_kat();
    let receipt = valid_ack_receipt(original, 1);
    let mut changed = original;
    changed.ack_statement.sender_role = 2;
    validate_kat_receipt(receipt, changed, 1, false);
}

#[test(should_fail_with = "Reciprocal acknowledgement parties do not select an authenticated leg")]
fn rejects_changed_recipient() {
    let original = ack_kat();
    let receipt = valid_ack_receipt(original, 1);
    let mut changed = original;
    changed.ack_statement.recipient_role = 1;
    validate_kat_receipt(receipt, changed, 1, false);
}

#[test(should_fail_with = "Reciprocal acknowledgement sender identity mismatch")]
fn rejects_changed_sender_identity() {
    let original = ack_kat();
    let receipt = valid_ack_receipt(original, 1);
    let mut changed = original;
    changed.ack_statement.sender_identity_key = PINNED_CONSUMER_IDENTITY_KEY;
    validate_kat_receipt(receipt, changed, 1, false);
}

#[test(should_fail_with = "Reciprocal acknowledgement recipient identity mismatch")]
fn rejects_changed_recipient_identity() {
    let original = ack_kat();
    let receipt = valid_ack_receipt(original, 1);
    let mut changed = original;
    changed.ack_statement.recipient_identity_key = PINNED_PRODUCER_IDENTITY_KEY;
    validate_kat_receipt(receipt, changed, 1, false);
}

#[test(should_fail_with = "Recipient acknowledgement signature is invalid")]
fn rejects_sender_identity_signature_replay() {
    let mut vector = ack_kat();
    vector.ack_statement.sender_identity_key = PINNED_CONSUMER_IDENTITY_KEY;
    validate_ack_signature(
        vector.ack_statement,
        vector.recipient_ack_public_key,
        vector.ack_signature,
    );
}

#[test(should_fail_with = "Recipient acknowledgement signature is invalid")]
fn rejects_recipient_identity_signature_replay() {
    let mut vector = ack_kat();
    vector.ack_statement.recipient_identity_key = PINNED_PRODUCER_IDENTITY_KEY;
    validate_ack_signature(
        vector.ack_statement,
        vector.recipient_ack_public_key,
        vector.ack_signature,
    );
}

#[test(should_fail_with = "Recipient acknowledgement status is not accepted")]
fn rejects_changed_status() {
    let original = ack_kat();
    let receipt = valid_ack_receipt(original, 1);
    let mut changed = original;
    changed.ack_statement.status = 2;
    validate_kat_receipt(receipt, changed, 1, false);
}

#[test(should_fail_with = "Recipient acknowledgement deadline mismatch")]
fn rejects_changed_deadline() {
    let original = ack_kat();
    let receipt = valid_ack_receipt(original, 1);
    let mut changed = original;
    changed.ack_statement.deadline += 1;
    validate_kat_receipt(receipt, changed, 1, false);
}

#[test(should_fail_with = "Recipient acknowledgement was issued after its deadline")]
fn rejects_issued_at_after_deadline() {
    let original = ack_kat();
    let receipt = valid_ack_receipt(original, 1);
    let mut changed = original;
    changed.ack_statement.issued_at = changed.ack_statement.deadline + 1;
    validate_kat_receipt(receipt, changed, 1, false);
}

#[test(should_fail_with = "Reciprocal acknowledgement output mismatch")]
fn rejects_changed_next_input() {
    let original = ack_kat();
    let receipt = valid_ack_receipt(original, 1);
    let mut changed = original;
    changed.ack_statement.next_input_or_terminal += 1;
    validate_kat_receipt(receipt, changed, 1, false);
}

#[test(should_fail_with = "Reciprocal terminal acknowledgement commitment mismatch")]
fn rejects_changed_terminal_marker() {
    let original = terminal_ack_kat();
    let mut changed = original;
    changed.ack_statement.next_input_or_terminal += 1;
    let mut receipt = valid_ack_receipt(original, 2);
    receipt.output_commitment = changed.ack_statement.next_input_or_terminal;
    receipt = finalize_test_receipt(receipt, test_workflow_path());
    validate_kat_receipt(receipt, changed, 2, true);
}

#[test(should_fail_with = "Reciprocal acknowledgement terminal mode mismatch")]
fn rejects_interior_acknowledgement_as_terminal() {
    let vector = ack_kat();
    validate_kat_receipt(valid_ack_receipt(vector, 1), vector, 1, true);
}

#[test(should_fail_with = "Reciprocal acknowledgement terminal mode mismatch")]
fn rejects_terminal_acknowledgement_as_interior() {
    let vector = terminal_ack_kat();
    validate_kat_receipt(valid_ack_receipt(vector, 2), vector, 2, false);
}

#[test(should_fail_with = "Wrong canonical reciprocal acknowledgement profile id")]
fn rejects_changed_profile() {
    let vector = ack_kat();
    let mut receipt = valid_ack_receipt(vector, 1);
    receipt.profile_id += 1;
    receipt = finalize_test_receipt(receipt, test_workflow_path());
    validate_kat_receipt(receipt, vector, 1, false);
}

#[test(should_fail_with = "Reciprocal acknowledgement requires attested assurance")]
fn rejects_changed_assurance() {
    let vector = ack_kat();
    let mut receipt = valid_ack_receipt(vector, 1);
    receipt.assurance_class = 1;
    receipt = finalize_test_receipt(receipt, test_workflow_path());
    validate_kat_receipt(receipt, vector, 1, false);
}

#[test(should_fail_with = "Acknowledgement does not claim data availability")]
fn rejects_nonzero_data_availability() {
    let vector = ack_kat();
    let mut receipt = valid_ack_receipt(vector, 1);
    receipt.data_availability_commitment = 1;
    receipt = finalize_test_receipt(receipt, test_workflow_path());
    validate_kat_receipt(receipt, vector, 1, false);
}

#[test(should_fail_with = "Reciprocal acknowledgement evidence mismatch")]
fn rejects_changed_evidence_commitment() {
    let vector = ack_kat();
    let mut receipt = valid_ack_receipt(vector, 1);
    receipt.external_fact_commitment += 1;
    receipt = finalize_test_receipt(receipt, test_workflow_path());
    validate_kat_receipt(receipt, vector, 1, false);
}

#[test(should_fail_with = "Reciprocal prior-leg cross-link mismatch")]
fn rejects_changed_initial_state() {
    let vector = ack_kat();
    let mut receipt = valid_ack_receipt(vector, 1);
    receipt.initial_state_commitment += 1;
    receipt.pre_state_commitment = receipt.initial_state_commitment;
    receipt = finalize_test_receipt(receipt, test_workflow_path());
    validate_kat_receipt(receipt, vector, 1, false);
}

#[test(should_fail_with = "Reciprocal acknowledgement gate state mismatch")]
fn rejects_changed_acknowledgement_gate_state() {
    let vector = ack_kat();
    let mut receipt = valid_ack_receipt(vector, 1);
    receipt.post_state_commitment += 1;
    receipt = finalize_test_receipt(receipt, test_workflow_path());
    validate_kat_receipt(receipt, vector, 1, false);
}

#[test(should_fail_with = "Reciprocal setup leg directions must be canonical")]
fn rejects_same_direction_authenticated_setup() {
    let mut vector = ack_kat();
    vector.setup.leg2_sender_role = vector.setup.producer_role;
    vector.setup.leg2_recipient_role = vector.setup.consumer_role;
    validate_setup_delegation(
        vector.setup,
        vector.producer_setup_signature,
        vector.consumer_setup_signature,
    );
}

#[test(should_fail_with = "Reciprocal setup leg directions must be canonical")]
fn rejects_joint_mode_switch_under_same_direction_setup() {
    let mut vector = ack_kat();
    vector.setup.leg2_sender_role = vector.setup.producer_role;
    vector.setup.leg2_recipient_role = vector.setup.consumer_role;
    let receipt = valid_ack_receipt(vector, 2);
    validate_kat_receipt(receipt, vector, 2, true);
}

#[test(should_fail_with = "Reciprocal acknowledgement leg index does not match signed parties")]
fn rejects_joint_leg_and_terminal_switch() {
    let vector = ack_kat();
    let receipt = valid_ack_receipt(vector, 2);
    validate_kat_receipt(receipt, vector, 2, true);
}

#[test(should_fail_with = "Wrong canonical reciprocal acknowledgement profile id")]
fn rejects_self_consistent_synthetic_ack_profile() {
    let vector = ack_kat();
    let mut receipt = valid_ack_receipt(vector, 1);
    receipt.profile_id = 5001;
    receipt = finalize_test_receipt(receipt, test_workflow_path());
    validate_kat_receipt(receipt, vector, 1, false);
}

#[test(should_fail_with = "Reciprocal setup compute profiles must be canonical")]
fn rejects_signed_setup_with_synthetic_compute_profiles() {
    let mut vector = ack_kat();
    vector.setup.leg1_compute_profile_id = 4001;
    vector.setup.leg2_compute_profile_id = 4001;
    let legacy_producer_signature: [u8; 64] = [
        0xa8, 0x3e, 0x0a, 0x3e, 0x67, 0x3c, 0xbe, 0x04, 0x3a, 0xc5, 0x61, 0x0e, 0xf3, 0x59, 0x06,
        0xa8, 0x74, 0xd2, 0xf1, 0xea, 0x67, 0xa0, 0x5d, 0x91, 0x74, 0xcf, 0xcb, 0xfb, 0x2f, 0x2f,
        0x84, 0xdb, 0x33, 0x64, 0xe9, 0x2d, 0x1a, 0x63, 0x24, 0xb0, 0x0e, 0xc4, 0x02, 0x72, 0x98,
        0x9b, 0xad, 0x14, 0xf0, 0x4c, 0x73, 0x57, 0x2f, 0xe1, 0x76, 0x9b, 0xb9, 0x39, 0x95, 0xa4,
        0xb5, 0x6a, 0x4a, 0x37,
    ];
    let legacy_consumer_signature: [u8; 64] = [
        0x6f, 0xf9, 0x16, 0x6e, 0x68, 0xc7, 0x9a, 0x36, 0x69, 0x74, 0x2b, 0x32, 0x5c, 0x99, 0x0d,
        0x91, 0xfa, 0x4f, 0xa4, 0xa6, 0x48, 0xd9, 0xc6, 0x8d, 0x36, 0x6a, 0x8f, 0x10, 0x7d, 0x47,
        0x12, 0x41, 0x0a, 0x3c, 0xae, 0xe7, 0x81, 0xa8, 0x61, 0xa3, 0xda, 0xca, 0xd7, 0xd4, 0xb0,
        0x12, 0x8d, 0x42, 0x76, 0x2d, 0xd4, 0xd2, 0xa7, 0xbf, 0xfc, 0xa5, 0x37, 0x0f, 0x30, 0x24,
        0x00, 0x70, 0xae, 0x47,
    ];
    validate_setup_delegation(
        vector.setup,
        legacy_producer_signature,
        legacy_consumer_signature,
    );
}
