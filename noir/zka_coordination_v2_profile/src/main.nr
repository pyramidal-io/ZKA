use zka_coord_v2::{
    CoordReceiptV2, receipt_public_inputs, validate_profile_policy, validate_receipt,
};

global RECEIPT_PUBLIC_INPUT_SIZE: u32 = 30;
global PROOF_TYPE_HONK_ZK: u32 = 6;

fn validate_application_binding(
    receipt: CoordReceiptV2,
    application_public_inputs: [Field; 30],
    application_key_hash: Field,
    profile_leaf_index: Field,
    profile_path: [Field; 32],
) {
    assert(
        (receipt.assurance_class == 1) | (receipt.assurance_class == 3),
        "Profile adapter requires assurance class 1 or 3",
    );
    let expected_public_inputs = receipt_public_inputs(receipt);
    for i in 0..RECEIPT_PUBLIC_INPUT_SIZE {
        assert(
            application_public_inputs[i] == expected_public_inputs[i],
            "Application proof public inputs do not match Coord receipt",
        );
    }
    assert(
        application_key_hash == receipt.profile_vk_hash,
        "Application proof VK does not match execution profile",
    );
    validate_profile_policy(receipt, profile_leaf_index, profile_path);
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
    application_verification_key: [Field; 115],
    application_proof: [Field; 458],
    application_public_inputs: [Field; 30],
    application_key_hash: Field,
    profile_leaf_index: Field,
    profile_path: [Field; 32],
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
    validate_application_binding(
        receipt,
        application_public_inputs,
        application_key_hash,
        profile_leaf_index,
        profile_path,
    );
    std::verify_proof_with_type(
        application_verification_key,
        application_proof,
        application_public_inputs,
        application_key_hash,
        PROOF_TYPE_HONK_ZK,
    );
}

fn sample_receipt() -> CoordReceiptV2 {
    CoordReceiptV2 {
        protocol_version: 2,
        workflow_definition_hash: 1,
        workflow_instance_id: 2,
        context: 3,
        initial_state_commitment: 4,
        profile_id: 5,
        profile_version: 1,
        profile_manifest_hash: 6,
        profile_vk_hash: 7,
        verifier_policy_root: 0,
        assurance_class: 1,
        step_id: 8,
        step_index: 0,
        predecessor_count: 0,
        predecessor_step_ids: [0; 4],
        input_commitments: [0; 4],
        input_set_commitment: 9,
        pre_state_commitment: 4,
        output_commitment: 10,
        post_state_commitment: 11,
        external_fact_commitment: 0,
        data_availability_commitment: 0,
        topology_commitment: 12,
        receipt_commitment: 13,
    }
}

fn authorize_profile(mut receipt: CoordReceiptV2) -> CoordReceiptV2 {
    let leaf = zka_coord_v2::compute_profile_leaf(
        receipt.profile_id,
        receipt.profile_version,
        receipt.profile_manifest_hash,
        receipt.profile_vk_hash,
        receipt.assurance_class,
    );
    receipt.verifier_policy_root = zka_lib::compute_merkle_root(leaf, 0, [0; 32]);
    receipt
}

#[test]
fn accepts_exact_profile_and_receipt_vector() {
    let receipt = authorize_profile(sample_receipt());
    validate_application_binding(receipt, receipt_public_inputs(receipt), 7, 0, [0; 32]);
}

#[test]
fn accepts_exact_attested_profile_and_receipt_vector() {
    let mut receipt = sample_receipt();
    receipt.assurance_class = 3;
    receipt = authorize_profile(receipt);
    validate_application_binding(receipt, receipt_public_inputs(receipt), 7, 0, [0; 32]);
}

#[test(should_fail_with = "Application proof public inputs do not match Coord receipt")]
fn rejects_same_width_different_receipt_order() {
    let receipt = authorize_profile(sample_receipt());
    let mut fields = receipt_public_inputs(receipt);
    let displaced = fields[2];
    fields[2] = fields[3];
    fields[3] = displaced;
    validate_application_binding(receipt, fields, 7, 0, [0; 32]);
}

#[test(should_fail_with = "Application proof VK does not match execution profile")]
fn rejects_unknown_or_malicious_vk() {
    let receipt = authorize_profile(sample_receipt());
    validate_application_binding(receipt, receipt_public_inputs(receipt), 99, 0, [0; 32]);
}

#[test(should_fail_with = "Execution profile is not authorized by verifier policy")]
fn rejects_stale_profile_version() {
    let receipt = authorize_profile(sample_receipt());
    let mut stale = receipt;
    stale.profile_version = 2;
    validate_application_binding(stale, receipt_public_inputs(stale), 7, 0, [0; 32]);
}

#[test(should_fail_with = "Profile adapter requires assurance class 1 or 3")]
fn rejects_zero_assurance_class() {
    let mut confused = sample_receipt();
    confused.assurance_class = 0;
    confused = authorize_profile(confused);
    validate_application_binding(confused, receipt_public_inputs(confused), 7, 0, [0; 32]);
}

#[test(should_fail_with = "Profile adapter requires assurance class 1 or 3")]
fn rejects_proof_producing_external_assurance_class() {
    let mut confused = sample_receipt();
    confused.assurance_class = 2;
    confused = authorize_profile(confused);
    validate_application_binding(confused, receipt_public_inputs(confused), 7, 0, [0; 32]);
}

#[test(should_fail_with = "Profile adapter requires assurance class 1 or 3")]
fn rejects_unknown_assurance_class() {
    let mut confused = sample_receipt();
    confused.assurance_class = 4;
    confused = authorize_profile(confused);
    validate_application_binding(confused, receipt_public_inputs(confused), 7, 0, [0; 32]);
}
