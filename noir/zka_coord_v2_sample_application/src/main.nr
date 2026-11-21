use zka_coord_v2::{CoordReceiptV2, validate_receipt};
use zka_lib::poseidon2;

fn validate_sample_transition(
    pre_state_commitment: Field,
    output_commitment: Field,
    post_state_commitment: Field,
    transition_secret: Field,
) {
    assert(
        output_commitment == poseidon2(pre_state_commitment, transition_secret),
        "Sample application output does not follow its execution predicate",
    );
    assert(
        post_state_commitment == poseidon2(output_commitment, transition_secret),
        "Sample application post-state does not follow its execution predicate",
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
    transition_secret: Field,
) {
    validate_receipt(
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
    );
    validate_sample_transition(
        pre_state_commitment,
        output_commitment,
        post_state_commitment,
        transition_secret,
    );
}

#[test]
fn accepts_valid_sample_transition() {
    let secret = 9;
    let output = poseidon2(4, secret);
    validate_sample_transition(4, output, poseidon2(output, secret), secret);
}

#[test(should_fail_with = "Sample application output does not follow its execution predicate")]
fn rejects_permissive_output_substitution() {
    validate_sample_transition(4, 10, 11, 9);
}
