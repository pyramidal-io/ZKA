use zka_coord_v2::{
    compute_input_set_commitment, compute_receipt_commitment, compute_topology_commitment,
    compute_workflow_metadata_commitment, CoordReceiptV2, validate_receipt,
};

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
}

fn canonical_one_step_workflow_path(receipt: CoordReceiptV2) -> [Field; 32] {
    let mut path = [0; 32];
    path[0] = compute_workflow_metadata_commitment(
        2,
        1,
        receipt.step_id,
        receipt.initial_state_commitment,
    );
    let mut empty_subtree = 0;
    for i in 1..32 {
        empty_subtree = zka_lib::poseidon2(empty_subtree, empty_subtree);
        path[i] = empty_subtree;
    }
    path
}

fn genesis_receipt() -> CoordReceiptV2 {
    let mut receipt = CoordReceiptV2 {
        protocol_version: 2,
        workflow_definition_hash: 1,
        workflow_instance_id: 2,
        context: 3,
        initial_state_commitment: 4,
        profile_id: 5,
        profile_version: 1,
        profile_manifest_hash: 6,
        profile_vk_hash: 7,
        verifier_policy_root: 8,
        assurance_class: 1,
        step_id: 9,
        step_index: 0,
        predecessor_count: 0,
        predecessor_step_ids: [0; 4],
        input_commitments: [0; 4],
        input_set_commitment: 0,
        pre_state_commitment: 4,
        output_commitment: 10,
        post_state_commitment: 11,
        external_fact_commitment: 0,
        data_availability_commitment: 0,
        topology_commitment: 0,
        receipt_commitment: 0,
    };
    receipt.input_set_commitment = compute_input_set_commitment(0, [0; 4], [0; 4]);
    receipt.topology_commitment = compute_topology_commitment(receipt);
    let siblings = canonical_one_step_workflow_path(receipt);
    receipt.workflow_definition_hash =
        zka_lib::compute_merkle_root(receipt.topology_commitment, 1, siblings);
    receipt.receipt_commitment = compute_receipt_commitment(receipt);
    receipt
}

fn finalize_receipt(mut receipt: CoordReceiptV2, workflow_path: [Field; 32]) -> CoordReceiptV2 {
    receipt.input_set_commitment = compute_input_set_commitment(
        receipt.predecessor_count,
        receipt.predecessor_step_ids,
        receipt.input_commitments,
    );
    receipt.topology_commitment = compute_topology_commitment(receipt);
    receipt.workflow_definition_hash = zka_lib::compute_merkle_root(
        receipt.topology_commitment,
        (receipt.step_index + 1) as Field,
        workflow_path,
    );
    receipt.receipt_commitment = compute_receipt_commitment(receipt);
    receipt
}

#[test]
fn accepts_canonical_genesis_receipt() {
    let receipt = genesis_receipt();
    validate_receipt(receipt, canonical_one_step_workflow_path(receipt));
}

#[test(should_fail_with = "Coord v2 protocol version must be 2")]
fn rejects_wrong_protocol_version() {
    let mut receipt = genesis_receipt();
    receipt.protocol_version = 1;
    validate_receipt(receipt, canonical_one_step_workflow_path(receipt));
}

#[test(should_fail_with = "Inactive predecessor slots must be zero")]
fn rejects_noncanonical_inactive_slot() {
    let mut receipt = genesis_receipt();
    receipt.predecessor_step_ids[3] = 99;
    validate_receipt(receipt, canonical_one_step_workflow_path(receipt));
}

#[test(should_fail_with = "Assurance class must be in 1..=3")]
fn rejects_unknown_assurance_class() {
    let mut receipt = genesis_receipt();
    receipt.assurance_class = 4;
    validate_receipt(receipt, canonical_one_step_workflow_path(receipt));
}

#[test(should_fail_with = "Step index exceeds Coord v2 bound")]
fn rejects_reserved_maximum_step_index() {
    let mut receipt = genesis_receipt();
    receipt.step_index = 0xffffffff;
    validate_receipt(receipt, canonical_one_step_workflow_path(receipt));
}

#[test(should_fail_with = "Predecessor count exceeds fan-in bound")]
fn rejects_predecessor_count_above_four() {
    let mut receipt = genesis_receipt();
    receipt.predecessor_count = 5;
    validate_receipt(receipt, canonical_one_step_workflow_path(receipt));
}

#[test(should_fail_with = "Genesis must not have predecessors")]
fn rejects_predecessor_material_on_genesis() {
    let mut receipt = genesis_receipt();
    receipt.predecessor_count = 1;
    receipt.predecessor_step_ids[0] = 12;
    receipt.input_commitments[0] = 13;
    let path = canonical_one_step_workflow_path(receipt);
    receipt = finalize_receipt(receipt, path);
    validate_receipt(receipt, path);
}

#[test(should_fail_with = "Genesis pre-state must equal initial state")]
fn rejects_genesis_pre_state_substitution() {
    let mut receipt = genesis_receipt();
    receipt.pre_state_commitment = 55;
    receipt.receipt_commitment = compute_receipt_commitment(receipt);
    validate_receipt(receipt, canonical_one_step_workflow_path(receipt));
}

#[test(should_fail_with = "Non-genesis step requires a predecessor")]
fn rejects_second_implicit_genesis() {
    let mut receipt = genesis_receipt();
    receipt.step_index = 1;
    let path = canonical_one_step_workflow_path(receipt);
    receipt = finalize_receipt(receipt, path);
    validate_receipt(receipt, path);
}

#[test(should_fail_with = "Active predecessor ids must be unique")]
fn rejects_duplicate_active_predecessors() {
    let mut receipt = genesis_receipt();
    receipt.step_index = 1;
    receipt.predecessor_count = 2;
    receipt.predecessor_step_ids = [12, 12, 0, 0];
    receipt.input_commitments = [13, 14, 0, 0];
    let path = canonical_one_step_workflow_path(receipt);
    receipt = finalize_receipt(receipt, path);
    validate_receipt(receipt, path);
}

#[test(should_fail_with = "Input set commitment mismatch")]
fn rejects_input_order_commitment_substitution() {
    let mut receipt = genesis_receipt();
    receipt.input_set_commitment = 99;
    validate_receipt(receipt, canonical_one_step_workflow_path(receipt));
}

#[test(should_fail_with = "Topology commitment mismatch")]
fn rejects_profile_bound_topology_substitution() {
    let mut receipt = genesis_receipt();
    receipt.topology_commitment = 99;
    validate_receipt(receipt, canonical_one_step_workflow_path(receipt));
}

#[test(should_fail_with = "Workflow topology membership mismatch")]
fn rejects_wrong_workflow_membership_path() {
    let receipt = genesis_receipt();
    let mut path = canonical_one_step_workflow_path(receipt);
    path[0] += 1;
    validate_receipt(receipt, path);
}

#[test(should_fail_with = "Receipt commitment mismatch")]
fn rejects_context_tampering() {
    let mut receipt = genesis_receipt();
    receipt.context = 99;
    validate_receipt(receipt, canonical_one_step_workflow_path(receipt));
}

fn change_receipt_offset(mut receipt: CoordReceiptV2, offset: u32) -> CoordReceiptV2 {
    if offset == 0 {
        receipt.protocol_version = 3;
    } else if offset == 1 {
        receipt.workflow_definition_hash += 1;
    } else if offset == 2 {
        receipt.workflow_instance_id += 1;
    } else if offset == 3 {
        receipt.context += 1;
    } else if offset == 4 {
        receipt.initial_state_commitment += 1;
    } else if offset == 5 {
        receipt.profile_id += 1;
    } else if offset == 6 {
        receipt.profile_version += 1;
    } else if offset == 7 {
        receipt.profile_manifest_hash += 1;
    } else if offset == 8 {
        receipt.profile_vk_hash += 1;
    } else if offset == 9 {
        receipt.verifier_policy_root += 1;
    } else if offset == 10 {
        receipt.assurance_class += 1;
    } else if offset == 11 {
        receipt.step_id += 1;
    } else if offset == 12 {
        receipt.step_index += 1;
    } else if offset == 13 {
        receipt.predecessor_count += 1;
    } else if offset < 18 {
        receipt.predecessor_step_ids[offset - 14] += 1;
    } else if offset < 22 {
        receipt.input_commitments[offset - 18] += 1;
    } else if offset == 22 {
        receipt.input_set_commitment += 1;
    } else if offset == 23 {
        receipt.pre_state_commitment += 1;
    } else if offset == 24 {
        receipt.output_commitment += 1;
    } else if offset == 25 {
        receipt.post_state_commitment += 1;
    } else if offset == 26 {
        receipt.external_fact_commitment += 1;
    } else if offset == 27 {
        receipt.data_availability_commitment += 1;
    } else {
        receipt.topology_commitment += 1;
    }
    receipt
}

fn change_topology_member(mut receipt: CoordReceiptV2, offset: u32) -> CoordReceiptV2 {
    if offset == 0 {
        receipt.step_id += 1;
    } else if offset == 1 {
        receipt.step_index += 1;
    } else if offset == 2 {
        receipt.initial_state_commitment += 1;
    } else if offset == 3 {
        receipt.profile_id += 1;
    } else if offset == 4 {
        receipt.profile_version += 1;
    } else if offset == 5 {
        receipt.profile_manifest_hash += 1;
    } else if offset == 6 {
        receipt.profile_vk_hash += 1;
    } else if offset == 7 {
        receipt.assurance_class += 1;
    } else if offset == 8 {
        receipt.predecessor_count += 1;
    } else {
        receipt.predecessor_step_ids[offset - 9] += 1;
    }
    receipt
}

#[test]
fn receipt_fold_binds_every_public_offset_except_itself() {
    let receipt = genesis_receipt();
    let commitment = compute_receipt_commitment(receipt);
    for offset in 0..29 {
        assert(compute_receipt_commitment(change_receipt_offset(receipt, offset)) != commitment);
    }
}

#[test]
fn topology_fold_binds_every_member() {
    let receipt = genesis_receipt();
    let commitment = compute_topology_commitment(receipt);
    for offset in 0..13 {
        assert(compute_topology_commitment(change_topology_member(receipt, offset)) != commitment);
    }
}

#[test(should_fail_with = "Workflow topology membership mismatch")]
fn rejects_self_consistent_initial_state_substitution() {
    let mut receipt = genesis_receipt();
    let approved_path = canonical_one_step_workflow_path(receipt);
    receipt.initial_state_commitment += 1;
    receipt.pre_state_commitment = receipt.initial_state_commitment;
    receipt.topology_commitment = compute_topology_commitment(receipt);
    receipt.receipt_commitment = compute_receipt_commitment(receipt);
    validate_receipt(receipt, approved_path);
}

#[test]
fn input_fold_binds_count_and_every_slot() {
    let receipt = genesis_receipt();
    let commitment = compute_input_set_commitment(
        receipt.predecessor_count,
        receipt.predecessor_step_ids,
        receipt.input_commitments,
    );
    assert(
        compute_input_set_commitment(1, receipt.predecessor_step_ids, receipt.input_commitments)
            != commitment,
    );
    for i in 0..4 {
        let mut predecessor_step_ids = receipt.predecessor_step_ids;
        predecessor_step_ids[i] = 1;
        assert(
            compute_input_set_commitment(
                receipt.predecessor_count,
                predecessor_step_ids,
                receipt.input_commitments,
            )
                != commitment,
        );
        let mut input_commitments = receipt.input_commitments;
        input_commitments[i] = 1;
        assert(
            compute_input_set_commitment(
                receipt.predecessor_count,
                receipt.predecessor_step_ids,
                input_commitments,
            )
                != commitment,
        );
    }
    let ordered = compute_input_set_commitment(2, [12, 13, 0, 0], [14, 15, 0, 0]);
    let permuted = compute_input_set_commitment(2, [13, 12, 0, 0], [15, 14, 0, 0]);
    assert(ordered != permuted);
}
