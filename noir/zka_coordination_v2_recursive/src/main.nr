use zka_coord_v2::{
    compute_graph_commitment, compute_state_input_commitment, CoordReceiptV2,
    receipt_from_public_inputs, receipt_public_inputs, validate_coord_artifact_policy,
};

global FAN_IN: u32 = 4;
global RECEIPT_SIZE: u32 = 30;
global RECURSIVE_PUBLIC_INPUT_SIZE: u32 = 33;
global VK_SIZE: u32 = 115;
global PROOF_SIZE: u32 = 458;
global PROOF_TYPE_HONK_ZK: u32 = 6;
global MAX_PROOF_NODE_COUNT: u32 = 4096;
global MAX_RECURSIVE_DEPTH: u32 = 32;
global PROFILE_ADAPTER_ROLE: Field = 1;
global COORD_RECURSIVE_ROLE: Field = 2;

fn receipt_from_recursive_inputs(fields: [Field; 33]) -> CoordReceiptV2 {
    let mut receipt_fields = [0; 30];
    for i in 0..RECEIPT_SIZE {
        receipt_fields[i] = fields[i];
    }
    receipt_from_public_inputs(receipt_fields)
}

fn validate_composition(
    receipt: CoordReceiptV2,
    graph_commitment: Field,
    proof_node_count: Field,
    max_depth: Field,
    adapter_public_inputs: [Field; 30],
    predecessor_public_inputs: [[Field; 33]; 4],
) {
    let expected_receipt = receipt_public_inputs(receipt);
    for i in 0..RECEIPT_SIZE {
        assert(
            adapter_public_inputs[i] == expected_receipt[i],
            "Profile-adapter public inputs do not match current receipt",
        );
    }

    let mut predecessor_post_states = [0; 4];
    let mut predecessor_graphs = [0; 4];
    let mut expected_node_count: Field = 1;
    let proof_node_count_u32 = proof_node_count as u32;
    let max_depth_u32 = max_depth as u32;
    let mut predecessor_max_depth: u32 = 0;
    for i in 0..FAN_IN {
        if i < receipt.predecessor_count as u32 {
            let predecessor = receipt_from_recursive_inputs(predecessor_public_inputs[i]);
            assert(
                predecessor.workflow_definition_hash == receipt.workflow_definition_hash,
                "Predecessor workflow definition mismatch",
            );
            assert(
                predecessor.workflow_instance_id == receipt.workflow_instance_id,
                "Predecessor workflow instance mismatch",
            );
            assert(predecessor.context == receipt.context, "Predecessor context mismatch");
            assert(
                predecessor.initial_state_commitment == receipt.initial_state_commitment,
                "Predecessor initial state mismatch",
            );
            assert(
                predecessor.verifier_policy_root == receipt.verifier_policy_root,
                "Predecessor verifier policy mismatch",
            );
            assert(
                predecessor.step_id == receipt.predecessor_step_ids[i],
                "Predecessor step identity or order mismatch",
            );
            assert(
                predecessor.output_commitment == receipt.input_commitments[i],
                "Predecessor output does not match successor input",
            );
            assert(
                predecessor.step_index < receipt.step_index,
                "Predecessor step must precede successor",
            );
            predecessor_post_states[i] = predecessor.post_state_commitment;
            predecessor_graphs[i] = predecessor_public_inputs[i][30];
            expected_node_count = expected_node_count + predecessor_public_inputs[i][31];
            let active_depth = predecessor_public_inputs[i][32] as u32;
            if active_depth > predecessor_max_depth {
                predecessor_max_depth = active_depth;
            }
        } else {
            for j in 0..RECURSIVE_PUBLIC_INPUT_SIZE {
                assert(
                    predecessor_public_inputs[i][j] == 0,
                    "Inactive predecessor public inputs must be zero",
                );
            }
        }
    }

    let expected_depth = if receipt.predecessor_count == 0 {
        1
    } else {
        (predecessor_max_depth + 1) as Field
    };
    assert(proof_node_count == expected_node_count, "Recursive proof-node count mismatch");
    assert(max_depth == expected_depth, "Recursive maximum depth mismatch");
    assert(proof_node_count_u32 >= 1, "Recursive proof-node count must be non-zero");
    assert(
        proof_node_count_u32 <= MAX_PROOF_NODE_COUNT,
        "Recursive proof-node count exceeds bound",
    );
    assert(max_depth_u32 >= 1, "Recursive maximum depth must be non-zero");
    assert(max_depth_u32 <= MAX_RECURSIVE_DEPTH, "Recursive maximum depth exceeds bound");

    if receipt.predecessor_count == 0 {
        assert(
            receipt.pre_state_commitment == receipt.initial_state_commitment,
            "Genesis pre-state must equal initial state",
        );
    } else {
        assert(
            receipt.pre_state_commitment
                == compute_state_input_commitment(
                    receipt.predecessor_count,
                    predecessor_post_states,
                ),
            "Successor pre-state does not match ordered predecessor states",
        );
    }
    assert(
        graph_commitment
            == compute_graph_commitment(
                receipt.receipt_commitment,
                receipt.predecessor_count,
                predecessor_graphs,
                proof_node_count,
                max_depth,
            ),
        "Recursive graph commitment mismatch",
    );
}

fn assert_inactive_proof_slot(
    verification_key: [Field; 115],
    proof: [Field; 458],
    key_hash: Field,
    role: Field,
    circuit_id_hash: Field,
    artifact_entry_hash: Field,
    schema_hash: Field,
    target_hash: Field,
    policy_vk_hash: Field,
    leaf_index: Field,
    path: [Field; 32],
) {
    for i in 0..VK_SIZE {
        assert(verification_key[i] == 0, "Inactive predecessor VK must be zero");
    }
    for i in 0..PROOF_SIZE {
        assert(proof[i] == 0, "Inactive predecessor proof must be zero");
    }
    assert(key_hash == 0, "Inactive predecessor key hash must be zero");
    assert(
        (role == 0)
            & (circuit_id_hash == 0)
            & (artifact_entry_hash == 0)
            & (schema_hash == 0)
            & (target_hash == 0)
            & (policy_vk_hash == 0)
            & (leaf_index == 0),
        "Inactive predecessor artifact material must be zero",
    );
    for i in 0..32 {
        assert(path[i] == 0, "Inactive predecessor artifact path must be zero");
    }
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
    graph_commitment: pub Field,
    proof_node_count: pub Field,
    max_depth: pub Field,
    adapter_verification_key: [Field; 115],
    adapter_proof: [Field; 458],
    adapter_public_inputs: [Field; 30],
    adapter_key_hash: Field,
    adapter_role: Field,
    adapter_circuit_id_hash: Field,
    adapter_artifact_entry_hash: Field,
    adapter_schema_hash: Field,
    adapter_target_hash: Field,
    adapter_policy_vk_hash: Field,
    adapter_leaf_index: Field,
    adapter_path: [Field; 32],
    predecessor_verification_keys: [[Field; 115]; 4],
    predecessor_proofs: [[Field; 458]; 4],
    predecessor_public_inputs: [[Field; 33]; 4],
    predecessor_key_hashes: [Field; 4],
    predecessor_roles: [Field; 4],
    predecessor_circuit_id_hashes: [Field; 4],
    predecessor_artifact_entry_hashes: [Field; 4],
    predecessor_schema_hashes: [Field; 4],
    predecessor_target_hashes: [Field; 4],
    predecessor_policy_vk_hashes: [Field; 4],
    predecessor_leaf_indices: [Field; 4],
    predecessor_paths: [[Field; 32]; 4],
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
    validate_composition(
        receipt,
        graph_commitment,
        proof_node_count,
        max_depth,
        adapter_public_inputs,
        predecessor_public_inputs,
    );
    validate_coord_artifact_policy(
        verifier_policy_root,
        PROFILE_ADAPTER_ROLE,
        adapter_role,
        adapter_circuit_id_hash,
        adapter_artifact_entry_hash,
        adapter_schema_hash,
        adapter_target_hash,
        adapter_policy_vk_hash,
        adapter_key_hash,
        adapter_leaf_index,
        adapter_path,
    );
    std::verify_proof_with_type(
        adapter_verification_key,
        adapter_proof,
        adapter_public_inputs,
        adapter_key_hash,
        PROOF_TYPE_HONK_ZK,
    );

    for i in 0..FAN_IN {
        if i < predecessor_count as u32 {
            validate_coord_artifact_policy(
                verifier_policy_root,
                COORD_RECURSIVE_ROLE,
                predecessor_roles[i],
                predecessor_circuit_id_hashes[i],
                predecessor_artifact_entry_hashes[i],
                predecessor_schema_hashes[i],
                predecessor_target_hashes[i],
                predecessor_policy_vk_hashes[i],
                predecessor_key_hashes[i],
                predecessor_leaf_indices[i],
                predecessor_paths[i],
            );
            std::verify_proof_with_type(
                predecessor_verification_keys[i],
                predecessor_proofs[i],
                predecessor_public_inputs[i],
                predecessor_key_hashes[i],
                PROOF_TYPE_HONK_ZK,
            );
        } else {
            assert_inactive_proof_slot(
                predecessor_verification_keys[i],
                predecessor_proofs[i],
                predecessor_key_hashes[i],
                predecessor_roles[i],
                predecessor_circuit_id_hashes[i],
                predecessor_artifact_entry_hashes[i],
                predecessor_schema_hashes[i],
                predecessor_target_hashes[i],
                predecessor_policy_vk_hashes[i],
                predecessor_leaf_indices[i],
                predecessor_paths[i],
            );
        }
    }
}

fn sample_receipt() -> CoordReceiptV2 {
    CoordReceiptV2 {
        protocol_version: 2,
        workflow_definition_hash: 100,
        workflow_instance_id: 101,
        context: 102,
        initial_state_commitment: 103,
        profile_id: 104,
        profile_version: 1,
        profile_manifest_hash: 105,
        profile_vk_hash: 106,
        verifier_policy_root: 107,
        assurance_class: 1,
        step_id: 200,
        step_index: 0,
        predecessor_count: 0,
        predecessor_step_ids: [0; 4],
        input_commitments: [0; 4],
        input_set_commitment: 108,
        pre_state_commitment: 103,
        output_commitment: 201,
        post_state_commitment: 202,
        external_fact_commitment: 0,
        data_availability_commitment: 0,
        topology_commitment: 109,
        receipt_commitment: 110,
    }
}

fn recursive_inputs(
    receipt: CoordReceiptV2,
    graph: Field,
    count: Field,
    depth: Field,
) -> [Field; 33] {
    let fields = receipt_public_inputs(receipt);
    let mut result = [0; 33];
    for i in 0..RECEIPT_SIZE {
        result[i] = fields[i];
    }
    result[30] = graph;
    result[31] = count;
    result[32] = depth;
    result
}

#[test]
fn accepts_genesis_and_ordered_fan_in_metadata() {
    let genesis = sample_receipt();
    let genesis_graph = compute_graph_commitment(genesis.receipt_commitment, 0, [0; 4], 1, 1);
    validate_composition(
        genesis,
        genesis_graph,
        1,
        1,
        receipt_public_inputs(genesis),
        [[0; 33]; 4],
    );

    let mut left = genesis;
    left.step_id = 301;
    left.output_commitment = 401;
    left.post_state_commitment = 501;
    let mut right = genesis;
    right.step_id = 302;
    right.output_commitment = 402;
    right.post_state_commitment = 502;
    let left_graph = 601;
    let right_graph = 602;
    let mut predecessors = [[0; 33]; 4];
    predecessors[0] = recursive_inputs(left, left_graph, 1, 1);
    predecessors[1] = recursive_inputs(right, right_graph, 1, 1);
    let mut current = genesis;
    current.step_id = 303;
    current.step_index = 1;
    current.predecessor_count = 2;
    current.predecessor_step_ids = [301, 302, 0, 0];
    current.input_commitments = [401, 402, 0, 0];
    current.pre_state_commitment = compute_state_input_commitment(2, [501, 502, 0, 0]);
    let graph = compute_graph_commitment(
        current.receipt_commitment,
        2,
        [left_graph, right_graph, 0, 0],
        3,
        2,
    );
    validate_composition(
        current,
        graph,
        3,
        2,
        receipt_public_inputs(current),
        predecessors,
    );
}

#[test(should_fail_with = "Predecessor step identity or order mismatch")]
fn rejects_reordered_predecessors() {
    let mut predecessor = sample_receipt();
    predecessor.step_id = 301;
    predecessor.output_commitment = 401;
    predecessor.post_state_commitment = 501;
    let mut current = sample_receipt();
    current.step_id = 302;
    current.step_index = 1;
    current.predecessor_count = 1;
    current.predecessor_step_ids = [999, 0, 0, 0];
    current.input_commitments = [401, 0, 0, 0];
    current.pre_state_commitment = compute_state_input_commitment(1, [501, 0, 0, 0]);
    let mut predecessors = [[0; 33]; 4];
    predecessors[0] = recursive_inputs(predecessor, 601, 1, 1);
    validate_composition(
        current,
        0,
        2,
        2,
        receipt_public_inputs(current),
        predecessors,
    );
}

#[test(should_fail_with = "Predecessor context mismatch")]
fn rejects_cross_context_predecessor() {
    let mut predecessor = sample_receipt();
    predecessor.step_id = 301;
    predecessor.output_commitment = 401;
    predecessor.post_state_commitment = 501;
    predecessor.context = 999;
    let mut current = sample_receipt();
    current.step_id = 302;
    current.step_index = 1;
    current.predecessor_count = 1;
    current.predecessor_step_ids = [301, 0, 0, 0];
    current.input_commitments = [401, 0, 0, 0];
    current.pre_state_commitment = compute_state_input_commitment(1, [501, 0, 0, 0]);
    let mut predecessors = [[0; 33]; 4];
    predecessors[0] = recursive_inputs(predecessor, 601, 1, 1);
    validate_composition(
        current,
        0,
        2,
        2,
        receipt_public_inputs(current),
        predecessors,
    );
}

#[test(should_fail_with = "Inactive predecessor public inputs must be zero")]
fn rejects_inactive_slot_abuse() {
    let genesis = sample_receipt();
    let mut predecessors = [[0; 33]; 4];
    predecessors[0][0] = 1;
    validate_composition(
        genesis,
        0,
        1,
        1,
        receipt_public_inputs(genesis),
        predecessors,
    );
}

#[test(should_fail_with = "Predecessor output does not match successor input")]
fn rejects_predecessor_output_mismatch() {
    let mut predecessor = sample_receipt();
    predecessor.step_id = 301;
    predecessor.output_commitment = 401;
    predecessor.post_state_commitment = 501;
    let mut current = sample_receipt();
    current.step_id = 302;
    current.step_index = 1;
    current.predecessor_count = 1;
    current.predecessor_step_ids = [301, 0, 0, 0];
    current.input_commitments = [999, 0, 0, 0];
    current.pre_state_commitment = compute_state_input_commitment(1, [501, 0, 0, 0]);
    let mut predecessors = [[0; 33]; 4];
    predecessors[0] = recursive_inputs(predecessor, 601, 1, 1);
    validate_composition(
        current,
        0,
        2,
        2,
        receipt_public_inputs(current),
        predecessors,
    );
}

#[test(should_fail_with = "Successor pre-state does not match ordered predecessor states")]
fn rejects_predecessor_state_mismatch() {
    let mut predecessor = sample_receipt();
    predecessor.step_id = 301;
    predecessor.output_commitment = 401;
    predecessor.post_state_commitment = 501;
    let mut current = sample_receipt();
    current.step_id = 302;
    current.step_index = 1;
    current.predecessor_count = 1;
    current.predecessor_step_ids = [301, 0, 0, 0];
    current.input_commitments = [401, 0, 0, 0];
    current.pre_state_commitment = 999;
    let mut predecessors = [[0; 33]; 4];
    predecessors[0] = recursive_inputs(predecessor, 601, 1, 1);
    validate_composition(
        current,
        0,
        2,
        2,
        receipt_public_inputs(current),
        predecessors,
    );
}

#[test(should_fail_with = "Recursive proof-node count mismatch")]
fn rejects_omitted_predecessor_count_metadata() {
    let mut predecessor = sample_receipt();
    predecessor.step_id = 301;
    predecessor.output_commitment = 401;
    predecessor.post_state_commitment = 501;
    let mut current = sample_receipt();
    current.step_id = 302;
    current.step_index = 1;
    current.predecessor_count = 1;
    current.predecessor_step_ids = [301, 0, 0, 0];
    current.input_commitments = [401, 0, 0, 0];
    current.pre_state_commitment = compute_state_input_commitment(1, [501, 0, 0, 0]);
    let mut predecessors = [[0; 33]; 4];
    predecessors[0] = recursive_inputs(predecessor, 601, 1, 1);
    validate_composition(
        current,
        0,
        1,
        2,
        receipt_public_inputs(current),
        predecessors,
    );
}

#[test]
fn accepts_declared_maximum_recursive_depth() {
    let mut predecessor = sample_receipt();
    predecessor.step_id = 301;
    predecessor.output_commitment = 401;
    predecessor.post_state_commitment = 501;
    let mut current = sample_receipt();
    current.step_id = 302;
    current.step_index = 1;
    current.predecessor_count = 1;
    current.predecessor_step_ids = [301, 0, 0, 0];
    current.input_commitments = [401, 0, 0, 0];
    current.pre_state_commitment = compute_state_input_commitment(1, [501, 0, 0, 0]);
    let mut predecessors = [[0; 33]; 4];
    predecessors[0] = recursive_inputs(predecessor, 601, 1, 31);
    let graph = compute_graph_commitment(current.receipt_commitment, 1, [601, 0, 0, 0], 2, 32);
    validate_composition(
        current,
        graph,
        2,
        32,
        receipt_public_inputs(current),
        predecessors,
    );
}

#[test(should_fail_with = "Recursive maximum depth exceeds bound")]
fn rejects_recursive_depth_above_bound() {
    let mut predecessor = sample_receipt();
    predecessor.step_id = 301;
    predecessor.output_commitment = 401;
    predecessor.post_state_commitment = 501;
    let mut current = sample_receipt();
    current.step_id = 302;
    current.step_index = 1;
    current.predecessor_count = 1;
    current.predecessor_step_ids = [301, 0, 0, 0];
    current.input_commitments = [401, 0, 0, 0];
    current.pre_state_commitment = compute_state_input_commitment(1, [501, 0, 0, 0]);
    let mut predecessors = [[0; 33]; 4];
    predecessors[0] = recursive_inputs(predecessor, 601, 1, 32);
    let graph = compute_graph_commitment(current.receipt_commitment, 1, [601, 0, 0, 0], 2, 33);
    validate_composition(
        current,
        graph,
        2,
        33,
        receipt_public_inputs(current),
        predecessors,
    );
}
