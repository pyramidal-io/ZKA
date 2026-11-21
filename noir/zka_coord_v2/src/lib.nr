use zka_lib::{compute_merkle_root, poseidon2};

pub global DOMAIN_INPUTS: Field =
    0x000000000000000000000000007a6b612f636f6f72642f76322f696e70757473;
pub global DOMAIN_TOPOLOGY: Field =
    0x00000000000000000000007a6b612f636f6f72642f76322f746f706f6c6f6779;
pub global DOMAIN_WORKFLOW: Field =
    0x00000000000000000000007a6b612f636f6f72642f76322f776f726b666c6f77;
pub global DOMAIN_RECEIPT: Field =
    0x0000000000000000000000007a6b612f636f6f72642f76322f72656365697074;
pub global DOMAIN_PROFILE: Field =
    0x0000000000000000000000007a6b612f636f6f72642f76322f70726f66696c65;
pub global DOMAIN_STATE_INPUTS: Field =
    0x00000000007a6b612f636f6f72642f76322f73746174652d696e70757473;
pub global DOMAIN_GRAPH: Field = 0x00000000000000000000000000007a6b612f636f6f72642f76322f6772617068;
pub global DOMAIN_COORD_ARTIFACT: Field =
    0x000000007a6b612f636f6f72642f76322f636f6f72642d6172746966616374;

#[test]
fn recursive_folds_bind_order_and_bounds() {
    let post_states = [11, 12, 0, 0];
    let ordered = compute_state_input_commitment(2, post_states);
    assert(compute_state_input_commitment(2, [12, 11, 0, 0]) != ordered);
    assert(compute_state_input_commitment(1, [11, 0, 0, 0]) != ordered);

    let graph = compute_graph_commitment(7, 2, [21, 22, 0, 0], 3, 2);
    assert(compute_graph_commitment(7, 2, [22, 21, 0, 0], 3, 2) != graph);
    assert(compute_graph_commitment(7, 2, [21, 22, 0, 0], 4, 2) != graph);
    assert(compute_graph_commitment(7, 2, [21, 22, 0, 0], 3, 3) != graph);
}

#[test]
fn coord_artifact_leaf_binds_role_and_complete_identity() {
    let leaf = compute_coord_artifact_leaf(1, 2, 3, 4, 5, 6);
    assert(compute_coord_artifact_leaf(2, 2, 3, 4, 5, 6) != leaf);
    assert(compute_coord_artifact_leaf(1, 7, 3, 4, 5, 6) != leaf);
    assert(compute_coord_artifact_leaf(1, 2, 7, 4, 5, 6) != leaf);
    assert(compute_coord_artifact_leaf(1, 2, 3, 7, 5, 6) != leaf);
    assert(compute_coord_artifact_leaf(1, 2, 3, 4, 7, 6) != leaf);
    assert(compute_coord_artifact_leaf(1, 2, 3, 4, 5, 7) != leaf);
}

pub struct CoordReceiptV2 {
    pub protocol_version: u8,
    pub workflow_definition_hash: Field,
    pub workflow_instance_id: Field,
    pub context: Field,
    pub initial_state_commitment: Field,
    pub profile_id: Field,
    pub profile_version: u32,
    pub profile_manifest_hash: Field,
    pub profile_vk_hash: Field,
    pub verifier_policy_root: Field,
    pub assurance_class: u8,
    pub step_id: Field,
    pub step_index: u32,
    pub predecessor_count: u8,
    pub predecessor_step_ids: [Field; 4],
    pub input_commitments: [Field; 4],
    pub input_set_commitment: Field,
    pub pre_state_commitment: Field,
    pub output_commitment: Field,
    pub post_state_commitment: Field,
    pub external_fact_commitment: Field,
    pub data_availability_commitment: Field,
    pub topology_commitment: Field,
    pub receipt_commitment: Field,
}

pub fn field_fold_start(domain: Field, length: Field) -> Field {
    poseidon2(domain, length)
}

pub fn compute_state_input_commitment(
    predecessor_count: u8,
    predecessor_post_states: [Field; 4],
) -> Field {
    let mut state = field_fold_start(DOMAIN_STATE_INPUTS, 5);
    state = poseidon2(state, predecessor_count as Field);
    for i in 0..4 {
        state = poseidon2(state, predecessor_post_states[i]);
    }
    state
}

pub fn compute_graph_commitment(
    receipt_commitment: Field,
    predecessor_count: u8,
    predecessor_graph_commitments: [Field; 4],
    proof_node_count: Field,
    max_depth: Field,
) -> Field {
    let mut state = field_fold_start(DOMAIN_GRAPH, 8);
    state = poseidon2(state, receipt_commitment);
    state = poseidon2(state, predecessor_count as Field);
    for i in 0..4 {
        state = poseidon2(state, predecessor_graph_commitments[i]);
    }
    state = poseidon2(state, proof_node_count);
    poseidon2(state, max_depth)
}

pub fn compute_coord_artifact_leaf(
    role: Field,
    circuit_id_hash: Field,
    artifact_entry_hash: Field,
    schema_hash: Field,
    target_hash: Field,
    vk_hash: Field,
) -> Field {
    let mut state = field_fold_start(DOMAIN_COORD_ARTIFACT, 6);
    state = poseidon2(state, role);
    state = poseidon2(state, circuit_id_hash);
    state = poseidon2(state, artifact_entry_hash);
    state = poseidon2(state, schema_hash);
    state = poseidon2(state, target_hash);
    poseidon2(state, vk_hash)
}

pub fn compute_input_set_commitment(
    predecessor_count: u8,
    predecessor_step_ids: [Field; 4],
    input_commitments: [Field; 4],
) -> Field {
    let mut state = field_fold_start(DOMAIN_INPUTS, 5);
    state = poseidon2(state, predecessor_count as Field);
    for i in 0..4 {
        state = poseidon2(
            state,
            poseidon2(predecessor_step_ids[i], input_commitments[i]),
        );
    }
    state
}

pub fn compute_workflow_metadata_commitment(
    protocol_version: u8,
    step_count: u32,
    completion_step_id: Field,
    initial_state_commitment: Field,
) -> Field {
    let mut state = field_fold_start(DOMAIN_WORKFLOW, 4);
    state = poseidon2(state, protocol_version as Field);
    state = poseidon2(state, step_count as Field);
    state = poseidon2(state, completion_step_id);
    state = poseidon2(state, initial_state_commitment);
    state
}

pub fn compute_topology_commitment(receipt: CoordReceiptV2) -> Field {
    let mut state = field_fold_start(DOMAIN_TOPOLOGY, 13);
    state = poseidon2(state, receipt.step_id);
    state = poseidon2(state, receipt.step_index as Field);
    state = poseidon2(state, receipt.initial_state_commitment);
    state = poseidon2(state, receipt.profile_id);
    state = poseidon2(state, receipt.profile_version as Field);
    state = poseidon2(state, receipt.profile_manifest_hash);
    state = poseidon2(state, receipt.profile_vk_hash);
    state = poseidon2(state, receipt.assurance_class as Field);
    state = poseidon2(state, receipt.predecessor_count as Field);
    for i in 0..4 {
        state = poseidon2(state, receipt.predecessor_step_ids[i]);
    }
    state
}

pub fn compute_receipt_commitment(receipt: CoordReceiptV2) -> Field {
    let mut state = field_fold_start(DOMAIN_RECEIPT, 29);
    state = poseidon2(state, receipt.protocol_version as Field);
    state = poseidon2(state, receipt.workflow_definition_hash);
    state = poseidon2(state, receipt.workflow_instance_id);
    state = poseidon2(state, receipt.context);
    state = poseidon2(state, receipt.initial_state_commitment);
    state = poseidon2(state, receipt.profile_id);
    state = poseidon2(state, receipt.profile_version as Field);
    state = poseidon2(state, receipt.profile_manifest_hash);
    state = poseidon2(state, receipt.profile_vk_hash);
    state = poseidon2(state, receipt.verifier_policy_root);
    state = poseidon2(state, receipt.assurance_class as Field);
    state = poseidon2(state, receipt.step_id);
    state = poseidon2(state, receipt.step_index as Field);
    state = poseidon2(state, receipt.predecessor_count as Field);
    for i in 0..4 {
        state = poseidon2(state, receipt.predecessor_step_ids[i]);
    }
    for i in 0..4 {
        state = poseidon2(state, receipt.input_commitments[i]);
    }
    state = poseidon2(state, receipt.input_set_commitment);
    state = poseidon2(state, receipt.pre_state_commitment);
    state = poseidon2(state, receipt.output_commitment);
    state = poseidon2(state, receipt.post_state_commitment);
    state = poseidon2(state, receipt.external_fact_commitment);
    state = poseidon2(state, receipt.data_availability_commitment);
    state = poseidon2(state, receipt.topology_commitment);
    state
}

/// Return the canonical public-input vector consumed by application proofs and
/// emitted by every Coord v2 profile adapter. Keeping this in the shared
/// library prevents same-width-but-different-order substitution.
pub fn receipt_public_inputs(receipt: CoordReceiptV2) -> [Field; 30] {
    let mut fields = [0; 30];
    fields[0] = receipt.protocol_version as Field;
    fields[1] = receipt.workflow_definition_hash;
    fields[2] = receipt.workflow_instance_id;
    fields[3] = receipt.context;
    fields[4] = receipt.initial_state_commitment;
    fields[5] = receipt.profile_id;
    fields[6] = receipt.profile_version as Field;
    fields[7] = receipt.profile_manifest_hash;
    fields[8] = receipt.profile_vk_hash;
    fields[9] = receipt.verifier_policy_root;
    fields[10] = receipt.assurance_class as Field;
    fields[11] = receipt.step_id;
    fields[12] = receipt.step_index as Field;
    fields[13] = receipt.predecessor_count as Field;
    for i in 0..4 {
        fields[14 + i] = receipt.predecessor_step_ids[i];
        fields[18 + i] = receipt.input_commitments[i];
    }
    fields[22] = receipt.input_set_commitment;
    fields[23] = receipt.pre_state_commitment;
    fields[24] = receipt.output_commitment;
    fields[25] = receipt.post_state_commitment;
    fields[26] = receipt.external_fact_commitment;
    fields[27] = receipt.data_availability_commitment;
    fields[28] = receipt.topology_commitment;
    fields[29] = receipt.receipt_commitment;
    fields
}

pub fn receipt_from_public_inputs(fields: [Field; 30]) -> CoordReceiptV2 {
    CoordReceiptV2 {
        protocol_version: fields[0] as u8,
        workflow_definition_hash: fields[1],
        workflow_instance_id: fields[2],
        context: fields[3],
        initial_state_commitment: fields[4],
        profile_id: fields[5],
        profile_version: fields[6] as u32,
        profile_manifest_hash: fields[7],
        profile_vk_hash: fields[8],
        verifier_policy_root: fields[9],
        assurance_class: fields[10] as u8,
        step_id: fields[11],
        step_index: fields[12] as u32,
        predecessor_count: fields[13] as u8,
        predecessor_step_ids: [fields[14], fields[15], fields[16], fields[17]],
        input_commitments: [fields[18], fields[19], fields[20], fields[21]],
        input_set_commitment: fields[22],
        pre_state_commitment: fields[23],
        output_commitment: fields[24],
        post_state_commitment: fields[25],
        external_fact_commitment: fields[26],
        data_availability_commitment: fields[27],
        topology_commitment: fields[28],
        receipt_commitment: fields[29],
    }
}

pub fn recursive_public_inputs(
    receipt: CoordReceiptV2,
    graph_commitment: Field,
    proof_node_count: Field,
    max_depth: Field,
) -> [Field; 33] {
    let receipt_fields = receipt_public_inputs(receipt);
    let mut fields = [0; 33];
    for i in 0..30 {
        fields[i] = receipt_fields[i];
    }
    fields[30] = graph_commitment;
    fields[31] = proof_node_count;
    fields[32] = max_depth;
    fields
}

pub fn compute_profile_leaf(
    profile_id: Field,
    profile_version: u32,
    profile_manifest_hash: Field,
    profile_vk_hash: Field,
    assurance_class: u8,
) -> Field {
    let mut state = field_fold_start(DOMAIN_PROFILE, 5);
    state = poseidon2(state, profile_id);
    state = poseidon2(state, profile_version as Field);
    state = poseidon2(state, profile_manifest_hash);
    state = poseidon2(state, profile_vk_hash);
    poseidon2(state, assurance_class as Field)
}

pub fn validate_profile_policy(receipt: CoordReceiptV2, leaf_index: Field, path: [Field; 32]) {
    let leaf = compute_profile_leaf(
        receipt.profile_id,
        receipt.profile_version,
        receipt.profile_manifest_hash,
        receipt.profile_vk_hash,
        receipt.assurance_class,
    );
    assert(
        compute_merkle_root(leaf, leaf_index, path) == receipt.verifier_policy_root,
        "Execution profile is not authorized by verifier policy",
    );
}

pub fn validate_coord_artifact_policy(
    verifier_policy_root: Field,
    expected_role: Field,
    role: Field,
    circuit_id_hash: Field,
    artifact_entry_hash: Field,
    schema_hash: Field,
    target_hash: Field,
    policy_vk_hash: Field,
    actual_key_hash: Field,
    leaf_index: Field,
    path: [Field; 32],
) {
    assert(role == expected_role, "Coord artifact role mismatch");
    assert(actual_key_hash == policy_vk_hash, "Recursive VK does not match Coord artifact policy");
    let leaf = compute_coord_artifact_leaf(
        role,
        circuit_id_hash,
        artifact_entry_hash,
        schema_hash,
        target_hash,
        policy_vk_hash,
    );
    assert(
        compute_merkle_root(leaf, leaf_index, path) == verifier_policy_root,
        "Coord artifact is not authorized by verifier policy",
    );
}

pub fn validate_receipt(receipt: CoordReceiptV2, workflow_path: [Field; 32]) {
    assert(receipt.protocol_version == 2, "Coord v2 protocol version must be 2");
    assert(receipt.workflow_definition_hash != 0, "Workflow definition hash must be non-zero");
    assert(receipt.workflow_instance_id != 0, "Workflow instance must be non-zero");
    assert(receipt.context != 0, "Coord v2 context must be non-zero");
    assert(receipt.profile_id != 0, "Profile id must be non-zero");
    assert(receipt.profile_version != 0, "Profile version must be non-zero");
    assert(receipt.profile_manifest_hash != 0, "Profile manifest hash must be non-zero");
    assert(receipt.profile_vk_hash != 0, "Profile VK hash must be non-zero");
    assert(receipt.verifier_policy_root != 0, "Verifier policy root must be non-zero");
    assert(receipt.step_id != 0, "Step id must be non-zero");
    assert(
        receipt.assurance_class >= 1 & receipt.assurance_class <= 3,
        "Assurance class must be in 1..=3",
    );
    assert(receipt.step_index != 0xffffffff, "Step index exceeds Coord v2 bound");
    assert(receipt.predecessor_count <= 4, "Predecessor count exceeds fan-in bound");

    for i in 0..4 {
        if i < receipt.predecessor_count as u32 {
            assert(receipt.predecessor_step_ids[i] != 0, "Active predecessor id must be non-zero");
        } else {
            assert(
                (receipt.predecessor_step_ids[i] == 0) & (receipt.input_commitments[i] == 0),
                "Inactive predecessor slots must be zero",
            );
        }
    }

    for i in 0..4 {
        for j in (i + 1)..4 {
            if i < receipt.predecessor_count as u32 & j < receipt.predecessor_count as u32 {
                assert(
                    receipt.predecessor_step_ids[i] != receipt.predecessor_step_ids[j],
                    "Active predecessor ids must be unique",
                );
            }
        }
    }

    assert(
        receipt.input_set_commitment
            == compute_input_set_commitment(
                receipt.predecessor_count,
                receipt.predecessor_step_ids,
                receipt.input_commitments,
            ),
        "Input set commitment mismatch",
    );

    if receipt.step_index == 0 {
        assert(receipt.predecessor_count == 0, "Genesis must not have predecessors");
        assert(
            receipt.pre_state_commitment == receipt.initial_state_commitment,
            "Genesis pre-state must equal initial state",
        );
    } else {
        assert(receipt.predecessor_count > 0, "Non-genesis step requires a predecessor");
    }

    assert(
        receipt.topology_commitment == compute_topology_commitment(receipt),
        "Topology commitment mismatch",
    );
    let workflow_root = compute_merkle_root(
        receipt.topology_commitment,
        (receipt.step_index + 1) as Field,
        workflow_path,
    );
    assert(
        workflow_root == receipt.workflow_definition_hash,
        "Workflow topology membership mismatch",
    );
    assert(
        receipt.receipt_commitment == compute_receipt_commitment(receipt),
        "Receipt commitment mismatch",
    );
}

#[test]
fn workflow_metadata_fold_binds_every_member() {
    let commitment = compute_workflow_metadata_commitment(2, 1, 9, 4);
    assert(compute_workflow_metadata_commitment(3, 1, 9, 4) != commitment);
    assert(compute_workflow_metadata_commitment(2, 2, 9, 4) != commitment);
    assert(compute_workflow_metadata_commitment(2, 1, 10, 4) != commitment);
    assert(compute_workflow_metadata_commitment(2, 1, 9, 5) != commitment);
}

#[test]
fn profile_leaf_binds_complete_identity() {
    let leaf = compute_profile_leaf(1, 2, 3, 4, 1);
    assert(compute_profile_leaf(2, 2, 3, 4, 1) != leaf);
    assert(compute_profile_leaf(1, 3, 3, 4, 1) != leaf);
    assert(compute_profile_leaf(1, 2, 4, 4, 1) != leaf);
    assert(compute_profile_leaf(1, 2, 3, 5, 1) != leaf);
    assert(compute_profile_leaf(1, 2, 3, 4, 2) != leaf);
}
