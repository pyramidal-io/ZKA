// =============================================================================
// ZKA Multi-Asset Transfer Circuit (Noir / BN254)
//
// Spec Reference: ZKA v0.4.0, Section 3.2 (extended)
//
// Proves a private multi-asset transfer for up to MAX_ASSETS (4) assets in
// a single proof. Each active slot enforces 6 constraints:
//   1. Input note commitment validity
//   2. Merkle membership of input note
//   3. Nullifier correctness (double-spend prevention)
//   4. Ownership verification (spending key -> address)
//   5. Output note commitment validity
//   6. Value conservation (input == output)
//
// Additional global constraints:
//   - num_assets must be in {1, 2, 3, 4}
//   - Inactive slots (i >= num_assets) must have zero nullifiers and commitments
//   - At least one active slot must have non-zero value
//   - Context binding via public input
//
// A single spending_key owns all input notes (batch transfer by one sender).
//
// Public Inputs (14):
//   nullifiers[4]          - Prevents double-spending per slot
//   output_commitments[4]  - New notes entering the system
//   merkle_root            - Shared state tree anchor
//   context                - Replay protection
//   asset_commitments[4]   - Asset type per slot
//   num_assets             - Active slot count (1-4)
// =============================================================================

use zka_lib::{
    compute_merkle_root, compute_note_commitment, compute_nullifier, derive_address, MERKLE_DEPTH,
};

/// Maximum number of asset slots in a single multi-transfer proof.
global MAX_ASSETS: u32 = 4;

fn main(
    // === Public Inputs ===
    nullifiers: pub [Field; 4],
    output_commitments: pub [Field; 4],
    merkle_root: pub Field,
    context: pub Field,
    asset_commitments: pub [Field; 4],
    num_assets: pub Field,
    // === Private Inputs: Input Notes ===
    input_values: [Field; 4],
    input_recipients: [Field; 4],
    input_randomnesses: [Field; 4],
    // === Private Inputs: Merkle Paths ===
    merkle_siblings: [[Field; 32]; 4],
    merkle_path_indices: [Field; 4],
    // === Private Inputs: Spending Key ===
    spending_key: Field,
    // === Private Inputs: Output Notes ===
    output_values: [Field; 4],
    output_recipients: [Field; 4],
    output_randomnesses: [Field; 4],
) {
    // =========================================================================
    // GLOBAL: num_assets must be in {1, 2, 3, 4}
    //
    // Algebraic enforcement: (n-1)(n-2)(n-3)(n-4) == 0
    // This is zero iff n in {1,2,3,4}. No branching needed.
    // =========================================================================
    let n = num_assets;
    let valid_count = (n - 1) * (n - 2) * (n - 3) * (n - 4);
    assert(valid_count == 0, "num_assets must be 1, 2, 3, or 4");

    // =========================================================================
    // Derive the sender address once (shared across all slots)
    // =========================================================================
    let sender_address = derive_address(spending_key);

    // =========================================================================
    // Track whether at least one active slot has non-zero value
    // =========================================================================
    let mut has_nonzero_value = false;

    // =========================================================================
    // Per-slot constraints
    // =========================================================================
    for i in 0..MAX_ASSETS {
        let idx = i as Field;

        // Determine if this slot is active.
        // Active when idx < num_assets, i.e., (idx + 1) <= num_assets.
        // We use an algebraic check: multiply (num_assets - j) for j in 0..=idx.
        // This product is non-zero iff num_assets > idx.
        let mut activity_product: Field = 1;
        for j in 0..(i + 1) {
            activity_product *= (num_assets - (j as Field));
        }
        // activity_product != 0 means this slot is active
        // We need a boolean: use the fact that for inactive slots, activity_product == 0.

        if activity_product != 0 {
            // === ACTIVE SLOT ===

            assert(output_randomnesses[i] != 0, "Output randomness must be non-zero");
            for input_slot in 0..MAX_ASSETS {
                let mut input_activity_product: Field = 1;
                for active_index in 0..(input_slot + 1) {
                    input_activity_product *= (num_assets - (active_index as Field));
                }
                if input_activity_product != 0 {
                    assert(
                        output_randomnesses[i] != input_randomnesses[input_slot],
                        "Output randomness must not reuse any active input randomness",
                    );
                }
            }
            for prior in 0..MAX_ASSETS {
                if prior < i {
                    assert(
                        output_randomnesses[i] != output_randomnesses[prior],
                        "Active output randomness must be distinct",
                    );
                }
            }

            has_nonzero_value |= (input_values[i] != 0);

            // 1. INPUT NOTE COMMITMENT
            let input_commitment = compute_note_commitment(
                asset_commitments[i],
                input_values[i],
                input_recipients[i],
                input_randomnesses[i],
            );

            // 2. MERKLE MEMBERSHIP
            let computed_root =
                compute_merkle_root(input_commitment, merkle_path_indices[i], merkle_siblings[i]);
            assert(
                computed_root == merkle_root,
                "Merkle root mismatch: input note not in state tree",
            );

            // 3. NULLIFIER CORRECTNESS
            let expected_nullifier = compute_nullifier(input_commitment, spending_key);
            assert(expected_nullifier == nullifiers[i], "Nullifier mismatch");

            // 4. OWNERSHIP VERIFICATION
            assert(sender_address == input_recipients[i], "Ownership verification failed");

            // 5. OUTPUT NOTE COMMITMENT
            let expected_output = compute_note_commitment(
                asset_commitments[i],
                output_values[i],
                output_recipients[i],
                output_randomnesses[i],
            );
            assert(expected_output == output_commitments[i], "Output commitment mismatch");

            // 6. VALUE CONSERVATION
            assert(input_values[i] == output_values[i], "Value conservation violated");
        } else {
            // === INACTIVE SLOT ===
            // Inactive slots must have zero nullifiers and output commitments
            assert(nullifiers[i] == 0, "Inactive slot must have zero nullifier");
            assert(output_commitments[i] == 0, "Inactive slot must have zero output commitment");
        }
    }

    // =========================================================================
    // GLOBAL: At least one active slot must transfer non-zero value
    // =========================================================================
    assert(has_nonzero_value, "At least one asset must have non-zero value");
}

// =============================================================================
// Test Helpers
// =============================================================================

/// Build valid test data for a single slot, returning all the fields needed.
/// Uses zero-siblings Merkle paths for simplicity.
fn build_slot(
    spending_key: Field,
    asset_id: Field,
    value: Field,
    output_recipient: Field,
    input_rand: Field,
    output_rand: Field,
) -> (Field, Field, Field, Field, Field, Field, Field, [Field; 32], Field, Field) {
    let sender = derive_address(spending_key);
    let asset_comm = zka_lib::compute_asset_commitment(asset_id);
    let input_commitment = compute_note_commitment(asset_comm, value, sender, input_rand);
    let nullifier = compute_nullifier(input_commitment, spending_key);
    let siblings: [Field; 32] = [0; 32];
    let merkle_root = compute_merkle_root(input_commitment, 0, siblings);
    let output_comm = compute_note_commitment(asset_comm, value, output_recipient, output_rand);

    // Returns: (nullifier, output_comm, merkle_root, asset_comm,
    //           input_value, input_recipient, input_rand,
    //           siblings, path_index,
    //           output_value)
    // Note: output_recipient and output_rand are passed through by caller
    (nullifier, output_comm, merkle_root, asset_comm, value, sender, input_rand, siblings, 0, value)
}

/// Create zero-filled inactive slot public data
fn zero_slot() -> (Field, Field, Field) {
    (0, 0, 0) // nullifier, output_commitment, asset_commitment
}

// =============================================================================
// Tests
// =============================================================================

#[test]
fn test_valid_single_asset() {
    // Single asset transfer (num_assets = 1), mirrors basic zka_transfer behavior
    let spending_key = 0x42;
    let output_recipient = 0xdeadbeef;
    let (nf, out_comm, root, asset_comm, val, sender, in_rand, siblings, path_idx, out_val) =
        build_slot(spending_key, 0x01, 1000, output_recipient, 0xaabb, 0xccdd);

    main(
        [nf, 0, 0, 0],
        [out_comm, 0, 0, 0],
        root,
        0x12345678,
        [asset_comm, 0, 0, 0],
        1,
        // Private inputs
        [val, 0, 0, 0],
        [sender, 0, 0, 0],
        [in_rand, 0, 0, 0],
        [siblings, [0; 32], [0; 32], [0; 32]],
        [path_idx, 0, 0, 0],
        spending_key,
        [out_val, 0, 0, 0],
        [output_recipient, 0, 0, 0],
        [0xccdd, 0, 0, 0],
    );
}

#[test]
fn test_valid_two_assets() {
    // Two different assets transferred in one proof
    let spending_key = 0x42;
    let sender = derive_address(spending_key);
    let out_recip_1 = 0xaaaa;
    let out_recip_2 = 0xbbbb;

    // Both slots must share the same merkle_root, so we need to build
    // a tree that contains both input commitments. For testing with zero
    // siblings, we place them at different path indices so they share a root
    // only if the tree is constructed properly.
    //
    // For simplicity in tests, we use the same root by having both leaves
    // at index 0 in separate trees -- but in the circuit, there's one shared root.
    // We handle this by putting both at different indices with zero siblings,
    // which yields different roots. Instead, we construct both at index 0
    // and adjust: the circuit checks each leaf against the SAME root.
    //
    // Strategy: both input commitments use zero-siblings, placed at different
    // indices so the Merkle root matches. Actually with zero siblings, the
    // root depends on the leaf and index. We need them to share a root.
    //
    // Simplest approach: use the same leaf for both (same asset/value/etc)
    // OR build a real 2-leaf tree. Let's use a real approach:
    // Put leaf_0 at index 0, leaf_1 at index 1.
    // For depth-32 tree with zero siblings except sibling[0] = the other leaf.

    let asset_comm_1 = zka_lib::compute_asset_commitment(0x01);
    let asset_comm_2 = zka_lib::compute_asset_commitment(0x02);

    let in_comm_1 = compute_note_commitment(asset_comm_1, 1000, sender, 0xaa);
    let in_comm_2 = compute_note_commitment(asset_comm_2, 2000, sender, 0xbb);

    // Build a Merkle tree where leaf at index 0 = in_comm_1, leaf at index 1 = in_comm_2.
    // sibling of index 0 at level 0 = in_comm_2
    // sibling of index 1 at level 0 = in_comm_1
    // All other siblings are 0 (empty subtrees).
    let mut siblings_1: [Field; 32] = [0; 32];
    siblings_1[0] = in_comm_2;

    let mut siblings_2: [Field; 32] = [0; 32];
    siblings_2[0] = in_comm_1;

    let root = compute_merkle_root(in_comm_1, 0, siblings_1);
    // Verify both paths lead to the same root
    let root_check = compute_merkle_root(in_comm_2, 1, siblings_2);
    assert(root == root_check);

    let nf_1 = compute_nullifier(in_comm_1, spending_key);
    let nf_2 = compute_nullifier(in_comm_2, spending_key);

    let out_comm_1 = compute_note_commitment(asset_comm_1, 1000, out_recip_1, 0xcc);
    let out_comm_2 = compute_note_commitment(asset_comm_2, 2000, out_recip_2, 0xdd);

    main(
        [nf_1, nf_2, 0, 0],
        [out_comm_1, out_comm_2, 0, 0],
        root,
        0x12345678,
        [asset_comm_1, asset_comm_2, 0, 0],
        2,
        // Private inputs
        [1000, 2000, 0, 0],
        [sender, sender, 0, 0],
        [0xaa, 0xbb, 0, 0],
        [siblings_1, siblings_2, [0; 32], [0; 32]],
        [0, 1, 0, 0],
        spending_key,
        [1000, 2000, 0, 0],
        [out_recip_1, out_recip_2, 0, 0],
        [0xcc, 0xdd, 0, 0],
    );
}

#[test(should_fail_with = "Output randomness must not reuse any active input randomness")]
fn test_cross_slot_input_randomness_reuse_fails() {
    let spending_key = 0x42;
    let sender = derive_address(spending_key);
    let asset_comm_1 = zka_lib::compute_asset_commitment(0x01);
    let asset_comm_2 = zka_lib::compute_asset_commitment(0x02);
    let values: [Field; 2] = [1000, 2000];
    let input_randomnesses: [Field; 2] = [0xaa, 0xbb];
    let output_recipients: [Field; 2] = [0xaaaa, 0xbbbb];

    let input_commitment_1 =
        compute_note_commitment(asset_comm_1, values[0], sender, input_randomnesses[0]);
    let input_commitment_2 =
        compute_note_commitment(asset_comm_2, values[1], sender, input_randomnesses[1]);
    let mut siblings_1: [Field; 32] = [0; 32];
    siblings_1[0] = input_commitment_2;
    let mut siblings_2: [Field; 32] = [0; 32];
    siblings_2[0] = input_commitment_1;
    let root = compute_merkle_root(input_commitment_1, 0, siblings_1);

    let nullifiers = [
        compute_nullifier(input_commitment_1, spending_key),
        compute_nullifier(input_commitment_2, spending_key),
        0,
        0,
    ];
    // Swap the two active input blindings. Per-slot inequality still holds,
    // but neither value is fresh with respect to the complete input set.
    let output_randomnesses: [Field; 4] = [input_randomnesses[1], input_randomnesses[0], 0, 0];
    let output_commitments = [
        compute_note_commitment(
            asset_comm_1,
            values[0],
            output_recipients[0],
            output_randomnesses[0],
        ),
        compute_note_commitment(
            asset_comm_2,
            values[1],
            output_recipients[1],
            output_randomnesses[1],
        ),
        0,
        0,
    ];

    main(
        nullifiers,
        output_commitments,
        root,
        0x12345678,
        [asset_comm_1, asset_comm_2, 0, 0],
        2,
        [values[0], values[1], 0, 0],
        [sender, sender, 0, 0],
        [input_randomnesses[0], input_randomnesses[1], 0, 0],
        [siblings_1, siblings_2, [0; 32], [0; 32]],
        [0, 1, 0, 0],
        spending_key,
        [values[0], values[1], 0, 0],
        [output_recipients[0], output_recipients[1], 0, 0],
        output_randomnesses,
    );
}

#[test]
fn test_valid_four_assets() {
    // All 4 slots active
    let spending_key = 0x42;
    let sender = derive_address(spending_key);

    let asset_comms = [
        zka_lib::compute_asset_commitment(0x01),
        zka_lib::compute_asset_commitment(0x02),
        zka_lib::compute_asset_commitment(0x03),
        zka_lib::compute_asset_commitment(0x04),
    ];
    let values: [Field; 4] = [100, 200, 300, 400];
    let in_rands: [Field; 4] = [0xa1, 0xa2, 0xa3, 0xa4];
    let out_rands: [Field; 4] = [0xb1, 0xb2, 0xb3, 0xb4];
    let out_recips: [Field; 4] = [0xc1, 0xc2, 0xc3, 0xc4];

    // Compute input commitments
    let in_comms = [
        compute_note_commitment(asset_comms[0], values[0], sender, in_rands[0]),
        compute_note_commitment(asset_comms[1], values[1], sender, in_rands[1]),
        compute_note_commitment(asset_comms[2], values[2], sender, in_rands[2]),
        compute_note_commitment(asset_comms[3], values[3], sender, in_rands[3]),
    ];

    // Build a 4-leaf Merkle tree.
    // Indices: 0, 1, 2, 3
    // Level 0 pairs: (in_comms[0], in_comms[1]) and (in_comms[2], in_comms[3])
    // We need internal nodes for sibling paths.
    //
    // For a depth-32 tree with 4 leaves at indices 0-3:
    //   Level 0 siblings: leaf at index 0 needs sibling = leaf at index 1, etc.
    //   Level 1: hash of (leaf[0], leaf[1]) and hash of (leaf[2], leaf[3])
    //   Level 2+: all zeros (empty subtrees)

    // Compute level-1 internal nodes using Poseidon2 (matching zka_lib::compute_merkle_root)
    let node_01 = zka_lib::poseidon2(in_comms[0], in_comms[1]);
    let node_23 = zka_lib::poseidon2(in_comms[2], in_comms[3]);

    // Sibling arrays for each leaf
    let mut siblings_0: [Field; 32] = [0; 32];
    siblings_0[0] = in_comms[1]; // sibling at level 0
    siblings_0[1] = node_23; // sibling at level 1

    let mut siblings_1: [Field; 32] = [0; 32];
    siblings_1[0] = in_comms[0]; // sibling at level 0
    siblings_1[1] = node_23; // sibling at level 1

    let mut siblings_2: [Field; 32] = [0; 32];
    siblings_2[0] = in_comms[3]; // sibling at level 0
    siblings_2[1] = node_01; // sibling at level 1

    let mut siblings_3: [Field; 32] = [0; 32];
    siblings_3[0] = in_comms[2]; // sibling at level 0
    siblings_3[1] = node_01; // sibling at level 1

    let root = compute_merkle_root(in_comms[0], 0, siblings_0);

    // Nullifiers
    let nfs = [
        compute_nullifier(in_comms[0], spending_key),
        compute_nullifier(in_comms[1], spending_key),
        compute_nullifier(in_comms[2], spending_key),
        compute_nullifier(in_comms[3], spending_key),
    ];

    // Output commitments
    let out_comms = [
        compute_note_commitment(asset_comms[0], values[0], out_recips[0], out_rands[0]),
        compute_note_commitment(asset_comms[1], values[1], out_recips[1], out_rands[1]),
        compute_note_commitment(asset_comms[2], values[2], out_recips[2], out_rands[2]),
        compute_note_commitment(asset_comms[3], values[3], out_recips[3], out_rands[3]),
    ];

    main(
        nfs,
        out_comms,
        root,
        0xfeedface,
        asset_comms,
        4,
        // Private inputs
        values,
        [sender, sender, sender, sender],
        in_rands,
        [siblings_0, siblings_1, siblings_2, siblings_3],
        [0, 1, 2, 3],
        spending_key,
        values,
        out_recips,
        out_rands,
    );
}

#[test(should_fail_with = "Value conservation violated")]
fn test_value_mismatch_fails() {
    let spending_key = 0x42;
    let sender = derive_address(spending_key);
    let asset_comm = zka_lib::compute_asset_commitment(0x01);

    let input_commitment = compute_note_commitment(asset_comm, 1000, sender, 0xaa);
    let nf = compute_nullifier(input_commitment, spending_key);
    let siblings: [Field; 32] = [0; 32];
    let root = compute_merkle_root(input_commitment, 0, siblings);

    // Mismatched output value: 500 != 1000
    let out_comm = compute_note_commitment(asset_comm, 500, 0xcc, 0xbb);

    main(
        [nf, 0, 0, 0],
        [out_comm, 0, 0, 0],
        root,
        0x00,
        [asset_comm, 0, 0, 0],
        1,
        [1000, 0, 0, 0],
        [sender, 0, 0, 0],
        [0xaa, 0, 0, 0],
        [siblings, [0; 32], [0; 32], [0; 32]],
        [0, 0, 0, 0],
        spending_key,
        [500, 0, 0, 0],
        [0xcc, 0, 0, 0],
        [0xbb, 0, 0, 0],
    );
}

#[test(should_fail_with = "Inactive slot must have zero nullifier")]
fn test_inactive_slots_must_be_zero() {
    // num_assets = 1 but slot 1 has a non-zero nullifier
    let spending_key = 0x42;
    let sender = derive_address(spending_key);
    let asset_comm = zka_lib::compute_asset_commitment(0x01);

    let input_commitment = compute_note_commitment(asset_comm, 1000, sender, 0xaa);
    let nf = compute_nullifier(input_commitment, spending_key);
    let siblings: [Field; 32] = [0; 32];
    let root = compute_merkle_root(input_commitment, 0, siblings);
    let out_comm = compute_note_commitment(asset_comm, 1000, 0xcc, 0xbb);

    main(
        [nf, 0xBAD, 0, 0], // slot 1 nullifier is non-zero but inactive
        [out_comm, 0, 0, 0],
        root,
        0x00,
        [asset_comm, 0, 0, 0],
        1,
        [1000, 0, 0, 0],
        [sender, 0, 0, 0],
        [0xaa, 0, 0, 0],
        [siblings, [0; 32], [0; 32], [0; 32]],
        [0, 0, 0, 0],
        spending_key,
        [1000, 0, 0, 0],
        [0xcc, 0, 0, 0],
        [0xbb, 0, 0, 0],
    );
}

#[test(should_fail_with = "num_assets must be 1, 2, 3, or 4")]
fn test_num_assets_zero_fails() {
    main(
        [0, 0, 0, 0],
        [0, 0, 0, 0],
        0,
        0,
        [0, 0, 0, 0],
        0,
        [0, 0, 0, 0],
        [0, 0, 0, 0],
        [0, 0, 0, 0],
        [[0; 32], [0; 32], [0; 32], [0; 32]],
        [0, 0, 0, 0],
        0,
        [0, 0, 0, 0],
        [0, 0, 0, 0],
        [0, 0, 0, 0],
    );
}

#[test(should_fail_with = "Ownership verification failed")]
fn test_wrong_spending_key_fails() {
    let real_key = 0x42;
    let wrong_key = 0x99;
    let sender = derive_address(real_key);
    let asset_comm = zka_lib::compute_asset_commitment(0x01);

    let input_commitment = compute_note_commitment(asset_comm, 500, sender, 0xaa);
    // Use wrong_key for nullifier -- but ownership check uses wrong_key's address != sender
    let nf = compute_nullifier(input_commitment, wrong_key);
    let siblings: [Field; 32] = [0; 32];
    let root = compute_merkle_root(input_commitment, 0, siblings);
    let out_comm = compute_note_commitment(asset_comm, 500, 0xcc, 0xbb);

    main(
        [nf, 0, 0, 0],
        [out_comm, 0, 0, 0],
        root,
        0x00,
        [asset_comm, 0, 0, 0],
        1,
        [500, 0, 0, 0],
        [sender, 0, 0, 0],
        [0xaa, 0, 0, 0],
        [siblings, [0; 32], [0; 32], [0; 32]],
        [0, 0, 0, 0],
        wrong_key,
        [500, 0, 0, 0],
        [0xcc, 0, 0, 0],
        [0xbb, 0, 0, 0],
    );
}
