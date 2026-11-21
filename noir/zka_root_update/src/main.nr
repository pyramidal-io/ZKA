// =============================================================================
// ZKA S.3.3 -- Root Update Circuit (zka_root_update)
//
// Proves: folding the deterministic interleave of `deposit_commitments` (in
// event-log order) and `blob_commitments` (in blob-payload order) into
// `prev_root` via Poseidon2 incremental insertion yields `new_root`.
//
// Bridge contracts verify this proof before advancing the accepted-root
// window. The proof establishes consistency with the prover-supplied private
// `blob_commitments`; it does not prove that those values came from published
// blob data or prevent their omission/substitution without a separate binding.
//
// Public inputs (ZKA S.3.3 RootUpdateProof.publicInputs):
//   prev_root               - tree root before this batch
//   new_root                - tree root after this batch
//   prev_total              - commitments folded so far (tree leaf count before)
//   new_total               - commitments folded after this update
//   blob_kzg_commitment     - legacy-named, non-zero proof-bound tag; not a blob binding
//   deposit_commitments     - ordered by on-chain event-log position
//   deposit_commitments_len - number of active entries in deposit_commitments
//
// Private inputs:
//   blob_commitments        - prover-supplied values; not bound to blob_kzg_commitment
//   blob_commitments_len    - number of active blob commitments
//   intermediate_paths      - one Merkle sibling path per insertion
//
// MERKLE_DEPTH and Poseidon2 parameters per ZKA S.2.4 / S.2.1.
// =============================================================================

use zka_lib::compute_merkle_root;
use zka_lib::POSEIDON2_EMPTY_ROOT_DEPTH_32;

global MERKLE_DEPTH: u32 = 32;
// Implementation limits; S.3.3 leaves batch size open. 16 = typical max
// Ethereum event-log count per L1 block; 400 = typical max EIP-4844
// blob commitments per blob at ~256-byte ciphertext payloads. Changing
// these requires re-proving the circuit verifier.
global MAX_DEPOSIT_COMMITMENTS: u32 = 16;
global MAX_BLOB_COMMITMENTS: u32 = 400;
global MAX_BATCH_SIZE: u32 = 416; // MAX_DEPOSIT_COMMITMENTS + MAX_BLOB_COMMITMENTS

fn main(
    // === Public inputs ===
    prev_root: pub Field,
    new_root: pub Field,
    prev_total: pub u64,
    new_total: pub u64,
    blob_kzg_commitment: pub Field,
    deposit_commitments: pub [Field; MAX_DEPOSIT_COMMITMENTS],
    deposit_commitments_len: pub u32,
    // === Private inputs ===
    blob_commitments: [Field; MAX_BLOB_COMMITMENTS],
    blob_commitments_len: u32,
    intermediate_paths: [[Field; MERKLE_DEPTH]; MAX_BATCH_SIZE],
) {
    // -----------------------------------------------------------------
    // Constraint 1 (ZKA S.3.3 C1): Count consistency
    //   new_total - prev_total == deposit_commitments_len + blob_commitments_len
    // -----------------------------------------------------------------
    assert(
        deposit_commitments_len <= MAX_DEPOSIT_COMMITMENTS,
        "deposit_commitments_len exceeds MAX_DEPOSIT_COMMITMENTS",
    );
    assert(
        blob_commitments_len <= MAX_BLOB_COMMITMENTS,
        "blob_commitments_len exceeds MAX_BLOB_COMMITMENTS",
    );

    let total_inserted: u64 = (deposit_commitments_len as u64) + (blob_commitments_len as u64);
    assert(
        new_total - prev_total == total_inserted,
        "Count consistency violated: new_total - prev_total != deposit_len + blob_len",
    );

    // -----------------------------------------------------------------
    // Constraint 6 (ZKA S.3.3 C6): legacy blob-tag non-zero check
    //   blob_kzg_commitment is proof-bound as a public input but is otherwise
    //   unconstrained except for this non-zero assertion. This circuit neither
    //   computes/verifies a KZG commitment nor relates blob_commitments to a
    //   blob preimage. The deployed legacy APLBridge also accepts this value
    //   from calldata without executing BLOBHASH, so this check provides no
    //   blob data-availability or leaf-binding guarantee. A successor must bind
    //   a same-transaction blob versioned hash on-chain and prove that the
    //   ordered commitment projection decoded from the canonical blob contents
    //   equals the private commitments being folded.
    // -----------------------------------------------------------------
    assert(blob_kzg_commitment != 0, "blob_kzg_commitment must be non-zero");

    // -----------------------------------------------------------------
    // Constraint 2 (ZKA S.3.3 C2): Deterministic interleave order
    //   Deposits come first (event-log order), then blob commitments.
    //   Build the combined ordered array.
    // -----------------------------------------------------------------
    let combined: [Field; MAX_BATCH_SIZE] = build_interleaved(
        deposit_commitments,
        deposit_commitments_len,
        blob_commitments,
        blob_commitments_len,
    );

    // -----------------------------------------------------------------
    // Constraints 3, 4, 5 (ZKA S.3.3 C3/C4/C5):
    //   Incremental insertion, Poseidon2, tree depth=32.
    //
    // For each insertion i in 0..total_inserted:
    //   - leaf index = prev_total + i
    //   - BEFORE insertion: tree root with empty leaf at this index
    //     = compute_merkle_root(0, prev_total+i, intermediate_paths[i])
    //     must equal current_root (prev_root for i=0, root after prior
    //     insertion for i>0)
    //   - AFTER insertion: tree root with combined[i] at this index
    //     = compute_merkle_root(combined[i], prev_total+i, intermediate_paths[i])
    //     becomes the new current_root
    //
    // By checking the pre-insertion root matches, we cryptographically
    // chain consecutive insertions through prev_root to new_root.
    // -----------------------------------------------------------------
    let final_root = fold_insertions(
        prev_root,
        combined,
        total_inserted as u32,
        prev_total,
        intermediate_paths,
    );

    assert(
        final_root == new_root,
        "Incremental insertion fold did not produce the expected new_root",
    );
}

// Build the combined interleaved array: deposits first, then blobs.
// Entries beyond their respective lengths are left as 0 (ignored by fold).
fn build_interleaved(
    deposits: [Field; MAX_DEPOSIT_COMMITMENTS],
    deposits_len: u32,
    blobs: [Field; MAX_BLOB_COMMITMENTS],
    blobs_len: u32,
) -> [Field; MAX_BATCH_SIZE] {
    let mut out: [Field; MAX_BATCH_SIZE] = [0; MAX_BATCH_SIZE];
    for i in 0..MAX_DEPOSIT_COMMITMENTS {
        if i < deposits_len {
            out[i] = deposits[i];
        }
    }
    for j in 0..MAX_BLOB_COMMITMENTS {
        if j < blobs_len {
            out[deposits_len + j] = blobs[j];
        }
    }
    out
}

// Incremental insertion fold.
//
// For each insertion i in 0..count:
//   1. Verify the pre-insertion root: compute_merkle_root(0, leaf_index, paths[i])
//      must equal current_root. This chains insertions through prev_root.
//   2. Compute post-insertion root: compute_merkle_root(combined[i], leaf_index, paths[i]).
//   3. Advance current_root.
//
// Returns the root after all `count` insertions.
//
// Soundness: Poseidon2 collision resistance means there is at most one leaf
// value at this index that maps to current_root via paths[i]. The pre-check
// establishes that the slot is empty (leaf=0), so the same path correctly
// computes the unique post-insertion root. A path forgery would require a
// Poseidon2 collision.
//
// NOTE: The circuit uses MAX_BATCH_SIZE iterations (fixed per Noir's loop model).
// Only the first `count` iterations do real work; the rest are no-ops that keep
// current_root unchanged (guarded by the `if i < count` check).
fn fold_insertions(
    prev_root: Field,
    combined: [Field; MAX_BATCH_SIZE],
    count: u32,
    start_index: u64,
    paths: [[Field; MERKLE_DEPTH]; MAX_BATCH_SIZE],
) -> Field {
    let mut current_root = prev_root;
    for i in 0..MAX_BATCH_SIZE {
        if i < count {
            let leaf_index: Field = (start_index + (i as u64)) as Field;

            // C3 pre-insertion check: path witnesses tree state before this insertion.
            // The empty-leaf check binds current_root to intermediate_paths[i].
            let pre_root = compute_merkle_root(0, leaf_index, paths[i]);
            assert(
                pre_root == current_root,
                "Intermediate Merkle path does not match current root before insertion",
            );

            // C3/C4/C5 post-insertion: compute root after inserting combined[i].
            let post_root = compute_merkle_root(combined[i], leaf_index, paths[i]);
            current_root = post_root;
        }
    }
    current_root
}

// =============================================================================
// Tests
// =============================================================================

// KAT golden constants. These are the canonical Noir Poseidon2 (poseidon v0.3.0)
// values. POSEIDON2_EMPTY_ROOT_DEPTH_32 is imported from zka_lib (single source
// of truth); a drift there will surface here immediately.

// Empty subtree hashes e[0..31] where e[0]=0, e[i+1]=poseidon2(e[i],e[i]).
// Used to build sibling paths for insertions into the empty tree.
global E: [Field; 32] = [
    0x00,
    0x0b63a53787021a4a962a452c2921b3663aff1ffd8d5510540f8e659e782956f1,
    0x0e34ac2c09f45a503d2908bcb12f1cbae5fa4065759c88d501c097506a8b2290,
    0x21f9172d72fdcdafc312eee05cf5092980dda821da5b760a9fb8dbdf607c8a20,
    0x2373ea368857ec7af97e7b470d705848e2bf93ed7bef142a490f2119bcf82d8e,
    0x120157cfaaa49ce3da30f8b47879114977c24b266d58b0ac18b325d878aafddf,
    0x01c28fe1059ae0237b72334700697bdf465e03df03986fe05200cadeda66bd76,
    0x2d78ed82f93b61ba718b17c2dfe5b52375b4d37cbbed6f1fc98b47614b0cf21b,
    0x067243231eddf4222f3911defbba7705aff06ed45960b27f6f91319196ef97e1,
    0x1849b85f3c693693e732dfc4577217acc18295193bede09ce8b97ad910310972,
    0x2a775ea761d20435b31fa2c33ff07663e24542ffb9e7b293dfce3042eb104686,
    0x0f320b0703439a8114f81593de99cd0b8f3b9bf854601abb5b2ea0e8a3dda4a7,
    0x0d07f6e7a8a0e9199d6d92801fff867002ff5b4808962f9da2ba5ce1bdd26a73,
    0x1c4954081e324939350febc2b918a293ebcdaead01be95ec02fcbe8d2c1635d1,
    0x0197f2171ef99c2d053ee1fb5ff5ab288d56b9b41b4716c9214a4d97facc4c4a,
    0x2b9cdd484c5ba1e4d6efcc3f18734b5ac4c4a0b9102e2aeb48521a661d3feee9,
    0x14f44d672eb357739e42463497f9fdac46623af863eea4d947ca00a497dcdeb3,
    0x071d7627ae3b2eabda8a810227bf04206370ac78dbf6c372380182dbd3711fe3,
    0x2fdc08d9fe075ac58cb8c00f98697861a13b3ab6f9d41a4e768f75e477475bf5,
    0x20165fe405652104dceaeeca92950aa5adc571b8cafe192878cba58ff1be49c5,
    0x1c8c3ca0b3a3d75850fcd4dc7bf1e3445cd0cfff3ca510630fd90b47e8a24755,
    0x1f0c1a8fb16b0d2ac9a146d7ae20d8d179695a92a79ed66fc45d9da4532459b3,
    0x038146ec5a2573e1c30d2fb32c66c8440f426fbd108082df41c7bebd1d521c30,
    0x17d3d12b17fe762de4b835b2180b012e808816a7f2ff69ecb9d65188235d8fd4,
    0x0e1a6b7d63a6e5a9e54e8f391dd4e9d49cdfedcbc87f02cd34d4641d2eb30491,
    0x09244eec34977ff795fc41036996ce974136377f521ac8eb9e04642d204783d2,
    0x1646d6f544ec36df9dc41f778a7ef1690a53c730b501471b6acd202194a7e8e9,
    0x064769603ba3f6c41f664d266ecb9a3a0f6567cd3e48b40f34d4894ee4c361b3,
    0x1595bb3cd19f84619dc2e368175a88d8627a7439eda9397202cdb1167531fd3f,
    0x2a529be462b81ca30265b558763b1498289c9d88277ab14f0838cb1fce4b472c,
    0x0c08da612363088ad0bbc78abd233e8ace4c05a56fdabdd5e5e9b05e428bdaee,
    0x14748d0241710ef47f54b931ac5a58082b1d56b0f0c30d55fb71a6e8c9a6be14,
];

// KAT 1: Empty fold -- zero insertions; prev_root == new_root.
// Verifies count-consistency (0==0) and that the circuit is an identity
// when no leaves are inserted.
// When count=0, fold_insertions performs no pre-insertion check; the only
// validation is final_root == new_root, which holds because final_root is
// the unchanged prev_root. This is the intended genesis behavior.
#[test]
fn kat_empty_fold() {
    let deposit_commitments: [Field; MAX_DEPOSIT_COMMITMENTS] = [0; MAX_DEPOSIT_COMMITMENTS];
    let blob_commitments: [Field; MAX_BLOB_COMMITMENTS] = [0; MAX_BLOB_COMMITMENTS];
    let intermediate_paths: [[Field; MERKLE_DEPTH]; MAX_BATCH_SIZE] =
        [[0; MERKLE_DEPTH]; MAX_BATCH_SIZE];

    main(
        POSEIDON2_EMPTY_ROOT_DEPTH_32, // prev_root
        POSEIDON2_EMPTY_ROOT_DEPTH_32, // new_root (same -- no change)
        0, // prev_total
        0, // new_total
        0x01, // blob_kzg_commitment (nonzero)
        deposit_commitments,
        0, // deposit_commitments_len
        blob_commitments,
        0, // blob_commitments_len
        intermediate_paths,
    );
}

// KAT 2: Single insertion -- leaf=0x1234 at index 0 into the empty tree.
// new_root pre-computed offline by manual Poseidon2 folding (see the `E` table
// of empty-subtree hashes above and the kat_poseidon2_empty_root_depth_32
// test in zka_lib for the cross-check primitive). Reproducible by hand
// using poseidon2(left, right) at each tree level.
// The sibling path for index 0 is all empty-subtree hashes: e[0..31].
#[test]
fn kat_single_insertion() {
    // Single deposit commitment: leaf = 0x1234
    let mut deposit_commitments: [Field; MAX_DEPOSIT_COMMITMENTS] = [0; MAX_DEPOSIT_COMMITMENTS];
    deposit_commitments[0] = 0x1234;

    let blob_commitments: [Field; MAX_BLOB_COMMITMENTS] = [0; MAX_BLOB_COMMITMENTS];

    // Sibling path for index 0: all e[0..31] (empty right siblings).
    // Only paths[0] matters (count=1); the rest are zero-filled no-ops.
    let mut intermediate_paths: [[Field; MERKLE_DEPTH]; MAX_BATCH_SIZE] =
        [[0; MERKLE_DEPTH]; MAX_BATCH_SIZE];
    intermediate_paths[0] = E;

    // Expected new_root: pre-computed offline by manual Poseidon2 folding
    // (see the `E` table above and kat_poseidon2_empty_root_depth_32 in zka_lib).
    let expected_new_root: Field =
        0x0a74b6e980510ccb256d744b331bdb9475874bdd39947d5d302b45a715524e06;

    main(
        POSEIDON2_EMPTY_ROOT_DEPTH_32, // prev_root = empty tree
        expected_new_root, // new_root after inserting 0x1234
        0, // prev_total
        1, // new_total
        0x0102, // blob_kzg_commitment (nonzero)
        deposit_commitments,
        1, // deposit_commitments_len
        blob_commitments,
        0, // blob_commitments_len
        intermediate_paths,
    );
}

// KAT 3: Wrong new_root MUST fail -- the circuit is not vacuous.
// Take the single-insertion vector and corrupt new_root by XORing 0x1.
#[test(should_fail_with = "Incremental insertion fold did not produce the expected new_root")]
fn kat_wrong_root_must_fail() {
    let mut deposit_commitments: [Field; MAX_DEPOSIT_COMMITMENTS] = [0; MAX_DEPOSIT_COMMITMENTS];
    deposit_commitments[0] = 0x1234;

    let blob_commitments: [Field; MAX_BLOB_COMMITMENTS] = [0; MAX_BLOB_COMMITMENTS];

    let mut intermediate_paths: [[Field; MERKLE_DEPTH]; MAX_BATCH_SIZE] =
        [[0; MERKLE_DEPTH]; MAX_BATCH_SIZE];
    intermediate_paths[0] = E;

    // Corrupt new_root: XOR the correct value with 0x1 (flip LSB)
    let corrupted_new_root: Field =
        0x0a74b6e980510ccb256d744b331bdb9475874bdd39947d5d302b45a715524e07;

    main(
        POSEIDON2_EMPTY_ROOT_DEPTH_32,
        corrupted_new_root, // WRONG: should be 0x...06, not 0x...07
        0,
        1,
        0x0102,
        deposit_commitments,
        1,
        blob_commitments,
        0,
        intermediate_paths,
    );
}

// KAT 4: Batched insertion -- 2 deposits + 3 blobs = 5 insertions.
//
// Leaves (deposit_commitments): [1, 2], deposit_commitments_len = 2
// Leaves (blob_commitments):    [0x101, 0x102, 0x103], blob_commitments_len = 3
// Inserted sequentially at indices 0..4 from the empty tree.
//
// Sibling paths and new_root pre-computed offline by manual Poseidon2 folding
// (see the `E` table of empty-subtree hashes above and the
// kat_poseidon2_empty_root_depth_32 test in zka_lib for the cross-check
// primitive). Reproducible by hand using poseidon2(left, right) at each
// tree level.
//
// Final new_root = 0x03f5124fc06de54927adc816293d15dfd8e68169b960f4d549892584b108591d
#[test]
fn kat_batched_insertion() {
    let mut deposit_commitments: [Field; MAX_DEPOSIT_COMMITMENTS] = [0; MAX_DEPOSIT_COMMITMENTS];
    deposit_commitments[0] = 1;
    deposit_commitments[1] = 2;

    let mut blob_commitments: [Field; MAX_BLOB_COMMITMENTS] = [0; MAX_BLOB_COMMITMENTS];
    blob_commitments[0] = 0x101;
    blob_commitments[1] = 0x102;
    blob_commitments[2] = 0x103;

    // Sibling paths pre-computed offline by manual Poseidon2 folding (insertion i uses paths[i]).
    // Each path is [sibling_d0, sibling_d1, ..., sibling_d31].
    let mut intermediate_paths: [[Field; MERKLE_DEPTH]; MAX_BATCH_SIZE] =
        [[0; MERKLE_DEPTH]; MAX_BATCH_SIZE];

    // Insertion 0 (leaf=1, index=0): all empty right-siblings
    intermediate_paths[0] = E;

    // Insertion 1 (leaf=2, index=1): sibling at d=0 is leaf 1, rest are empty
    intermediate_paths[1] = [
        0x01, // left sibling = leaf 1
        0x0b63a53787021a4a962a452c2921b3663aff1ffd8d5510540f8e659e782956f1, // e[1]
        0x0e34ac2c09f45a503d2908bcb12f1cbae5fa4065759c88d501c097506a8b2290, // e[2]
        0x21f9172d72fdcdafc312eee05cf5092980dda821da5b760a9fb8dbdf607c8a20, // e[3]
        0x2373ea368857ec7af97e7b470d705848e2bf93ed7bef142a490f2119bcf82d8e, // e[4]
        0x120157cfaaa49ce3da30f8b47879114977c24b266d58b0ac18b325d878aafddf, // e[5]
        0x01c28fe1059ae0237b72334700697bdf465e03df03986fe05200cadeda66bd76, // e[6]
        0x2d78ed82f93b61ba718b17c2dfe5b52375b4d37cbbed6f1fc98b47614b0cf21b, // e[7]
        0x067243231eddf4222f3911defbba7705aff06ed45960b27f6f91319196ef97e1, // e[8]
        0x1849b85f3c693693e732dfc4577217acc18295193bede09ce8b97ad910310972, // e[9]
        0x2a775ea761d20435b31fa2c33ff07663e24542ffb9e7b293dfce3042eb104686, // e[10]
        0x0f320b0703439a8114f81593de99cd0b8f3b9bf854601abb5b2ea0e8a3dda4a7, // e[11]
        0x0d07f6e7a8a0e9199d6d92801fff867002ff5b4808962f9da2ba5ce1bdd26a73, // e[12]
        0x1c4954081e324939350febc2b918a293ebcdaead01be95ec02fcbe8d2c1635d1, // e[13]
        0x0197f2171ef99c2d053ee1fb5ff5ab288d56b9b41b4716c9214a4d97facc4c4a, // e[14]
        0x2b9cdd484c5ba1e4d6efcc3f18734b5ac4c4a0b9102e2aeb48521a661d3feee9, // e[15]
        0x14f44d672eb357739e42463497f9fdac46623af863eea4d947ca00a497dcdeb3, // e[16]
        0x071d7627ae3b2eabda8a810227bf04206370ac78dbf6c372380182dbd3711fe3, // e[17]
        0x2fdc08d9fe075ac58cb8c00f98697861a13b3ab6f9d41a4e768f75e477475bf5, // e[18]
        0x20165fe405652104dceaeeca92950aa5adc571b8cafe192878cba58ff1be49c5, // e[19]
        0x1c8c3ca0b3a3d75850fcd4dc7bf1e3445cd0cfff3ca510630fd90b47e8a24755, // e[20]
        0x1f0c1a8fb16b0d2ac9a146d7ae20d8d179695a92a79ed66fc45d9da4532459b3, // e[21]
        0x038146ec5a2573e1c30d2fb32c66c8440f426fbd108082df41c7bebd1d521c30, // e[22]
        0x17d3d12b17fe762de4b835b2180b012e808816a7f2ff69ecb9d65188235d8fd4, // e[23]
        0x0e1a6b7d63a6e5a9e54e8f391dd4e9d49cdfedcbc87f02cd34d4641d2eb30491, // e[24]
        0x09244eec34977ff795fc41036996ce974136377f521ac8eb9e04642d204783d2, // e[25]
        0x1646d6f544ec36df9dc41f778a7ef1690a53c730b501471b6acd202194a7e8e9, // e[26]
        0x064769603ba3f6c41f664d266ecb9a3a0f6567cd3e48b40f34d4894ee4c361b3, // e[27]
        0x1595bb3cd19f84619dc2e368175a88d8627a7439eda9397202cdb1167531fd3f, // e[28]
        0x2a529be462b81ca30265b558763b1498289c9d88277ab14f0838cb1fce4b472c, // e[29]
        0x0c08da612363088ad0bbc78abd233e8ace4c05a56fdabdd5e5e9b05e428bdaee, // e[30]
        0x14748d0241710ef47f54b931ac5a58082b1d56b0f0c30d55fb71a6e8c9a6be14, // e[31]
    ];

    // Insertion 2 (leaf=0x101, index=2): d=0 empty, d=1 = poseidon2(1,2) = Noir KAT golden
    intermediate_paths[2] = [
        0x00, // e[0]
        0x038682aa1cb5ae4e0a3f13da432a95c77c5c111f6f030faf9cad641ce1ed7383, // poseidon2(1,2)
        0x0e34ac2c09f45a503d2908bcb12f1cbae5fa4065759c88d501c097506a8b2290, // e[2]
        0x21f9172d72fdcdafc312eee05cf5092980dda821da5b760a9fb8dbdf607c8a20, // e[3]
        0x2373ea368857ec7af97e7b470d705848e2bf93ed7bef142a490f2119bcf82d8e, // e[4]
        0x120157cfaaa49ce3da30f8b47879114977c24b266d58b0ac18b325d878aafddf, // e[5]
        0x01c28fe1059ae0237b72334700697bdf465e03df03986fe05200cadeda66bd76, // e[6]
        0x2d78ed82f93b61ba718b17c2dfe5b52375b4d37cbbed6f1fc98b47614b0cf21b, // e[7]
        0x067243231eddf4222f3911defbba7705aff06ed45960b27f6f91319196ef97e1, // e[8]
        0x1849b85f3c693693e732dfc4577217acc18295193bede09ce8b97ad910310972, // e[9]
        0x2a775ea761d20435b31fa2c33ff07663e24542ffb9e7b293dfce3042eb104686, // e[10]
        0x0f320b0703439a8114f81593de99cd0b8f3b9bf854601abb5b2ea0e8a3dda4a7, // e[11]
        0x0d07f6e7a8a0e9199d6d92801fff867002ff5b4808962f9da2ba5ce1bdd26a73, // e[12]
        0x1c4954081e324939350febc2b918a293ebcdaead01be95ec02fcbe8d2c1635d1, // e[13]
        0x0197f2171ef99c2d053ee1fb5ff5ab288d56b9b41b4716c9214a4d97facc4c4a, // e[14]
        0x2b9cdd484c5ba1e4d6efcc3f18734b5ac4c4a0b9102e2aeb48521a661d3feee9, // e[15]
        0x14f44d672eb357739e42463497f9fdac46623af863eea4d947ca00a497dcdeb3, // e[16]
        0x071d7627ae3b2eabda8a810227bf04206370ac78dbf6c372380182dbd3711fe3, // e[17]
        0x2fdc08d9fe075ac58cb8c00f98697861a13b3ab6f9d41a4e768f75e477475bf5, // e[18]
        0x20165fe405652104dceaeeca92950aa5adc571b8cafe192878cba58ff1be49c5, // e[19]
        0x1c8c3ca0b3a3d75850fcd4dc7bf1e3445cd0cfff3ca510630fd90b47e8a24755, // e[20]
        0x1f0c1a8fb16b0d2ac9a146d7ae20d8d179695a92a79ed66fc45d9da4532459b3, // e[21]
        0x038146ec5a2573e1c30d2fb32c66c8440f426fbd108082df41c7bebd1d521c30, // e[22]
        0x17d3d12b17fe762de4b835b2180b012e808816a7f2ff69ecb9d65188235d8fd4, // e[23]
        0x0e1a6b7d63a6e5a9e54e8f391dd4e9d49cdfedcbc87f02cd34d4641d2eb30491, // e[24]
        0x09244eec34977ff795fc41036996ce974136377f521ac8eb9e04642d204783d2, // e[25]
        0x1646d6f544ec36df9dc41f778a7ef1690a53c730b501471b6acd202194a7e8e9, // e[26]
        0x064769603ba3f6c41f664d266ecb9a3a0f6567cd3e48b40f34d4894ee4c361b3, // e[27]
        0x1595bb3cd19f84619dc2e368175a88d8627a7439eda9397202cdb1167531fd3f, // e[28]
        0x2a529be462b81ca30265b558763b1498289c9d88277ab14f0838cb1fce4b472c, // e[29]
        0x0c08da612363088ad0bbc78abd233e8ace4c05a56fdabdd5e5e9b05e428bdaee, // e[30]
        0x14748d0241710ef47f54b931ac5a58082b1d56b0f0c30d55fb71a6e8c9a6be14, // e[31]
    ];

    // Insertion 3 (leaf=0x102, index=3): d=0 is 0x101, d=1 = poseidon2(1,2), rest e
    intermediate_paths[3] = [
        0x0101, // left sibling = 0x101
        0x038682aa1cb5ae4e0a3f13da432a95c77c5c111f6f030faf9cad641ce1ed7383, // poseidon2(1,2)
        0x0e34ac2c09f45a503d2908bcb12f1cbae5fa4065759c88d501c097506a8b2290, // e[2]
        0x21f9172d72fdcdafc312eee05cf5092980dda821da5b760a9fb8dbdf607c8a20, // e[3]
        0x2373ea368857ec7af97e7b470d705848e2bf93ed7bef142a490f2119bcf82d8e, // e[4]
        0x120157cfaaa49ce3da30f8b47879114977c24b266d58b0ac18b325d878aafddf, // e[5]
        0x01c28fe1059ae0237b72334700697bdf465e03df03986fe05200cadeda66bd76, // e[6]
        0x2d78ed82f93b61ba718b17c2dfe5b52375b4d37cbbed6f1fc98b47614b0cf21b, // e[7]
        0x067243231eddf4222f3911defbba7705aff06ed45960b27f6f91319196ef97e1, // e[8]
        0x1849b85f3c693693e732dfc4577217acc18295193bede09ce8b97ad910310972, // e[9]
        0x2a775ea761d20435b31fa2c33ff07663e24542ffb9e7b293dfce3042eb104686, // e[10]
        0x0f320b0703439a8114f81593de99cd0b8f3b9bf854601abb5b2ea0e8a3dda4a7, // e[11]
        0x0d07f6e7a8a0e9199d6d92801fff867002ff5b4808962f9da2ba5ce1bdd26a73, // e[12]
        0x1c4954081e324939350febc2b918a293ebcdaead01be95ec02fcbe8d2c1635d1, // e[13]
        0x0197f2171ef99c2d053ee1fb5ff5ab288d56b9b41b4716c9214a4d97facc4c4a, // e[14]
        0x2b9cdd484c5ba1e4d6efcc3f18734b5ac4c4a0b9102e2aeb48521a661d3feee9, // e[15]
        0x14f44d672eb357739e42463497f9fdac46623af863eea4d947ca00a497dcdeb3, // e[16]
        0x071d7627ae3b2eabda8a810227bf04206370ac78dbf6c372380182dbd3711fe3, // e[17]
        0x2fdc08d9fe075ac58cb8c00f98697861a13b3ab6f9d41a4e768f75e477475bf5, // e[18]
        0x20165fe405652104dceaeeca92950aa5adc571b8cafe192878cba58ff1be49c5, // e[19]
        0x1c8c3ca0b3a3d75850fcd4dc7bf1e3445cd0cfff3ca510630fd90b47e8a24755, // e[20]
        0x1f0c1a8fb16b0d2ac9a146d7ae20d8d179695a92a79ed66fc45d9da4532459b3, // e[21]
        0x038146ec5a2573e1c30d2fb32c66c8440f426fbd108082df41c7bebd1d521c30, // e[22]
        0x17d3d12b17fe762de4b835b2180b012e808816a7f2ff69ecb9d65188235d8fd4, // e[23]
        0x0e1a6b7d63a6e5a9e54e8f391dd4e9d49cdfedcbc87f02cd34d4641d2eb30491, // e[24]
        0x09244eec34977ff795fc41036996ce974136377f521ac8eb9e04642d204783d2, // e[25]
        0x1646d6f544ec36df9dc41f778a7ef1690a53c730b501471b6acd202194a7e8e9, // e[26]
        0x064769603ba3f6c41f664d266ecb9a3a0f6567cd3e48b40f34d4894ee4c361b3, // e[27]
        0x1595bb3cd19f84619dc2e368175a88d8627a7439eda9397202cdb1167531fd3f, // e[28]
        0x2a529be462b81ca30265b558763b1498289c9d88277ab14f0838cb1fce4b472c, // e[29]
        0x0c08da612363088ad0bbc78abd233e8ace4c05a56fdabdd5e5e9b05e428bdaee, // e[30]
        0x14748d0241710ef47f54b931ac5a58082b1d56b0f0c30d55fb71a6e8c9a6be14, // e[31]
    ];

    // Insertion 4 (leaf=0x103, index=4): d=0=e[0], d=1=e[1], d=2=hash(pair01,pair23)
    // Pre-computed offline by manual Poseidon2 folding (see the `E` table above).
    intermediate_paths[4] = [
        0x00, // e[0]
        0x0b63a53787021a4a962a452c2921b3663aff1ffd8d5510540f8e659e782956f1, // e[1]
        0x1fafdb0db994fe3bd80cfef85b64d7d2f5f340e8d5b1967d3698b2f0a5a8d066, // hash(pair01, pair23)
        0x21f9172d72fdcdafc312eee05cf5092980dda821da5b760a9fb8dbdf607c8a20, // e[3]
        0x2373ea368857ec7af97e7b470d705848e2bf93ed7bef142a490f2119bcf82d8e, // e[4]
        0x120157cfaaa49ce3da30f8b47879114977c24b266d58b0ac18b325d878aafddf, // e[5]
        0x01c28fe1059ae0237b72334700697bdf465e03df03986fe05200cadeda66bd76, // e[6]
        0x2d78ed82f93b61ba718b17c2dfe5b52375b4d37cbbed6f1fc98b47614b0cf21b, // e[7]
        0x067243231eddf4222f3911defbba7705aff06ed45960b27f6f91319196ef97e1, // e[8]
        0x1849b85f3c693693e732dfc4577217acc18295193bede09ce8b97ad910310972, // e[9]
        0x2a775ea761d20435b31fa2c33ff07663e24542ffb9e7b293dfce3042eb104686, // e[10]
        0x0f320b0703439a8114f81593de99cd0b8f3b9bf854601abb5b2ea0e8a3dda4a7, // e[11]
        0x0d07f6e7a8a0e9199d6d92801fff867002ff5b4808962f9da2ba5ce1bdd26a73, // e[12]
        0x1c4954081e324939350febc2b918a293ebcdaead01be95ec02fcbe8d2c1635d1, // e[13]
        0x0197f2171ef99c2d053ee1fb5ff5ab288d56b9b41b4716c9214a4d97facc4c4a, // e[14]
        0x2b9cdd484c5ba1e4d6efcc3f18734b5ac4c4a0b9102e2aeb48521a661d3feee9, // e[15]
        0x14f44d672eb357739e42463497f9fdac46623af863eea4d947ca00a497dcdeb3, // e[16]
        0x071d7627ae3b2eabda8a810227bf04206370ac78dbf6c372380182dbd3711fe3, // e[17]
        0x2fdc08d9fe075ac58cb8c00f98697861a13b3ab6f9d41a4e768f75e477475bf5, // e[18]
        0x20165fe405652104dceaeeca92950aa5adc571b8cafe192878cba58ff1be49c5, // e[19]
        0x1c8c3ca0b3a3d75850fcd4dc7bf1e3445cd0cfff3ca510630fd90b47e8a24755, // e[20]
        0x1f0c1a8fb16b0d2ac9a146d7ae20d8d179695a92a79ed66fc45d9da4532459b3, // e[21]
        0x038146ec5a2573e1c30d2fb32c66c8440f426fbd108082df41c7bebd1d521c30, // e[22]
        0x17d3d12b17fe762de4b835b2180b012e808816a7f2ff69ecb9d65188235d8fd4, // e[23]
        0x0e1a6b7d63a6e5a9e54e8f391dd4e9d49cdfedcbc87f02cd34d4641d2eb30491, // e[24]
        0x09244eec34977ff795fc41036996ce974136377f521ac8eb9e04642d204783d2, // e[25]
        0x1646d6f544ec36df9dc41f778a7ef1690a53c730b501471b6acd202194a7e8e9, // e[26]
        0x064769603ba3f6c41f664d266ecb9a3a0f6567cd3e48b40f34d4894ee4c361b3, // e[27]
        0x1595bb3cd19f84619dc2e368175a88d8627a7439eda9397202cdb1167531fd3f, // e[28]
        0x2a529be462b81ca30265b558763b1498289c9d88277ab14f0838cb1fce4b472c, // e[29]
        0x0c08da612363088ad0bbc78abd233e8ace4c05a56fdabdd5e5e9b05e428bdaee, // e[30]
        0x14748d0241710ef47f54b931ac5a58082b1d56b0f0c30d55fb71a6e8c9a6be14, // e[31]
    ];

    // Expected final root after all 5 insertions (pre-computed offline by manual
    // Poseidon2 folding; reproducible using poseidon2(left, right) at each level).
    let expected_final_root: Field =
        0x03f5124fc06de54927adc816293d15dfd8e68169b960f4d549892584b108591d;

    main(
        POSEIDON2_EMPTY_ROOT_DEPTH_32, // prev_root = empty tree
        expected_final_root, // new_root after 5 insertions
        0, // prev_total
        5, // new_total
        0x0deed, // blob_kzg_commitment (nonzero)
        deposit_commitments,
        2, // deposit_commitments_len = 2
        blob_commitments,
        3, // blob_commitments_len = 3
        intermediate_paths,
    );
}
