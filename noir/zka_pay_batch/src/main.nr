mod payment_vk;

use payment_vk::{PAYMENT_RECURSIVE_VK, PAYMENT_RECURSIVE_VK_HASH};
use zka_lib::{compute_merkle_root, poseidon2, verify_nullifier_absent_and_insert};

global MAX_PAYMENTS: u32 = 4;
global PAYMENT_PUBLIC_INPUTS: u32 = 15;
global MAX_DEPOSITS: u32 = 4;
global MAX_BATCH_OUTPUTS: u32 = 16;
global MAX_BATCH_NULLIFIERS: u32 = 8;
global COMMITMENT_TREE_DEPTH: u32 = 32;
global NULLIFIER_TREE_DEPTH: u32 = 128;
global VK_SIZE: u32 = 115;
global PROOF_SIZE: u32 = 458;
global PROOF_TYPE_HONK_ZK: u32 = 6;
global MAX_BATCH_DATA_FIELDS: u32 = 72;
global MAX_NOTE_VALUE_WEI: u128 = 0xffffffffffffffffffffffffffffff;
global COMMITMENT_TREE_CAPACITY: u64 = 0x100000000;

// Exact unsigned big-endian encodings of the SDD's UTF-8 digest tags.
global DEPOSIT_PREFIX_TAG: Field = 0x7a6b612f7061792f6465706f7369742d7072656669782f7631;
global BATCH_DATA_TAG: Field = 0x7a6b612f7061792f62617463682d646174612f7631;

global PI_COMMITMENT_ROOT: u32 = 5;
global PI_POOL_CONTEXT: u32 = 6;
global PI_INTERACTION_CONTEXT: u32 = 7;
global PI_ANNOUNCEMENT_HASH_HI: u32 = 8;
global PI_ANNOUNCEMENT_HASH_LO: u32 = 9;
global PI_FEE_RECIPIENT: u32 = 10;
global PI_ASSET_COMMITMENT: u32 = 11;
global PI_NUM_INPUTS: u32 = 12;
global PI_HAS_CHANGE: u32 = 13;
global PI_HAS_FEE: u32 = 14;

struct DepositRecords {
    commitments: [Field; 4],
    amounts: [u128; 4],
    announcement_hash_hi: [u128; 4],
    announcement_hash_lo: [u128; 4],
}

struct BatchTransition {
    old_commitment_root: Field,
    new_commitment_root: Field,
    old_nullifier_root: Field,
    new_nullifier_root: Field,
    old_commitment_count: u64,
    new_commitment_count: u64,
    old_deposit_index: u64,
    new_deposit_index: u64,
    deposit_prefix_digest: Field,
    batch_data_digest: Field,
    payment_count: u8,
    asset_commitment: Field,
    pool_context: Field,
    deposit_count: u8,
    stored_deposits: DepositRecords,
    calldata_deposits: DepositRecords,
    payment_public_inputs: [[Field; 15]; 4],
    commitment_paths: [[Field; 32]; 16],
    nullifier_paths: [[Field; 128]; 8],
}

fn fold_digest(tag: Field, fields: [Field; 72], length: u32) -> Field {
    assert(length <= MAX_BATCH_DATA_FIELDS, "digest field stream exceeds fixed capacity");
    let mut state = poseidon2(tag, length as Field);
    for i in 0..MAX_BATCH_DATA_FIELDS {
        if i < length {
            state = poseidon2(state, fields[i]);
        }
    }
    state
}

fn deposit_prefix_digest_for(
    old_deposit_index: u64,
    deposit_count: u8,
    deposits: DepositRecords,
) -> Field {
    let mut fields: [Field; 72] = [0; 72];
    let mut cursor: u32 = 0;
    for i in 0..MAX_DEPOSITS {
        if i < deposit_count as u32 {
            fields[cursor] = (old_deposit_index + i as u64) as Field;
            fields[cursor + 1] = deposits.commitments[i];
            fields[cursor + 2] = deposits.amounts[i] as Field;
            fields[cursor + 3] = deposits.announcement_hash_hi[i] as Field;
            fields[cursor + 4] = deposits.announcement_hash_lo[i] as Field;
            cursor += 5;
        }
    }
    fold_digest(DEPOSIT_PREFIX_TAG, fields, cursor)
}

fn batch_data_digest_for(
    old_deposit_index: u64,
    deposit_count: u8,
    payment_count: u8,
    deposits: DepositRecords,
    payments: [[Field; 15]; 4],
) -> Field {
    let mut fields: [Field; 72] = [0; 72];
    fields[0] = 1; // canonical batchData version
    fields[1] = old_deposit_index as Field;
    fields[2] = deposit_count as Field;
    fields[3] = payment_count as Field;
    let mut cursor: u32 = 4;

    for i in 0..MAX_DEPOSITS {
        if i < deposit_count as u32 {
            fields[cursor] = (old_deposit_index + i as u64) as Field;
            fields[cursor + 1] = deposits.commitments[i];
            fields[cursor + 2] = deposits.amounts[i] as Field;
            fields[cursor + 3] = deposits.announcement_hash_hi[i] as Field;
            fields[cursor + 4] = deposits.announcement_hash_lo[i] as Field;
            cursor += 5;
        }
    }

    for i in 0..MAX_PAYMENTS {
        if i < payment_count as u32 {
            let payment = payments[i];
            // Exact twelve-field canonical payment record from SDD section 5.
            fields[cursor] = payment[0];
            fields[cursor + 1] = payment[1];
            fields[cursor + 2] = payment[2];
            fields[cursor + 3] = payment[3];
            fields[cursor + 4] = payment[4];
            fields[cursor + 5] = payment[PI_INTERACTION_CONTEXT];
            fields[cursor + 6] = payment[PI_FEE_RECIPIENT];
            fields[cursor + 7] = payment[PI_ANNOUNCEMENT_HASH_HI];
            fields[cursor + 8] = payment[PI_ANNOUNCEMENT_HASH_LO];
            fields[cursor + 9] = payment[PI_NUM_INPUTS];
            fields[cursor + 10] = payment[PI_HAS_CHANGE];
            fields[cursor + 11] = payment[PI_HAS_FEE];
            cursor += 12;
        }
    }
    fold_digest(BATCH_DATA_TAG, fields, cursor)
}

fn assert_zero_deposit_slot(records: DepositRecords, i: u32) {
    assert(records.commitments[i] == 0, "inactive deposit commitment must be zero");
    assert(records.amounts[i] == 0, "inactive deposit amount must be zero");
    assert(
        records.announcement_hash_hi[i] == 0,
        "inactive deposit announcement hash high limb must be zero",
    );
    assert(
        records.announcement_hash_lo[i] == 0,
        "inactive deposit announcement hash low limb must be zero",
    );
}

fn assert_payment_record(
    payment: [Field; 15],
    old_commitment_root: Field,
    asset_commitment: Field,
    pool_context: Field,
) {
    assert(payment[PI_COMMITMENT_ROOT] == old_commitment_root, "payment commitment root mismatch");
    assert(payment[PI_ASSET_COMMITMENT] == asset_commitment, "payment asset mismatch");
    assert(payment[PI_POOL_CONTEXT] == pool_context, "payment pool context mismatch");
    assert(
        (payment[PI_NUM_INPUTS] == 1) | (payment[PI_NUM_INPUTS] == 2),
        "payment num_inputs must be 1 or 2",
    );
    assert(
        (payment[PI_HAS_CHANGE] == 0) | (payment[PI_HAS_CHANGE] == 1),
        "payment has_change must be boolean",
    );
    assert(
        (payment[PI_HAS_FEE] == 0) | (payment[PI_HAS_FEE] == 1),
        "payment has_fee must be boolean",
    );
    assert(payment[0] != 0, "active payment nullifier must be non-zero");
    if payment[PI_NUM_INPUTS] == 1 {
        assert(payment[1] == 0, "inactive payment nullifier must be zero");
    } else {
        assert(payment[1] != 0, "active payment nullifier must be non-zero");
    }
    assert(payment[2] != 0, "recipient output commitment must be non-zero");
    if payment[PI_HAS_CHANGE] == 0 {
        assert(payment[3] == 0, "inactive change commitment must be zero");
    } else {
        assert(payment[3] != 0, "active change commitment must be non-zero");
    }
    if payment[PI_HAS_FEE] == 0 {
        assert(payment[4] == 0, "inactive fee commitment must be zero");
        assert(payment[PI_FEE_RECIPIENT] == 0, "inactive fee recipient must be zero");
    } else {
        assert(payment[4] != 0, "active fee commitment must be non-zero");
        assert(payment[PI_FEE_RECIPIENT] != 0, "active fee recipient must be non-zero");
    }
}

fn assert_batch_transition(input: BatchTransition) {
    assert(input.deposit_count as u32 <= MAX_DEPOSITS, "deposit_count exceeds MAX_DEPOSITS");
    assert(input.payment_count as u32 <= MAX_PAYMENTS, "payment_count exceeds MAX_PAYMENTS");
    assert(input.pool_context != 0, "pool context must be non-zero");
    assert(input.asset_commitment != 0, "asset commitment must be non-zero");

    let mut leaves: [Field; 16] = [0; 16];
    let mut leaf_count: u32 = 0;
    for i in 0..MAX_DEPOSITS {
        if i < input.deposit_count as u32 {
            assert(
                input.stored_deposits.commitments[i] == input.calldata_deposits.commitments[i],
                "calldata deposit commitment mismatch",
            );
            assert(
                input.stored_deposits.amounts[i] == input.calldata_deposits.amounts[i],
                "calldata deposit amount mismatch",
            );
            assert(
                input.stored_deposits.announcement_hash_hi[i]
                    == input.calldata_deposits.announcement_hash_hi[i],
                "calldata deposit announcement high limb mismatch",
            );
            assert(
                input.stored_deposits.announcement_hash_lo[i]
                    == input.calldata_deposits.announcement_hash_lo[i],
                "calldata deposit announcement low limb mismatch",
            );
            assert(
                input.stored_deposits.commitments[i] != 0,
                "active deposit commitment must be non-zero",
            );
            assert(input.stored_deposits.amounts[i] > 0, "active deposit amount must be non-zero");
            assert(
                input.stored_deposits.amounts[i] <= MAX_NOTE_VALUE_WEI,
                "active deposit amount exceeds launch bound",
            );
            leaves[leaf_count] = input.stored_deposits.commitments[i];
            leaf_count += 1;
        } else {
            assert_zero_deposit_slot(input.stored_deposits, i);
            assert_zero_deposit_slot(input.calldata_deposits, i);
        }
    }

    for i in 0..MAX_PAYMENTS {
        if i < input.payment_count as u32 {
            let payment = input.payment_public_inputs[i];
            assert_payment_record(
                payment,
                input.old_commitment_root,
                input.asset_commitment,
                input.pool_context,
            );
            leaves[leaf_count] = payment[2];
            leaf_count += 1;
            if payment[PI_HAS_CHANGE] == 1 {
                leaves[leaf_count] = payment[3];
                leaf_count += 1;
            }
            if payment[PI_HAS_FEE] == 1 {
                leaves[leaf_count] = payment[4];
                leaf_count += 1;
            }
        } else {
            for j in 0..PAYMENT_PUBLIC_INPUTS {
                assert(
                    input.payment_public_inputs[i][j] == 0,
                    "inactive payment public input must be zero",
                );
            }
        }
    }

    assert(
        input.new_deposit_index == input.old_deposit_index + input.deposit_count as u64,
        "deposit index counter mismatch",
    );
    assert(
        input.new_commitment_count == input.old_commitment_count + leaf_count as u64,
        "commitment counter mismatch",
    );
    if leaf_count > 0 {
        assert(
            input.old_commitment_count < COMMITMENT_TREE_CAPACITY,
            "commitment append cannot start at depth-32 tree capacity",
        );
    }
    assert(
        input.new_commitment_count <= COMMITMENT_TREE_CAPACITY,
        "commitment count exceeds depth-32 tree capacity",
    );

    let mut commitment_root = input.old_commitment_root;
    for i in 0..MAX_BATCH_OUTPUTS {
        if i < leaf_count {
            let leaf_index = (input.old_commitment_count + i as u64) as Field;
            assert(
                compute_merkle_root(0, leaf_index, input.commitment_paths[i]) == commitment_root,
                "commitment append path does not prove an empty leaf",
            );
            commitment_root = compute_merkle_root(leaves[i], leaf_index, input.commitment_paths[i]);
        } else {
            for depth in 0..COMMITMENT_TREE_DEPTH {
                assert(
                    input.commitment_paths[i][depth] == 0,
                    "inactive commitment append path must be zero",
                );
            }
        }
    }
    assert(commitment_root == input.new_commitment_root, "new commitment root mismatch");

    let mut nullifier_root = input.old_nullifier_root;
    let mut nullifier_count: u32 = 0;
    for i in 0..MAX_PAYMENTS {
        if i < input.payment_count as u32 {
            let payment = input.payment_public_inputs[i];
            let active_inputs: u32 = if payment[PI_NUM_INPUTS] == 1 { 1 } else { 2 };
            for j in 0..2 {
                if j < active_inputs {
                    nullifier_root = verify_nullifier_absent_and_insert(
                        nullifier_root,
                        payment[j],
                        input.nullifier_paths[nullifier_count],
                    );
                    nullifier_count += 1;
                }
            }
        }
    }
    for i in 0..MAX_BATCH_NULLIFIERS {
        if i >= nullifier_count {
            for depth in 0..NULLIFIER_TREE_DEPTH {
                assert(
                    input.nullifier_paths[i][depth] == 0,
                    "inactive nullifier path must be zero",
                );
            }
        }
    }
    assert(nullifier_root == input.new_nullifier_root, "new nullifier root mismatch");

    let computed_deposit_prefix_digest = deposit_prefix_digest_for(
        input.old_deposit_index,
        input.deposit_count,
        input.stored_deposits,
    );
    assert(
        computed_deposit_prefix_digest == input.deposit_prefix_digest,
        "deposit prefix digest mismatch",
    );
    let computed_batch_data_digest = batch_data_digest_for(
        input.old_deposit_index,
        input.deposit_count,
        input.payment_count,
        input.calldata_deposits,
        input.payment_public_inputs,
    );
    assert(computed_batch_data_digest == input.batch_data_digest, "batch data digest mismatch");
}

fn assert_active_payment_vk_hash(key_hash: Field) {
    assert(
        key_hash == PAYMENT_RECURSIVE_VK_HASH,
        "active payment VK hash is not the pinned zka_pay_transition VK hash",
    );
}

fn assert_active_payment_vk(verification_key: [Field; 115], key_hash: Field) {
    for i in 0..VK_SIZE {
        assert(
            verification_key[i] == PAYMENT_RECURSIVE_VK[i],
            "active payment verification key field mismatch",
        );
    }
    assert_active_payment_vk_hash(key_hash);
}

fn assert_inactive_recursive_slot(
    verification_key: [Field; 115],
    proof: [Field; 458],
    payment_public_inputs: [Field; 15],
    key_hash: Field,
) {
    assert(key_hash == 0, "inactive payment key hash must be zero");
    for j in 0..VK_SIZE {
        assert(verification_key[j] == 0, "inactive payment VK must be zero");
    }
    for j in 0..PROOF_SIZE {
        assert(proof[j] == 0, "inactive payment proof must be zero");
    }
    for j in 0..PAYMENT_PUBLIC_INPUTS {
        assert(payment_public_inputs[j] == 0, "inactive payment public input must be zero");
    }
}

fn main(
    old_commitment_root: pub Field,
    new_commitment_root: pub Field,
    old_nullifier_root: pub Field,
    new_nullifier_root: pub Field,
    old_commitment_count: pub u64,
    new_commitment_count: pub u64,
    old_deposit_index: pub u64,
    new_deposit_index: pub u64,
    deposit_prefix_digest: pub Field,
    batch_data_digest: pub Field,
    payment_count: pub u8,
    asset_commitment: pub Field,
    pool_context: pub Field,
    deposit_count: u8,
    stored_deposit_commitments: [Field; 4],
    stored_deposit_amounts: [u128; 4],
    stored_deposit_announcement_hash_hi: [u128; 4],
    stored_deposit_announcement_hash_lo: [u128; 4],
    calldata_deposit_commitments: [Field; 4],
    calldata_deposit_amounts: [u128; 4],
    calldata_deposit_announcement_hash_hi: [u128; 4],
    calldata_deposit_announcement_hash_lo: [u128; 4],
    commitment_paths: [[Field; 32]; 16],
    nullifier_paths: [[Field; 128]; 8],
    verification_keys: [[Field; 115]; 4],
    proofs: [[Field; 458]; 4],
    proof_public_inputs: [[Field; 15]; 4],
    key_hashes: [Field; 4],
) {
    assert(payment_count as u32 <= MAX_PAYMENTS, "payment_count exceeds MAX_PAYMENTS");
    for i in 0..MAX_PAYMENTS {
        if i < payment_count as u32 {
            assert_active_payment_vk(verification_keys[i], key_hashes[i]);
            std::verify_proof_with_type(
                verification_keys[i],
                proofs[i],
                proof_public_inputs[i],
                key_hashes[i],
                PROOF_TYPE_HONK_ZK,
            );
        } else {
            assert_inactive_recursive_slot(
                verification_keys[i],
                proofs[i],
                proof_public_inputs[i],
                key_hashes[i],
            );
        }
    }

    assert_batch_transition(
        BatchTransition {
            old_commitment_root,
            new_commitment_root,
            old_nullifier_root,
            new_nullifier_root,
            old_commitment_count,
            new_commitment_count,
            old_deposit_index,
            new_deposit_index,
            deposit_prefix_digest,
            batch_data_digest,
            payment_count,
            asset_commitment,
            pool_context,
            deposit_count,
            stored_deposits: DepositRecords {
                commitments: stored_deposit_commitments,
                amounts: stored_deposit_amounts,
                announcement_hash_hi: stored_deposit_announcement_hash_hi,
                announcement_hash_lo: stored_deposit_announcement_hash_lo,
            },
            calldata_deposits: DepositRecords {
                commitments: calldata_deposit_commitments,
                amounts: calldata_deposit_amounts,
                announcement_hash_hi: calldata_deposit_announcement_hash_hi,
                announcement_hash_lo: calldata_deposit_announcement_hash_lo,
            },
            payment_public_inputs: proof_public_inputs,
            commitment_paths,
            nullifier_paths,
        },
    );
}

#[test(should_fail_with = "deposit prefix digest mismatch")]
fn deposit_prefix_digest_mismatch_is_rejected() {
    let records = DepositRecords {
        commitments: [7, 0, 0, 0],
        amounts: [1, 0, 0, 0],
        announcement_hash_hi: [2, 0, 0, 0],
        announcement_hash_lo: [3, 0, 0, 0],
    };
    let actual = deposit_prefix_digest_for(0, 1, records);
    assert(actual == actual + 1, "deposit prefix digest mismatch");
}

#[test(should_fail_with = "batch data digest mismatch")]
fn batch_data_digest_mismatch_is_rejected() {
    let records = DepositRecords {
        commitments: [0; 4],
        amounts: [0; 4],
        announcement_hash_hi: [0; 4],
        announcement_hash_lo: [0; 4],
    };
    let actual = batch_data_digest_for(0, 0, 0, records, [[0; 15]; 4]);
    assert(actual == actual + 1, "batch data digest mismatch");
}

// Cross-language Task 11 KAT. These are the same mixed canonical batch record
// fields and frozen digests asserted by `src/zka-sdk/tests/pool_sync.rs`.
#[test]
fn mixed_batch_digest_matches_rust_codec_kat() {
    let deposits = DepositRecords {
        commitments: [11, 12, 0, 0],
        amounts: [25, 1208925819614629174706185, 0, 0],
        announcement_hash_hi: [
            180410050690947439035525611716458078501,
            328687790109994924496516066545139331988,
            0,
            0,
        ],
        announcement_hash_lo: [
            214559734573943289911622257412057795993,
            160639812295140055202075729082768551554,
            0,
            0,
        ],
    };
    let payments = [
        [
            21,
            22,
            31,
            32,
            33,
            0,
            0,
            41,
            238164623168051966930707317156840716094,
            57205664987832044444880200926091091205,
            51,
            0,
            2,
            1,
            1,
        ],
        [
            23,
            0,
            34,
            0,
            0,
            0,
            0,
            42,
            129219847221843927295791680321083866452,
            183828613794063962495426599178993696964,
            0,
            0,
            1,
            0,
            0,
        ],
        [0; 15],
        [0; 15],
    ];
    assert(
        deposit_prefix_digest_for(7, 2, deposits)
            == 0x2e7bab936f56dd68e33b94ea281b2b866ea9ec24c522c223442c503797c1df34,
        "mixed deposit-prefix KAT drift",
    );
    assert(
        batch_data_digest_for(7, 2, 2, deposits, payments)
            == 0x2dc1313bccb93be80ebb915eea29ef34855e5c98c5667bd3ce210ac0b08d01ea,
        "mixed batch-data KAT drift",
    );
}

fn empty_deposit_records() -> DepositRecords {
    DepositRecords {
        commitments: [0; 4],
        amounts: [0; 4],
        announcement_hash_hi: [0; 4],
        announcement_hash_lo: [0; 4],
    }
}

fn empty_commitment_path() -> [Field; 32] {
    let mut siblings: [Field; 32] = [0; 32];
    let mut empty: Field = 0;
    for depth in 0..COMMITMENT_TREE_DEPTH {
        siblings[depth] = empty;
        empty = poseidon2(empty, empty);
    }
    siblings
}

fn empty_nullifier_path() -> [Field; 128] {
    let mut siblings: [Field; 128] = [0; 128];
    let mut empty: Field = 0;
    for depth in 0..NULLIFIER_TREE_DEPTH {
        siblings[depth] = empty;
        empty = poseidon2(empty, empty);
    }
    siblings
}

fn sparse_root_for_test(leaf: Field, index: Field, siblings: [Field; 128]) -> Field {
    let bits: [bool; 128] = index.to_be_bits();
    let mut current = leaf;
    for depth in 0..NULLIFIER_TREE_DEPTH {
        let is_right = bits[127 - depth];
        let left = if is_right { siblings[depth] } else { current };
        let right = if is_right { current } else { siblings[depth] };
        current = poseidon2(left, right);
    }
    current
}

fn identity_fixture() -> BatchTransition {
    let commitment_path = empty_commitment_path();
    let nullifier_path = empty_nullifier_path();
    let commitment_root = compute_merkle_root(0, 0, commitment_path);
    let nullifier_root = sparse_root_for_test(0, 0, nullifier_path);
    let deposits = empty_deposit_records();
    BatchTransition {
        old_commitment_root: commitment_root,
        new_commitment_root: commitment_root,
        old_nullifier_root: nullifier_root,
        new_nullifier_root: nullifier_root,
        old_commitment_count: 0,
        new_commitment_count: 0,
        old_deposit_index: 0,
        new_deposit_index: 0,
        deposit_prefix_digest: deposit_prefix_digest_for(0, 0, deposits),
        batch_data_digest: batch_data_digest_for(0, 0, 0, deposits, [[0; 15]; 4]),
        payment_count: 0,
        asset_commitment: 0xa55e7,
        pool_context: 0xc001,
        deposit_count: 0,
        stored_deposits: deposits,
        calldata_deposits: deposits,
        payment_public_inputs: [[0; 15]; 4],
        commitment_paths: [[0; 32]; 16],
        nullifier_paths: [[0; 128]; 8],
    }
}

fn payment_record(
    nullifier: Field,
    output: Field,
    interaction_context: Field,
    commitment_root: Field,
    asset_commitment: Field,
    pool_context: Field,
) -> [Field; 15] {
    let mut payment: [Field; 15] = [0; 15];
    payment[0] = nullifier;
    payment[2] = output;
    payment[PI_COMMITMENT_ROOT] = commitment_root;
    payment[PI_POOL_CONTEXT] = pool_context;
    payment[PI_INTERACTION_CONTEXT] = interaction_context;
    payment[PI_ANNOUNCEMENT_HASH_HI] = 0x11110000 + nullifier;
    payment[PI_ANNOUNCEMENT_HASH_LO] = 0x22220000 + nullifier;
    payment[PI_ASSET_COMMITMENT] = asset_commitment;
    payment[PI_NUM_INPUTS] = 1;
    payment
}

fn refresh_digests(mut fixture: BatchTransition) -> BatchTransition {
    fixture.deposit_prefix_digest = deposit_prefix_digest_for(
        fixture.old_deposit_index,
        fixture.deposit_count,
        fixture.stored_deposits,
    );
    fixture.batch_data_digest = batch_data_digest_for(
        fixture.old_deposit_index,
        fixture.deposit_count,
        fixture.payment_count,
        fixture.calldata_deposits,
        fixture.payment_public_inputs,
    );
    fixture
}

fn one_payment_fixture() -> BatchTransition {
    let mut fixture = identity_fixture();
    fixture.payment_count = 1;
    fixture.payment_public_inputs[0] = payment_record(
        1,
        0x101,
        0x9001,
        fixture.old_commitment_root,
        fixture.asset_commitment,
        fixture.pool_context,
    );
    let commitment_path = empty_commitment_path();
    fixture.commitment_paths[0] = commitment_path;
    fixture.new_commitment_root = compute_merkle_root(0x101, 0, commitment_path);
    fixture.new_commitment_count = 1;
    let nullifier_path = empty_nullifier_path();
    fixture.nullifier_paths[0] = nullifier_path;
    fixture.new_nullifier_root = sparse_root_for_test(1, 1, nullifier_path);
    refresh_digests(fixture)
}

fn four_payment_fixture() -> BatchTransition {
    let mut fixture = identity_fixture();
    fixture.payment_count = 4;
    for i in 0..4 {
        fixture.payment_public_inputs[i] = payment_record(
            (i + 1) as Field,
            (0x101 + i) as Field,
            (0x9001 + i) as Field,
            fixture.old_commitment_root,
            fixture.asset_commitment,
            fixture.pool_context,
        );
    }

    let empty_commitment = empty_commitment_path();
    fixture.commitment_paths[0] = empty_commitment;
    fixture.commitment_paths[1] = empty_commitment;
    fixture.commitment_paths[1][0] = 0x101;
    let left_pair = poseidon2(0x101, 0x102);
    fixture.commitment_paths[2] = empty_commitment;
    fixture.commitment_paths[2][1] = left_pair;
    fixture.commitment_paths[3] = empty_commitment;
    fixture.commitment_paths[3][0] = 0x103;
    fixture.commitment_paths[3][1] = left_pair;
    fixture.new_commitment_root = compute_merkle_root(0x104, 3, fixture.commitment_paths[3]);
    fixture.new_commitment_count = 4;

    let empty_nullifier = empty_nullifier_path();
    fixture.nullifier_paths[0] = empty_nullifier;
    fixture.nullifier_paths[1] = empty_nullifier;
    fixture.nullifier_paths[1][0] = 0;
    fixture.nullifier_paths[1][1] = poseidon2(0, 1);
    fixture.nullifier_paths[2] = empty_nullifier;
    fixture.nullifier_paths[2][0] = 2;
    fixture.nullifier_paths[2][1] = poseidon2(0, 1);
    fixture.nullifier_paths[3] = empty_nullifier;
    fixture.nullifier_paths[3][0] = 0;
    fixture.nullifier_paths[3][1] = poseidon2(0, 0);
    fixture.nullifier_paths[3][2] = poseidon2(poseidon2(0, 1), poseidon2(2, 3));
    fixture.new_nullifier_root = sparse_root_for_test(4, 4, fixture.nullifier_paths[3]);
    refresh_digests(fixture)
}

fn deposits_only_fixture() -> BatchTransition {
    let mut fixture = identity_fixture();
    fixture.deposit_count = 2;
    fixture.old_deposit_index = 7;
    fixture.new_deposit_index = 9;
    fixture.stored_deposits = DepositRecords {
        commitments: [0xd1, 0xd2, 0, 0],
        amounts: [10, 20, 0, 0],
        announcement_hash_hi: [0xa1, 0xa2, 0, 0],
        announcement_hash_lo: [0xb1, 0xb2, 0, 0],
    };
    fixture.calldata_deposits = fixture.stored_deposits;
    let empty = empty_commitment_path();
    fixture.commitment_paths[0] = empty;
    fixture.commitment_paths[1] = empty;
    fixture.commitment_paths[1][0] = 0xd1;
    fixture.new_commitment_root = compute_merkle_root(0xd2, 1, fixture.commitment_paths[1]);
    fixture.new_commitment_count = 2;
    refresh_digests(fixture)
}

fn mixed_fixture() -> BatchTransition {
    let mut fixture = identity_fixture();
    fixture.deposit_count = 1;
    fixture.old_deposit_index = 4;
    fixture.new_deposit_index = 5;
    fixture.stored_deposits = DepositRecords {
        commitments: [0xd1, 0, 0, 0],
        amounts: [10, 0, 0, 0],
        announcement_hash_hi: [0xa1, 0, 0, 0],
        announcement_hash_lo: [0xb1, 0, 0, 0],
    };
    fixture.calldata_deposits = fixture.stored_deposits;
    fixture.payment_count = 1;
    fixture.payment_public_inputs[0] = payment_record(
        1,
        0x101,
        0x9001,
        fixture.old_commitment_root,
        fixture.asset_commitment,
        fixture.pool_context,
    );
    let empty = empty_commitment_path();
    fixture.commitment_paths[0] = empty;
    fixture.commitment_paths[1] = empty;
    fixture.commitment_paths[1][0] = 0xd1;
    fixture.new_commitment_root = compute_merkle_root(0x101, 1, fixture.commitment_paths[1]);
    fixture.new_commitment_count = 2;
    let sparse = empty_nullifier_path();
    fixture.nullifier_paths[0] = sparse;
    fixture.new_nullifier_root = sparse_root_for_test(1, 1, sparse);
    refresh_digests(fixture)
}

#[test]
fn one_payment_advances_both_roots() {
    assert_batch_transition(one_payment_fixture());
}

#[test]
fn four_payments_allow_distinct_interaction_contexts() {
    assert_batch_transition(four_payment_fixture());
}

#[test]
fn deposits_only_append_in_prefix_order() {
    assert_batch_transition(deposits_only_fixture());
}

#[test]
fn mixed_batch_appends_deposits_before_payment_outputs() {
    assert_batch_transition(mixed_fixture());
}

#[test(should_fail)]
fn duplicate_nullifier_is_rejected() {
    let mut fixture = four_payment_fixture();
    fixture.payment_public_inputs[1][0] = fixture.payment_public_inputs[0][0];
    assert_batch_transition(fixture);
}

#[test(should_fail_with = "nullifier is present or path is invalid")]
fn previously_present_nullifier_is_rejected() {
    let mut fixture = one_payment_fixture();
    fixture.old_nullifier_root = fixture.new_nullifier_root;
    assert_batch_transition(fixture);
}

#[test(should_fail_with = "deposit prefix digest mismatch")]
fn altered_public_deposit_prefix_digest_is_rejected() {
    let mut fixture = deposits_only_fixture();
    fixture.deposit_prefix_digest += 1;
    assert_batch_transition(fixture);
}

#[test(should_fail)]
fn payment_output_order_mismatch_is_rejected() {
    let mut fixture = four_payment_fixture();
    let first = fixture.payment_public_inputs[0][2];
    fixture.payment_public_inputs[0][2] = fixture.payment_public_inputs[1][2];
    fixture.payment_public_inputs[1][2] = first;
    assert_batch_transition(fixture);
}

#[test(should_fail_with = "payment commitment root mismatch")]
fn old_commitment_root_mismatch_is_rejected() {
    let mut fixture = one_payment_fixture();
    fixture.old_commitment_root += 1;
    assert_batch_transition(fixture);
}

#[test(should_fail_with = "commitment counter mismatch")]
fn commitment_counter_mismatch_is_rejected() {
    let mut fixture = one_payment_fixture();
    fixture.new_commitment_count += 1;
    assert_batch_transition(fixture);
}

#[test(should_fail_with = "deposit index counter mismatch")]
fn deposit_index_counter_mismatch_is_rejected() {
    let mut fixture = deposits_only_fixture();
    fixture.new_deposit_index += 1;
    assert_batch_transition(fixture);
}

#[test(should_fail_with = "payment asset mismatch")]
fn wrong_payment_asset_commitment_is_rejected() {
    let mut fixture = one_payment_fixture();
    fixture.payment_public_inputs[0][PI_ASSET_COMMITMENT] += 1;
    assert_batch_transition(fixture);
}

#[test(should_fail_with = "payment pool context mismatch")]
fn wrong_payment_pool_context_is_rejected() {
    let mut fixture = one_payment_fixture();
    fixture.payment_public_inputs[0][PI_POOL_CONTEXT] += 1;
    assert_batch_transition(fixture);
}

#[test(should_fail_with = "batch data digest mismatch")]
fn altered_interaction_context_is_rejected() {
    let mut fixture = one_payment_fixture();
    fixture.payment_public_inputs[0][PI_INTERACTION_CONTEXT] += 1;
    assert_batch_transition(fixture);
}

#[test(should_fail_with = "batch data digest mismatch")]
fn changed_ciphertext_byte_digest_is_rejected() {
    // The contract's strict parser changes this public digest when one
    // ciphertext byte changes; the recursively verified payment limbs do not.
    let mut fixture = one_payment_fixture();
    fixture.batch_data_digest += 1;
    assert_batch_transition(fixture);
}

#[test(should_fail_with = "batch data digest mismatch")]
fn payment_and_batch_announcement_hash_mismatch_is_rejected() {
    let mut fixture = one_payment_fixture();
    fixture.payment_public_inputs[0][PI_ANNOUNCEMENT_HASH_HI] += 1;
    assert_batch_transition(fixture);
}

#[test(should_fail_with = "inactive fee recipient must be zero")]
fn fee_recipient_mismatch_is_rejected() {
    let mut fixture = one_payment_fixture();
    fixture.payment_public_inputs[0][PI_FEE_RECIPIENT] = 0xfefe;
    assert_batch_transition(fixture);
}

#[test(should_fail)]
fn changed_canonical_batch_data_field_is_rejected() {
    let mut fixture = one_payment_fixture();
    fixture.payment_public_inputs[0][PI_HAS_CHANGE] = 1;
    assert_batch_transition(fixture);
}

#[test(should_fail_with = "active payment VK hash is not the pinned zka_pay_transition VK hash")]
fn wrong_active_payment_vk_hash_is_rejected() {
    assert_active_payment_vk_hash(PAYMENT_RECURSIVE_VK_HASH + 1);
}

#[test]
fn pinned_active_payment_vk_is_accepted() {
    assert_active_payment_vk(PAYMENT_RECURSIVE_VK, PAYMENT_RECURSIVE_VK_HASH);
}

#[test(should_fail_with = "active payment verification key field mismatch")]
fn altered_active_payment_vk_field_is_rejected_with_pinned_claimed_hash() {
    let mut verification_key = PAYMENT_RECURSIVE_VK;
    verification_key[42] += 1;
    assert_active_payment_vk(verification_key, PAYMENT_RECURSIVE_VK_HASH);
}

fn last_commitment_leaf_fixture() -> BatchTransition {
    let mut fixture = one_payment_fixture();
    fixture.old_commitment_count = 0xffffffff;
    fixture.new_commitment_count = 0x100000000;
    fixture.new_commitment_root =
        compute_merkle_root(0x101, 0xffffffff, fixture.commitment_paths[0]);
    fixture
}

#[test]
fn last_depth_32_leaf_append_reaches_full_count() {
    assert_batch_transition(last_commitment_leaf_fixture());
}

#[test]
fn identity_at_full_depth_32_count_is_valid() {
    let mut fixture = identity_fixture();
    fixture.old_commitment_count = 0x100000000;
    fixture.new_commitment_count = 0x100000000;
    assert_batch_transition(fixture);
}

#[test(should_fail_with = "commitment append cannot start at depth-32 tree capacity")]
fn append_cannot_start_at_depth_32_capacity() {
    let mut fixture = one_payment_fixture();
    fixture.old_commitment_count = 0x100000000;
    fixture.new_commitment_count = 0x100000001;
    assert_batch_transition(fixture);
}

#[test(should_fail_with = "commitment count exceeds depth-32 tree capacity")]
fn identity_above_depth_32_capacity_is_rejected() {
    let mut fixture = identity_fixture();
    fixture.old_commitment_count = 0x100000001;
    fixture.new_commitment_count = 0x100000001;
    assert_batch_transition(fixture);
}

#[test(should_fail_with = "inactive payment key hash must be zero")]
fn inactive_key_hash_is_zero_constrained() {
    assert_inactive_recursive_slot([0; 115], [0; 458], [0; 15], 1);
}

#[test(should_fail_with = "inactive payment VK must be zero")]
fn inactive_vk_is_zero_constrained() {
    let mut vk: [Field; 115] = [0; 115];
    vk[0] = 1;
    assert_inactive_recursive_slot(vk, [0; 458], [0; 15], 0);
}

#[test(should_fail_with = "inactive payment proof must be zero")]
fn inactive_proof_is_zero_constrained() {
    let mut proof: [Field; 458] = [0; 458];
    proof[229] = 1;
    assert_inactive_recursive_slot([0; 115], proof, [0; 15], 0);
}

#[test(should_fail_with = "inactive payment public input must be zero")]
fn inactive_public_inputs_are_zero_constrained() {
    let mut public_inputs: [Field; 15] = [0; 15];
    public_inputs[7] = 1;
    assert_inactive_recursive_slot([0; 115], [0; 458], public_inputs, 0);
}
