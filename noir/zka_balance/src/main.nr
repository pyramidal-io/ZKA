// =============================================================================
// ZKA Balance Proof Circuit (Noir / BN254)
//
// Spec Reference: ZKA v0.4.0, Section 6.1
//
// Proves knowledge of a note with specific balance properties WITHOUT spending
// it (no nullifier is produced). Supports three comparison modes:
//
//   proof_type 0: balance >= threshold       (solvency proof)
//   proof_type 1: balance <= threshold       (limit proof)
//   proof_type 2: lower <= balance <= upper  (range proof)
//
// Constraints:
//   1. Note commitment validity (asset, value, recipient, randomness)
//   2. Merkle membership (note exists in state tree)
//   3. Ownership verification (spending key derives correct recipient)
//   4. proof_type is one of {0, 1, 2}
//   5. Both published bounds lie in the u64 balance domain
//   6. The published (proof_type, bounds) triple is the CANONICAL encoding
//   7. note_value is an integer in [threshold_or_lower, upper_bound]
//   8. context is non-zero (verifier/session replay binding)
//
// Public Inputs (6):
//   [0] merkle_root        - State anchor (note membership)
//   [1] asset_commitment   - Identifies asset type
//   [2] threshold_or_lower - ALWAYS the interval LOW bound
//   [3] upper_bound        - ALWAYS the interval HIGH bound
//   [4] proof_type         - Comparison mode: 0, 1, or 2
//   [5] context            - Verifier/session replay binding, non-zero
//
// Canonical saturating-interval encoding. Every mode publishes a genuine
// closed interval [low, high] over the u64 domain, so [2] is ALWAYS the low
// bound and [3] is ALWAYS the high bound regardless of mode:
//
//   proof_type 0 (>= T):   low = T,  high = U64_MAX  (2^64 - 1)
//   proof_type 1 (<= T):   low = 0,  high = T
//   proof_type 2 (range):  low = lo, high = hi       (both free)
//
// The circuit ENFORCES this encoding (section 6), so `v >= T` and
// `v in [T, U64_MAX]` are the SAME statement, not an approximation.
//
// Soundness. With low, high, (value - low) and (high - value) each constrained
// to [0, 2^64), the circuit proves note_value is a genuine INTEGER in
// [low, high] subset of [0, 2^64). Proof sketch for why four range checks are
// the complete minimal set: writing d_lo = value - low and d_hi = high - value,
// we have d_lo + d_hi === high - low (mod p). The left-hand side is < 2^65, so
// an inverted interval (whose right-hand side is p - (low - high) > 2^254) is
// UNSATISFIABLE. Hence high >= low, d_lo + d_hi = high - low exactly as
// integers, and note_value = low + d_lo <= high < 2^64 is FORCED. A separate
// range check on note_value or on (high - low) would be redundant; those two
// derived properties are pinned by tests instead of by extra constraints.
//
// The pre-P6b circuit did NOT establish this: a note_value near p satisfied
// `value <= 500`, and a threshold_or_lower of p-1 satisfied `value >= T`
// because the difference wrapped. Both were reproduced under the pinned
// toolchain (nargo 1.0.0-beta.25).
//
// Security notes:
//   - No nullifier is emitted, so the note is NOT consumed.
//   - The comparison mode is PUBLIC (index [4]). A verifier MUST compare it
//     against the mode it requested and reject a mismatch; a proof that is
//     valid for one mode is otherwise trivially replayable as another.
//     Mode-hiding is deliberately abandoned -- see ADR-0007.
//   - `context` MUST be non-zero and MUST be a per-session value the VERIFIER
//     itself derived. A caller-supplied context is never authoritative, and a
//     static per-verifier context degrades replay protection from per-session
//     to per-verifier (which this circuit cannot detect).
//   - Range checks use `assert_max_bit_size::<64>` via `zka_lib::assert_fits_u64`,
//     which survives dead-code elimination (a bare `as u64` round-trip does not).
// =============================================================================

use zka_lib::{
    assert_fits_u64, compute_merkle_root, compute_note_commitment, derive_address, U64_MAX,
};

fn main(
    // === Public Inputs ===
    merkle_root: pub Field,
    asset_commitment: pub Field,
    threshold_or_lower: pub Field,
    upper_bound: pub Field,
    // === Private Inputs: Note ===
    note_value: Field,
    note_recipient: Field,
    note_randomness: Field,
    // === Private Inputs: Spending Key ===
    spending_key: Field,
    // === Private Inputs: Merkle Path ===
    merkle_siblings: [Field; 32],
    merkle_path_index: Field,
    // === Public Inputs (continued) ===
    proof_type: pub Field,
    context: pub Field,
) {
    // -------------------------------------------------------------------------
    // 1. NOTE COMMITMENT
    // -------------------------------------------------------------------------
    let commitment = compute_note_commitment(
        asset_commitment,
        note_value,
        note_recipient,
        note_randomness,
    );

    // -------------------------------------------------------------------------
    // 2. MERKLE MEMBERSHIP
    // -------------------------------------------------------------------------
    let computed_root = compute_merkle_root(commitment, merkle_path_index, merkle_siblings);
    assert(computed_root == merkle_root, "Merkle root mismatch: note not in state tree");

    // -------------------------------------------------------------------------
    // 3. OWNERSHIP VERIFICATION
    // -------------------------------------------------------------------------
    let derived_address = derive_address(spending_key);
    assert(
        derived_address == note_recipient,
        "Ownership verification failed: spending key does not match recipient",
    );

    // -------------------------------------------------------------------------
    // 4. PROOF TYPE VALIDATION
    //
    //    proof_type must be 0, 1, or 2.
    //    Enforced via: proof_type * (proof_type - 1) * (proof_type - 2) == 0
    //
    //    STILL REQUIRED now that proof_type is public: making an input public
    //    does not constrain it. A prover may submit 7, and this assert is what
    //    stops a value outside {0, 1, 2} reaching a consumer that reads [4]
    //    without recomputing anything.
    // -------------------------------------------------------------------------
    assert(
        proof_type * (proof_type - 1) * (proof_type - 2) == 0,
        "Invalid proof_type: must be 0, 1, or 2",
    );

    // -------------------------------------------------------------------------
    // 5. BOUND DOMAIN
    //
    //    Both bounds are caller-supplied PUBLIC values. Without these checks a
    //    prover can submit threshold_or_lower = p-1 and the difference wraps:
    //    `1000 - (p-1) = 1001 (mod p)` fits u64. Verified against the pre-P6b
    //    circuit under nargo 1.0.0-beta.25. Unexploitable under today's exact-
    //    equality verifier, a total break under P6d's monotone ordering.
    // -------------------------------------------------------------------------
    assert_fits_u64(threshold_or_lower);
    assert_fits_u64(upper_bound);

    // -------------------------------------------------------------------------
    // 6. CANONICAL INTERVAL ENCODING
    //
    //    Written as `selector * delta == 0` over Fields so each constraint
    //    feeds an assert directly and cannot be dead-code-eliminated.
    // -------------------------------------------------------------------------
    let sel0: Field = (proof_type == 0) as Field;
    let sel1: Field = (proof_type == 1) as Field;
    assert(
        sel0 * (upper_bound - U64_MAX) == 0,
        "proof_type 0 requires upper_bound == U64_MAX (canonical interval)",
    );
    assert(
        sel1 * threshold_or_lower == 0,
        "proof_type 1 requires threshold_or_lower == 0 (canonical interval)",
    );
    // proof_type 2 leaves both bounds free.

    // -------------------------------------------------------------------------
    // 7. INTERVAL MEMBERSHIP
    //
    //    Unconditional under the canonical encoding: every mode is an interval.
    // -------------------------------------------------------------------------
    let d_lo = note_value - threshold_or_lower;
    let d_hi = upper_bound - note_value;
    assert_fits_u64(d_lo); // note_value >= threshold_or_lower
    assert_fits_u64(d_hi); // note_value <= upper_bound

    // -------------------------------------------------------------------------
    // 8. CONTEXT
    //
    //    Replay binding, per ADR-0001 Option A: a separate co-equal public
    //    input, never folded into the claim binding.
    // -------------------------------------------------------------------------
    assert(context != 0, "context must be non-zero");
}

// =============================================================================
// Tests
// =============================================================================

/// House test context literal, matching the zka_transfer/zka_withdrawal fixtures.
global TEST_CONTEXT: Field = 0x12345678;

/// Helper: build valid Merkle root and siblings for a commitment at index 0
fn test_merkle(commitment: Field) -> ([Field; 32], Field) {
    let siblings: [Field; 32] = [0; 32];
    let root = compute_merkle_root(commitment, 0, siblings);
    (siblings, root)
}

/// Helper: derive a note commitment with standard test parameters
fn test_note(
    spending_key: Field,
    value: Field,
    randomness: Field,
    asset_commitment: Field,
) -> (Field, Field) {
    let recipient = derive_address(spending_key);
    let commitment = compute_note_commitment(asset_commitment, value, recipient, randomness);
    (recipient, commitment)
}

// ---------------------------------------------------------------------------
// Positive tests
// ---------------------------------------------------------------------------

#[test]
fn test_balance_above_threshold() {
    // Prove: balance (1000) >= threshold (500) -- proof_type 0
    // Canonical interval for mode 0: [500, U64_MAX].
    let sk = 0x42;
    let asset = zka_lib::compute_asset_commitment(0x01);
    let value: Field = 1000;
    let randomness = 0xaabb;

    let (recipient, commitment) = test_note(sk, value, randomness, asset);
    let (siblings, root) = test_merkle(commitment);

    main(
        root,
        asset,
        500,
        zka_lib::U64_MAX,
        value,
        recipient,
        randomness,
        sk,
        siblings,
        0,
        0, // proof_type = 0 (balance >= threshold)
        TEST_CONTEXT,
    );
}

#[test]
fn test_balance_above_exact_threshold() {
    // Edge case: balance (500) >= threshold (500) -- equality is valid
    let sk = 0x42;
    let asset = zka_lib::compute_asset_commitment(0x01);
    let value: Field = 500;
    let randomness = 0xaabb;

    let (recipient, commitment) = test_note(sk, value, randomness, asset);
    let (siblings, root) = test_merkle(commitment);

    main(
        root,
        asset,
        500,
        zka_lib::U64_MAX,
        value,
        recipient,
        randomness,
        sk,
        siblings,
        0,
        0, // proof_type = 0
        TEST_CONTEXT,
    );
}

#[test]
fn test_balance_below_threshold() {
    // Prove: balance (300) <= threshold (500) -- proof_type 1
    // Canonical interval for mode 1: [0, 500].
    let sk = 0x42;
    let asset = zka_lib::compute_asset_commitment(0x01);
    let value: Field = 300;
    let randomness = 0xaabb;

    let (recipient, commitment) = test_note(sk, value, randomness, asset);
    let (siblings, root) = test_merkle(commitment);

    main(
        root,
        asset,
        0,
        500,
        value,
        recipient,
        randomness,
        sk,
        siblings,
        0,
        1, // proof_type = 1 (balance <= threshold)
        TEST_CONTEXT,
    );
}

#[test]
fn test_balance_in_range() {
    // Prove: 100 <= balance (500) <= 1000 -- proof_type 2
    let sk = 0x42;
    let asset = zka_lib::compute_asset_commitment(0x01);
    let value: Field = 500;
    let randomness = 0xaabb;

    let (recipient, commitment) = test_note(sk, value, randomness, asset);
    let (siblings, root) = test_merkle(commitment);

    main(
        root,
        asset,
        100,
        1000,
        value,
        recipient,
        randomness,
        sk,
        siblings,
        0,
        2, // proof_type = 2 (range)
        TEST_CONTEXT,
    );
}

#[test]
fn test_balance_range_at_boundaries() {
    // Edge case: balance (100) at exact lower bound -- 100 <= 100 <= 1000
    let sk = 0x42;
    let asset = zka_lib::compute_asset_commitment(0x01);
    let value: Field = 100;
    let randomness = 0xaabb;

    let (recipient, commitment) = test_note(sk, value, randomness, asset);
    let (siblings, root) = test_merkle(commitment);

    main(
        root,
        asset,
        100,
        1000,
        value,
        recipient,
        randomness,
        sk,
        siblings,
        0,
        2, // proof_type = 2
        TEST_CONTEXT,
    );
}

#[test]
fn range_proof_over_full_domain_accepts() {
    // The saturating encoding is expressible as a genuine mode-2 statement:
    // [0, U64_MAX] is the whole balance domain. Pins the cross-mode
    // subsumption path P6d builds on.
    let sk = 0x42;
    let asset = zka_lib::compute_asset_commitment(0x01);
    let value: Field = 10_000;
    let randomness = 0xaabb;

    let (recipient, commitment) = test_note(sk, value, randomness, asset);
    let (siblings, root) = test_merkle(commitment);

    main(
        root,
        asset,
        0,
        zka_lib::U64_MAX,
        value,
        recipient,
        randomness,
        sk,
        siblings,
        0,
        2, // proof_type = 2 over the full domain
        TEST_CONTEXT,
    );
}

// ---------------------------------------------------------------------------
// Negative tests
// ---------------------------------------------------------------------------

#[test(should_fail)]
fn test_balance_below_threshold_fails_type0() {
    // balance (300) >= threshold (500) should FAIL for proof_type 0
    let sk = 0x42;
    let asset = zka_lib::compute_asset_commitment(0x01);
    let value: Field = 300;
    let randomness = 0xaabb;

    let (recipient, commitment) = test_note(sk, value, randomness, asset);
    let (siblings, root) = test_merkle(commitment);

    main(
        root,
        asset,
        500,
        zka_lib::U64_MAX,
        value,
        recipient,
        randomness,
        sk,
        siblings,
        0,
        0, // proof_type = 0 -- 300 >= 500 is false
        TEST_CONTEXT,
    );
}

#[test(should_fail)]
fn test_balance_above_threshold_fails_type1() {
    // balance (1000) <= threshold (500) should FAIL for proof_type 1
    let sk = 0x42;
    let asset = zka_lib::compute_asset_commitment(0x01);
    let value: Field = 1000;
    let randomness = 0xaabb;

    let (recipient, commitment) = test_note(sk, value, randomness, asset);
    let (siblings, root) = test_merkle(commitment);

    main(
        root,
        asset,
        0,
        500,
        value,
        recipient,
        randomness,
        sk,
        siblings,
        0,
        1, // proof_type = 1 -- 1000 <= 500 is false
        TEST_CONTEXT,
    );
}

#[test(should_fail)]
fn test_balance_out_of_range_above() {
    // balance (2000) not in [100, 1000] -- exceeds upper bound
    let sk = 0x42;
    let asset = zka_lib::compute_asset_commitment(0x01);
    let value: Field = 2000;
    let randomness = 0xaabb;

    let (recipient, commitment) = test_note(sk, value, randomness, asset);
    let (siblings, root) = test_merkle(commitment);

    main(
        root,
        asset,
        100,
        1000,
        value,
        recipient,
        randomness,
        sk,
        siblings,
        0,
        2, // proof_type = 2 -- 2000 > 1000
        TEST_CONTEXT,
    );
}

#[test(should_fail)]
fn test_balance_out_of_range_below() {
    // balance (50) not in [100, 1000] -- below lower bound
    let sk = 0x42;
    let asset = zka_lib::compute_asset_commitment(0x01);
    let value: Field = 50;
    let randomness = 0xaabb;

    let (recipient, commitment) = test_note(sk, value, randomness, asset);
    let (siblings, root) = test_merkle(commitment);

    main(
        root,
        asset,
        100,
        1000,
        value,
        recipient,
        randomness,
        sk,
        siblings,
        0,
        2, // proof_type = 2 -- 50 < 100
        TEST_CONTEXT,
    );
}

#[test(should_fail_with = "Ownership verification failed")]
fn test_wrong_spending_key_fails() {
    // Wrong spending key should fail ownership check
    let real_key = 0x42;
    let wrong_key = 0x99;
    let asset = zka_lib::compute_asset_commitment(0x01);
    let value: Field = 1000;
    let randomness = 0xaabb;

    // Note is created with real_key's address
    let (recipient, commitment) = test_note(real_key, value, randomness, asset);
    let (siblings, root) = test_merkle(commitment);

    main(
        root,
        asset,
        500,
        zka_lib::U64_MAX,
        value,
        recipient,
        randomness,
        wrong_key, // wrong key
        siblings,
        0,
        0,
        TEST_CONTEXT,
    );
}

#[test(should_fail_with = "Merkle root mismatch")]
fn test_wrong_merkle_root_fails() {
    // Wrong Merkle root should fail membership check
    let sk = 0x42;
    let asset = zka_lib::compute_asset_commitment(0x01);
    let value: Field = 1000;
    let randomness = 0xaabb;

    let (recipient, _commitment) = test_note(sk, value, randomness, asset);
    let siblings: [Field; 32] = [0; 32];

    main(
        0xBAD000,
        asset,
        500,
        zka_lib::U64_MAX,
        value,
        recipient,
        randomness,
        sk,
        siblings,
        0,
        0,
        TEST_CONTEXT,
    );
}

#[test(should_fail_with = "Invalid proof_type")]
fn test_invalid_proof_type_fails() {
    // proof_type = 3 is invalid and should be rejected.
    //
    // The cubic constraint is STILL REQUIRED now that proof_type is a public
    // input: publishing a value does not constrain it. With proof_type = 3 the
    // canonical-encoding selectors sel0 and sel1 are both 0, so section 6
    // passes vacuously -- the cubic assert in section 4 is genuinely the one
    // that fires here.
    let sk = 0x42;
    let asset = zka_lib::compute_asset_commitment(0x01);
    let value: Field = 1000;
    let randomness = 0xaabb;

    let (recipient, commitment) = test_note(sk, value, randomness, asset);
    let (siblings, root) = test_merkle(commitment);

    main(
        root,
        asset,
        500,
        zka_lib::U64_MAX,
        value,
        recipient,
        randomness,
        sk,
        siblings,
        0,
        3, // invalid proof_type
        TEST_CONTEXT,
    );
}

#[test(should_fail_with = "context must be non-zero")]
fn zero_context_fails() {
    // A zero context provides no replay binding at all.
    let sk = 0x42;
    let asset = zka_lib::compute_asset_commitment(0x01);
    let value: Field = 1000;
    let randomness = 0xaabb;

    let (recipient, commitment) = test_note(sk, value, randomness, asset);
    let (siblings, root) = test_merkle(commitment);

    main(
        root,
        asset,
        500,
        zka_lib::U64_MAX,
        value,
        recipient,
        randomness,
        sk,
        siblings,
        0,
        0,
        0, // zero context
    );
}

#[test(should_fail_with = "canonical interval")]
fn noncanonical_ge_upper_bound_fails() {
    // proof_type 0 must saturate its HIGH bound at U64_MAX. A narrower
    // upper_bound would publish a range statement labelled as a >= statement.
    let sk = 0x42;
    let asset = zka_lib::compute_asset_commitment(0x01);
    let value: Field = 1000;
    let randomness = 0xaabb;

    let (recipient, commitment) = test_note(sk, value, randomness, asset);
    let (siblings, root) = test_merkle(commitment);

    main(
        root,
        asset,
        500,
        20_000, // not U64_MAX
        value,
        recipient,
        randomness,
        sk,
        siblings,
        0,
        0,
        TEST_CONTEXT,
    );
}

#[test(should_fail_with = "canonical interval")]
fn noncanonical_le_lower_bound_fails() {
    // proof_type 1 must pin its LOW bound at 0.
    let sk = 0x42;
    let asset = zka_lib::compute_asset_commitment(0x01);
    let value: Field = 300;
    let randomness = 0xaabb;

    let (recipient, commitment) = test_note(sk, value, randomness, asset);
    let (siblings, root) = test_merkle(commitment);

    main(
        root,
        asset,
        100, // not 0
        500,
        value,
        recipient,
        randomness,
        sk,
        siblings,
        0,
        1,
        TEST_CONTEXT,
    );
}

#[test(should_fail)]
fn oversized_lower_bound_fails() {
    // REGRESSION: this input SATISFIED the pre-P6b circuit. With
    // threshold_or_lower = p-1, the difference `1000 - (p-1)` wraps to 1001,
    // which fits u64, so a note worth 1000 "proved" a balance of at least
    // p-1. Section 5's bound-domain check is what closes it.
    let sk = 0x42;
    let asset = zka_lib::compute_asset_commitment(0x01);
    let value: Field = 1000;
    let randomness = 0xaabb;

    let (recipient, commitment) = test_note(sk, value, randomness, asset);
    let (siblings, root) = test_merkle(commitment);

    main(
        root,
        asset,
        21888242871839275222246405745257275088548364400416034343698204186575808495616,
        zka_lib::U64_MAX,
        value,
        recipient,
        randomness,
        sk,
        siblings,
        0,
        2,
        TEST_CONTEXT,
    );
}

#[test(should_fail)]
fn oversized_upper_bound_fails() {
    // The HIGH bound is equally caller-supplied and equally range-checked.
    let sk = 0x42;
    let asset = zka_lib::compute_asset_commitment(0x01);
    let value: Field = 1000;
    let randomness = 0xaabb;

    let (recipient, commitment) = test_note(sk, value, randomness, asset);
    let (siblings, root) = test_merkle(commitment);

    main(
        root,
        asset,
        100,
        zka_lib::U64_MAX + 1,
        value,
        recipient,
        randomness,
        sk,
        siblings,
        0,
        2,
        TEST_CONTEXT,
    );
}

#[test(should_fail)]
fn field_wrapped_note_value_fails() {
    // REGRESSION: this input also SATISFIED the pre-P6b circuit. note_value
    // had no width constraint anywhere, so the field element `500 - 1000 mod p`
    // satisfied `value <= 500` -- an unbounded note "proving" a small balance.
    // Section 7's unconditional d_lo check is what closes it.
    let sk = 0x42;
    let asset = zka_lib::compute_asset_commitment(0x01);
    let value: Field =
        21888242871839275222246405745257275088548364400416034343698204186575808495117;
    let randomness = 0xaabb;

    let (recipient, commitment) = test_note(sk, value, randomness, asset);
    let (siblings, root) = test_merkle(commitment);

    main(
        root,
        asset,
        0,
        500,
        value,
        recipient,
        randomness,
        sk,
        siblings,
        0,
        1,
        TEST_CONTEXT,
    );
}

#[test(should_fail)]
fn inverted_interval_fails() {
    // Pins the DERIVED property no explicit hi-lo constraint enforces: with
    // both bounds and both differences in [0, 2^64), d_lo + d_hi === hi - lo
    // (mod p) has a left side < 2^65 while an inverted interval's right side
    // exceeds 2^254, so the system is unsatisfiable for any note_value.
    let sk = 0x42;
    let asset = zka_lib::compute_asset_commitment(0x01);
    let value: Field = 50;
    let randomness = 0xaabb;

    let (recipient, commitment) = test_note(sk, value, randomness, asset);
    let (siblings, root) = test_merkle(commitment);

    main(
        root,
        asset,
        100, // lo > hi
        10,
        value,
        recipient,
        randomness,
        sk,
        siblings,
        0,
        2,
        TEST_CONTEXT,
    );
}
