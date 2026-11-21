use aztec::oracle::nullifiers::check_nullifier_exists;

/// Readable-revert precheck for verify_compliance. Unconstrained and
/// value-free: the constrained non-revocation check is
/// assert_nullifier_did_not_exist_by in verify_compliance.
pub unconstrained fn assert_not_revoked_hint(inner_nullifier: Field) {
    assert(!check_nullifier_exists(inner_nullifier), "Credential has been revoked");
}
