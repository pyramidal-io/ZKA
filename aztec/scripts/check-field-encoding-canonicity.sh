#!/usr/bin/env bash
# =============================================================================
# ZKA Field-Encoding Canonicity Gate (Aztec workspace)
#
# `Field::to_be_bytes::<32>()` / `to_le_bytes::<32>()` does NOT determine the
# bytes. Under nargo/aztec-nargo 1.0.0-beta.25 a 32-byte decomposition compiles
# to exactly 32 eight-bit range checks plus ONE recomposition equation, and that
# equation is a `Field` equation -- it holds *modulo p*. Since 2^256 > 5p, every
# field element has FIVE valid 32-byte witnesses (x, x+p, ... x+4p), and the
# lowest ~29% of the field has six. Any value hashed through such an encoding is
# therefore not a function of its inputs alone.
#
# This matters most at cross-environment boundaries, where an L1 contract
# reconstructs the same preimage from canonical values: `withdraw_content_hash`
# feeds the Aztec Outbox message that `ZKAAztecPortal.withdraw` reproduces via
# `abi.encodeWithSignature`.
#
# WHY THIS GATE IS SOURCE-LEVEL, not an ACIR/bytecode grep (unlike the sibling
# noir/scripts/check-nullifier-index-canonicity.sh):
#
#   1. The consumer, `ZKATransfer::_process_withdrawal`, is an `#[external("public")]`
#      function. Public Aztec functions compile to Brillig and are transpiled to
#      AVM bytecode -- they are NOT part of any ACIR circuit. `aztec-nargo compile
#      --print-acir` for this contract contains zero 32-byte field decompositions,
#      so there is nothing in the ACIR to assert on.
#   2. Grepping for the BN254 modulus limbs cannot discriminate here anyway. The
#      contract's ACIR already carries hundreds of PLO/PHI occurrences from
#      aztec-nr's own `decompose` calls, and measured on this fix the limb counts
#      in `_process_withdrawal`'s Brillig bytecode are IDENTICAL before and after
#      (PLO-1 x1, PHI x1 either way) even though the body grew 31210 -> 36113
#      bytes, because the compiler deduplicates the constants. So neither a
#      ">= 1 occurrence" nor an exact-count assertion separates sound from
#      unsound.
#
# So the check that actually discriminates is the source pattern, which also has
# the advantage of covering private (ACIR) and public (AVM) code uniformly.
#
# `nargo test` provably cannot catch this class: the honest witness solver always
# emits the canonical decomposition, so the sound and unsound versions agree on
# every honest input (the cross-env golden is byte-identical either way).
# =============================================================================
set -euo pipefail

AZTEC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

status=0

echo "==> Source check: no raw >= 32-byte Field decomposition in aztec/"
# The width can be written two ways, and BOTH must be caught -- the original bug
# used the second form:
#     let b = x.to_be_bytes::<32>();          // turbofish
#     let b: [u8; 32] = x.to_be_bytes();      // inferred from the annotation
# Statements are reassembled across line breaks (awk accumulates until `;`) so a
# wrapped annotation cannot slip through, and comments are stripped first so the
# rationale written next to the fixed code -- which necessarily names the banned
# construct -- does not trip the gate.
raw_encodings="$(
    find "$AZTEC_DIR" -name '*.nr' -not -path '*/target/*' -print0 |
        xargs -0 awk '
            FNR == 1 { stmt = ""; start = 0 }
            {
                code = $0
                sub(/\/\/.*/, "", code)
                if (stmt == "") start = FNR
                stmt = stmt " " code
                if (code !~ /;/) next

                if (stmt ~ /to_(be|le)_bytes/ &&
                    (stmt ~ /to_(be|le)_bytes::<(3[2-9]|[4-9][0-9]|[1-9][0-9][0-9])>/ ||
                     stmt ~ /\[u8; *(3[2-9]|[4-9][0-9]|[1-9][0-9][0-9])\]/)) {
                    gsub(/^ +| +$/, "", stmt)
                    printf "%s:%d: %s\n", FILENAME, start, stmt
                }
                stmt = ""
            }
        '
)"

if [ -n "$raw_encodings" ]; then
    printf '%s\n' "$raw_encodings"
    echo "::error::a raw >= 32-byte Field decomposition was found in aztec/."
    echo "::error::Such an encoding is satisfied by x, x+p, ... x+4p alike, so it does not"
    echo "::error::determine the bytes and the resulting hash is not a function of its inputs."
    echo "::error::Use the canonical helper (std::field::bn254::decompose + two 16-byte limbs),"
    echo "::error::e.g. zka_transfer_aztec::withdrawal::canonical_be_bytes_32."
    status=1
else
    echo "    ok: none found"
fi

echo
echo "==> Source check: the withdrawal encoding still routes through decompose"
withdrawal_src="$AZTEC_DIR/zka_transfer_aztec/src/withdrawal.nr"
if [ ! -f "$withdrawal_src" ]; then
    echo "::error::expected $withdrawal_src to exist"
    status=1
elif grep -qE '^\s*use std::field::bn254::decompose;' "$withdrawal_src" &&
    grep -qE 'let \(lo, hi\) = decompose\(x\);' "$withdrawal_src"; then
    echo "    ok: canonical_be_bytes_32 binds its input to a canonical representative"
else
    echo "::error::withdrawal.nr no longer derives its 32-byte encoding from"
    echo "::error::std::field::bn254::decompose. The L2->L1 content hash must be a"
    echo "::error::function of (recipient, amount) alone -- see docs/adr/0002."
    status=1
fi

echo
if [ "$status" -eq 0 ]; then
    echo "Aztec field-encoding canonicity gate: PASS"
else
    echo "Aztec field-encoding canonicity gate: FAIL"
fi
exit "$status"
