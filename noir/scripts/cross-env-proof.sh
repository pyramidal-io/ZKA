#!/usr/bin/env bash
# =============================================================================
# ZKA Real Native/EVM Proof Test
#
# The zka_cross_env_tests package asserts that the standalone Noir circuits and
# the Aztec contracts compute IDENTICAL cryptographic values at the LIBRARY
# level (self-consistency: same zka_lib functions -> same outputs). That is
# necessary but not sufficient -- it never generates a REAL proof.
#
# This script closes that gap for the §5.2 identity-binding circuit.
# It generates and verifies a REAL UltraHonk proof and asserts that the proof's
# PUBLIC INPUTS are byte-identical across the native Barretenberg verifier and
# the generated Ethereum UltraVerifier artifact. Aztec-native selective
# disclosure is a separate ZKC surface and is not asserted by this script.
#
# Flow:
#   1. nargo compile + execute the zka_credential circuit with the committed
#      cross-env vector (noir/zka_credential/Prover.toml). Because main() asserts
#      note/holder commitments and membership root against its own zka_lib-based
#      computation, a successful execute proves the circuit ACCEPTS
#      the cross-environment public inputs (the circuit-level cross-env check).
#   2. bb write_vk + prove + verify (EVM target = keccak, ZK), producing a real
#      proof and verifying it natively.
#   3. Assert the proof's public_inputs == the GOLDEN native/EVM vector below.
#
# The golden vector uses one private master seed for both the note-owner and ZKC
# holder branches. This script proves the constants survive a real UltraHonk
# proof end-to-end.
#
# Prerequisites (versions pinned by .noir-version and .bb-version):
#   - nargo (or aztec-nargo as a fallback) on PATH
#   - bb    (or aztec-bb as a fallback)    on PATH
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NOIR_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
ROOT_DIR="$(cd "$NOIR_DIR/.." && pwd)"

PKG="zka_credential"
WITNESS="cross_env_proof_witness"
OUT="target/cross_env_proof"

# GOLDEN native/EVM public inputs (32-byte big-endian field elements),
# in circuit public-input order: [note_commitment, holder_commitment,
# merkle_root, context]. These MUST match noir/zka_credential/Prover.toml.
EXPECTED_NOTE="06da602ba213de15352e6833939726f354987619ce123022f31d0b34950152f8"
EXPECTED_HOLDER="24dd41c93a298e537c6ac62487057a09229c1ab00b2baec40b45a325712840bf"
EXPECTED_ROOT="183fd62609dc483f6b08adaa4e5edfc8a8c02488897e630e02b3f5dc9b322440"
EXPECTED_CONTEXT="00000000000000000000000000000000000000000000000000000000deadbeef"
EXPECTED_PUBLIC_INPUTS="${EXPECTED_NOTE}${EXPECTED_HOLDER}${EXPECTED_ROOT}${EXPECTED_CONTEXT}"

# Prefer the repo-pinned standalone toolchain. An installed Aztec release may
# bundle a different Noir/bb version, so it is only a compatibility fallback.
NARGO="$(command -v nargo || command -v aztec-nargo || true)"
BB="$(command -v bb || command -v aztec-bb || true)"
if [[ -z "$NARGO" ]]; then
    echo "ERROR: neither 'aztec-nargo' nor 'nargo' found on PATH." >&2
    exit 1
fi
if [[ -z "$BB" ]]; then
    echo "ERROR: neither 'aztec-bb' nor 'bb' found on PATH." >&2
    exit 1
fi

cd "$NOIR_DIR"
echo "=== [1/4] Compiling + executing ${PKG} with the native/EVM vector ==="
"$NARGO" compile --package "$PKG"

# Verify-after-fetch: the compile above just (re)populated nargo's dependency
# cache. Hash it against the committed golden digest before trusting anything
# built from it -- fail closed on a mismatch. See
# docs/poseidon-dependency-upgrade.md. Never bypass this gate.
"$ROOT_DIR/scripts/check-poseidon-source-integrity.sh"

# A successful execute means main() accepted the cross-env public inputs in
# Prover.toml (it asserts them against its own zka_lib computation).
"$NARGO" execute --package "$PKG" "$WITNESS"

rm -rf "$OUT" && mkdir -p "$OUT"
CIRCUIT="target/${PKG}.json"
WITNESS_PATH="target/${WITNESS}.gz"

echo "=== [2/4] Writing verification key (UltraHonk, EVM/keccak target) ==="
"$BB" write_vk -s ultra_honk -b "$CIRCUIT" -o "$OUT" -t evm

echo "=== [3/4] Proving + verifying a REAL UltraHonk proof ==="
"$BB" prove -s ultra_honk -b "$CIRCUIT" -w "$WITNESS_PATH" -o "$OUT" -k "$OUT/vk" -t evm --verify
"$BB" verify -s ultra_honk -k "$OUT/vk" -p "$OUT/proof" -i "$OUT/public_inputs" -t evm

echo "=== [4/4] Asserting proof public inputs == native/EVM golden vector ==="
ACTUAL="$(od -An -v -tx1 "$OUT/public_inputs" | tr -d '[:space:]')"
if [[ "$ACTUAL" != "$EXPECTED_PUBLIC_INPUTS" ]]; then
    echo "FAIL: proof public inputs do not match the native/EVM golden vector." >&2
    echo "  expected: $EXPECTED_PUBLIC_INPUTS" >&2
    echo "  actual:   $ACTUAL" >&2
    echo "If this changed intentionally, regenerate Prover.toml and update this script." >&2
    exit 1
fi

echo ""
echo "PASS: real UltraHonk proof verified; public inputs [note, holder, root, context]"
echo "      are byte-identical to the native/EVM golden values:"
echo "        note      = 0x${EXPECTED_NOTE}"
echo "        holder    = 0x${EXPECTED_HOLDER}"
echo "        root      = 0x${EXPECTED_ROOT}"
echo "        context   = 0x${EXPECTED_CONTEXT}"
