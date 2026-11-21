#!/usr/bin/env bash
# Verify the exact Aztec dependency checkouts consumed by aztec-nargo.
#
# Since V6, aztec-nr ships from aztec-labs-eng/aztec-nr and depends on the
# protocol types in AztecProtocol/aztec-packages at the same tag, so the
# resolved closure contains two Aztec checkouts. Both are pinned.

set -euo pipefail

readonly PINNED_TAG="v6.0.0"
readonly NARGO_GIT_ROOT="${HOME}/nargo/github.com"

readonly AZTEC_NR_COMMIT="0472012201fdff1429d184f8d25cecf13ca94326"
readonly AZTEC_NR_ARCHIVE_SHA256="e1f70e0fad4a92795a200923ace03f5c8f56b45e8416b4bfa3510f16384d688e"
readonly AZTEC_NR_DEP_DIR="${AZTEC_NR_DEP_DIR:-${NARGO_GIT_ROOT}/aztec-labs-eng/aztec-nr/${PINNED_TAG}}"

readonly AZTEC_PACKAGES_COMMIT="0219f11d8133970df3974fe5ae65e006bf8c193a"
readonly AZTEC_PACKAGES_ARCHIVE_SHA256="3316c480e73529e796352cfc01428105925b769e05b343d8d5e4bcdddbaa4ad8"
readonly AZTEC_PACKAGES_DEP_DIR="${AZTEC_PACKAGES_DEP_DIR:-${NARGO_GIT_ROOT}/AztecProtocol/aztec-packages/${PINNED_TAG}}"

fail() {
    echo "AZTEC SOURCE INTEGRITY: FAIL — $1" >&2
    exit 1
}

verify_checkout() {
    local label="$1" dep_dir="$2" pinned_commit="$3" pinned_digest="$4"
    local actual_commit actual_digest

    [[ -d "${dep_dir}/.git" ]] || fail "${label}: fetched dependency checkout missing at ${dep_dir}; run this check after aztec-nargo fetches the workspace"

    actual_commit="$(git -C "${dep_dir}" rev-parse HEAD)"
    [[ "${actual_commit}" == "${pinned_commit}" ]] || fail "${label}: fetched HEAD ${actual_commit} does not match ${pinned_commit}"

    [[ -z "$(git -C "${dep_dir}" status --porcelain --untracked-files=all)" ]] || fail "${label}: fetched dependency checkout contains modified or untracked content"

    actual_digest="$(git -C "${dep_dir}" archive --format=tar HEAD | sha256sum | cut -d' ' -f1)"
    [[ "${actual_digest}" == "${pinned_digest}" ]] || fail "${label}: archive digest ${actual_digest} does not match ${pinned_digest}"

    git -C "${dep_dir}" fsck --strict --no-progress >/dev/null
    echo "AZTEC SOURCE INTEGRITY: OK (${label} ${PINNED_TAG} @ ${actual_commit}, digest ${actual_digest})"
}

verify_checkout "aztec-nr" "${AZTEC_NR_DEP_DIR}" "${AZTEC_NR_COMMIT}" "${AZTEC_NR_ARCHIVE_SHA256}"
verify_checkout "aztec-packages" "${AZTEC_PACKAGES_DEP_DIR}" "${AZTEC_PACKAGES_COMMIT}" "${AZTEC_PACKAGES_ARCHIVE_SHA256}"
