#!/usr/bin/env bash
# Install the reviewed Aztec V6.0.0 toolchain bootstrap and verify source tags.

set -euo pipefail

readonly AZTEC_VERSION="6.0.0"
# Reviewed against the 5.2.0 installer; must match scripts/ci/install-aztec.sh.
readonly INSTALL_SHA256="f7a00e039647cb4101a0011da10070ae0a559f7a032adfdc65513a380ab603b1"
# The installer resolves its npm graph from this release lock bundle; pin it too.
readonly PACKAGES_LOCK_SHA256="8f92bcd92cf5d2e27893ec590a38be2f3c004785eb9828859c697cafacce9491"
readonly VERSIONS_SHA256="21993dc771fd85439ca76f2ef9808125737d9a213069af0ba68225c149e78e2f"
# Match the private CI pin for the nested Foundry bootstrap.
readonly FOUNDRYUP_INIT_REVISION="ecc549d64cf908784f252629885bc84d345932b5"
readonly FOUNDRYUP_INIT_SHA256="5a8990dff59498a094cb3562ed4be917b3000f32781b50c2b60b399b4ea37dd7"
# Both v6.0.0 tags are lightweight: each pin is the commit the tag ref names.
readonly AZTEC_PACKAGES_COMMIT="0219f11d8133970df3974fe5ae65e006bf8c193a"
readonly AZTEC_NODE_COMMIT="d2e67c1d938f06a6476dd7d4bd01e73771923dd1"
SCRATCH=$(mktemp -d "${RUNNER_TEMP:-/tmp}/zka-aztec.XXXXXX")
readonly SCRATCH
trap 'rm -rf -- "$SCRATCH"' EXIT
readonly INSTALL_PATH="${SCRATCH}/install.sh"
readonly MIRROR="${SCRATCH}/mirror"
readonly UPSTREAM="https://install.aztec-labs.com/${AZTEC_VERSION}"
readonly HOME_DIR="${AZTEC_HOME:-${HOME}/.aztec}"

# Exactly one line, the lightweight tag ref, naming the pinned commit. A moved,
# deleted or re-annotated tag fails closed.
verify_lightweight_tag() {
    local repo="$1" want="$2" tag="v${AZTEC_VERSION}" refs
    refs="$(git ls-remote "${repo}" "refs/tags/${tag}" "refs/tags/${tag}^{}")"
    if [[ "${refs}" != "$(printf '%s\trefs/tags/%s' "${want}" "${tag}")" ]]; then
        echo "ERROR: ${repo} tag ${tag} no longer names pinned commit ${want}:" >&2
        printf '%s\n' "${refs}" >&2
        exit 1
    fi
}

verify_lightweight_tag https://github.com/AztecProtocol/aztec-packages "${AZTEC_PACKAGES_COMMIT}"
verify_lightweight_tag https://github.com/aztec-labs-eng/aztec-node "${AZTEC_NODE_COMMIT}"

fetch_pinned() {
    local url="$1" digest="$2" output="$3" actual
    curl --fail --silent --show-error --location --retry 3 --max-time 120 "$url" --output "$output"
    actual=$(sha256sum "$output")
    if [[ "${actual%% *}" != "$digest" ]]; then
        printf 'SHA-256 mismatch for %s\n' "${output##*/}" >&2
        return 1
    fi
}
mkdir -p "${MIRROR}/${AZTEC_VERSION}" "${SCRATCH}/shim"
fetch_pinned "${UPSTREAM}/install" "${INSTALL_SHA256}" "${INSTALL_PATH}"
fetch_pinned "${UPSTREAM}/packages.tar.gz" "${PACKAGES_LOCK_SHA256}" "${MIRROR}/${AZTEC_VERSION}/packages.tar.gz"
fetch_pinned "${UPSTREAM}/versions" "${VERSIONS_SHA256}" "${MIRROR}/${AZTEC_VERSION}/versions"
fetch_pinned "https://raw.githubusercontent.com/foundry-rs/foundryup/${FOUNDRYUP_INIT_REVISION}/foundryup-init.sh" \
    "${FOUNDRYUP_INIT_SHA256}" "${SCRATCH}/foundryup-init.sh"

# The pinned Aztec installer pipes this exact URL into bash. Serve the reviewed
# bytes locally and let every other request retain the runner's normal routing.
cat > "${SCRATCH}/shim/curl" <<'SHIM'
#!/usr/bin/env bash
set -euo pipefail
for arg in "$@"; do
    if [[ "$arg" == https://foundry.paradigm.xyz ]]; then
        exec cat "$ZKA_FOUNDRYUP_INIT"
    fi
done
exec "$ZKA_REAL_CURL" "$@"
SHIM
chmod +x "${SCRATCH}/shim/curl"

# Serve the version manifest and package lock from the verified local mirror.
ZKA_REAL_CURL="$(command -v curl)" \
ZKA_FOUNDRYUP_INIT="${SCRATCH}/foundryup-init.sh" \
PATH="${SCRATCH}/shim:${PATH}" \
AZTEC_HOME="${HOME_DIR}" \
INSTALL_URI="file://${MIRROR}" \
VERSION="${AZTEC_VERSION}" \
NON_INTERACTIVE=1 \
AZTEC_UP_SKIP_PACKAGE_LOCK=0 \
bash "${INSTALL_PATH}"

# aztec-up, which is not used here, is what normally creates this link.
ln -sfn "${HOME_DIR}/versions/${AZTEC_VERSION}" "${HOME_DIR}/current"

{
    echo "${HOME_DIR}/current/bin"
    echo "${HOME_DIR}/current/internal-bin"
} >> "${GITHUB_PATH:?GITHUB_PATH is required}"
