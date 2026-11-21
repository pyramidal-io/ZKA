#!/usr/bin/env bash
# Restore the exact Snappy native package omitted by some Aztec v6.0.0
# installs, and pin the Snappy loader that selects it.

set -euo pipefail

# Aztec 6.0.0 pins snappy 7.2.2 in its release package lock. That release
# has a native-only loader; the WASI fallback was introduced in Snappy 7.3.
EXPECTED_SNAPPY_VERSION="7.2.2"
EXPECTED_AZTEC_VERSION="6.0.0"
NATIVE_PACKAGE="@napi-rs/snappy-linux-x64-gnu"
EXPECTED_NATIVE_SHA512="8d9b7c262b7f1c70dc6afb7cd33c44903a47f91d48734b2c8950a8b9e012ccc5daeefc0f25e178671672a94c38a9e4b2ee7f14504c689aef06f196cfe952a183"
EXPECTED_INDEX_SHA256="17cee0176b71ce2f7d7ca8b2ab19bcb1763d19445a85963ed3ebbf0dd89dd3a3"
AZTEC_INSTALL_ROOT="${AZTEC_INSTALL_ROOT:-${AZTEC_HOME:-${HOME}/.aztec}/versions/${AZTEC_VERSION:-6.0.0}}"
SNAPPY_PACKAGE_ROOT="${AZTEC_INSTALL_ROOT}/node_modules/snappy"
SNAPPY_INDEX_ENTRY_POINT="${SNAPPY_PACKAGE_ROOT}/index.js"

if [[ ! -d "${SNAPPY_PACKAGE_ROOT}" ]]; then
    echo "ERROR: Aztec Snappy package not found under ${AZTEC_INSTALL_ROOT}" >&2
    exit 1
fi

package_version() {
    PACKAGE_JSON_PATH="$1" node -p 'require(process.env.PACKAGE_JSON_PATH).version'
}

snappy_index_sha256() {
    local digest
    digest="$(sha256sum "${SNAPPY_INDEX_ENTRY_POINT}")"
    printf '%s\n' "${digest%% *}"
}

verify_snappy_index() {
    if [[ ! -f "${SNAPPY_INDEX_ENTRY_POINT}" ]]; then
        echo "ERROR: Snappy index.js is missing from ${SNAPPY_PACKAGE_ROOT}" >&2
        exit 1
    fi
    if [[ "$(snappy_index_sha256)" != "${EXPECTED_INDEX_SHA256}" ]]; then
        echo "ERROR: unexpected Snappy index.js digest" >&2
        exit 1
    fi
}

aztec_package_json="${AZTEC_INSTALL_ROOT}/node_modules/@aztec-labs/aztec/package.json"
snappy_package_json="${SNAPPY_PACKAGE_ROOT}/package.json"
installed_aztec_version="$(package_version "${aztec_package_json}")"
if [[ "${installed_aztec_version}" != "${EXPECTED_AZTEC_VERSION}" ]]; then
    echo "ERROR: expected @aztec-labs/aztec@${EXPECTED_AZTEC_VERSION}, found ${installed_aztec_version}" >&2
    exit 1
fi

installed_snappy_version="$(package_version "${snappy_package_json}")"
if [[ "${installed_snappy_version}" != "${EXPECTED_SNAPPY_VERSION}" ]]; then
    echo "ERROR: expected snappy@${EXPECTED_SNAPPY_VERSION}, found ${installed_snappy_version}" >&2
    exit 1
fi

case "$(uname -s)/$(uname -m)" in
    Linux/x86_64|Linux/amd64)
        ;;
    *)
        echo "ERROR: pinned TXE Snappy repair supports Linux x86_64 only" >&2
        exit 1
        ;;
esac

# snappy@7.2.2 publishes its NAPI-RS loader as index.js; the exact native
# package installed below is the Linux glibc target it selects.
# Pin the loader's bytes and fail closed if it is missing or altered -- never
# write or overwrite a loader.
verify_snappy_index

root_metadata_fingerprint() {
    local file
    for file in package.json package-lock.json; do
        if [[ -f "${AZTEC_INSTALL_ROOT}/${file}" ]]; then
            sha256sum "${AZTEC_INSTALL_ROOT}/${file}"
        else
            printf 'missing %s\n' "${file}"
        fi
    done
}

root_metadata_before="$(root_metadata_fingerprint)"
DOWNLOAD_DIR="${SNAPPY_PACKAGE_ROOT}/.zka-snappy-downloads"
mkdir -p "${DOWNLOAD_DIR}"
download_and_verify() {
    local package="$1"
    local expected="$2"
    local archive_name
    local archive_path
    local actual
    archive_name="$(npm pack "${package}@${EXPECTED_SNAPPY_VERSION}" --pack-destination "${DOWNLOAD_DIR}" --silent)"
    archive_path="${DOWNLOAD_DIR}/${archive_name}"
    actual="$(sha512sum "${archive_path}")"
    actual="${actual%% *}"
    if [[ "${actual}" != "${expected}" ]]; then
        echo "ERROR: tarball SHA-512 mismatch for ${package}@${EXPECTED_SNAPPY_VERSION}" >&2
        exit 1
    fi
    printf '%s\n' "${archive_path}"
}

native_archive="$(download_and_verify "${NATIVE_PACKAGE}" "${EXPECTED_NATIVE_SHA512}")"
# Install inside Snappy's package-local resolution tree. Installing at the
# Aztec root while ignoring its lock could re-resolve the root's 6.0.0
# dependencies and silently replace the pinned toolchain.
npm install \
    --prefix "${SNAPPY_PACKAGE_ROOT}" \
    --no-save \
    --package-lock=false \
    --ignore-scripts \
    --omit=dev \
    "${native_archive}"
if [[ "$(root_metadata_fingerprint)" != "${root_metadata_before}" ]]; then
    echo "ERROR: Snappy repair mutated Aztec root package metadata" >&2
    exit 1
fi
verify_snappy_index

native_package_json="${SNAPPY_PACKAGE_ROOT}/node_modules/${NATIVE_PACKAGE}/package.json"
installed_native_version="$(package_version "${native_package_json}")"
if [[ "${installed_native_version}" != "${EXPECTED_SNAPPY_VERSION}" ]]; then
    echo "ERROR: expected ${NATIVE_PACKAGE}@${EXPECTED_SNAPPY_VERSION}, found ${installed_native_version}" >&2
    exit 1
fi
# The JavaScript uses its own template literal; shell expansion is unwanted.
# shellcheck disable=SC2016
SNAPPY_INDEX_ENTRY_POINT="${SNAPPY_INDEX_ENTRY_POINT}" \
node --input-type=module -e '
import { pathToFileURL } from "node:url";

const input = Buffer.from("zka-txe-snappy-self-test");

function assertRoundTrip(snappy, label) {
  const compressed = snappy.compressSync(input);
  const uncompressed = Buffer.from(snappy.uncompressSync(compressed));
  if (!uncompressed.equals(input)) {
    throw new Error(`${label} round-trip self-test failed`);
  }
}

const index = await import(pathToFileURL(process.env.SNAPPY_INDEX_ENTRY_POINT).href);
assertRoundTrip(index, "Snappy index.js");
'

installed_aztec_version="$(package_version "${aztec_package_json}")"
if [[ "${installed_aztec_version}" != "${EXPECTED_AZTEC_VERSION}" ]]; then
    echo "ERROR: Snappy repair changed @aztec-labs/aztec to ${installed_aztec_version}" >&2
    exit 1
fi

echo "Snappy binding ready: ${NATIVE_PACKAGE}@${EXPECTED_SNAPPY_VERSION}"
