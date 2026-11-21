#!/usr/bin/env bash
# Install the pinned Nargo toolchain for public CI (x86_64 Linux runners).
#
# The release tarball is downloaded directly from the noir-lang/noir release
# and verified against a pinned SHA-256 digest before anything is executed, so
# neither a moved release tag nor a compromised intermediate installer can
# substitute a different binary. The installed binary must also self-report
# exactly the requested version. Bumping the toolchain requires updating
# NARGO_VERSION in .noir-version and the digest here in the same review.
set -euo pipefail

# Noir v1.0.0-beta.25 Linux x86_64 GNU release asset 485845294.
NARGO_TARBALL_SHA256="bf3410ab94933a4aebd1f988b67ae974c6c227f9456ed0f1e4a3716bb8a30fe9"

usage() {
  echo "usage: $0 <nargo-version>" >&2
  exit 64
}

if [[ "$#" -ne 1 || -z "${1:-}" ]]; then
  usage
fi

NARGO_VERSION="$1"
NARGO_HOME="${NARGO_HOME:-${HOME:?HOME must be set}/.nargo}"
NARGO_URL="https://github.com/noir-lang/noir/releases/download/v${NARGO_VERSION}/nargo-x86_64-unknown-linux-gnu.tar.gz"

if ! command -v curl >/dev/null 2>&1; then
  echo "required tool missing: curl" >&2
  exit 1
fi

if command -v sha256sum >/dev/null 2>&1; then
  sha256_of() {
    local output
    output="$(sha256sum "$1")"
    printf '%s\n' "${output%%[[:space:]]*}"
  }
elif command -v shasum >/dev/null 2>&1; then
  sha256_of() {
    local output
    output="$(shasum -a 256 "$1")"
    printf '%s\n' "${output%%[[:space:]]*}"
  }
else
  echo "required digest tool missing: sha256sum or shasum" >&2
  exit 1
fi

tarball="$(mktemp)"
trap 'rm -f "$tarball"' EXIT

curl --fail --silent --show-error --location --output "$tarball" "$NARGO_URL"

actual_digest="$(sha256_of "$tarball")"
if [[ "$actual_digest" != "$NARGO_TARBALL_SHA256" ]]; then
  echo "nargo tarball digest mismatch: expected $NARGO_TARBALL_SHA256, got $actual_digest" >&2
  exit 1
fi

mkdir -p "$NARGO_HOME/bin"
tar -xzf "$tarball" -C "$NARGO_HOME/bin" nargo
chmod +x "$NARGO_HOME/bin/nargo"

if [[ ! -x "$NARGO_HOME/bin/nargo" ]]; then
  echo "nargo missing after installation" >&2
  exit 1
fi

actual="$("$NARGO_HOME/bin/nargo" --version)"
installed_version=""
version_line_count=0
malformed_version_line=0
while IFS= read -r line || [[ -n "$line" ]]; do
  if [[ "$line" =~ ^nargo[[:space:]]version ]]; then
    if [[ "$line" =~ ^nargo[[:space:]]version[[:space:]]=[[:space:]]([^[:space:]]+)$ ]]; then
      installed_version="${BASH_REMATCH[1]}"
      version_line_count=$((version_line_count + 1))
    else
      malformed_version_line=1
    fi
  fi
done <<< "$actual"

if [[ "$malformed_version_line" -ne 0 || "$version_line_count" -ne 1 || "$installed_version" != "$NARGO_VERSION" ]]; then
  echo "nargo version mismatch: expected $NARGO_VERSION, got $actual" >&2
  exit 1
fi
