#!/usr/bin/env bash
# Fail-closed policy inventory gate for the public ZKA snapshot.
#
# 1. The tracked tree must equal the union of PUBLIC_ALLOWLIST (exported
#    private files) and PUBLIC_SURFACE (public-only overlay files), exactly.
# 2. Every tracked entry must be a regular file (mode 100644 or 100755).
# 3. Every workflow `uses:` reference must be pinned to a full 40-hex-char
#    commit SHA.
set -euo pipefail

fail() {
  echo "::error::$1" >&2
  exit 1
}

[ -f PUBLIC_ALLOWLIST ] || fail "PUBLIC_ALLOWLIST is missing"
[ -f PUBLIC_SURFACE ] || fail "PUBLIC_SURFACE is missing"

strip_policy() {
  grep -vE '^[[:space:]]*(#|$)' "$1" || true
}

allowlist="$(strip_policy PUBLIC_ALLOWLIST)"
surface="$(strip_policy PUBLIC_SURFACE)"

overlap="$(comm -12 <(printf '%s\n' "$allowlist" | sort -u) <(printf '%s\n' "$surface" | sort -u))"
if [ -n "$overlap" ]; then
  printf '%s\n' "$overlap" >&2
  fail "paths listed in both PUBLIC_ALLOWLIST and PUBLIC_SURFACE"
fi

expected="$(printf '%s\n%s\n' "$allowlist" "$surface" | sort)"
dupes="$(printf '%s\n' "$expected" | uniq -d)"
if [ -n "$dupes" ]; then
  printf '%s\n' "$dupes" >&2
  fail "duplicate entries in policy inventory"
fi

actual="$(git ls-files | sort)"
if ! diff <(printf '%s\n' "$expected") <(printf '%s\n' "$actual") >&2; then
  fail "tracked tree does not match PUBLIC_ALLOWLIST + PUBLIC_SURFACE"
fi

bad_modes="$(git ls-files -s | awk '$1 != "100644" && $1 != "100755" { print $1, $4 }')"
if [ -n "$bad_modes" ]; then
  printf '%s\n' "$bad_modes" >&2
  fail "tracked entries with non-regular git modes (symlink/submodule)"
fi

unpinned=0
while IFS= read -r workflow; do
  while IFS= read -r line; do
    if ! printf '%s\n' "$line" | grep -qE 'uses:[[:space:]]*[^@[:space:]]+@[0-9a-f]{40}([[:space:]]*#.*)?$'; then
      echo "unpinned action reference in $workflow: $line" >&2
      unpinned=1
    fi
  done < <(grep -E '^[[:space:]]*(-[[:space:]]*)?uses:' "$workflow" || true)
done < <(git ls-files '.github/workflows/*.yml' '.github/workflows/*.yaml')
[ "$unpinned" -eq 0 ] || fail "workflow action references must be pinned to full commit SHAs"

echo "public surface inventory, file modes, and workflow pins verified"
