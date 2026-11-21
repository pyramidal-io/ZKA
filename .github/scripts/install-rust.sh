#!/usr/bin/env bash
# Install the registry and adapter MSRV on a clean Linux amd64 runner.
set -euo pipefail

readonly RUST_VERSION="1.88.0"
readonly DIST="https://static.rust-lang.org/dist/2025-06-26"
readonly TARGET="x86_64-unknown-linux-gnu"

downloads=$(mktemp -d "${RUNNER_TEMP:?}/zka-rust-downloads.XXXXXX")
trap 'rm -rf -- "$downloads"' EXIT
prefix=$(mktemp -d "${RUNNER_TEMP}/zka-rust.XXXXXX")

install_component() {
    local component="$1" digest="$2" archive
    archive="${component}-${RUST_VERSION}-${TARGET}"
    curl --fail --silent --show-error --location --retry 3 --max-time 180 \
        "${DIST}/${archive}.tar.xz" --output "${downloads}/${archive}.tar.xz"
    printf '%s  %s\n' "$digest" "${downloads}/${archive}.tar.xz" | sha256sum --check --strict
    tar -xJf "${downloads}/${archive}.tar.xz" -C "$downloads"
    bash "${downloads}/${archive}/install.sh" --prefix="$prefix" --disable-ldconfig
}

# Values are the xz_hash entries in the Rust 1.88.0 release manifest.
install_component rustc b049fd57fce274d10013e2cf0e05f215f68f6580865abc52178f66ae9bf43fd8
install_component rust-std 36d7eacf46bd5199cb433e49a9ed9c9b380d82f8a0ebc05e89b43b51c070c955
install_component cargo 856962610ee821648cee32e3d6abac667af7bb7ea6ec6f3d184cc31e66044f6b

for tool in rustc cargo; do
    reported=$("${prefix}/bin/${tool}" --version)
    if [[ "$reported" != "$tool $RUST_VERSION "* ]]; then
        printf 'Expected %s %s, got %s\n' "$tool" "$RUST_VERSION" "$reported" >&2
        exit 1
    fi
    printf '%s\n' "$reported"
done

printf '%s\n' "${prefix}/bin" >> "${GITHUB_PATH:?}"
printf 'CARGO_HOME=%s\n' "${prefix}/cargo-home" >> "${GITHUB_ENV:?}"
