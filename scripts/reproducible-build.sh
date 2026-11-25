#!/usr/bin/env bash
# Trusset KYC: reproducible release build of the native binaries.
#
# Every bundle records `manifest.toolchain.proverSha256`, the SHA-256 of the
# prover binary that produced it. That pin is only useful if a reviewer can
# rebuild the same bytes from the same source. This script builds the release
# binaries with every machine-specific path remapped, so two checkouts of the
# same commit, in different directories and under different users, produce
# byte-identical binaries for the same toolchain and host triple.
#
# Usage:
#   scripts/reproducible-build.sh [target-dir]
#
# Default target-dir is `target/reproducible`. The script prints the SHA-256
# of each binary in the form a manifest records (`0x` + 64 hex). Run your
# production batches with the `trusset-prover` it builds (set
# TRUSSET_PROVER_BIN, or copy it to target/release), and publish the printed
# proverSha256 next to the source commit.
#
# Inputs that must match for the digests to match:
#   - the source tree (commit, plus any local changes),
#   - Cargo.lock (the build runs with --locked),
#   - the toolchain in rust-toolchain.toml,
#   - the host triple (`rustc -vV | grep host`); an x86_64 build under
#     Rosetta and a native aarch64 build differ.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

TARGET_DIR="${1:-$REPO_ROOT/target/reproducible}"
CARGO_HOME_DIR="${CARGO_HOME:-$HOME/.cargo}"
RUSTUP_HOME_DIR="${RUSTUP_HOME:-$HOME/.rustup}"

log() { printf "\033[1;34m[repro]\033[0m %s\n" "$*"; }

export RUSTFLAGS="--remap-path-prefix=${REPO_ROOT}=/trusset-kyc --remap-path-prefix=${CARGO_HOME_DIR}=/cargo --remap-path-prefix=${RUSTUP_HOME_DIR}=/rustup"
export CARGO_INCREMENTAL=0

log "host:    $(rustc -vV | awk '/^host:/ {print $2}')"
log "rustc:   $(rustc --version)"
log "source:  $(git rev-parse --short HEAD 2>/dev/null || echo unknown)$(git diff --quiet 2>/dev/null || echo '+dirty')"
log "target:  ${TARGET_DIR}"

cargo build --release --locked --target-dir "$TARGET_DIR" \
    -p trusset-prover -p trusset-verifier --bins

for bin in trusset-prover trusset-registry trusset-verifier-cli trusset-archive; do
    sha="$(shasum -a 256 "$TARGET_DIR/release/$bin" | awk '{print $1}')"
    printf "%-22s 0x%s\n" "$bin" "$sha"
done
log "proverSha256 is the trusset-prover line."
