#!/usr/bin/env bash
# Trusset KYC hashing — reproducible WASM verifier build for vendoring.
#
# The Trusset issuer backend does not shell out to the native verifier: it
# vendors a wasm32 build of `trusset-verifier` under
# `services/customers/zk-verifier/wasm/` and drives its own check ladder
# through the granular exports (proof_digest_hex, public_digest_hex,
# leaf_hash_hex, merkle_root_hex, merkle_root_hex_v, manifest_signing_bytes,
# verify_manifest_signature, verify_leaf_stark). Its `provenance.json`
# records the tool commit and the artifact SHA-256, and that pair feeds the
# backend's VERIFIER_VERSION string, which is persisted into every
# verification report.
#
# This script produces the artifact and the provenance block so the vendored
# copy is reproducible from a checkout rather than from an ad-hoc build.
#
# Usage:
#   scripts/rebuild-wasm.sh [output-dir]
#
# Default output-dir is `target/wasm-vendor`. Copy its contents over the
# backend's `services/customers/zk-verifier/wasm/` directory and commit the
# result there (the backend keeps its own provenance).
#
# Prereq: wasm-bindgen-cli pinned to the version in Cargo.lock.
#   cargo install wasm-bindgen-cli --version 0.2.121 --locked

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

OUT_DIR="${1:-$REPO_ROOT/target/wasm-vendor}"
WASM_BINDGEN_VERSION="0.2.121"

log() { printf "\033[1;34m[wasm]\033[0m %s\n" "$*"; }
err() { printf "\033[1;31m[wasm]\033[0m %s\n" "$*" >&2; }

if ! command -v wasm-bindgen >/dev/null 2>&1; then
    err "wasm-bindgen not found."
    err "Install: cargo install wasm-bindgen-cli --version ${WASM_BINDGEN_VERSION} --locked"
    exit 1
fi

FOUND_VERSION="$(wasm-bindgen --version | awk '{print $2}')"
if [ "$FOUND_VERSION" != "$WASM_BINDGEN_VERSION" ]; then
    err "wasm-bindgen ${FOUND_VERSION} found, ${WASM_BINDGEN_VERSION} required."
    err "A version mismatch produces glue the backend cannot load."
    exit 1
fi

if ! rustup target list --installed 2>/dev/null | grep -q '^wasm32-unknown-unknown$'; then
    err "wasm32-unknown-unknown target not installed."
    err "Install: rustup target add wasm32-unknown-unknown"
    exit 1
fi

log "Building trusset-verifier for wasm32-unknown-unknown..."
# cargo rustc --crate-type=cdylib rather than declaring cdylib in
# verifier/Cargo.toml: declaring it there breaks `cargo test --workspace`
# on macOS x86_64 (cargo issue #6313).
cargo rustc --release --target wasm32-unknown-unknown \
    -p trusset-verifier --features wasm --lib --crate-type=cdylib

ARTIFACT="$REPO_ROOT/target/wasm32-unknown-unknown/release/trusset_verifier.wasm"
if [ ! -f "$ARTIFACT" ]; then
    err "expected artifact not found: $ARTIFACT"
    exit 1
fi

log "Generating nodejs bindings into ${OUT_DIR}..."
rm -rf "$OUT_DIR"
mkdir -p "$OUT_DIR"
wasm-bindgen --target nodejs --no-typescript --out-dir "$OUT_DIR" "$ARTIFACT"

BG_WASM="$OUT_DIR/trusset_verifier_bg.wasm"
if [ ! -f "$BG_WASM" ]; then
    err "wasm-bindgen did not produce trusset_verifier_bg.wasm"
    exit 1
fi

WASM_SHA="$(shasum -a 256 "$BG_WASM" | awk '{print $1}')"
TOOL_COMMIT="$(git rev-parse --short HEAD 2>/dev/null || echo unknown)"
if ! git diff --quiet 2>/dev/null || ! git diff --cached --quiet 2>/dev/null; then
    TOOL_COMMIT="${TOOL_COMMIT}+dirty"
fi

cat > "$OUT_DIR/provenance.json" <<JSON
{
  "component": "trusset-verifier (wasm32, --features wasm)",
  "toolRepo": "github.com/Trusset/trusset-kyc-zk-proofs",
  "toolCommit": "${TOOL_COMMIT}",
  "wasmSha256": "${WASM_SHA}",
  "builtWith": "wasm-bindgen ${WASM_BINDGEN_VERSION} --target nodejs",
  "note": "Rebuild via scripts/rebuild-wasm.sh in the tool repo; keep toolCommit + wasmSha256 in sync with VERIFIER_VERSION."
}
JSON

log "Exports:"
grep -oE '^(module\.exports\.|exports\.)[a-zA-Z_0-9]+' "$OUT_DIR/trusset_verifier.js" \
    | sed -E 's/^(module\.)?exports\.//' | sort -u | sed 's/^/  /'

# The issuer backend's check ladder depends on these by name. A rename or
# a dropped export breaks it at runtime rather than at build time, so fail
# here instead.
REQUIRED_EXPORTS="proof_digest_hex public_digest_hex leaf_hash_hex merkle_root_hex merkle_root_hex_v manifest_signing_bytes verify_manifest_signature verify_leaf_stark"
for name in $REQUIRED_EXPORTS; do
    grep -qE "^(module\.exports\.|exports\.)${name}\b" "$OUT_DIR/trusset_verifier.js" \
        || { err "required export missing from the build: ${name}"; exit 1; }
done
log "all required backend exports present"

log "Artifact:  ${BG_WASM}"
log "SHA-256:   ${WASM_SHA}"
log "Commit:    ${TOOL_COMMIT}"
log "Copy ${OUT_DIR}/ over the backend's services/customers/zk-verifier/wasm/."
