#!/usr/bin/env bash
# Trusset KYC v2 — WASM runtime parity (Phase 2C Stage 30).
#
# Validates that the WASM verifier loaded into Node produces a
# byte-identical VerifyReport JSON to the native `trusset-verifier-cli`
# binary, across the same on-disk bundle. This is the runtime
# complement to the structural drift check in
# `verifier/tests/wasm_build_check.rs` — together they catch every
# class of native↔WASM divergence:
#   - structural drift (ABI / exports / determinism) → wasm_build_check
#   - runtime drift (different per-leaf outcomes for the same input) → this script
#
# Pre-requisites:
#   1. wasm-bindgen-cli installed at the version pinned in Cargo.lock
#      (currently 0.2.121). Install with:
#         cargo install wasm-bindgen-cli --version 0.2.121 --locked
#   2. `cargo build --release` has produced the native binaries.
#   3. `cargo rustc --release --target wasm32-unknown-unknown \
#         -p trusset-verifier --features wasm --lib --crate-type=cdylib`
#      has produced `target/wasm32-unknown-unknown/release/trusset_verifier.wasm`.
#
# This script handles step 3 internally if the WASM artifact is missing.
# Step 1 is operator-managed because installing the CLI is ~2 min of
# compile time.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO_ROOT"

# Test fixtures (same as canary.sh — pinned for byte-stability).
export TRUSSET_KYC_MASTER_KEY="000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
export TRUSSET_KYC_SIGNING_KEY="4242424242424242424242424242424242424242424242424242424242424242"
export TRUSSET_KYC_EPOCH_DAYS="20587"
# ed25519 verifying key derived from the test signing key above.
TEST_PUBLIC_KEY_HEX="2152f8d19b791d24453242e15f2eab6cb7cffa7b6a5ed30097960e069881db12"

log()  { printf "\033[1;34m[wasm-parity]\033[0m %s\n" "$*"; }
fail() { printf "\033[1;31m[wasm-parity]\033[0m %s\n" "$*" >&2; exit 1; }
ok()   { printf "\033[1;32m[wasm-parity]\033[0m %s\n" "$*"; }

# ---- Pre-flight checks ---------------------------------------------------

command -v wasm-bindgen >/dev/null 2>&1 \
    || fail "wasm-bindgen-cli not installed. Run: cargo install wasm-bindgen-cli --version 0.2.121 --locked"

NATIVE_BIN="$REPO_ROOT/target/release/trusset-verifier-cli"
PROVER_BIN="$REPO_ROOT/target/release/trusset-prover"
[ -x "$NATIVE_BIN" ] || fail "missing $NATIVE_BIN — run 'cargo build --release'"
[ -x "$PROVER_BIN" ] || fail "missing $PROVER_BIN — run 'cargo build --release'"
[ -f "$REPO_ROOT/cli/dist/index.js" ] || fail "missing cli/dist/index.js — run 'cd cli && npm run build'"

# ---- Build WASM artifact if missing -------------------------------------

WASM_ARTIFACT="$REPO_ROOT/target/wasm32-unknown-unknown/release/trusset_verifier.wasm"
if [ ! -f "$WASM_ARTIFACT" ]; then
    log "WASM artifact missing — building"
    cargo rustc --release --target wasm32-unknown-unknown -p trusset-verifier \
        --features wasm --lib --crate-type=cdylib >/dev/null 2>&1 \
        || fail "WASM build failed"
fi

# ---- Generate Node-loadable WASM glue -----------------------------------

WASM_OUT="$REPO_ROOT/target/wasm-bindings/node"
mkdir -p "$WASM_OUT"
log "running wasm-bindgen --target nodejs"
wasm-bindgen "$WASM_ARTIFACT" --out-dir "$WASM_OUT" --target nodejs --no-typescript >/dev/null
[ -f "$WASM_OUT/trusset_verifier.js" ] \
    || fail "wasm-bindgen failed to produce trusset_verifier.js"

# ---- Produce a fresh bundle -------------------------------------------

WORK="$(mktemp -d -t trusset-wasm-parity-XXXXXX)"
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$WORK/input" "$WORK/output"

if command -v jq >/dev/null 2>&1; then
    jq '.security.epochDaysSource = "env:TRUSSET_KYC_EPOCH_DAYS"' \
        "$REPO_ROOT/config.example.json" > "$WORK/config.json"
else
    sed 's|"epochDaysSource": "utc_today"|"epochDaysSource": "env:TRUSSET_KYC_EPOCH_DAYS"|' \
        "$REPO_ROOT/config.example.json" > "$WORK/config.json"
fi
cp -r "$REPO_ROOT/config" "$WORK/config"

cat > "$WORK/input/parity.json" <<'EOF'
[
  {
    "walletAddress": "0xabcdef0123456789abcdef0123456789abcdef01",
    "country": "DEU",
    "investorType": "PROFESSIONAL",
    "firstName": "Alice",
    "lastName": "Anderson",
    "dateOfBirth": "1985-04-12",
    "nationality": "DEU",
    "documentType": "PASSPORT",
    "documentNumber": "P12345678",
    "documentIssuingCountry": "DEU"
  }
]
EOF

export TRUSSET_PROVER_BIN="$PROVER_BIN"
export TRUSSET_VERIFIER_BIN="$NATIVE_BIN"

log "producing fresh production bundle"
(cd "$WORK" && node "$REPO_ROOT/cli/dist/index.js" hash >/dev/null 2>&1) \
    || fail "bundle generation failed"

# Locate the single produced bundle directory under output/.
BUNDLE_DIR="$(find "$WORK/output" -maxdepth 1 -type d -name "0x*" | head -1)"
[ -d "$BUNDLE_DIR" ] || fail "no bundle directory produced under $WORK/output"
log "bundle: $BUNDLE_DIR"

# ---- Native verifier run ------------------------------------------------

log "native verifier"
NATIVE_JSON="$WORK/native.json"
"$NATIVE_BIN" --bundle "$BUNDLE_DIR" --public-key "$TEST_PUBLIC_KEY_HEX" --json \
    > "$NATIVE_JSON" 2>/dev/null \
    || fail "native verifier failed"

# ---- WASM verifier run via Node -----------------------------------------

log "WASM verifier (Node)"
WASM_JSON="$WORK/wasm.json"
node - "$BUNDLE_DIR" "$TEST_PUBLIC_KEY_HEX" "$WASM_OUT/trusset_verifier.js" > "$WASM_JSON" <<'NODE_EOF'
const fs = require('fs');
const path = require('path');
const [bundleDir, pubKeyHex, wasmModulePath] = process.argv.slice(2);
const wasm = require(wasmModulePath);

const manifestBytes = fs.readFileSync(path.join(bundleDir, 'manifest.json'));
const kycHashText = fs.readFileSync(path.join(bundleDir, 'kycHash.hex'), 'utf-8');
const signature = fs.readFileSync(path.join(bundleDir, 'manifest.sig'));
const manifest = JSON.parse(manifestBytes.toString('utf-8'));

const proofs = {};
for (const leaf of manifest.leaves) {
    const buf = fs.readFileSync(path.join(bundleDir, leaf.proofPath));
    proofs[leaf.proofPath] = Array.from(buf);
}
const proofsJson = JSON.stringify(proofs);

const pubKeyBytes = new Uint8Array(Buffer.from(pubKeyHex, 'hex'));
if (pubKeyBytes.length !== 32) {
    console.error(`pubkey must be 32 bytes, got ${pubKeyBytes.length}`);
    process.exit(1);
}

const reportJson = wasm.verify_strict(
    new Uint8Array(manifestBytes),
    kycHashText,
    new Uint8Array(signature),
    proofsJson,
    pubKeyBytes
);
process.stdout.write(reportJson);
NODE_EOF

# ---- Compare -----------------------------------------------------------

# Normalize both via jq (canonical key ordering) before comparing.
if command -v jq >/dev/null 2>&1; then
    jq -S . < "$NATIVE_JSON" > "$NATIVE_JSON.sorted"
    jq -S . < "$WASM_JSON"   > "$WASM_JSON.sorted"
else
    cp "$NATIVE_JSON" "$NATIVE_JSON.sorted"
    cp "$WASM_JSON"   "$WASM_JSON.sorted"
fi

if cmp -s "$NATIVE_JSON.sorted" "$WASM_JSON.sorted"; then
    ok "native and WASM VerifyReports match byte-for-byte (after canonical key sort)"
else
    echo "--- native ---"
    cat "$NATIVE_JSON.sorted"
    echo "--- wasm ---"
    cat "$WASM_JSON.sorted"
    echo "--- diff ---"
    diff "$NATIVE_JSON.sorted" "$WASM_JSON.sorted" || true
    fail "native and WASM verifier reports differ"
fi

# ---- Negative case: tamper a proof, confirm both reject identically ----

log "tamper test: flipping one byte in a proof file"
TAMPER_BUNDLE="$WORK/tampered"
cp -r "$BUNDLE_DIR" "$TAMPER_BUNDLE"
# Pick the first proof file and flip a single byte in the middle.
FIRST_PROOF="$(ls "$TAMPER_BUNDLE"/proofs/*.bin 2>/dev/null | head -1)"
[ -n "$FIRST_PROOF" ] || fail "no proof file to tamper in $TAMPER_BUNDLE"
PROOF_SIZE="$(wc -c < "$FIRST_PROOF" | tr -d ' ')"
MID=$((PROOF_SIZE / 2))
# Read byte at MID, XOR with 0xff, write back.
python3 - "$FIRST_PROOF" "$MID" <<'PY'
import sys
path = sys.argv[1]; off = int(sys.argv[2])
with open(path, "rb") as f:
    data = bytearray(f.read())
data[off] ^= 0xff
with open(path, "wb") as f:
    f.write(data)
PY

NATIVE_TAMPER_JSON="$WORK/native_tamper.json"
"$NATIVE_BIN" --bundle "$TAMPER_BUNDLE" --public-key "$TEST_PUBLIC_KEY_HEX" --json \
    > "$NATIVE_TAMPER_JSON" 2>/dev/null || true   # exit nonzero on rejection is expected

WASM_TAMPER_JSON="$WORK/wasm_tamper.json"
node - "$TAMPER_BUNDLE" "$TEST_PUBLIC_KEY_HEX" "$WASM_OUT/trusset_verifier.js" > "$WASM_TAMPER_JSON" <<'NODE_EOF'
const fs = require('fs');
const path = require('path');
const [bundleDir, pubKeyHex, wasmModulePath] = process.argv.slice(2);
const wasm = require(wasmModulePath);

const manifestBytes = fs.readFileSync(path.join(bundleDir, 'manifest.json'));
const kycHashText = fs.readFileSync(path.join(bundleDir, 'kycHash.hex'), 'utf-8');
const signature = fs.readFileSync(path.join(bundleDir, 'manifest.sig'));
const manifest = JSON.parse(manifestBytes.toString('utf-8'));

const proofs = {};
for (const leaf of manifest.leaves) {
    const buf = fs.readFileSync(path.join(bundleDir, leaf.proofPath));
    proofs[leaf.proofPath] = Array.from(buf);
}
const proofsJson = JSON.stringify(proofs);
const pubKeyBytes = new Uint8Array(Buffer.from(pubKeyHex, 'hex'));
const reportJson = wasm.verify_strict(
    new Uint8Array(manifestBytes), kycHashText,
    new Uint8Array(signature), proofsJson, pubKeyBytes
);
process.stdout.write(reportJson);
NODE_EOF

if command -v jq >/dev/null 2>&1; then
    jq -S . < "$NATIVE_TAMPER_JSON" > "$NATIVE_TAMPER_JSON.sorted"
    jq -S . < "$WASM_TAMPER_JSON"   > "$WASM_TAMPER_JSON.sorted"
else
    cp "$NATIVE_TAMPER_JSON" "$NATIVE_TAMPER_JSON.sorted"
    cp "$WASM_TAMPER_JSON"   "$WASM_TAMPER_JSON.sorted"
fi

if cmp -s "$NATIVE_TAMPER_JSON.sorted" "$WASM_TAMPER_JSON.sorted"; then
    ok "tampered-bundle reports also match byte-for-byte (failure mode agreement)"
else
    echo "--- native ---"; cat "$NATIVE_TAMPER_JSON.sorted"
    echo "--- wasm ---";   cat "$WASM_TAMPER_JSON.sorted"
    fail "tampered-bundle reports diverge — native and WASM disagree on failure"
fi

# Sanity: both must report overall_pass=false on the tampered bundle.
NATIVE_OVERALL=$(jq -r '.overall_pass' < "$NATIVE_TAMPER_JSON" 2>/dev/null || echo "?")
[ "$NATIVE_OVERALL" = "false" ] \
    || fail "tampered bundle was not rejected — overall_pass = $NATIVE_OVERALL (expected false)"
ok "tampered bundle rejected with overall_pass=false in both implementations"

log "Phase 2C Stage 30 WASM runtime parity: PASS"
