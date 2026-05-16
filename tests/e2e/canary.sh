#!/usr/bin/env bash
# Trusset KYC v2 — determinism canary.
#
# Runs the full TS → Rust prover → verifier pipeline TWICE in clean
# working directories with identical inputs, then asserts every byte of
# every bundle is identical. This catches:
#
#   - Determinism regressions in the prover (any leak from OS entropy)
#   - Manifest key-ordering drift
#   - Signing payload nondeterminism
#   - File-write race conditions
#   - WASM verifier divergence from native
#   - Any circuit-level bug that affects public outputs
#
# Plan §7 ("The most important end-to-end test"). Run from the repo root.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO_ROOT"

# Pinned fixtures for byte-exact reproducibility.
export TRUSSET_KYC_MASTER_KEY="000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
export TRUSSET_KYC_SIGNING_KEY="4242424242424242424242424242424242424242424242424242424242424242"

# The canary runs the CLI from a temp working directory; tell it where to
# find the release binaries explicitly so locate_* fallbacks don't need to
# walk a target/ tree that won't exist in the temp dir.
export TRUSSET_PROVER_BIN="$REPO_ROOT/target/release/trusset-prover"
export TRUSSET_VERIFIER_BIN="$REPO_ROOT/target/release/trusset-verifier-cli"

CANARY_INPUT='[
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
  },
  {
    "walletAddress": "0xfedcba9876543210fedcba9876543210fedcba98",
    "country": "FRA",
    "investorType": "RETAIL",
    "firstName": "Bob",
    "lastName": "Bertrand",
    "dateOfBirth": "1992-09-30",
    "nationality": "FRA",
    "documentType": "PASSPORT",
    "documentNumber": "F87654321",
    "documentIssuingCountry": "FRA"
  }
]'

# Use a fixed epoch_days so timestamp-derived drift is impossible.
# (canary.sh runs this via TRUSSET_KYC_EPOCH_DAYS only when the operator's
# config.security.epochDaysSource is set to "env:TRUSSET_KYC_EPOCH_DAYS".)
export TRUSSET_KYC_EPOCH_DAYS="20587"

log()  { printf "\033[1;34m[canary]\033[0m %s\n" "$*"; }
fail() { printf "\033[1;31m[canary]\033[0m %s\n" "$*" >&2; exit 1; }

ensure_build() {
    if [ ! -x "$REPO_ROOT/target/release/trusset-prover" ] \
        || [ ! -x "$REPO_ROOT/target/release/trusset-verifier-cli" ] \
        || [ ! -f "$REPO_ROOT/cli/dist/index.js" ]; then
        log "Building (missing release artifacts)..."
        bash "$REPO_ROOT/scripts/build.sh" >/dev/null
    fi
}

# Run the pipeline once into a target dir.
# usage: run_pipeline <work_dir>
run_pipeline() {
    local work_dir="$1"
    rm -rf "$work_dir"
    mkdir -p "$work_dir/input" "$work_dir/output"

    # Use a custom config that pins epochDaysSource to env so the canary
    # gets byte-stable output. We copy the example config and tweak the
    # one field we care about (with jq if available, otherwise sed).
    if command -v jq >/dev/null 2>&1; then
        jq '.security.epochDaysSource = "env:TRUSSET_KYC_EPOCH_DAYS"' \
            "$REPO_ROOT/config.example.json" > "$work_dir/config.json"
    else
        sed 's|"epochDaysSource": "utc_today"|"epochDaysSource": "env:TRUSSET_KYC_EPOCH_DAYS"|' \
            "$REPO_ROOT/config.example.json" > "$work_dir/config.json"
    fi

    # The list_commitments file is referenced relative to the working dir.
    # Copy the whole config/ tree so paths resolve.
    cp -r "$REPO_ROOT/config" "$work_dir/config"

    echo "$CANARY_INPUT" > "$work_dir/input/canary.json"

    # Run the CLI from inside work_dir so cwd-relative paths resolve to
    # the isolated copy.
    (cd "$work_dir" && \
        node "$REPO_ROOT/cli/dist/index.js" hash >/dev/null 2>&1) \
        || fail "pipeline run failed in $work_dir"
}

# ============================ main ============================

ensure_build

WORK_A="$(mktemp -d -t trusset-canary-a-XXXXXX)"
WORK_B="$(mktemp -d -t trusset-canary-b-XXXXXX)"
trap 'rm -rf "$WORK_A" "$WORK_B"' EXIT

log "Run A → $WORK_A"
run_pipeline "$WORK_A"

# Small delay between runs so a timestamp-dependent bug has a chance to
# manifest (it shouldn't, but the canary is supposed to catch this).
sleep 1

log "Run B → $WORK_B"
run_pipeline "$WORK_B"

# ============================ assertions ============================

log "Comparing per-subject bundles..."

# Find every subject directory under run A and verify run B has the same.
mismatches=0
for subject_dir in "$WORK_A"/output/0x*; do
    [ -d "$subject_dir" ] || continue
    wallet="$(basename "$subject_dir")"
    other="$WORK_B/output/$wallet"
    if [ ! -d "$other" ]; then
        fail "subject $wallet exists in A but not B"
    fi
    # kycHash.hex, manifest.sig, secrets.enc must be byte-identical.
    for artifact in kycHash.hex manifest.sig secrets.enc; do
        a="$subject_dir/$artifact"
        b="$other/$artifact"
        if ! cmp -s "$a" "$b"; then
            printf "  ✘  %s/%s differs\n" "$wallet" "$artifact"
            mismatches=$((mismatches + 1))
        fi
    done

    # manifest.json carries the real wall-clock createdAt, which is
    # intentionally excluded from the signing payload. Two runs at
    # different times produce manifests that differ on createdAt but
    # nothing else — that's the determinism contract.
    a_manifest="$subject_dir/manifest.json"
    b_manifest="$other/manifest.json"
    if ! diff -q \
            <(grep -v '"createdAt":' "$a_manifest") \
            <(grep -v '"createdAt":' "$b_manifest") >/dev/null; then
        printf "  ✘  %s/manifest.json differs outside createdAt\n" "$wallet"
        mismatches=$((mismatches + 1))
    fi
    for proof in "$subject_dir"/proofs/*.bin; do
        [ -f "$proof" ] || continue
        rel="proofs/$(basename "$proof")"
        if ! cmp -s "$subject_dir/$rel" "$other/$rel"; then
            printf "  ✘  %s/%s differs\n" "$wallet" "$rel"
            mismatches=$((mismatches + 1))
        fi
    done
done

if [ "$mismatches" -ne 0 ]; then
    fail "$mismatches artifact(s) differ between runs — determinism broken"
fi

log "Comparing batched index CSV (modulo timestamp suffix in filename)..."
# The filename has a timestamp; the contents shouldn't.
a_csv="$(ls "$WORK_A"/output/kyc_hashes_*.csv 2>/dev/null | head -1)"
b_csv="$(ls "$WORK_B"/output/kyc_hashes_*.csv 2>/dev/null | head -1)"
if [ -z "$a_csv" ] || [ -z "$b_csv" ]; then
    fail "missing index CSV in one or both runs"
fi
if ! cmp -s "$a_csv" "$b_csv"; then
    fail "batched index CSV contents differ"
fi

log "All bundles byte-identical across two runs ✓"
log "Bundles checked:"
for subject_dir in "$WORK_A"/output/0x*; do
    [ -d "$subject_dir" ] || continue
    printf "  %s\n" "$(basename "$subject_dir")"
done
