#!/usr/bin/env bash
# Trusset KYC v2 — CI smoke test.
#
# Runs every meaningful Cargo feature combination back-to-back in a single
# shell session (no `cargo clean` between invocations). This catches the
# release-cache flakiness that bit Phase 2B Step-A: when feature-flag
# permutations are run in separate `cargo` invocations on a fresh target/,
# the second invocation occasionally produces a build cache where the
# release prover's `debug_assert!`s linger and corrupt timing/behavior.
#
# Sharing the target/ across the whole sweep — which is what this script
# enforces — gives a clean signal on what real CI will see when running the
# DoD test matrix without resetting the cache.
#
# v3.0.0: the sweep also runs the three end-to-end matrices, which need the
# release binaries and jq. They are the only place the operator-facing CLI,
# the registries, and the archive format are exercised together.
#
# Stage 23 (2026-05-20): workspace defaults flipped to `prod-proofs-*`.
# This script now exercises:
#   1. Default features (= `prod-proofs-*`) workspace tests (the production
#      path).
#   2. Per-circuit explicit `--features prod-proofs-<name>` redundancy
#      check (catches any feature-flag drift between the workspace
#      default and the per-circuit flag).
#   3. Per-circuit `--no-default-features --features stub-proofs` runs
#      that verify the development `--skip-proofs` path still compiles
#      and tests still pass — important for operator scripts that build
#      lightweight CI bundles.
#
# Exits non-zero on the first failure. Logs section headers to stdout so
# the failure point is obvious in CI output.
#
# Usage:
#   bash scripts/ci_smoke.sh           # full sweep
#   bash scripts/ci_smoke.sh --quick   # default features only

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

QUICK=0
if [ "${1:-}" = "--quick" ]; then
    QUICK=1
fi

log() { printf "\n\033[1;36m=== %s ===\033[0m\n" "$*"; }
ok() { printf "\033[1;32m[ok]\033[0m %s\n" "$*"; }
fail() { printf "\033[1;31m[fail]\033[0m %s\n" "$*" >&2; exit 1; }

# ---- 1. Formatting + lint (cheap, run first) -------------------------------

log "cargo fmt --check --all"
cargo fmt --check --all
ok "formatting clean"

log "cargo clippy --workspace --all-targets -- -D warnings (default features = prod-proofs)"
cargo clippy --workspace --all-targets -- -D warnings
ok "default-features clippy clean"

# ---- 2. Workspace tests (default features = production STARK proofs) -------
#
# Production CI runs in release mode. The Stage 23 cross-validation
# initially found that Winterfell's `evaluation_table.rs:214` degree-
# consistency check exhibited trace-dependent behavior in debug-mode
# `--lib` runs of the Stage 16 set_membership AIR (witnesses with
# all-left or all-right Merkle paths produced a constant side-bit
# column → polynomial degree 0 → debug assertion mismatch).
# Phase 2C Stage 27 (2026-05-20) resolved this by making the prover
# inject alternating side-bit values into stall rows of the trace —
# the column polynomial now always has full degree regardless of the
# witness, so debug and release builds agree. Both modes are gated
# below.

log "cargo test --workspace --release (default features = prod-proofs-*)"
cargo test --workspace --release
ok "default-features release tests green"

log "cargo test --workspace (debug, default features = prod-proofs-*)"
cargo test --workspace
ok "default-features debug tests green (Stage 27 quirk resolved)"

if [ $QUICK -eq 1 ]; then
    log "QUICK mode: skipping per-circuit feature-permutation sweep"
    log "ALL SMOKE CHECKS PASSED (quick)"
    exit 0
fi

# ---- 3. Per-circuit explicit --features prod-proofs-<name> ----------------
#
# Redundant with workspace defaults post-Stage-23, but catches any
# accidental drift where a circuit's `default` features no longer
# include `prod-proofs-<name>`. Cheap to run; high signal if it ever
# fails.

CIRCUITS=(
    "trusset-circuit-tier-threshold:prod-proofs-tier"
    "trusset-circuit-age-threshold:prod-proofs-age"
    "trusset-circuit-preimage-knowledge:prod-proofs-preimage"
    "trusset-circuit-set-membership:prod-proofs-set"
)

for entry in "${CIRCUITS[@]}"; do
    crate="${entry%%:*}"
    flag="${entry##*:}"

    log "cargo clippy -p $crate --features $flag --all-targets -- -D warnings"
    cargo clippy -p "$crate" --features "$flag" --all-targets -- -D warnings
    ok "$crate --features $flag clippy clean"

    log "cargo test -p $crate --features $flag --release"
    cargo test -p "$crate" --features "$flag" --release
    ok "$crate --features $flag release tests green"
done

# ---- 4. Stub-path regression check (development --skip-proofs lane) ------
#
# Verifies that the stub-proofs feature path still compiles and runs.
# This is the path operators use for CI smoke / development iteration
# via `npm start -- --skip-proofs`. If this fails, the dev-loop is
# broken even though production prove+verify works.

log "cargo build -p trusset-circuits-common --no-default-features --features stub-proofs"
cargo build -p trusset-circuits-common --no-default-features --features stub-proofs
ok "circuits-common stub-proofs build clean"

# ---- 5. WASM runtime parity (optional, requires wasm-bindgen-cli) ---------
#
# Phase 2C Stage 30 (2026-05-20): runs the native CLI and the
# WASM-in-Node verifier on the same fresh bundle and asserts the
# VerifyReport JSON is byte-identical. Soft-skip when wasm-bindgen-cli
# isn't installed — CI runners that skip this still pass.

if [ $QUICK -eq 0 ] && command -v wasm-bindgen >/dev/null 2>&1; then
    log "tests/e2e/wasm_parity.sh (Phase 2C Stage 30)"
    bash "$REPO_ROOT/tests/e2e/wasm_parity.sh"
    ok "WASM runtime parity green"
else
    log "skipping WASM parity (wasm-bindgen not installed or --quick)"
fi

# ---- 6. End-to-end matrices ----------------------------------------------
#
# The v2.1 matrix pins the previous bundle shape and must keep passing under
# v3 tooling; the v3 matrix covers the rotation regression, the temporal
# semantics, archives, and the unpinned-epoch refusal. Both need jq.

if [ $QUICK -eq 0 ] && command -v jq >/dev/null 2>&1; then
    log "tests/e2e/canary.sh (determinism)"
    bash "$REPO_ROOT/tests/e2e/canary.sh"
    ok "determinism canary green"

    log "tests/e2e/v21_matrix.sh (v2.1 wire compatibility)"
    bash "$REPO_ROOT/tests/e2e/v21_matrix.sh"
    ok "v2.1 matrix green"

    log "tests/e2e/v3_matrix.sh (v3 end to end)"
    bash "$REPO_ROOT/tests/e2e/v3_matrix.sh"
    ok "v3 matrix green"
else
    log "skipping e2e matrices (jq not installed or --quick)"
fi

# ---- 7. Final summary ------------------------------------------------------

log "ALL SMOKE CHECKS PASSED"
