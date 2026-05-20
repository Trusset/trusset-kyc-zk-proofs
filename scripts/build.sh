#!/usr/bin/env bash
# Trusset KYC hashing — root build driver.
# Builds the Rust workspace (release), the WASM verifier, and the TS CLI.
# Invoked from `npm install` postinstall and `npm run build`.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

log() { printf "\033[1;34m[build]\033[0m %s\n" "$*"; }
err() { printf "\033[1;31m[build]\033[0m %s\n" "$*" >&2; }

# ---- Toolchain checks ------------------------------------------------------

if ! command -v cargo >/dev/null 2>&1; then
    err "cargo not found. Trusset KYC v2 requires Rust >= 1.75 (see README §Quick Start)."
    err "Install: https://rustup.rs"
    exit 1
fi

# ---- Rust workspace (native release) --------------------------------------

log "Building Rust workspace (release)..."
cargo build --release --workspace --locked 2>/dev/null \
    || cargo build --release --workspace

# ---- WASM verifier (optional) ---------------------------------------------

if rustup target list --installed 2>/dev/null | grep -q '^wasm32-unknown-unknown$'; then
    log "Building WASM verifier..."
    # Use cargo rustc --crate-type=cdylib instead of declaring cdylib in
    # verifier/Cargo.toml. Declaring it there triggers a workspace-wide
    # `cargo test --workspace` link failure on macOS x86_64 (cargo issue
    # #6313: rlib+cdylib dual-output collides with the sibling bin).
    cargo rustc --release --target wasm32-unknown-unknown -p trusset-verifier --features wasm --lib --crate-type=cdylib
else
    log "Skipping WASM verifier (wasm32-unknown-unknown target not installed)."
fi

# ---- TypeScript CLI -------------------------------------------------------

log "Installing CLI node_modules (if missing)..."
if [ ! -d "$REPO_ROOT/cli/node_modules" ]; then
    (cd "$REPO_ROOT/cli" && npm install --no-audit --no-fund --silent --ignore-scripts)
fi

log "Building TypeScript CLI..."
(cd "$REPO_ROOT/cli" && "$REPO_ROOT/cli/node_modules/.bin/tsc")

log "Build complete."
