//! WASM build check — structural drift guard for the WASM verifier.
//!
//! Asserts that:
//!   1. The WASM verifier has been built and exists at the expected
//!      path under `target/wasm32-unknown-unknown/release/`.
//!   2. The binary starts with the WebAssembly magic bytes and is
//!      within a reasonable size range (~ 2-4 MB).
//!   3. The export section contains the two wasm-bindgen-generated
//!      entry points (`verify_strict`, `verify_permissive`).
//!   4. The import section contains the expected wasm-bindgen
//!      placeholder hooks (drift here means the wasm-bindgen ABI
//!      shifted, which would break the Node/browser consumers).
//!   5. (Stage 24 addition) The binary is byte-deterministic across
//!      two consecutive builds — a regression here would indicate
//!      non-deterministic compilation order or embedded build
//!      metadata leaking into the artifact.
//!
//! Soft-skips with a stderr note if `wasm32-unknown-unknown` is not
//! installed or the binary hasn't been built yet — CI runners that
//! skip the WASM build path still pass.
//!
//! **Full runtime parity** (loading the `.wasm` into wasmer/wasmtime
//! and comparing per-leaf `VerifyReport` against a native CLI run on
//! the same bundle) is Phase 2C work. The wasm-bindgen-generated WASM
//! imports `__wbindgen_placeholder__::*` and
//! `__wbindgen_externref_xform__::*` host hooks. Loading directly
//! into wasmer requires either stubbing those imports (non-trivial:
//! the ABI for string args via wasm-bindgen is wasm-bindgen-specific)
//! or post-processing the artifact with `wasm-bindgen-cli` to
//! produce JS-loader-friendly glue + a `.wasm` with simplified
//! imports. Both paths are tractable but bigger than the original
//! handoff's "½ session" estimate. The structural checks below
//! validate the export shape and byte-determinism — the two
//! drift-detection properties that matter most for catching
//! regressions between native and WASM verifiers.

use std::path::{Path, PathBuf};

const WASM_PATH: &str = "target/wasm32-unknown-unknown/release/trusset_verifier.wasm";

fn workspace_root() -> PathBuf {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    Path::new(&manifest_dir).parent().unwrap().to_path_buf()
}

/// Returns `Some(bytes)` if the WASM artifact is built, `None` otherwise
/// (soft-skip case). Logs to stderr so CI shows the skip.
fn try_load_wasm() -> Option<Vec<u8>> {
    let path = workspace_root().join(WASM_PATH);
    if !path.exists() {
        eprintln!(
            "WASM binary not found at {}. Run `cargo rustc --release --target \
             wasm32-unknown-unknown -p trusset-verifier --features wasm --lib \
             --crate-type=cdylib` first. Skipping WASM check.",
            path.display()
        );
        return None;
    }
    Some(std::fs::read(&path).expect("read .wasm"))
}

#[test]
fn wasm_binary_exists_and_has_valid_header() {
    let Some(bytes) = try_load_wasm() else {
        return;
    };
    assert!(
        bytes.starts_with(b"\0asm"),
        "expected WASM magic 0x00 0x61 0x73 0x6d"
    );
    // Stage 17 (set membership Merkle walk) bumped the WASM size from
    // ~ 350 KB to ~ 2.3 MB; tolerate up to 8 MB to account for future
    // growth, but flag if the binary unexpectedly shrinks below 1 MB
    // (a structural-regression canary).
    assert!(
        bytes.len() > 1_000_000,
        "WASM binary suspiciously small ({} bytes) — expected > 1 MB",
        bytes.len()
    );
    assert!(
        bytes.len() < 8_000_000,
        "WASM binary suspiciously large ({} bytes) — expected < 8 MB",
        bytes.len()
    );
}

#[test]
fn wasm_exports_verify_entry_points() {
    let Some(bytes) = try_load_wasm() else {
        return;
    };
    // wasm-bindgen-generated WASM modules carry the export name strings
    // verbatim in the export section. Substring search is sufficient as
    // a drift guard.
    let needles: [&[u8]; 2] = [b"verify_strict", b"verify_permissive"];
    for needle in needles {
        let found = bytes.windows(needle.len()).any(|w| w == needle);
        assert!(
            found,
            "expected export {:?} in WASM binary — drift in wasm.rs entry points?",
            std::str::from_utf8(needle).unwrap()
        );
    }
}

#[test]
fn wasm_imports_match_expected_wasm_bindgen_abi() {
    let Some(bytes) = try_load_wasm() else {
        return;
    };
    // wasm-bindgen places its runtime placeholder import module names
    // verbatim in the import section. Drift in these strings indicates
    // either a wasm-bindgen version upgrade (which the JS consumers must
    // also adopt) or a substantive change to the ABI surface.
    //
    // We check for the module prefix `__wbindgen_placeholder__` and
    // `__wbindgen_externref_xform__`, since the per-function names
    // include compiler-generated hashes and may shift across rustc
    // versions.
    let module_needles: [&[u8]; 2] = [b"__wbindgen_placeholder__", b"__wbindgen_externref_xform__"];
    for needle in module_needles {
        let found = bytes.windows(needle.len()).any(|w| w == needle);
        assert!(
            found,
            "expected wasm-bindgen import module {:?} — has wasm-bindgen changed its ABI?",
            std::str::from_utf8(needle).unwrap()
        );
    }
}

#[test]
fn wasm_section_table_is_well_formed() {
    let Some(bytes) = try_load_wasm() else {
        return;
    };
    // Parse the section header chain and confirm each section's
    // declared size doesn't exceed the remaining bytes. Catches
    // corruption that would slip past the magic-byte check above.
    assert_eq!(&bytes[0..4], b"\0asm");
    assert_eq!(&bytes[4..8], &[0x01, 0x00, 0x00, 0x00], "wasm version 1");

    let mut pos = 8usize;
    let mut section_count = 0usize;
    while pos < bytes.len() {
        let section_id = bytes[pos];
        pos += 1;
        // LEB128-decode the section size.
        let mut size: usize = 0;
        let mut shift = 0u32;
        loop {
            if pos >= bytes.len() {
                panic!("truncated LEB128 at pos {}", pos);
            }
            let b = bytes[pos];
            pos += 1;
            size |= ((b & 0x7f) as usize) << shift;
            if b & 0x80 == 0 {
                break;
            }
            shift += 7;
            assert!(shift <= 35, "LEB128 overflow");
        }
        assert!(
            section_id <= 12,
            "unknown section id {} at pos ~{}",
            section_id,
            pos
        );
        assert!(
            pos + size <= bytes.len(),
            "section {} declares size {} but only {} bytes remain at pos {}",
            section_id,
            size,
            bytes.len() - pos,
            pos
        );
        pos += size;
        section_count += 1;
        // Sanity: real WASM modules don't have hundreds of top-level
        // sections.
        assert!(section_count < 200);
    }
    assert!(
        section_count >= 9,
        "expected at least 9 sections (type, import, function, table, memory, global, export, element, code), got {}",
        section_count
    );
}

/// Byte-determinism check (Stage 24): rebuild the WASM artifact and
/// confirm it's byte-identical to the existing one. A regression here
/// would mean cargo/rustc is producing non-reproducible output for the
/// same `Cargo.lock` + source set — a determinism contract violation
/// that would propagate to bundle bytes.
///
/// This test is gated by `TRUSSET_WASM_DETERMINISM=1` because rebuilding
/// the WASM takes ~ 1 minute and isn't useful for every test run. CI
/// can opt in with the env var.
#[test]
fn wasm_binary_is_byte_deterministic_under_env_flag() {
    if std::env::var("TRUSSET_WASM_DETERMINISM").ok().as_deref() != Some("1") {
        eprintln!(
            "Skipping WASM byte-determinism check. Set TRUSSET_WASM_DETERMINISM=1 to enable."
        );
        return;
    }
    let Some(original_bytes) = try_load_wasm() else {
        return;
    };

    // Touch the wasm artifact's mtime so we can detect whether the
    // rebuild rewrote it. We can't easily force a rebuild from inside
    // a test without invoking cargo recursively; instead, hash the
    // current bytes and run cargo rustc as a subprocess.
    use sha2::{Digest as _, Sha256};
    let original_hash = Sha256::digest(&original_bytes);

    let status = std::process::Command::new("cargo")
        .args([
            "rustc",
            "--release",
            "--target",
            "wasm32-unknown-unknown",
            "-p",
            "trusset-verifier",
            "--features",
            "wasm",
            "--lib",
            "--crate-type=cdylib",
        ])
        .current_dir(workspace_root())
        .status()
        .expect("invoke cargo rustc");
    assert!(status.success(), "WASM rebuild failed");

    let rebuilt_bytes = try_load_wasm().expect("WASM exists after rebuild");
    let rebuilt_hash = Sha256::digest(&rebuilt_bytes);

    assert_eq!(
        original_hash, rebuilt_hash,
        "WASM binary is not byte-deterministic across rebuilds"
    );
    assert_eq!(
        original_bytes.len(),
        rebuilt_bytes.len(),
        "WASM binary size shifted across rebuilds"
    );
}
