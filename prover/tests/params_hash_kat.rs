//! Cross-language params_hash KAT.
//!
//! Reads `tests/kat/params_hash.json`, computes each entry's params_hash
//! using the circuit crates' native `Params::hash()` implementations, and
//! asserts the result matches the `expected` field in the JSON.
//!
//! When `TRUSSET_KAT_REFRESH=1` is set, the test instead rewrites the
//! JSON file with the computed values. Use after intentional changes to
//! a circuit's params layout.
//!
//! The TypeScript CLI has a matching test that reads the same JSON file
//! and verifies its TS `computeParamsHash` produces the same bytes —
//! catching cross-language drift.

use serde_json::Value;
use std::collections::BTreeMap;
use std::path::PathBuf;
use trusset_circuit_age_threshold as age;
use trusset_circuit_preimage_knowledge as preimage;
use trusset_circuit_set_membership as set;
use trusset_circuit_tier_threshold as tier;

fn kat_path() -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop(); // -> workspace root
    p.push("tests");
    p.push("kat");
    p.push("params_hash.json");
    p
}

fn hex_of(bytes: [u8; 32]) -> String {
    let mut s = String::with_capacity(2 + 64);
    s.push_str("0x");
    for b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

fn compute_for_vector(vector: &Value) -> String {
    let circuit = vector
        .get("circuit")
        .and_then(Value::as_str)
        .expect("vector missing circuit");
    // The Rust prover receives already-resolved parameters over the job
    // spec, so it hashes `resolvedParams` when the vector carries one.
    // The TS side hashes `params` and must reach the same value, which is
    // what makes tier names and `minAgeYears` cross-language-covered.
    let params = vector
        .get("resolvedParams")
        .or_else(|| vector.get("params"))
        .expect("vector missing params");

    let hash = match circuit {
        // `commitment_only` leaves reuse the preimage_knowledge parameter
        // shape; the mode changes what is proved, not the params hash.
        "commitment_only" | "preimage_knowledge" => {
            let max = params
                .get("maxValueBytes")
                .and_then(Value::as_u64)
                .expect("preimage_knowledge.maxValueBytes missing") as usize;
            preimage::Params {
                max_value_bytes: max,
            }
            .hash()
        }
        "tier_threshold" => {
            let min_tier = params
                .get("minTier")
                .and_then(Value::as_u64)
                .expect("tier_threshold.minTier missing") as u8;
            tier::Params { min_tier }.hash()
        }
        "age_threshold" => {
            let min_age_days = params
                .get("minAgeDays")
                .and_then(Value::as_u64)
                .expect("age_threshold.minAgeDays missing");
            age::Params { min_age_days }.hash()
        }
        "set_membership" => {
            let list_id = params
                .get("list")
                .and_then(Value::as_str)
                .expect("set_membership.list missing");
            set::Params {
                list_id: list_id.to_string(),
            }
            .hash()
        }
        other => panic!("unknown circuit in KAT: {}", other),
    };
    hex_of(hash)
}

#[test]
fn params_hash_kat_matches_pinned_values() {
    let kat_text =
        std::fs::read_to_string(kat_path()).expect("tests/kat/params_hash.json must exist");
    let mut kat: Value = serde_json::from_str(&kat_text).expect("KAT file is not valid JSON");

    let vectors = kat
        .get("vectors")
        .and_then(Value::as_array)
        .expect("KAT.vectors must be an array")
        .clone();
    let mut computed: BTreeMap<String, String> = BTreeMap::new();
    for v in &vectors {
        let name = v
            .get("name")
            .and_then(Value::as_str)
            .expect("vector missing name")
            .to_string();
        computed.insert(name, compute_for_vector(v));
    }

    let refresh = std::env::var("TRUSSET_KAT_REFRESH").ok().as_deref() == Some("1");

    if refresh {
        // Replace `expected` with the freshly computed values, preserve
        // the rest of the document, and write back.
        let expected_obj = serde_json::to_value(&computed).unwrap();
        kat.as_object_mut()
            .unwrap()
            .insert("expected".to_string(), expected_obj);
        let pretty = serde_json::to_string_pretty(&kat).unwrap();
        std::fs::write(kat_path(), pretty + "\n").unwrap();
        eprintln!(
            "[kat] refreshed {} entries → tests/kat/params_hash.json",
            computed.len()
        );
        return;
    }

    let expected = kat
        .get("expected")
        .and_then(Value::as_object)
        .expect("KAT.expected must be an object");

    let mut mismatches: Vec<String> = Vec::new();
    for (name, got) in &computed {
        let want = expected
            .get(name)
            .and_then(Value::as_str)
            .unwrap_or("<missing>");
        if want != got {
            mismatches.push(format!("  {}: expected {}, got {}", name, want, got));
        }
    }

    if !mismatches.is_empty() {
        panic!(
            "params_hash KAT drift in {} entries — refresh with `TRUSSET_KAT_REFRESH=1 cargo test -p trusset-prover --test params_hash_kat`:\n{}",
            mismatches.len(),
            mismatches.join("\n"),
        );
    }
    assert_eq!(
        computed.len(),
        expected.len(),
        "KAT vectors and expected entries must be 1:1"
    );
}
