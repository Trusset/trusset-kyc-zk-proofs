//! Tamper and fuzz matrix over the v3.1 formats: disclosures, headers,
//! inclusion paths, proofs, and whole manifests.
//!
//! Deterministic (a fixed xorshift seed), offline, and with no extra crates.
//! Every mutation must either be refused or leave a document that means the
//! same thing as the original; nothing may panic. `TRUSSET_FUZZ_ITERS` scales
//! the random rounds (default 400 per target).

mod common_v31;

use common_v31::*;
use serde_json::Value;
use std::collections::BTreeMap;
use std::path::PathBuf;
use trusset_bundle_format::disclosure::Disclosure;
use trusset_bundle_format::header::DisclosureHeader;
use trusset_bundle_format::manifest::{canonical_signing_bytes, Manifest};
use trusset_circuits_common::{digest_to_hex, hash_bytes_with_tag, LEAF_TAG};
use trusset_verifier::v31::verify_disclosure;
use trusset_verifier::{bundle, verify_loaded, AsOf, VerifyAnchors, VerifyOptions};

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n.max(1) as u64) as usize
    }
}

fn iters() -> usize {
    std::env::var("TRUSSET_FUZZ_ITERS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(400)
}

fn bundle_dir() -> PathBuf {
    vectors_dir().join("bundle").join(WALLET)
}

fn pk() -> [u8; 32] {
    signing().public_key()
}

fn leaves() -> Vec<String> {
    vec![
        "dateOfBirth".into(),
        "country".into(),
        "investorType".into(),
        "firstName".into(),
    ]
}

fn load(leaf: &str) -> (Vec<u8>, Vec<u8>) {
    let dir = bundle_dir();
    (
        std::fs::read(dir.join(format!("disclosures/{}.json", leaf))).unwrap(),
        std::fs::read(dir.join(format!("proofs/{}.bin", leaf))).unwrap(),
    )
}

/// The meaning of a disclosure: its parsed form with address case folded,
/// since addresses are compared as bytes.
fn meaning(bytes: &[u8]) -> Option<Value> {
    let d = Disclosure::parse(bytes).ok()?;
    let mut v = serde_json::to_value(d).ok()?;
    for k in ["wallet", "attester", "hub"] {
        let s = v["header"][k].as_str()?.to_ascii_lowercase();
        v["header"][k] = Value::String(s);
    }
    Some(v)
}

fn byte_mutation(rng: &mut Rng, input: &[u8]) -> Vec<u8> {
    let mut out = input.to_vec();
    match rng.below(4) {
        0 => {
            let i = rng.below(out.len());
            out[i] = (rng.next() & 0xff) as u8;
        }
        1 => {
            let i = rng.below(out.len());
            out.remove(i);
        }
        2 => {
            let i = rng.below(out.len() + 1);
            out.insert(i, b"{}[]\",:0aAx \n"[rng.below(13)]);
        }
        _ => {
            let n = rng.below(out.len());
            out.truncate(n);
        }
    }
    out
}

/// Walk to a random node of a JSON tree and change, drop, or add something.
fn structured_mutation(rng: &mut Rng, v: &mut Value) {
    match v {
        Value::Object(map) if !map.is_empty() => {
            let keys: Vec<String> = map.keys().cloned().collect();
            let k = keys[rng.below(keys.len())].clone();
            match rng.below(16) {
                0 | 1 => {
                    map.remove(&k);
                }
                2 => {
                    map.insert("injected".into(), Value::Bool(true));
                }
                _ => structured_mutation(rng, map.get_mut(&k).expect("key exists")),
            }
        }
        Value::Array(arr) if !arr.is_empty() => match rng.below(12) {
            0 | 1 => {
                let i = rng.below(arr.len());
                arr.remove(i);
            }
            2 => {
                let i = rng.below(arr.len());
                let dup = arr[i].clone();
                arr.push(dup);
            }
            _ => {
                let i = rng.below(arr.len());
                structured_mutation(rng, &mut arr[i]);
            }
        },
        Value::String(s) => {
            if s.is_empty() {
                s.push('x');
            } else {
                let mut chars: Vec<char> = s.chars().collect();
                let i = rng.below(chars.len());
                let pool = ['0', '1', 'a', 'f', 'g', 'A', 'Z', 'x', '-', ' '];
                chars[i] = pool[rng.below(pool.len())];
                *s = chars.into_iter().collect();
            }
        }
        Value::Number(n) => {
            let base = n.as_u64().unwrap_or(0);
            let choices = [base.wrapping_add(1), base.wrapping_sub(1), 0, u64::MAX];
            *v = Value::from(choices[rng.below(choices.len())]);
        }
        Value::Bool(b) => *b = !*b,
        Value::Null => *v = Value::from(1),
        _ => *v = Value::Null,
    }
}

#[test]
fn disclosure_byte_and_structure_mutations_never_verify_a_changed_meaning() {
    let mut rng = Rng(0x7357_31A0_C0DE_F00D);
    let mut accepted_equivalent = 0usize;
    let mut refused = 0usize;
    for leaf in leaves() {
        let (doc, proof) = load(&leaf);
        let original = meaning(&doc).expect("vector parses");
        assert!(verify_disclosure(&doc, &proof, &pk(), Some(WALLET)).ok);
        for round in 0..iters() {
            let mutated = if round % 2 == 0 {
                byte_mutation(&mut rng, &doc)
            } else {
                let mut v: Value = serde_json::from_slice(&doc).unwrap();
                structured_mutation(&mut rng, &mut v);
                serde_json::to_vec(&v).unwrap()
            };
            let r = verify_disclosure(&mutated, &proof, &pk(), Some(WALLET));
            if r.ok {
                assert_eq!(
                    meaning(&mutated).as_ref(),
                    Some(&original),
                    "{}: a mutation that changes the disclosure verified:\n{}",
                    leaf,
                    String::from_utf8_lossy(&mutated)
                );
                accepted_equivalent += 1;
            } else {
                refused += 1;
            }
        }
    }
    assert!(
        refused > accepted_equivalent,
        "the matrix barely mutated anything"
    );
}

#[test]
fn proof_bytes_mutations_are_refused() {
    let mut rng = Rng(0x0BAD_5EED_1234_5678);
    for leaf in ["dateOfBirth", "country", "investorType"] {
        let (doc, proof) = load(leaf);
        for _ in 0..iters() / 4 {
            let mutated = byte_mutation(&mut rng, &proof);
            if mutated == proof {
                continue;
            }
            let r = verify_disclosure(&doc, &mutated, &pk(), None);
            assert!(!r.ok, "{}: a changed proof verified", leaf);
            assert!(!r.leaf_valid);
        }
    }
}

#[test]
fn every_sibling_of_every_path_is_load_bearing() {
    let other = digest_to_hex(&hash_bytes_with_tag(&LEAF_TAG, b"sibling"));
    for leaf in leaves() {
        let (doc, proof) = load(&leaf);
        let v: Value = serde_json::from_slice(&doc).unwrap();
        let depth = v["path"].as_array().unwrap().len();
        for i in 0..depth {
            let mut m = v.clone();
            m["path"][i] = Value::String(other.clone());
            let r = verify_disclosure(&serde_json::to_vec(&m).unwrap(), &proof, &pk(), None);
            assert!(!r.ok && !r.inclusion_valid, "{} sibling {}", leaf, i);
        }
        for i in 0..depth {
            for j in (i + 1)..depth {
                let mut m = v.clone();
                let a = m["path"][i].clone();
                let b = m["path"][j].clone();
                if a == b {
                    continue;
                }
                m["path"][i] = b;
                m["path"][j] = a;
                let r = verify_disclosure(&serde_json::to_vec(&m).unwrap(), &proof, &pk(), None);
                assert!(!r.ok, "{} swapped siblings {} and {}", leaf, i, j);
            }
        }
    }
}

#[test]
fn header_mutations_change_the_signed_bytes_or_are_refused() {
    let mut rng = Rng(0x4EAD_E2F0_0D00_0001);
    let bytes = std::fs::read(bundle_dir().join("header.json")).unwrap();
    let original: DisclosureHeader = serde_json::from_slice(&bytes).unwrap();
    let original_signing = original.signing_bytes().unwrap();
    let sig_bytes = std::fs::read(bundle_dir().join("header.sig")).unwrap();
    let mut sig = [0u8; 64];
    sig.copy_from_slice(&sig_bytes);
    for _ in 0..iters() * 2 {
        let mutated = byte_mutation(&mut rng, &bytes);
        let Ok(h) = serde_json::from_slice::<DisclosureHeader>(&mutated) else {
            continue;
        };
        let Ok(signing_bytes) = h.signing_bytes() else {
            continue;
        };
        if trusset_bundle_format::sign::verify_strict(&pk(), &signing_bytes, &sig) {
            assert_eq!(signing_bytes, original_signing);
        } else {
            assert_ne!(signing_bytes, original_signing);
        }
    }
}

#[test]
fn manifest_mutations_never_pass_whole_bundle_verification() {
    let mut rng = Rng(0x3A11_FE57_0000_0031);
    let dir = bundle_dir();
    let manifest_bytes = std::fs::read(dir.join("manifest.json")).unwrap();
    let original: Manifest = serde_json::from_slice(&manifest_bytes).unwrap();
    let original_signing = canonical_signing_bytes(&original).unwrap();
    let kyc_hash = std::fs::read_to_string(dir.join("kycHash.hex")).unwrap();
    let sig = std::fs::read(dir.join("manifest.sig")).unwrap();
    let header = std::fs::read(dir.join("header.json")).unwrap();
    let header_sig = std::fs::read(dir.join("header.sig")).unwrap();
    let mut proofs = BTreeMap::new();
    for l in &original.leaves {
        proofs.insert(
            l.proof_path.clone(),
            std::fs::read(dir.join(&l.proof_path)).unwrap(),
        );
    }
    let opts = |root: Option<String>| VerifyOptions {
        anchors: VerifyAnchors {
            expected_public_key: if root.is_some() { None } else { Some(pk()) },
            expected_root: root,
        },
        accept_stub: false,
        as_of: AsOf::Date { epoch_days: EPOCH },
        context: Default::default(),
        now_epoch_days: EPOCH,
    };
    let rounds = (iters() / 4).max(40);
    for round in 0..rounds {
        let mutated = if round % 3 == 0 {
            byte_mutation(&mut rng, &manifest_bytes)
        } else {
            let mut v: Value = serde_json::from_slice(&manifest_bytes).unwrap();
            structured_mutation(&mut rng, &mut v);
            serde_json::to_vec(&v).unwrap()
        };
        let Ok(loaded) = bundle::loaded_from_parts_with_header(
            &mutated,
            &kyc_hash,
            Some(sig.clone()),
            proofs.clone(),
            Some(header.clone()),
            Some(header_sig.clone()),
        ) else {
            continue;
        };
        let same = canonical_signing_bytes(&loaded.manifest)
            .map(|b| b == original_signing)
            .unwrap_or(false);
        let by_key = verify_loaded(&loaded, &opts(None));
        let by_root = verify_loaded(&loaded, &opts(Some(original.kyc_hash.clone())));
        if !same {
            assert!(
                !by_key.overall_pass,
                "a changed manifest passed under the operator key:\n{}",
                String::from_utf8_lossy(&mutated)
            );
        }
        if by_root.overall_pass && !same {
            // Under a root anchor alone the manifest signature is not checked,
            // so a change outside every leaf hash can pass: the chain block
            // and the expiry days are covered by the signatures only. What the
            // root authenticates (the leaves, so the class and the predicate
            // bits) must not move.
            let a = by_root
                .header
                .as_ref()
                .and_then(|h| h.attestation.clone())
                .expect("a passing 3.1.0 report carries the attestation");
            let b = trusset_bundle_format::attestation::AttestationFile::from_manifest(&original)
                .unwrap();
            assert_eq!(
                (a.root, a.subject, a.investor_class, a.predicates),
                (b.root, b.subject, b.investor_class, b.predicates),
                "a root-anchored manifest change altered what the leaves prove"
            );
            for (x, y) in loaded.manifest.leaves.iter().zip(original.leaves.iter()) {
                assert_eq!(x.leaf_hash, y.leaf_hash);
                assert_eq!(x.public_inputs, y.public_inputs);
                assert_eq!(x.binding, y.binding);
                assert_eq!(x.field_name, y.field_name);
            }
        }
    }
}
