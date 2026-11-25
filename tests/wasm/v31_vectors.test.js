// The shared v3.1 vectors through the WASM build, the way the issuer backend
// loads it. Build first:
//
//   bash scripts/rebuild-wasm.sh            # writes target/wasm-vendor/
//   node --test tests/wasm/
//
// TRUSSET_WASM_DIR points the test at another build (for example the copy
// vendored into the backend).

'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const REPO = path.join(__dirname, '..', '..');
const WASM_DIR = process.env.TRUSSET_WASM_DIR || path.join(REPO, 'target', 'wasm-vendor');
const VECTORS = path.join(REPO, 'test-vectors', 'v3.1');
const LEGACY = path.join(REPO, 'test-vectors', 'legacy');

const wasm = require(path.join(WASM_DIR, 'trusset_verifier.js'));
const vectors = JSON.parse(fs.readFileSync(path.join(VECTORS, 'vectors.json'), 'utf-8'));
const read = (rel) => fs.readFileSync(path.join(VECTORS, rel));
const hex = (s) => Buffer.from(s.replace(/^0x/, ''), 'hex');
const bundleDir = path.join(VECTORS, vectors.bundleDir);
const manifestBytes = fs.readFileSync(path.join(bundleDir, 'manifest.json'));
const manifest = JSON.parse(manifestBytes.toString('utf-8'));

function proofsJson(dir, m) {
  const out = {};
  for (const leaf of m.leaves) out[leaf.proofPath] = Array.from(fs.readFileSync(path.join(dir, leaf.proofPath)));
  return JSON.stringify(out);
}

function runCase(c) {
  return JSON.parse(
    wasm.verify_disclosure(read(c.disclosure), read(c.proof), hex(c.publicKey), c.expectedWallet),
  );
}

test('every positive disclosure verifies', () => {
  for (const c of vectors.positive) {
    const r = runCase(c);
    assert.equal(r.ok, true, `${c.name}: ${r.reason}`);
  }
});

test('every negative disclosure fails the named check', () => {
  assert.ok(vectors.negative.length >= 20);
  for (const c of vectors.negative) {
    const r = runCase(c);
    assert.equal(r.ok, false, `${c.name} verified`);
    assert.equal(r[c.expect.failed], false, `${c.name}: ${r.reason}`);
  }
});

test('header signing bytes and signature', () => {
  const headerJson = fs.readFileSync(path.join(bundleDir, 'header.json'));
  const bytes = Buffer.from(wasm.header_signing_bytes(headerJson));
  assert.equal(bytes.length, 155);
  assert.equal(bytes.toString('hex'), vectors.headerSigningBytes);
  const sig = fs.readFileSync(path.join(bundleDir, 'header.sig'));
  assert.equal('0x' + sig.toString('hex'), vectors.headerSignature);
  assert.equal(wasm.verify_header_signature(headerJson, sig, hex(vectors.operatorPublicKey)), true);
  assert.equal(wasm.verify_header_signature(headerJson, sig, hex(vectors.otherPublicKey)), false);
});

test('Merkle v3 root and every inclusion path', () => {
  const hashes = manifest.leaves.map((l) => l.leafHash);
  assert.equal(wasm.merkle_root_hex_v(JSON.stringify(hashes), 3), vectors.root);
  for (const leaf of vectors.leaves) {
    assert.equal(
      wasm.merkle_root_from_path_hex(leaf.leafHash, JSON.stringify(leaf.path), manifest.leaves.length),
      vectors.root,
    );
  }
});

test('leaf digests recompute', () => {
  for (const leaf of manifest.leaves) {
    assert.equal(wasm.public_digest_hex(leaf.circuitId, JSON.stringify(leaf.publicInputs)), leaf.publicDigest);
    assert.equal(wasm.proof_digest_hex(fs.readFileSync(path.join(bundleDir, leaf.proofPath))), leaf.proofDigest);
    assert.equal(wasm.binding_digest_hex(JSON.stringify(leaf.binding)), leaf.bindingDigest);
    assert.equal(
      wasm.leaf_hash_hex_bound(
        leaf.fieldName,
        leaf.circuitId,
        manifest.walletAddress,
        BigInt(manifest.epochDays),
        leaf.commitment,
        leaf.publicDigest,
        leaf.proofDigest,
        leaf.bindingDigest,
      ),
      leaf.leafHash,
    );
  }
});

test('attestation derived from the manifest', () => {
  assert.deepEqual(JSON.parse(wasm.attestation_from_manifest(manifestBytes)), vectors.attestation);
  const onDisk = JSON.parse(fs.readFileSync(path.join(bundleDir, 'attestation.json'), 'utf-8'));
  assert.deepEqual(onDisk, vectors.attestation);
});

test('whole 3.1.0 bundle verifies with its header, and tampered headers do not', () => {
  const kycHash = fs.readFileSync(path.join(bundleDir, 'kycHash.hex'), 'utf-8');
  const sig = fs.readFileSync(path.join(bundleDir, 'manifest.sig'));
  const proofs = proofsJson(bundleDir, manifest);
  const headerJson = fs.readFileSync(path.join(bundleDir, 'header.json'));
  const headerSig = fs.readFileSync(path.join(bundleDir, 'header.sig'));
  const ok = JSON.parse(
    wasm.verify_with_header(manifestBytes, kycHash, sig, proofs, headerJson, headerSig, hex(vectors.operatorPublicKey), vectors.root, false),
  );
  assert.equal(ok.overall_pass, true);
  assert.equal(ok.header.signature_valid, true);
  assert.equal(ok.header.consistent, true);
  assert.deepEqual(ok.header.attestation, vectors.attestation);

  for (const c of vectors.bundleNegative) {
    const r = JSON.parse(
      wasm.verify_with_header(manifestBytes, kycHash, sig, proofs, read(c.header), hex(c.headerSignature), hex(vectors.operatorPublicKey), '', false),
    );
    assert.equal(r.overall_pass, false, c.name);
    assert.equal(r.header[c.expect.failed], false, c.name);
  }

  const strict = JSON.parse(wasm.verify_strict(manifestBytes, kycHash, sig, proofs, hex(vectors.operatorPublicKey)));
  assert.equal(strict.overall_pass, false, 'a 3.1.0 bundle without its header must not pass');
});

test('bundles from earlier releases still verify in strict mode', { skip: !fs.existsSync(LEGACY) }, () => {
  const index = JSON.parse(fs.readFileSync(path.join(LEGACY, 'legacy.json'), 'utf-8'));
  assert.ok(index.bundles.length >= 2);
  for (const b of index.bundles) {
    const dir = path.join(LEGACY, b.dir);
    const mBytes = fs.readFileSync(path.join(dir, 'manifest.json'));
    const m = JSON.parse(mBytes.toString('utf-8'));
    assert.equal(m.version, b.version);
    const report = JSON.parse(
      wasm.verify_strict(
        mBytes,
        fs.readFileSync(path.join(dir, 'kycHash.hex'), 'utf-8'),
        fs.readFileSync(path.join(dir, 'manifest.sig')),
        proofsJson(dir, m),
        hex(index.operatorPublicKey),
      ),
    );
    assert.equal(report.overall_pass, true, `${b.version}: ${JSON.stringify(report.leaves.filter((l) => !l.pass))}`);
    assert.equal(report.header, null);
    assert.equal(report.kyc_hash, b.root);
  }
});
