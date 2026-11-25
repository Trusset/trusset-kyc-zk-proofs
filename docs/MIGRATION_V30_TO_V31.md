# Migrating from 3.0 to 3.1

3.1.0 binds every bundle to one IdentityHub attestation, removes clear-text
personal values from bundles, lets a holder disclose one leaf at a time, and
moves the operator key out of environment variables.

## What keeps working

- **Existing bundles.** 2.0.0, 2.1.0 and 3.0.0 bundles verify unchanged under
  the 3.1 verifier, strict mode included. `test-vectors/legacy/` holds a 2.1.0
  and a 3.0.0 bundle proved by the 3.0.0 release; the native and WASM test
  suites verify them on every run.
- **Existing configs.** A config with no `manifest.version`, or with `3.0.0`,
  keeps producing 3.0.0 bundles with `npm start`. Nothing changes until you set
  `manifest.version` to `3.1.0`.
- **Every pre-3.1 WASM export**, with the same signature.

## What a 3.1.0 bundle adds

| File | Content |
|---|---|
| `header.json`, `header.sig` | The signed header: version, root, wallet, epochDays, attester, chainId, hub, keyId, merkleVersion, leafCount |
| `disclosures/<leaf>.json` | One leaf, its inclusion path, and the signed header |
| `attestation.json` | What the hub `attest` call needs: subject, root, investorClass, predicates, expiries, attester, chainId, hub, keyId |

The manifest gains a `chain` block, `merkleVersion: 3`, and
`binding.predicate` on proving leaves. `passthrough` holds only
`softExpiryDays` and `hardExpiryDays`. The index CSV drops the `country`
column.

## Steps

1. **Rebuild.** `npm run build`. Re-vendor the WASM verifier into the backend
   with `scripts/rebuild-wasm.sh` (new exports below).
2. **Move the keys into an encrypted store.**

   ```bash
   npm run key -- encrypt --from .trusset/keys.env      # asks for a passphrase
   ```

   Add the printed `keyStore` line to `config.json` under `security`, check it
   with `npm run key -- show --verify`, then delete `.trusset/keys.env`. The
   public key does not change. On macOS, `--keychain` stores the keys in the
   keychain instead. `TRUSSET_KYC_SIGNING_KEY` / `TRUSSET_KYC_MASTER_KEY`
   remain for CI only.
3. **Publish the operator key on the hub.** `npm run key -- show` prints the
   `setAttesterProfile(operatorKey, leiHash, metadataURI)` calldata. Send it
   from the attester wallet (the tool never sends anything). The hub assigns
   `keyId` 1 to an attester's first key and increments it on every change.
4. **Record the EEA list.**

   ```bash
   npm run list-version -- --list-id eea --source config/list_commitments/eea.source.txt
   ```

5. **Edit `config.json`.** Compare with `config.example.v3.1.json`:
   - `"manifest": { "version": "3.1.0", ... }`
   - `"chain": { "chainId": ..., "hub": "0x...", "attester": "0x...", "keyId": 1 }`
   - `investorType`: `{ "circuit": "tier_threshold", "params": { "minTier": "ATTESTED" }, "predicate": "INVESTOR_CLASS", ... }`
   - `country`: an `eea` leaf with `"predicate": "EEA_RESIDENT", "optional": true`, and, if you keep it, the allowlist leaf with `"predicate": "RESIDENCY_ON_FILE"`
   - `dateOfBirth`: `"predicate": "ADULT"`; `nationality`: `"predicate": "CITIZENSHIP_ON_FILE"`
6. **Issue.** `npm run issue -- --dry-run`, then `npm run issue`. Upload each
   `output/<wallet>/attestation.json` to the issuer app.

## For the issuer backend

- Accept manifest version `3.1.0` and circuitsVersion `3`. There is no
  circuitsVersion 4: Winterfell 0.13 has no zero-knowledge mode (see
  docs/SECURITY.md, "What a proof reveals").
- Pin the new list and parameters:
  - `approvedLists.eea`: root `0x2bc4dc54a457373e521626cf69795ff45ccc9a1a25cfc9e21afa1494e601df20`, depth 5, sourceSha256 `0x765c3d1ff5339e523290ba110051c3e7bdbf82708d280fc20c22b7a6fdae3fdc`, contentHash `0xdeac9fad7ef186a4075c42c60775295a9041fe836b68f2f0ad201d41e216a8aa`
  - `paramsHashByCircuit.set_membership` adds `0xd1a00261a15d110c67ca5a36ae068c42b027dc55133b6344363eecda15289432` (list `eea`)
  - `country_allowlist` (root `0x90785a7ea7ea20e096c8b18955971db0a3387dc522b42982d49041c65e3dc3a9`) and the age and tier hashes are unchanged.
- Build the attest calldata from `attestation_from_manifest(manifest)` on a
  verified bundle rather than from the uploaded `attestation.json`.
- Take the operator key from `operatorKeyAt(attester, header.keyId)` on the
  hub, not from `Instance.proofOperatorKey`.
- New WASM exports: `verify_disclosure`, `verify_with_header`,
  `header_signing_bytes`, `verify_header_signature`,
  `merkle_root_from_path_hex`, `attestation_from_manifest`.
  `merkle_root_hex_v(leafHashes, 3)` computes a v3 root.
- `test-vectors/` is the shared fixture set. Copy it and run the same cases.
