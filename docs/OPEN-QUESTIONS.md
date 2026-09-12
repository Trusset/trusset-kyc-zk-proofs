# Open questions

Design questions found while writing the public documentation for v3.0.0 and deliberately left open. Nothing here is a defect; defects are filed as issues. Each entry names the code that raises the question and what a decision needs to settle.

---

## 1. A `commitment_only` predicate on `country` or `investorType` labels the leaf as hidden while the value travels in cleartext

**Files:** `cli/src/config.ts` (`disclosureFor`), `cli/src/jobSpec.ts` (`buildSubject`).

`disclosureFor` returns `commitment_only` before it checks whether the field is one of the two plaintext-disclosed fields, so a `country` leaf configured as `commitment_only` is recorded with `disclosure: "commitment_only"`. The value is still written to `manifest.passthrough` and to the batch index CSV, because `buildSubject` always copies both fields there. A reader of the manifest is told the value is hidden when it is not.

**Needs a decision on:** whether `plaintext` should win whenever the value is in `passthrough`, or whether the tool should refuse the combination. Related: with `mapping.investorTypeField` omitted there is no `investorType` leaf, but `passthrough.investorType` and the CSV column still carry the configured default. Should absence mean absence?

---

## 2. Which platforms are supported

**Files:** `docs/RELEASE_GATE.md` (environment section), `cli/src/init.ts` (`which`, with a `win32` branch), `README.md` (the key-loading step).

The v3.0.0 gate ran on macOS only, under Rosetta 2. `init` carries a Windows branch for locating `cargo`, but the documented key-loading step (`set -a && . ./.trusset/keys.env && set +a`) is POSIX-only, and nothing has been run on Linux or Windows. The public documentation states "tested on macOS under Rosetta 2; Linux and Windows are untested".

**Needs a decision on:** whether Linux and Windows are targets. If they are, a CI matrix and a Windows key-loading instruction; if not, removing the `win32` branch so the code does not imply support it does not have.

---

## 3. `--now` and `--as-of-date` evaluate the same instant under different labels

**File:** `verifier/src/bin/cli.rs` (`build_as_of`, `now_epoch_days`), `verifier/src/lib.rs` (`resolve_as_of`).

`--as-of-date D` produces `AsOf::Date` and `--now D` overrides the clock under `AsOf::Now`. Both evaluate every validity window and revocation on day `D`; the only difference is the `temporal.as_of` label (`date` versus `now`) in the report. Neither consults the root history, which only `--as-of-block` does.

**Needs a decision on:** whether the two flags are meant to diverge, for example by having `--as-of-date` also resolve the root history by block timestamp (`RootHistory::resolve_at_timestamp` exists and is unused by the CLI), or whether one of them should go.

---

## 4. Whether `output.format: "json"` is a supported surface

**Files:** `cli/src/utils.ts` (`writeIndexFile`), `cli/src/bundleWriter.ts` (`writeBatchedIndex`), `cli/src/types.ts` (`OutputConfig`).

The batch index can be written as JSON (`kyc_hashes_<timestamp>.json`), but the field that suppresses it is called `emitIndexCsv`, the README calls the file "the index CSV" throughout, and nothing downstream is documented as consuming the JSON form.

**Needs a decision on:** keeping JSON as a supported format and naming the switch accordingly, or dropping the format to one shape.

---

## 5. Whether `npm run decrypt` is implemented or removed

**Files:** `package.json` (the `decrypt` script), `cli/src/index.ts` (the `decrypt` command).

The verb has been reserved since v2.0 and exits 70 with a message pointing at `prover/tests/end_to_end.rs`. The self-audit it describes, decrypt `secrets.enc`, re-prove every leaf, recompute the root, compare with `kycHash.hex`, exists only as a Rust test. An operator who finds the script in `package.json` expects it to work.

**Needs a decision on:** implementing the round trip in the CLI, or removing the script and documenting the deterministic re-run as the self-audit path.
