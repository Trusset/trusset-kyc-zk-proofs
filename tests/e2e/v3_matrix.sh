#!/usr/bin/env bash
# Trusset KYC hashing - v3.0.0 end-to-end matrix.
#
# Everything this release exists to do, exercised through the operator-facing
# CLI rather than the library API, in one clean working directory:
#
#   1.  init from nothing: keys, config, list registry, environment report
#   2.  dry run: every problem in one pass, before anything is written
#   3.  a batch covering every circuit, both leaf modes, and two predicate
#       instances on one field, with deliberate failures at both stages
#   4.  verification against the operator key and against the published root
#   5.  ROTATION REGRESSION: rotate the allowlist, re-verify the bundles
#       proved before it. They must still verify and still resolve to the
#       version they used
#   6.  validity windows: past a soft expiry, past a hard expiry
#   7.  as-of a past block: entitlement then must hold even though every
#       window has since closed
#   8.  lapse and voidance, and the difference between them
#   9.  archive: verify from one file on a clean directory with no access to
#       the output tree, the registry, or the config
#   10. determinism: two runs, byte-identical
#   11. the unpinned-epoch refusal
#
# Run from the repo root. Requires jq.

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
WORK_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/trusset-v3-matrix-XXXXXX")"
CLI="$REPO_ROOT/cli/dist/index.js"

PASS_COUNT=0
FAIL_COUNT=0

log()  { printf "\n\033[1;34m[v3]\033[0m %s\n" "$*"; }
ok()   { PASS_COUNT=$((PASS_COUNT + 1)); printf "  \033[1;32mok\033[0m   %s\n" "$*"; }
bad()  { FAIL_COUNT=$((FAIL_COUNT + 1)); printf "  \033[1;31mFAIL\033[0m %s\n" "$*"; }

assert_eq() {
    if [ "$1" = "$2" ]; then ok "$3"; else bad "$3 (expected '$2', got '$1')"; fi
}

# Substring checks use bash pattern matching rather than a pipe into `grep -q`.
# Under `set -o pipefail`, `grep -q` closes the pipe as soon as it matches, the
# writing `printf` dies of SIGPIPE with status 141, and the pipeline reports
# failure even though the match succeeded. Whether that happens depends on
# whether the writer finished before grep exited, so the bug shows up as a
# flaky assertion on long outputs and never on short ones.
contains() {
    case "$1" in
        *"$2"*) return 0 ;;
        *) return 1 ;;
    esac
}

assert_contains() {
    if contains "$1" "$2"; then ok "$3"; else bad "$3 (missing '$2')"; fi
}

assert_not_contains() {
    if contains "$1" "$2"; then bad "$3 (found '$2')"; else ok "$3"; fi
}

count_occurrences() {
    printf '%s\n' "$1" > "$WORK_ROOT/.count.txt"
    grep -c -- "$2" "$WORK_ROOT/.count.txt" || true
}

if ! command -v jq >/dev/null 2>&1; then
    echo "v3_matrix requires jq" >&2
    exit 1
fi

for bin in trusset-prover trusset-verifier-cli trusset-registry trusset-archive; do
    if [ ! -x "$REPO_ROOT/target/release/$bin" ]; then
        echo "missing $bin — run: cargo build --release --workspace" >&2
        exit 1
    fi
done
if [ ! -f "$CLI" ]; then
    echo "missing cli/dist/index.js — run: npm run build" >&2
    exit 1
fi

D="$WORK_ROOT/bank"
mkdir -p "$D/input" "$D/output" "$D/target/release" "$D/config/list_commitments"
cp "$REPO_ROOT/config/list_commitments/country_allowlist.source.txt" "$D/config/list_commitments/"
for bin in trusset-prover trusset-verifier-cli trusset-registry trusset-archive; do
    ln -sf "$REPO_ROOT/target/release/$bin" "$D/target/release/$bin"
done

run() { (cd "$D" && node "$CLI" "$@" >"$D/out.txt" 2>&1); echo $?; }
out() { cat "$D/out.txt"; }

# =====================================================================
log "1. init from nothing"
# =====================================================================
EXIT=$(run init --non-interactive \
    --issuer-name "Nordbank AG" --issuer-scheme LEI \
    --issuer-identifier 529900T8BM49AURSDO55 --issuer-jurisdiction DE \
    --key-id issuing-2026-08)
assert_eq "$EXIT" "0" "init succeeds on an empty working directory"
INIT_OUT="$(out)"
assert_contains "$INIT_OUT" "list registry version 1" "init records list version 1"
[ -f "$D/config.json" ] && ok "init wrote config.json" || bad "init wrote config.json"
[ -f "$D/.trusset/keys.env" ] && ok "init wrote a key file" || bad "init wrote a key file"
assert_eq "$(stat -f '%Lp' "$D/.trusset/keys.env" 2>/dev/null || stat -c '%a' "$D/.trusset/keys.env")" \
    "600" "the key file is mode 0600"

set -a; . "$D/.trusset/keys.env"; set +a
PK=$(node -e "console.log(require('$REPO_ROOT/cli/dist/keys').publicKeyHexFromSigningKey(process.env.TRUSSET_KYC_SIGNING_KEY))")
assert_contains "$INIT_OUT" "$PK" "init prints the operator public key"

EPOCH=$(jq -r '.security.epochDaysSource' "$D/config.json" | sed 's/fixed://')
assert_contains "$(jq -r '.security.epochDaysSource' "$D/config.json")" "fixed:" \
    "init pins the batch as-of date rather than leaving it on the clock"

# Give the batch a shape that exercises every circuit and both leaf modes:
# documentNumber proves preimage_knowledge, the other identity fields stay
# commitment_only, and dateOfBirth carries two instances.
jq '.predicates.dateOfBirth = [
      .predicates.dateOfBirth,
      { circuit: "age_threshold",
        params: { minAgeYears: 21 },
        descriptor: { legalBasis: { framework: "REG_D",
                                    reference: "Rule 501(a)",
                                    assertion: "Subject is at or above 21 years of age" },
                      evidenceClass: "AUTHORITATIVE_SOURCE" },
        validity: { days: 3650 } }
    ]
    | .predicates.documentNumber.circuit = "preimage_knowledge"
    | .predicates.documentNumber.descriptor.evidenceClass = "PHYSICAL_PRESENCE"' \
    "$D/config.json" > "$D/config.tmp" && mv "$D/config.tmp" "$D/config.json"

subject() {
    printf '{"walletAddress":"%s","country":"%s","investorType":"%s","firstName":"%s","lastName":"X","dateOfBirth":"%s","nationality":"%s","documentType":"PASSPORT","documentNumber":"%s","documentIssuingCountry":"%s","softExpiryDays":365,"hardExpiryDays":730,"evidenceDate":"%s"}' \
        "$1" "$2" "$3" "$4" "$5" "$6" "$7" "$8" "${9:-2026-08-01}"
}

# Three that must succeed, then one failure per stage and per predicate.
{
    echo '['
    subject 0xabcdef0123456789abcdef0123456789abcdef01 DEU PROFESSIONAL Alice 1985-04-12 DEU P1 DEU; echo ','
    subject 0xfedcba9876543210fedcba9876543210fedcba98 FRA ELIGIBLE_COUNTERPARTY Brigitte 1979-11-02 FRA P2 FRA 2026-07-15; echo ','
    subject 0x1111111111111111111111111111111111111111 GBR PROFESSIONAL Charles 1990-01-15 GBR P3 GBR; echo ','
    subject not-a-wallet DEU PROFESSIONAL Bad 1985-04-12 DEU P4 DEU; echo ','
    subject 0x2222222222222222222222222222222222222222 DEU PROFESSIONAL_INVESTOR Typo 1985-04-12 DEU P5 DEU; echo ','
    subject 0x5555555555555555555555555555555555555555 DEU PROFESSIONAL Kid 2015-06-01 DEU P6 DEU; echo ','
    subject 0x6666666666666666666666666666666666666666 DEU RETAIL LowTier 1985-04-12 DEU P7 DEU; echo ','
    subject 0x7777777777777777777777777777777777777777 DEU PROFESSIONAL OffList 1985-04-12 BRA P8 DEU; echo ','
    subject 0x8888888888888888888888888888888888888888 DEU PROFESSIONAL Nineteen 2008-01-01 DEU P9 DEU
    echo ']'
} > "$D/input/batch.json"
cp "$D/input/batch.json" "$WORK_ROOT/batch.json"

# =====================================================================
log "2. dry run reports every problem at once, and writes nothing"
# =====================================================================
EXIT=$(run hash --dry-run)
DRY="$(out)"
assert_eq "$EXIT" "2" "dry run exits 2 when the batch has problems"
assert_eq "$(ls "$D/output" | grep -c '^0x' || true)" "0" "dry run wrote no bundles"
assert_contains "$DRY" "walletAddress" "names the bad wallet field"
assert_contains "$DRY" "PROFESSIONAL_INVESTOR" "rejects a mistyped tier instead of coercing it"
assert_contains "$DRY" "dateOfBirth@7665d" "reports the 21-year instance separately"
assert_contains "$DRY" "E_TIER_BELOW_MIN" "reports the tier failure"
assert_contains "$DRY" "E_LIST_MEMBER_MISSING" "reports the allowlist failure"
assert_not_contains "$DRY" "'BRA'" "does not echo the subject's value"
# The under-age subject fails both age instances; both must be reported.
assert_eq "$(count_occurrences "$DRY" 'E_AGE_BELOW_MIN')" "3" \
    "reports every failing leaf, not just the first per subject"

# =====================================================================
log "3. the real batch"
# =====================================================================
cp "$WORK_ROOT/batch.json" "$D/input/batch.json"
EXIT=$(run hash)
assert_eq "$EXIT" "2" "partial batch exits 2"
BUNDLES=$(ls "$D/output" | grep -c '^0x' || true)
assert_eq "$BUNDLES" "3" "three subjects produced bundles"

ALICE="$D/output/0xabCDeF0123456789AbcdEf0123456789aBCDEF01"
M="$ALICE/manifest.json"
assert_eq "$(jq -r '.version' "$M")" "3.0.0" "manifest version 3.0.0"
assert_eq "$(jq -r '.issuer.name' "$M")" "Nordbank AG" "manifest records the issuer"
assert_eq "$(jq -r '.issuer.identifierScheme' "$M")" "LEI" "issuer identifier scheme"
assert_eq "$(jq -r '.asOfDate' "$M")" "$(jq -r '.leaves[0].binding.validity.from' "$M" | xargs -I{} node -e "console.log(require('$REPO_ROOT/cli/dist/dates').epochDaysToIsoDate({}))")" \
    "asOfDate matches the validity start"
assert_contains "$(jq -r '.epochDaysSource' "$M")" "fixed:" "manifest records how the date was chosen"
assert_eq "$(jq -r '.unpinnedEpoch // "absent"' "$M")" "absent" "a pinned run carries no unpinnedEpoch marker"
assert_contains "$(jq -r '.toolchain.proverSha256' "$M")" "0x" "manifest records the prover binary digest"
assert_eq "$(jq -r '.leaves | length' "$M")" "10" "ten leaves (nine fields plus the second age instance)"
assert_eq "$(jq -r '[.leaves[] | select(.binding == null)] | length' "$M")" "0" \
    "every leaf carries a claim descriptor"
assert_eq "$(jq -r '[.leaves[] | select(.bindingDigest == null)] | length' "$M")" "0" \
    "every leaf carries its binding digest"
assert_eq "$(jq -r '.leaves[] | select(.fieldName=="nationality") | .binding.listVersion.version' "$M")" "1" \
    "the set_membership leaf records the list version it used"
assert_eq "$(jq -r '.leaves[] | select(.fieldName=="documentNumber") | .binding.descriptor.evidenceClass' "$M")" \
    "PHYSICAL_PRESENCE" "per-predicate evidence class survives into the leaf"
# Both leaf modes: commitment_only writes a zero-byte proof, the rest do not.
assert_eq "$(stat -f%z "$ALICE/proofs/firstName.bin" 2>/dev/null || stat -c%s "$ALICE/proofs/firstName.bin")" "0" \
    "commitment_only leaf has a zero-byte proof"
[ "$(stat -f%z "$ALICE/proofs/documentNumber.bin" 2>/dev/null || stat -c%s "$ALICE/proofs/documentNumber.bin")" -gt 1000 ] \
    && ok "preimage_knowledge leaf has a real STARK" || bad "preimage_knowledge leaf has a real STARK"

FAILURES="$(cat "$D/output/failures.csv")"
assert_contains "$FAILURES" "E_AGE_BELOW_MIN" "failures.csv records the prover-stage failures"
assert_not_contains "$FAILURES" "'BRA'" "failures.csv does not disclose a witness value"

# =====================================================================
log "4. verification, both anchors"
# =====================================================================
ROOT=$(cat "$ALICE/kycHash.hex")
EXIT=$(run verify 0xabCDeF0123456789AbcdEf0123456789aBCDEF01 --public-key "$PK")
assert_eq "$EXIT" "0" "verifies against the operator public key"
assert_contains "$(out)" "Entitled:  YES" "and is entitled today"
EXIT=$(run verify 0xabCDeF0123456789AbcdEf0123456789aBCDEF01 --root "$ROOT")
assert_eq "$EXIT" "0" "verifies against the published root"
EXIT=$(run verify 0xabCDeF0123456789AbcdEf0123456789aBCDEF01 --root "0x$(printf 'a%.0s' $(seq 64))")
assert_eq "$EXIT" "2" "a wrong root fails"
EXIT=$(run verify 0xabCDeF0123456789AbcdEf0123456789aBCDEF01)
assert_eq "$EXIT" "1" "no anchor is a usage error"

# Anchor every published root so as-of checks resolve offline.
B=8000000; T=$(( (EPOCH * 86400) + 3600 ))
for dir in "$D"/output/0x*/; do
    (cd "$D" && node "$CLI" anchor --bundle "${dir#$D/}" --chain-id 1 --block $B --block-time $T >/dev/null 2>&1) \
        || bad "anchor failed for $dir"
    B=$((B+100)); T=$((T+1200))
done
ok "root anchors recorded for every bundle"

# =====================================================================
log "5. ROTATION REGRESSION: bundles proved before a rotation keep verifying"
# =====================================================================
grep -v '^FIN$' "$D/config/list_commitments/country_allowlist.source.txt" > "$D/src.tmp"
echo 'BRA' >> "$D/src.tmp"
mv "$D/src.tmp" "$D/config/list_commitments/country_allowlist.source.txt"
ROTATE_DAY=$((EPOCH + 8))
EXIT=$(run list-version --list-id country_allowlist \
    --source config/list_commitments/country_allowlist.source.txt \
    --effective-date "$ROTATE_DAY" --note "Sanctions review")
assert_eq "$EXIT" "0" "the allowlist rotates to version 2"
assert_contains "$(out)" "supersedes   version 1" "version 1's window is closed, not deleted"

REG="$D/config/registry/lists/country_allowlist.json"
assert_eq "$(jq -r '.versions | length' "$REG")" "2" "the registry retains both versions"
assert_eq "$(jq -r '.versions[0].values | length' "$REG")" "17" "version 1 keeps its own values"
assert_contains "$(jq -r '.versions[0].values | join(",")' "$REG")" "FIN" \
    "the superseded version still contains the entry that was removed"

ALL_OK=1
for dir in "$D"/output/0x*/; do
    w=$(basename "$dir")
    EXIT=$(run verify "$w" --public-key "$PK")
    REPORT="$(out)"
    if [ "$EXIT" != "0" ]; then
        ALL_OK=0
        printf "      %s: verify exited %s\n" "$w" "$EXIT"
    fi
    if ! contains "$REPORT" "country_allowlist v1 (resolved, 17 entries)"; then
        ALL_OK=0
        printf "      %s: did not resolve to list version 1\n" "$w"
    fi
done
assert_eq "$ALL_OK" "1" "every pre-rotation bundle still verifies and resolves to version 1"

# =====================================================================
log "6. validity windows"
# =====================================================================
SOFT_PAST=$(node -e "console.log(require('$REPO_ROOT/cli/dist/dates').epochDaysToIsoDate($EPOCH + 400))")
HARD_PAST=$(node -e "console.log(require('$REPO_ROOT/cli/dist/dates').epochDaysToIsoDate($EPOCH + 900))")
EXIT=$(run verify 0xabCDeF0123456789AbcdEf0123456789aBCDEF01 --public-key "$PK" --now "$SOFT_PAST")
SOFT="$(out)"
assert_eq "$EXIT" "3" "past the 365-day windows: verified but not entitled"
assert_contains "$SOFT" "Verifies:  PASS" "the bundle still verifies"
assert_contains "$SOFT" "outside_validity" "the lapsed-window leaves say so"
assert_contains "$SOFT" "investorType" "the 730-day leaf is still listed"
EXIT=$(run verify 0xabCDeF0123456789AbcdEf0123456789aBCDEF01 --public-key "$PK" --now "$HARD_PAST")
assert_eq "$EXIT" "3" "past the 730-day window too: still verified, still not entitled"

# =====================================================================
log "7. as-of a past block, long after every window closed"
# =====================================================================
EXIT=$(run verify 0xabCDeF0123456789AbcdEf0123456789aBCDEF01 --public-key "$PK" \
    --now "$HARD_PAST" --as-of-block 8000100 --chain-id 1)
ASOF="$(out)"
assert_eq "$EXIT" "0" "entitlement as of the publishing block still holds"
assert_contains "$ASOF" "root on chain then" "the historical root is resolved"
assert_contains "$ASOF" "Entitled:  YES" "and the answer is yes"

EXIT=$(run verify 0xabCDeF0123456789AbcdEf0123456789aBCDEF01 --public-key "$PK" \
    --as-of-block 7999999 --chain-id 1)
BEFORE="$(out)"
assert_eq "$EXIT" "3" "a block before any publication is not entitled"
assert_contains "$BEFORE" "no publication" "and the report says why"

# =====================================================================
log "8. lapse and voidance"
# =====================================================================
LAPSE_DAY=$(node -e "console.log(require('$REPO_ROOT/cli/dist/dates').epochDaysToIsoDate($EPOCH + 40))")
BEFORE_LAPSE=$(node -e "console.log(require('$REPO_ROOT/cli/dist/dates').epochDaysToIsoDate($EPOCH + 39))")
EXIT=$(run revoke --bundle output/0x1111111111111111111111111111111111111111 \
    --leaf investorType --effect lapsed --effective-date "$LAPSE_DAY" --reason PERIODIC_REVIEW_OVERDUE)
assert_eq "$EXIT" "0" "a lapse is recorded"

EXIT=$(run verify 0x1111111111111111111111111111111111111111 --public-key "$PK" --now "$BEFORE_LAPSE")
assert_eq "$EXIT" "0" "reliance the day before the lapse still stands"
EXIT=$(run verify 0x1111111111111111111111111111111111111111 --public-key "$PK" --now "$LAPSE_DAY")
LAPSED="$(out)"
assert_eq "$EXIT" "3" "reliance on the lapse date does not"
assert_contains "$LAPSED" "Verifies:  PASS" "a lapsed claim does not make the bundle unverifiable"
assert_contains "$LAPSED" "lapsed" "and the status says lapsed"

EXIT=$(run revoke --bundle output/0xfEdcBA9876543210FedCBa9876543210fEdCBa98 \
    --effect void_ab_initio --reason FRAUDULENT_ONBOARDING)
assert_eq "$EXIT" "0" "a voidance is recorded"
EXIT=$(run revoke --bundle output/0xfEdcBA9876543210FedCBa9876543210fEdCBa98 \
    --effect void_ab_initio --effective-date "$LAPSE_DAY" --reason X)
assert_eq "$EXIT" "1" "a voidance with an effective date is refused"

EXIT=$(run verify 0xfEdcBA9876543210FedCBa9876543210fEdCBa98 --public-key "$PK" --as-of-block 8000200 --chain-id 1)
VOID="$(out)"
assert_eq "$EXIT" "3" "a voided bundle is not entitled even at the block it was published"
assert_contains "$VOID" "Verifies:  PASS" "and still verifies cryptographically"
assert_contains "$VOID" "void_ab_initio" "with the status shown"

# =====================================================================
log "9. archive: verify from one file on a clean directory"
# =====================================================================
EXIT=$(run archive --output batch.tka --all output --archive-id nordbank-2026Q3)
assert_eq "$EXIT" "0" "the archive builds"
[ -f "$D/batch.tka" ] && ok "the archive file exists" || bad "the archive file exists"

CLEAN="$WORK_ROOT/cleanroom"
mkdir -p "$CLEAN"
cp "$D/batch.tka" "$CLEAN/"
ARCHIVE_OUT=$("$REPO_ROOT/target/release/trusset-verifier-cli" --archive "$CLEAN/batch.tka" --public-key "$PK" 2>&1)
ARCHIVE_EXIT=$?
assert_eq "$(count_occurrences "$ARCHIVE_OUT" 'Verifies:  PASS')" "3" \
    "all three bundles verify from the archive alone"
assert_contains "$ARCHIVE_OUT" "country_allowlist v1 (resolved, 17 entries)" \
    "the archive carries the list version the proofs used"
assert_contains "$ARCHIVE_OUT" "void_ab_initio" "the revocation travels with the archive"
assert_eq "$ARCHIVE_EXIT" "3" "and the voided subject reports as not entitled"

# Tamper with it.
jq '.subjects[0].kycHashHex = "0xdeadbeef"' "$CLEAN/batch.tka" > "$CLEAN/tampered.tka"
"$REPO_ROOT/target/release/trusset-verifier-cli" --archive "$CLEAN/tampered.tka" --public-key "$PK" >"$CLEAN/t.txt" 2>&1
assert_eq "$?" "66" "a modified archive is refused"
assert_contains "$(cat "$CLEAN/t.txt")" "integrity check failed" "with an integrity error"

# =====================================================================
log "10. determinism"
# =====================================================================
det_run() {
    local dir="$1"
    rm -rf "$dir"; mkdir -p "$dir/input" "$dir/output" "$dir/target/release"
    cp -r "$D/config" "$dir/config"
    cp "$D/config.json" "$dir/config.json"
    cp -r "$D/.trusset" "$dir/.trusset"
    cp "$WORK_ROOT/batch.json" "$dir/input/batch.json"
    for bin in trusset-prover trusset-verifier-cli trusset-registry trusset-archive; do
        ln -sf "$REPO_ROOT/target/release/$bin" "$dir/target/release/$bin"
    done
    (cd "$dir" && node "$CLI" hash >/dev/null 2>&1)
}
det_run "$WORK_ROOT/det-a"
det_run "$WORK_ROOT/det-b"
DIFFS=0
for dir in "$WORK_ROOT"/det-a/output/0x*/; do
    w=$(basename "$dir")
    for f in kycHash.hex manifest.sig secrets.enc; do
        cmp -s "$WORK_ROOT/det-a/output/$w/$f" "$WORK_ROOT/det-b/output/$w/$f" || DIFFS=$((DIFFS+1))
    done
    for p in "$WORK_ROOT/det-a/output/$w/proofs/"*.bin; do
        cmp -s "$p" "$WORK_ROOT/det-b/output/$w/proofs/$(basename "$p")" || DIFFS=$((DIFFS+1))
    done
    diff -q <(jq 'del(.createdAt)' "$WORK_ROOT/det-a/output/$w/manifest.json") \
            <(jq 'del(.createdAt)' "$WORK_ROOT/det-b/output/$w/manifest.json") >/dev/null || DIFFS=$((DIFFS+1))
done
assert_eq "$DIFFS" "0" "two runs with pinned parameters are byte-identical"

# =====================================================================
log "11. the unpinned-epoch refusal"
# =====================================================================
jq '.security.epochDaysSource = "utc_today"' "$D/config.json" > "$D/config.unpinned.json"
cp "$D/config.json" "$D/config.pinned.json"
mv "$D/config.unpinned.json" "$D/config.json"
cp "$WORK_ROOT/batch.json" "$D/input/batch.json"
EXIT=$(run hash)
UNPINNED="$(out)"
assert_eq "$EXIT" "1" "utc_today is refused"
assert_contains "$UNPINNED" "cannot be reproduced tomorrow" "the refusal explains why"
assert_contains "$UNPINNED" "--dev-unpinned-epoch" "and names the development escape hatch"

cp "$WORK_ROOT/batch.json" "$D/input/batch.json"
EXIT=$(run hash --dev-unpinned-epoch)
assert_eq "$EXIT" "2" "the development flag lets it through"
DEV_M="$D/output/0xabCDeF0123456789AbcdEf0123456789aBCDEF01/manifest.json"
assert_eq "$(jq -r '.unpinnedEpoch' "$DEV_M")" "true" \
    "and the bundle is marked unreproducible for the rest of its life"
mv "$D/config.pinned.json" "$D/config.json"

# =====================================================================
printf "\n\033[1;34m[v3]\033[0m results: %d passed, %d failed\n" "$PASS_COUNT" "$FAIL_COUNT"
if [ "$FAIL_COUNT" -ne 0 ]; then
    printf "\033[1;34m[v3]\033[0m work root kept for inspection: %s\n" "$WORK_ROOT"
    exit 1
fi
printf "\033[1;34m[v3]\033[0m work root kept at %s\n" "$WORK_ROOT"
exit 0
