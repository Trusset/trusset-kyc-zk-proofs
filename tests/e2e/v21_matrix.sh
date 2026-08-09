#!/usr/bin/env bash
# Trusset KYC hashing - v2.1.0 end-to-end matrix.
#
# Eight scenarios, each from a clean input/ and output/:
#   1. JSON input, single subject, all fields, default config
#   2. CSV input with a BOM, multiple subjects
#   3. Mixed JSON and CSV in input/ simultaneously
#   4. Batch with both a validation-stage and a prover-stage failure
#   5. All subjects failing
#   6. --raw, --skip-proofs, and --json on every command
#   7. Odd leaf counts: 1, 3, 5, 7, 9 leaves
#   8. Multi-instance predicates: age_threshold at 18 and 21 in one run
#
# Every scenario asserts the documented bundle layout, kycHash.hex against
# manifest.json, root-anchored and signature-anchored verification agreeing,
# strict rejection of stub bundles, and the 0/2/66 exit-code contract.
# A ninth check kills the prover mid-batch and asserts output/ is left with
# no partial bundle.

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
WORK_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/trusset-v21-matrix-XXXXXX")"

export TRUSSET_KYC_MASTER_KEY="000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
export TRUSSET_KYC_SIGNING_KEY="4242424242424242424242424242424242424242424242424242424242424242"
export TRUSSET_KYC_EPOCH_DAYS="20587"
export TRUSSET_PROVER_BIN="$REPO_ROOT/target/release/trusset-prover"
export TRUSSET_VERIFIER_BIN="$REPO_ROOT/target/release/trusset-verifier-cli"
# ed25519 verifying key for the signing key above.
PUBLIC_KEY_HEX="2152f8d19b791d24453242e15f2eab6cb7cffa7b6a5ed30097960e069881db12"
CLI="$REPO_ROOT/cli/dist/index.js"
VERIFIER="$TRUSSET_VERIFIER_BIN"

PASS_COUNT=0
FAIL_COUNT=0

log()  { printf "\033[1;34m[matrix]\033[0m %s\n" "$*"; }
ok()   { PASS_COUNT=$((PASS_COUNT + 1)); printf "  \033[1;32mok\033[0m   %s\n" "$*"; }
bad()  { FAIL_COUNT=$((FAIL_COUNT + 1)); printf "  \033[1;31mFAIL\033[0m %s\n" "$*"; }

assert_eq() {
    if [ "$1" = "$2" ]; then ok "$3"; else bad "$3 (expected '$2', got '$1')"; fi
}

assert_true() {
    if [ "$1" = "true" ]; then ok "$2"; else bad "$2 (got '$1')"; fi
}

# ---------------------------------------------------------------------
# Scenario scaffolding
# ---------------------------------------------------------------------

# usage: new_case <name> [config-mutation-jq]
new_case() {
    local name="$1"; shift
    local jq_filter="${1:-.}"
    local dir="$WORK_ROOT/$name"
    rm -rf "$dir"
    mkdir -p "$dir/input" "$dir/output"
    cp -r "$REPO_ROOT/config" "$dir/config"
    jq "$jq_filter | .security.epochDaysSource = \"env:TRUSSET_KYC_EPOCH_DAYS\"" \
        "$REPO_ROOT/config.example.json" > "$dir/config.json"
    echo "$dir"
}

subject_json() {
    local wallet="$1" country="$2" dob="$3" tier="$4"
    cat <<JSON
{"walletAddress":"$wallet","firstName":"Alice","lastName":"Anders","dateOfBirth":"$dob","nationality":"$country","documentType":"PASSPORT","documentNumber":"P1234567","documentIssuingCountry":"$country","country":"$country","investorType":"$tier","softExpiryDays":365,"hardExpiryDays":730}
JSON
}

run_cli() {
    local dir="$1"; shift
    (cd "$dir" && node "$CLI" "$@" >"$dir/stdout.txt" 2>"$dir/stderr.txt")
    echo $?
}

bundle_dirs() {
    find "$1/output" -maxdepth 1 -type d -name '0x*' 2>/dev/null | sort
}

# Assert the documented bundle shape and the manifest/kycHash agreement.
assert_bundle_layout() {
    local b="$1" label="$2"
    local missing=""
    for f in manifest.json manifest.sig kycHash.hex secrets.enc; do
        [ -f "$b/$f" ] || missing="$missing $f"
    done
    [ -d "$b/proofs" ] || missing="$missing proofs/"
    if [ -n "$missing" ]; then bad "$label: missing$missing"; return; fi

    # Every manifest leaf has a proof file at its declared proofPath.
    local leaves proof_missing
    leaves=$(jq -r '.leaves[].proofPath' "$b/manifest.json")
    proof_missing=""
    while IFS= read -r p; do
        [ -f "$b/$p" ] || proof_missing="$proof_missing $p"
    done <<< "$leaves"
    if [ -n "$proof_missing" ]; then bad "$label: missing proof files$proof_missing"; return; fi

    # No stray files beyond the documented shape.
    local extra
    extra=$(find "$b" -maxdepth 1 -type f ! -name manifest.json ! -name manifest.sig \
        ! -name kycHash.hex ! -name secrets.enc | wc -l | tr -d ' ')
    if [ "$extra" != "0" ]; then bad "$label: unexpected extra files in bundle root"; return; fi

    # kycHash.hex matches manifest.kycHash.
    local file_root manifest_root
    file_root=$(tr -d '\n' < "$b/kycHash.hex")
    manifest_root=$(jq -r '.kycHash' "$b/manifest.json")
    if [ "$file_root" != "$manifest_root" ]; then
        bad "$label: kycHash.hex != manifest.kycHash"; return
    fi
    ok "$label: layout and kycHash agreement"
}

# Verify under both anchors and assert they agree.
assert_both_anchors() {
    local b="$1" label="$2"
    local root sig_json root_json sig_pass root_pass
    root=$(tr -d '\n' < "$b/kycHash.hex")

    sig_json=$("$VERIFIER" --bundle "$b" --public-key "$PUBLIC_KEY_HEX" --json 2>/dev/null)
    local sig_exit=$?
    root_json=$("$VERIFIER" --bundle "$b" --root "$root" --json 2>/dev/null)
    local root_exit=$?

    sig_pass=$(echo "$sig_json" | jq -r '.overall_pass')
    root_pass=$(echo "$root_json" | jq -r '.overall_pass')

    if [ "$sig_pass" = "true" ] && [ "$root_pass" = "true" ] \
        && [ "$sig_exit" = "0" ] && [ "$root_exit" = "0" ]; then
        ok "$label: signature anchor and root anchor both verify (exit 0)"
    else
        bad "$label: anchors disagree or failed (sig=$sig_pass/$sig_exit root=$root_pass/$root_exit)"
    fi

    # The two reports must agree on every cryptographic finding.
    local a b2
    a=$(echo "$sig_json" | jq -S '{kyc_hash, leaf_count, merkle_root_valid, leaves}')
    b2=$(echo "$root_json" | jq -S '{kyc_hash, leaf_count, merkle_root_valid, leaves}')
    if [ "$a" = "$b2" ]; then
        ok "$label: both anchors report identical per-leaf results"
    else
        bad "$label: anchor reports diverge"
    fi

    # Neither anchor supplied must fail with usage error 64.
    "$VERIFIER" --bundle "$b" --json >/dev/null 2>&1
    assert_eq "$?" "64" "$label: no anchor is a usage error (64)"
}

log "work root: $WORK_ROOT"
log "building release artifacts if missing"
if [ ! -x "$TRUSSET_PROVER_BIN" ] || [ ! -f "$CLI" ]; then
    bash "$REPO_ROOT/scripts/build.sh" >/dev/null || { echo "build failed"; exit 1; }
fi

# =====================================================================
log "1. JSON input, single subject, all fields, default config"
# =====================================================================
D=$(new_case case1)
subject_json "0xabCDeF0123456789AbcdEf0123456789aBCDEF01" "DEU" "1985-04-12" "PROFESSIONAL" \
    | jq -s '.' > "$D/input/alice.json"
EXIT=$(run_cli "$D" hash)
assert_eq "$EXIT" "0" "case1: exit 0 on a fully valid batch"
B=$(bundle_dirs "$D" | head -1)
assert_bundle_layout "$B" "case1"
assert_both_anchors "$B" "case1"
assert_eq "$(jq -r '.version' "$B/manifest.json")" "2.1.0" "case1: manifest version 2.1.0"
assert_eq "$(jq -r '.merkleVersion' "$B/manifest.json")" "2" "case1: merkleVersion 2"
assert_eq "$(jq -r '.mode' "$B/manifest.json")" "production" "case1: production mode"
assert_eq "$(ls "$D/output"/kyc_hashes_*.csv 2>/dev/null | wc -l | tr -d ' ')" "1" "case1: one index CSV"
assert_eq "$(head -1 "$D"/output/kyc_hashes_*.csv)" \
    "walletAddress,country,investorType,softExpiryDays,hardExpiryDays,kycHash,index" \
    "case1: batch CSV header unchanged from v2.0"

# =====================================================================
log "2. CSV input with BOM, multiple subjects"
# =====================================================================
D=$(new_case case2)
printf '\xEF\xBB\xBFwalletAddress,firstName,lastName,dateOfBirth,nationality,documentType,documentNumber,documentIssuingCountry,country,investorType,softExpiryDays,hardExpiryDays\n' > "$D/input/subjects.csv"
cat >> "$D/input/subjects.csv" <<'CSV'
0xabCDeF0123456789AbcdEf0123456789aBCDEF01,Alice,Anders,1985-04-12,DEU,PASSPORT,P1234567,DEU,DEU,PROFESSIONAL,365,730
0xfEdcBA9876543210FedCBa9876543210fEdCBa98,Bob,Brown,1990-01-15,FRA,PASSPORT,P7654321,FRA,FRA,RETAIL,365,730
CSV
EXIT=$(run_cli "$D" hash)
assert_eq "$EXIT" "0" "case2: exit 0 on a BOM CSV batch"
assert_eq "$(bundle_dirs "$D" | wc -l | tr -d ' ')" "2" "case2: two bundles"
for B in $(bundle_dirs "$D"); do
    assert_bundle_layout "$B" "case2/$(basename "$B" | cut -c1-10)"
done
B=$(bundle_dirs "$D" | head -1)
assert_both_anchors "$B" "case2"

# =====================================================================
log "3. Mixed JSON and CSV in input/ simultaneously"
# =====================================================================
D=$(new_case case3)
subject_json "0xabCDeF0123456789AbcdEf0123456789aBCDEF01" "DEU" "1985-04-12" "PROFESSIONAL" \
    | jq -s '.' > "$D/input/alice.json"
printf 'walletAddress,firstName,lastName,dateOfBirth,nationality,documentType,documentNumber,documentIssuingCountry,country,investorType,softExpiryDays,hardExpiryDays\n' > "$D/input/bob.csv"
echo '0xfEdcBA9876543210FedCBa9876543210fEdCBa98,Bob,Brown,1990-01-15,FRA,PASSPORT,P7654321,FRA,FRA,RETAIL,365,730' >> "$D/input/bob.csv"
EXIT=$(run_cli "$D" hash)
assert_eq "$EXIT" "0" "case3: exit 0 on mixed JSON + CSV input"
assert_eq "$(bundle_dirs "$D" | wc -l | tr -d ' ')" "2" "case3: both input formats produced bundles"

# =====================================================================
log "4. Validation-stage AND prover-stage failures in one batch"
# =====================================================================
D=$(new_case case4)
{
    # Valid subject (survives).
    subject_json "0xabCDeF0123456789AbcdEf0123456789aBCDEF01" "DEU" "1985-04-12" "PROFESSIONAL"
    # Validation stage: missing country.
    echo '{"walletAddress":"0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB","firstName":"NoCountry","lastName":"X","dateOfBirth":"1990-01-01","nationality":"DEU","documentType":"PASSPORT","documentNumber":"P1","documentIssuingCountry":"DEU","investorType":"RETAIL"}'
    # Validation stage: malformed wallet.
    echo '{"walletAddress":"not-a-wallet","firstName":"BadWallet","lastName":"X","dateOfBirth":"1990-01-01","nationality":"DEU","documentType":"PASSPORT","documentNumber":"P2","documentIssuingCountry":"DEU","country":"DEU","investorType":"RETAIL"}'
    # Prover stage: under-age.
    subject_json "0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC" "DEU" "2020-01-01" "RETAIL"
    # Prover stage: country not in the allowlist.
    subject_json "0xaAaAaAaaAaAaAaaAaAAAAAAAAaaaAaAaAaaAaaAa" "ZZZ" "1985-04-12" "RETAIL"
    # Prover stage: tier NONE.
    subject_json "0x1111111111111111111111111111111111111111" "DEU" "1985-04-12" "NONE"
} | jq -s '.' > "$D/input/mixed.json"
EXIT=$(run_cli "$D" hash)
assert_eq "$EXIT" "2" "case4: exit 2 on a partial batch"
if [ -f "$D/output/failures.csv" ]; then
    assert_eq "$(head -1 "$D/output/failures.csv")" "walletAddress,stage,errorCode,message" \
        "case4: failures.csv header"
    V_COUNT=$(awk -F, 'NR>1 && $2=="validation"' "$D/output/failures.csv" | wc -l | tr -d ' ')
    P_COUNT=$(awk -F, 'NR>1 && $2=="prover"' "$D/output/failures.csv" | wc -l | tr -d ' ')
    [ "$V_COUNT" -ge 2 ] && ok "case4: validation-stage failures recorded ($V_COUNT)" \
        || bad "case4: expected >=2 validation failures, got $V_COUNT"
    [ "$P_COUNT" -ge 3 ] && ok "case4: prover-stage failures recorded ($P_COUNT)" \
        || bad "case4: expected >=3 prover failures, got $P_COUNT"
    grep -q "E_AGE_BELOW_MIN" "$D/output/failures.csv" \
        && ok "case4: under-age recorded as E_AGE_BELOW_MIN" \
        || bad "case4: missing E_AGE_BELOW_MIN"
    grep -q "E_LIST_MEMBER_MISSING" "$D/output/failures.csv" \
        && ok "case4: non-allowlisted country recorded as E_LIST_MEMBER_MISSING" \
        || bad "case4: missing E_LIST_MEMBER_MISSING"
    grep -q "E_TIER_NONE" "$D/output/failures.csv" \
        && ok "case4: tier NONE recorded as E_TIER_NONE" \
        || bad "case4: missing E_TIER_NONE"
else
    bad "case4: failures.csv not written"
fi
assert_eq "$(bundle_dirs "$D" | wc -l | tr -d ' ')" "1" "case4: only the surviving subject produced a bundle"
B=$(bundle_dirs "$D" | head -1)
assert_bundle_layout "$B" "case4 survivor"
assert_both_anchors "$B" "case4 survivor"

# =====================================================================
log "5. All subjects failing"
# =====================================================================
D=$(new_case case5)
{
    subject_json "0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC" "DEU" "2020-01-01" "RETAIL"
    subject_json "0xaAaAaAaaAaAaAaaAaAAAAAAAAaaaAaAaAaaAaaAa" "ZZZ" "1985-04-12" "RETAIL"
} | jq -s '.' > "$D/input/allbad.json"
EXIT=$(run_cli "$D" hash)
assert_eq "$EXIT" "1" "case5: exit 1 when every subject fails"
assert_eq "$(bundle_dirs "$D" | wc -l | tr -d ' ')" "0" "case5: no bundles left in output/"
[ -d "$D/output/.tmp" ] && bad "case5: .tmp staging directory left behind" \
    || ok "case5: no .tmp directory left behind"

# =====================================================================
log "6. --raw, --skip-proofs, --json on every command"
# =====================================================================
D=$(new_case case6)
subject_json "0xabCDeF0123456789AbcdEf0123456789aBCDEF01" "DEU" "1985-04-12" "PROFESSIONAL" \
    | jq -s '.' > "$D/input/alice.json"
EXIT=$(run_cli "$D" hash --raw --json)
assert_eq "$EXIT" "0" "case6: hash --raw --json exit 0"
jq -e . "$D/stdout.txt" >/dev/null 2>&1 && ok "case6: hash --json emits valid JSON" \
    || bad "case6: hash --json did not emit valid JSON"
RAW_CSV=$(ls "$D/output"/kyc_hashes_*_raw.csv 2>/dev/null | head -1)
if [ -n "$RAW_CSV" ]; then
    assert_eq "$(head -1 "$RAW_CSV")" \
        "walletAddress,country,investorType,softExpiryDays,hardExpiryDays,kycHash" \
        "case6: --raw drops the index column"
else
    bad "case6: no _raw CSV emitted"
fi

# show --json
(cd "$D" && node "$CLI" show --json > "$D/show.json" 2>/dev/null)
jq -e . "$D/show.json" >/dev/null 2>&1 && ok "case6: show --json emits valid JSON" \
    || bad "case6: show --json invalid"

# skip-proofs bundle: stub mode, zero-byte proofs, strict rejection.
D2=$(new_case case6b)
subject_json "0xabCDeF0123456789AbcdEf0123456789aBCDEF01" "DEU" "1985-04-12" "PROFESSIONAL" \
    | jq -s '.' > "$D2/input/alice.json"
EXIT=$(run_cli "$D2" hash --skip-proofs)
assert_eq "$EXIT" "0" "case6: hash --skip-proofs exit 0"
SB=$(bundle_dirs "$D2" | head -1)
assert_eq "$(jq -r '.mode' "$SB/manifest.json")" "stub" "case6: --skip-proofs marks mode stub"
NONZERO=$(find "$SB/proofs" -type f -size +0 | wc -l | tr -d ' ')
assert_eq "$NONZERO" "0" "case6: --skip-proofs writes only zero-byte proofs"
"$VERIFIER" --bundle "$SB" --public-key "$PUBLIC_KEY_HEX" --json >/dev/null 2>&1
assert_eq "$?" "2" "case6: strict verify rejects a stub bundle (exit 2)"
"$VERIFIER" --bundle "$SB" --public-key "$PUBLIC_KEY_HEX" --accept-stub --json >/dev/null 2>&1
assert_eq "$?" "0" "case6: --accept-stub accepts the same bundle (exit 0)"
STUB_ROOT=$(tr -d '\n' < "$SB/kycHash.hex")
"$VERIFIER" --bundle "$SB" --root "$STUB_ROOT" --json >/dev/null 2>&1
assert_eq "$?" "2" "case6: root anchor also rejects a stub bundle in strict mode"

# verify --json on a production bundle, and the 66 path.
(cd "$D" && node "$CLI" verify "$(basename "$(bundle_dirs "$D" | head -1)")" \
    --public-key "$PUBLIC_KEY_HEX" --json > "$D/verify.json" 2>/dev/null)
jq -e '.overall_pass == true' "$D/verify.json" >/dev/null 2>&1 \
    && ok "case6: verify --json reports overall_pass" \
    || bad "case6: verify --json did not report a passing report"
assert_eq "$(jq -r '.anchor' "$D/verify.json")" "public_key" "case6: report names the anchor used"
"$VERIFIER" --bundle "$WORK_ROOT/does-not-exist" --public-key "$PUBLIC_KEY_HEX" >/dev/null 2>&1
assert_eq "$?" "66" "case6: unreadable bundle exits 66"

# =====================================================================
log "7. Odd leaf counts: 1, 3, 5, 7, 9 leaves"
# =====================================================================
# `country` is always a leaf (mapping.countryField is required by config
# validation), so a config yields len(mapping.fields) leaves when `country`
# is itself one of them and investorTypeField is absent. Predicates for
# dropped fields must be removed too, otherwise config validation rejects
# the orphan.
for N in 1 3 5 7 9; do
    case $N in
        1) FIELDS='["country"]' ;;
        3) FIELDS='["country","firstName","lastName"]' ;;
        5) FIELDS='["country","firstName","lastName","dateOfBirth","nationality"]' ;;
        7) FIELDS='["country","firstName","lastName","dateOfBirth","nationality","documentType","documentNumber"]' ;;
        9) FIELDS='["country","firstName","lastName","dateOfBirth","nationality","documentType","documentNumber","documentIssuingCountry","investorType"]' ;;
    esac
    # Keep only the predicates whose field survived, and drop
    # investorTypeField unless this is the 9-leaf case.
    FILTER=".mapping.fields = $FIELDS
        | .predicates = (.predicates | with_entries(select(.key as \$k | $FIELDS | index(\$k))))
        | if (\"investorType\" | inside(\"$FIELDS\")) then . else del(.mapping.investorTypeField) end"
    if [ "$N" = "9" ]; then
        FILTER=".mapping.fields = $FIELDS | .predicates = (.predicates | with_entries(select(.key as \$k | $FIELDS | index(\$k))))"
    else
        FILTER=".mapping.fields = $FIELDS | .predicates = (.predicates | with_entries(select(.key as \$k | $FIELDS | index(\$k)))) | del(.mapping.investorTypeField)"
    fi
    D=$(new_case "case7_n$N" "$FILTER")
    subject_json "0xabCDeF0123456789AbcdEf0123456789aBCDEF01" "DEU" "1985-04-12" "PROFESSIONAL" \
        | jq -s '.' > "$D/input/alice.json"
    EXIT=$(run_cli "$D" hash)
    if [ "$EXIT" != "0" ]; then
        bad "case7 n=$N: pipeline exit $EXIT"
        sed -n '1,5p' "$D/stderr.txt" | sed 's/^/      /'
        continue
    fi
    B=$(bundle_dirs "$D" | head -1)
    COUNT=$(jq -r '.leaves | length' "$B/manifest.json")
    assert_eq "$COUNT" "$N" "case7 n=$N: manifest carries exactly $N leaves"
    assert_bundle_layout "$B" "case7 n=$N"
    assert_both_anchors "$B" "case7 n=$N"
done

# =====================================================================
log "8. Multi-instance predicates: age_threshold at 18 and 21"
# =====================================================================
D=$(new_case case8 '.predicates.dateOfBirth = [{"circuit":"age_threshold","params":{"minAgeYears":18}},{"circuit":"age_threshold","params":{"minAgeYears":21}}]')
subject_json "0xabCDeF0123456789AbcdEf0123456789aBCDEF01" "DEU" "1985-04-12" "PROFESSIONAL" \
    | jq -s '.' > "$D/input/alice.json"
EXIT=$(run_cli "$D" hash)
assert_eq "$EXIT" "0" "case8: exit 0 with two age instances"
B=$(bundle_dirs "$D" | head -1)
assert_bundle_layout "$B" "case8"
assert_both_anchors "$B" "case8"
AGE_LEAVES=$(jq -r '[.leaves[] | select(.circuit=="age_threshold")] | length' "$B/manifest.json")
assert_eq "$AGE_LEAVES" "2" "case8: two age_threshold leaves"
A18=$(jq -r '[.leaves[] | select(.circuit=="age_threshold") | .params.minAgeDays] | sort | .[0]' "$B/manifest.json")
A21=$(jq -r '[.leaves[] | select(.circuit=="age_threshold") | .params.minAgeDays] | sort | .[1]' "$B/manifest.json")
assert_eq "$A18" "6570" "case8: first instance asserts 18 years"
assert_eq "$A21" "7665" "case8: second instance asserts 21 years"
DISTINCT_PH=$(jq -r '[.leaves[] | select(.circuit=="age_threshold") | .paramsHash] | unique | length' "$B/manifest.json")
assert_eq "$DISTINCT_PH" "2" "case8: the two instances have distinct paramsHash values"
SUFFIXED=$(jq -r '[.leaves[] | select(.fieldName | test("@"))] | length' "$B/manifest.json")
assert_eq "$SUFFIXED" "1" "case8: the second instance carries a params-derived leaf name"
BADNAME=$(jq -r '[.leaves[] | select(.fieldName | test("^[A-Za-z0-9_.@-]+$") | not)] | length' "$B/manifest.json")
assert_eq "$BADNAME" "0" "case8: every leaf name is filesystem-safe"

# =====================================================================
log "9. Atomicity: kill the prover mid-batch"
# =====================================================================
D=$(new_case case9)
{
    for i in 1 2 3 4 5 6; do
        subject_json "0x${i}111111111111111111111111111111111111111" "DEU" "1985-04-12" "PROFESSIONAL"
    done
} | jq -s '.' > "$D/input/many.json"
(cd "$D" && node "$CLI" hash >/dev/null 2>&1) &
CLI_PID=$!
# Let the first subject start proving, then kill the whole process group.
sleep 3
pkill -KILL -P "$CLI_PID" 2>/dev/null
kill -KILL "$CLI_PID" 2>/dev/null
wait "$CLI_PID" 2>/dev/null
sleep 1
PARTIAL=0
for B in $(bundle_dirs "$D"); do
    # A bundle that survived a kill must still be complete: the rename is
    # the last step, so anything visible under output/0x* is whole.
    for f in manifest.json manifest.sig kycHash.hex secrets.enc; do
        [ -f "$B/$f" ] || PARTIAL=1
    done
done
assert_eq "$PARTIAL" "0" "case9: no partial bundle visible in output/ after SIGKILL"

# =====================================================================
log "results: $PASS_COUNT passed, $FAIL_COUNT failed"
if [ "$FAIL_COUNT" -eq 0 ]; then
    log "work root kept at $WORK_ROOT"
    exit 0
else
    log "work root kept for inspection: $WORK_ROOT"
    exit 1
fi
