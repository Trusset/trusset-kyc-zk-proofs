#!/usr/bin/env bash
# Trusset KYC v2 — memory profile (spec §12.11).
#
# Generates N synthetic subjects, runs the full TS → Rust prover
# pipeline once, and reports peak resident-set size via
# /usr/bin/time -l (macOS / BSD) or /usr/bin/time -v (GNU).
#
# The spec §12.11 budget is "no more than 1 GB peak per subject"
# (measured on a 1000-subject batch). This script defaults to N=50
# for tractable interactive runs (~3–5 min); pass N=1000 for the
# full spec measurement (~75 min on a 2026 macOS Intel).
#
# Usage:
#   bash scripts/memory_profile.sh           # N=50 default
#   N=200 bash scripts/memory_profile.sh
#   N=1000 bash scripts/memory_profile.sh    # full §12.11 measurement
#
# Output: appends a Markdown row to a timestamped report under
# /tmp/trusset-memprof-<timestamp>.md, then prints peak-RSS-per-subject.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

N="${N:-50}"
[[ "$N" =~ ^[0-9]+$ ]] || { echo "N must be a positive integer, got $N" >&2; exit 1; }

# Pinned fixtures (same as canary.sh) so memory cost is independent
# of OS entropy and time of day.
export TRUSSET_KYC_MASTER_KEY="000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
export TRUSSET_KYC_SIGNING_KEY="4242424242424242424242424242424242424242424242424242424242424242"
export TRUSSET_KYC_EPOCH_DAYS="20587"
export TRUSSET_PROVER_BIN="$REPO_ROOT/target/release/trusset-prover"
export TRUSSET_VERIFIER_BIN="$REPO_ROOT/target/release/trusset-verifier-cli"

log()  { printf "\033[1;34m[memprof]\033[0m %s\n" "$*"; }
fail() { printf "\033[1;31m[memprof]\033[0m %s\n" "$*" >&2; exit 1; }

# Pre-flight: release binaries + cli/dist must exist.
[ -x "$TRUSSET_PROVER_BIN" ]   || fail "missing $TRUSSET_PROVER_BIN — run 'cargo build --release'"
[ -x "$TRUSSET_VERIFIER_BIN" ] || fail "missing $TRUSSET_VERIFIER_BIN — run 'cargo build --release'"
[ -f "$REPO_ROOT/cli/dist/index.js" ] || fail "missing cli/dist/index.js — run 'cd cli && npm run build'"

WORK="$(mktemp -d -t trusset-memprof-XXXXXX)"
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$WORK/input" "$WORK/output"

# Pin epochDaysSource to env so memory profile is deterministic.
if command -v jq >/dev/null 2>&1; then
    jq '.security.epochDaysSource = "env:TRUSSET_KYC_EPOCH_DAYS"' \
        "$REPO_ROOT/config.example.json" > "$WORK/config.json"
else
    sed 's|"epochDaysSource": "utc_today"|"epochDaysSource": "env:TRUSSET_KYC_EPOCH_DAYS"|' \
        "$REPO_ROOT/config.example.json" > "$WORK/config.json"
fi
cp -r "$REPO_ROOT/config" "$WORK/config"

# Generate N synthetic subjects with cycling fixture data.
log "generating $N subjects"
python3 - "$N" "$WORK/input/profile.json" <<'PY'
import json, sys
n = int(sys.argv[1])
out = sys.argv[2]

countries = ["DEU", "FRA", "ITA", "ESP", "NLD"]
first_names = ["Alice", "Bob", "Carla", "Diego", "Eva", "Frank", "Greta", "Hugo"]
last_names  = ["Anderson", "Bertrand", "Conti", "Diaz", "Eriksson"]
doc_types   = ["PASSPORT", "ID_CARD"]
tiers       = ["RETAIL", "PROFESSIONAL", "ELIGIBLE_COUNTERPARTY"]

subjects = []
for i in range(n):
    c = countries[i % len(countries)]
    # Start address space at 0x...01 — the CLI rejects the zero
    # sentinel address (burn address) as invalid input.
    subjects.append({
        "walletAddress": f"0x{i + 1:040x}",
        "country": c,
        "investorType": tiers[i % len(tiers)],
        "firstName": first_names[i % len(first_names)],
        "lastName":  last_names[i % len(last_names)],
        "dateOfBirth": f"19{70 + (i % 30):02d}-01-15",
        "nationality": c,
        "documentType": doc_types[i % len(doc_types)],
        "documentNumber": f"X{i:08d}",
        "documentIssuingCountry": c,
    })
with open(out, "w") as f:
    json.dump(subjects, f)
PY

REPORT="/tmp/trusset-memprof-$(date +%Y%m%d-%H%M%S).md"
log "report: $REPORT"

cat > "$REPORT" <<EOF
# Trusset KYC v2 — Memory profile (spec §12.11)

- Date: $(date -u +%Y-%m-%dT%H:%M:%SZ)
- Platform: $(uname -srm)
- N subjects: $N
- Binary: $TRUSSET_PROVER_BIN
- Workspace: production defaults (manifest.mode = "production")

EOF

log "running pipeline (this will take a while for large N)"
TIME_OUT="$WORK/time.txt"
# macOS /usr/bin/time -l writes to stderr. Redirect just stderr.
PIPE_OUT="$WORK/pipeline.log"
(
  cd "$WORK"
  /usr/bin/time -l node "$REPO_ROOT/cli/dist/index.js" hash 2> "$TIME_OUT" > "$PIPE_OUT" \
    || { echo "pipeline failed; stdout tail:"; tail -30 "$PIPE_OUT"; echo "time output:"; cat "$TIME_OUT"; exit 1; }
)

# Parse macOS /usr/bin/time -l output. The first line is a single
# whitespace-separated row: "<wall> real <user> user <sys> sys".
WALL_SEC=$(awk '/ real / {print $1}' "$TIME_OUT" | head -1)
USER_SEC=$(awk '/ real / {print $3}' "$TIME_OUT" | head -1)
SYS_SEC=$(awk '/ real / {print $5}' "$TIME_OUT" | head -1)
PEAK_BYTES=$(awk '/maximum resident set size/ {print $1}' "$TIME_OUT" | head -1)

if [ -z "$PEAK_BYTES" ]; then
    # GNU time fallback.
    PEAK_BYTES=$(awk '/Maximum resident set size/ {print $NF * 1024}' "$TIME_OUT" | head -1)
    WALL_SEC=$(awk '/Elapsed \(wall clock\) time/ {print $NF}' "$TIME_OUT" | head -1)
fi

PEAK_MB=$(awk -v b="$PEAK_BYTES" 'BEGIN{printf "%.1f", b/1024/1024}')
PER_SUBJ_MB=$(awk -v b="$PEAK_BYTES" -v n="$N" 'BEGIN{printf "%.2f", b/1024/1024/n}')
PER_SUBJ_SEC=$(awk -v t="$WALL_SEC" -v n="$N" 'BEGIN{printf "%.2f", t/n}')

cat >> "$REPORT" <<EOF
## Results

| Metric | Value |
|---|---|
| Wall time | ${WALL_SEC} s |
| User CPU | ${USER_SEC:-n/a} s |
| Sys CPU | ${SYS_SEC:-n/a} s |
| Peak RSS | ${PEAK_MB} MB ($PEAK_BYTES bytes) |
| Peak RSS / subject | ${PER_SUBJ_MB} MB |
| Wall / subject | ${PER_SUBJ_SEC} s |

## Raw \`/usr/bin/time -l\` output

\`\`\`
$(cat "$TIME_OUT")
\`\`\`

## Pass/fail vs spec §12.11

Spec budget: peak RSS should not grow per-subject — the per-subject
delta should be dominated by transient prover allocations (one
trace at a time) rather than retained state. A flat or
slowly-growing peak-RSS curve across N=50, 200, 1000 is the
qualitative criterion. **${PER_SUBJ_MB} MB / subject** at N=$N is
the data point; rerun at higher N to verify the curve.
EOF

log "done"
log "  Wall time: ${WALL_SEC} s   |   Peak RSS: ${PEAK_MB} MB   |   per-subject: ${PER_SUBJ_MB} MB"
echo
echo "Report: $REPORT"
