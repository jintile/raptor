#!/usr/bin/env bash
#
# las-security-review.sh — layered application security review (LAS)
#
# Usage:
#   ./las-security-review.sh <project-name> [--pre-prod]
#
# Default (sprint boundary) runs Layers 1-3:
#   1. RAPTOR agentic scan
#   2. Dependency audit (npm audit / pip-audit, stack-detected)
#   3. Secret sweep (truffleHog)
#
# With --pre-prod, also walks interactive Layers 4-6:
#   4. STRIDE threat-model checklist (6 items)
#   5. Architecture review checklist (10 items)
#   6. OWASP ZAP DAST reminder
# and writes a dated review record (.txt) into the output folder.
#
# Statuses: CLEAN | FINDINGS | FAILED | SKIPPED
#   SKIPPED = the layer had nothing applicable to run (e.g. no manifest).

set -uo pipefail

# --------------------------------------------------------------------------
# Configuration
# --------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RAPTOR_DIR="$SCRIPT_DIR"
DEV_ROOT="/workspaces/Development"
OUT_BASE="/workspaces/raptor/out"
DATE="$(date +%Y%m%d)"

usage() {
    cat <<EOF
Usage: $(basename "$0") <project-name> [--pre-prod]

  <project-name>   directory under $DEV_ROOT to review
  --pre-prod       run the interactive pre-production gate (Layers 4-6)
EOF
}

# --------------------------------------------------------------------------
# Argument parsing (flag may appear before or after the project name)
# --------------------------------------------------------------------------
PRE_PROD=0
PROJECT=""
for arg in "$@"; do
    case "$arg" in
        --pre-prod) PRE_PROD=1 ;;
        -h|--help)  usage; exit 0 ;;
        --*)        echo "Unknown option: $arg" >&2; usage; exit 2 ;;
        *)
            if [ -z "$PROJECT" ]; then
                PROJECT="$arg"
            else
                echo "Unexpected extra argument: $arg" >&2; usage; exit 2
            fi
            ;;
    esac
done

if [ -z "$PROJECT" ]; then
    echo "Error: project name is required." >&2
    usage
    exit 2
fi

TARGET="$DEV_ROOT/$PROJECT"
OUTDIR="$OUT_BASE/las-review-$PROJECT-$DATE"
RECORD="$OUTDIR/las-review-$PROJECT-$DATE.txt"

if [ ! -d "$TARGET" ]; then
    echo "Error: target directory not found: $TARGET" >&2
    exit 2
fi

mkdir -p "$OUTDIR"

# Layer status holders
L1_STATUS="SKIPPED"
L2_STATUS="SKIPPED"
L3_STATUS="SKIPPED"
NPM_STATUS="SKIPPED"
PIP_STATUS="SKIPPED"
L3_COUNT=0

echo "=========================================================="
echo " LAS Security Review — $PROJECT"
echo " Target : $TARGET"
echo " Output : $OUTDIR"
echo " Mode   : $([ "$PRE_PROD" -eq 1 ] && echo 'pre-prod (Layers 1-6)' || echo 'sprint boundary (Layers 1-3)')"
echo "=========================================================="

# --------------------------------------------------------------------------
# Layer 1 — RAPTOR agentic scan
# --------------------------------------------------------------------------
echo
echo "[Layer 1] RAPTOR agentic scan ..."
L1_LOG="$OUTDIR/layer1-agentic.log"
( cd "$RAPTOR_DIR" && python raptor.py agentic --repo "$TARGET" ) 2>&1 | tee "$L1_LOG"
L1_RC=${PIPESTATUS[0]}

if [ "$L1_RC" -ne 0 ]; then
    L1_STATUS="FAILED"
elif grep -qiE 'findings:[[:space:]]*[1-9]' "$L1_LOG"; then
    L1_STATUS="FINDINGS"
else
    L1_STATUS="CLEAN"
fi

# --------------------------------------------------------------------------
# Layer 2 — dependency audit (stack-detected)
# --------------------------------------------------------------------------
echo
echo "[Layer 2] Dependency audit ..."
HAVE_NPM=0; HAVE_PIP=0
[ -f "$TARGET/package.json" ]     && HAVE_NPM=1
[ -f "$TARGET/requirements.txt" ] && HAVE_PIP=1

if [ "$HAVE_NPM" -eq 1 ]; then
    echo "  - package.json found -> npm audit"
    NPM_LOG="$OUTDIR/layer2-npm-audit.log"
    if command -v npm >/dev/null 2>&1; then
        ( cd "$TARGET" && npm audit ) >"$NPM_LOG" 2>&1
        npm_rc=$?
        if [ "$npm_rc" -eq 0 ]; then
            NPM_STATUS="CLEAN"
        elif grep -qiE 'vulnerab' "$NPM_LOG"; then
            NPM_STATUS="FINDINGS"
        else
            NPM_STATUS="FAILED"   # e.g. missing lockfile / tooling error
        fi
    else
        echo "  ! npm not installed" | tee "$NPM_LOG"
        NPM_STATUS="FAILED"
    fi
    echo "    npm audit: $NPM_STATUS"
fi

if [ "$HAVE_PIP" -eq 1 ]; then
    echo "  - requirements.txt found -> pip-audit"
    PIP_LOG="$OUTDIR/layer2-pip-audit.log"
    if command -v pip-audit >/dev/null 2>&1; then
        pip-audit -r "$TARGET/requirements.txt" >"$PIP_LOG" 2>&1
        pip_rc=$?
        if [ "$pip_rc" -eq 0 ]; then
            PIP_STATUS="CLEAN"
        elif grep -qiE 'vulnerab|found [1-9]' "$PIP_LOG"; then
            PIP_STATUS="FINDINGS"
        else
            PIP_STATUS="FAILED"
        fi
    else
        echo "  ! pip-audit not installed" | tee "$PIP_LOG"
        PIP_STATUS="FAILED"
    fi
    echo "    pip-audit: $PIP_STATUS"
fi

# Combine: FAILED > FINDINGS > CLEAN; SKIPPED only if nothing ran
combine_status() {
    local out="SKIPPED" s
    for s in "$@"; do
        case "$s" in
            FAILED)                                   out="FAILED" ;;
            FINDINGS) [ "$out" != "FAILED" ] && out="FINDINGS" ;;
            CLEAN)    [ "$out" = "SKIPPED" ] && out="CLEAN" ;;
        esac
    done
    echo "$out"
}

if [ "$HAVE_NPM" -eq 0 ] && [ "$HAVE_PIP" -eq 0 ]; then
    echo "  - no package.json or requirements.txt detected"
    L2_STATUS="SKIPPED"
else
    declare -a l2parts=()
    [ "$HAVE_NPM" -eq 1 ] && l2parts+=("$NPM_STATUS")
    [ "$HAVE_PIP" -eq 1 ] && l2parts+=("$PIP_STATUS")
    L2_STATUS="$(combine_status "${l2parts[@]}")"
fi

# --------------------------------------------------------------------------
# Layer 3 — secret sweep (truffleHog)
# --------------------------------------------------------------------------
echo
echo "[Layer 3] Secret sweep (truffleHog) ..."
L3_JSON="$OUTDIR/layer3-trufflehog.json"
L3_ERR="$OUTDIR/layer3-trufflehog.err"

if ! command -v truffleHog >/dev/null 2>&1; then
    echo "  ! truffleHog not installed" | tee "$L3_ERR"
    L3_STATUS="FAILED"
else
    truffleHog --regex --entropy=True --json "$TARGET" >"$L3_JSON" 2>"$L3_ERR"
    # Count findings, excluding high-entropy noise from package-lock.json
    L3_COUNT=$(grep '"reason"' "$L3_JSON" 2>/dev/null | grep -vc 'package-lock\.json')
    L3_COUNT=${L3_COUNT:-0}
    if [ ! -s "$L3_JSON" ] && [ -s "$L3_ERR" ] && grep -qiE 'error|not a git|fatal' "$L3_ERR"; then
        L3_STATUS="FAILED"
    elif [ "$L3_COUNT" -gt 0 ]; then
        L3_STATUS="FINDINGS"
    else
        L3_STATUS="CLEAN"
    fi
    echo "  - actionable secret findings (package-lock.json excluded): $L3_COUNT"
fi

# --------------------------------------------------------------------------
# Layers 4-6 — interactive pre-production gate
# --------------------------------------------------------------------------
declare -a STRIDE_Q=(
    "Spoofing: are all identities (users, services, tokens) authenticated?"
    "Tampering: is data integrity protected in transit and at rest?"
    "Repudiation: are security-relevant actions logged with attribution?"
    "Information Disclosure: is sensitive data encrypted and access-controlled?"
    "Denial of Service: are rate limits / resource quotas in place?"
    "Elevation of Privilege: is authorization enforced server-side on every privileged action?"
)
declare -a ARCH_Q=(
    "Secrets in env/vault only — none hardcoded or exposed client-side?"
    "Supabase RLS enabled on every table holding sensitive data?"
    "Service-role keys used server-side only, never shipped to the client?"
    "AuthN/AuthZ enforced server-side, not just gated in the UI?"
    "Input validation and output encoding applied to all external input?"
    "TLS/HTTPS enforced end-to-end?"
    "Dependencies pinned (no @latest) with lockfiles committed?"
    "Logging/monitoring in place without leaking secrets or PII?"
    "Error handling explicit — no stack traces or secrets in client responses?"
    "Backups and a data-retention/deletion policy defined?"
)

declare -a STRIDE_A=()
declare -a ARCH_A=()
L4_STATUS="SKIPPED"
L5_STATUS="SKIPPED"
L6_STATUS="SKIPPED"
ZAP_ANSWER="n/a"

ANSWER=""
ask_yn() {
    local q="$1" tag="$2" ans
    while true; do
        read -r -p "  [$tag] $q (y/n): " ans </dev/tty
        case "$ans" in
            [yY]) ANSWER="yes"; return 0 ;;
            [nN]) ANSWER="no";  return 0 ;;
            *)    echo "      please answer y or n" ;;
        esac
    done
}

if [ "$PRE_PROD" -eq 1 ]; then
    echo
    echo "[Layer 4] STRIDE threat-model checklist"
    l4_no=0
    for i in "${!STRIDE_Q[@]}"; do
        ask_yn "${STRIDE_Q[$i]}" "S$((i+1))"
        STRIDE_A+=("$ANSWER")
        [ "$ANSWER" = "no" ] && l4_no=$((l4_no+1))
    done
    L4_STATUS=$([ "$l4_no" -eq 0 ] && echo "CLEAN" || echo "FINDINGS")

    echo
    echo "[Layer 5] Architecture review checklist"
    l5_no=0
    for i in "${!ARCH_Q[@]}"; do
        ask_yn "${ARCH_Q[$i]}" "A$((i+1))"
        ARCH_A+=("$ANSWER")
        [ "$ANSWER" = "no" ] && l5_no=$((l5_no+1))
    done
    L5_STATUS=$([ "$l5_no" -eq 0 ] && echo "CLEAN" || echo "FINDINGS")

    echo
    echo "[Layer 6] OWASP ZAP — dynamic application security testing"
    echo "  Reminder: run a ZAP scan against the deployed staging URL before"
    echo "  promoting to production (baseline scan at minimum, full active scan"
    echo "  for externally-facing surfaces). ZAP is not automated by this script."
    ask_yn "Has a ZAP scan been completed and reviewed for this release?" "Z1"
    ZAP_ANSWER="$ANSWER"
    L6_STATUS=$([ "$ZAP_ANSWER" = "yes" ] && echo "CLEAN" || echo "FINDINGS")
fi

# --------------------------------------------------------------------------
# Summary table
# --------------------------------------------------------------------------
print_row() { printf '  %-9s %-58s %-9s\n' "$1" "$2" "$3"; }

echo
echo "=========================================================="
echo " LAS Review Summary — $PROJECT ($DATE)"
echo "=========================================================="
print_row "Layer" "Description" "Status"
echo "  ---------------------------------------------------------------------------"
print_row "Layer 1" "RAPTOR agentic scan" "$L1_STATUS"
print_row "Layer 2" "Dependency audit (npm/pip)" "$L2_STATUS"
print_row "Layer 3" "Secret sweep (truffleHog)" "$L3_STATUS"
if [ "$PRE_PROD" -eq 1 ]; then
    print_row "Layer 4" "STRIDE threat model" "$L4_STATUS"
    print_row "Layer 5" "Architecture review" "$L5_STATUS"
    print_row "Layer 6" "ZAP DAST reminder" "$L6_STATUS"
fi
echo "=========================================================="
echo " Output saved to: $OUTDIR"

# --------------------------------------------------------------------------
# Dated review record (pre-prod)
# --------------------------------------------------------------------------
if [ "$PRE_PROD" -eq 1 ]; then
    {
        echo "LAS SECURITY REVIEW RECORD"
        echo "=========================="
        echo "Project : $PROJECT"
        echo "Date    : $DATE"
        echo "Target  : $TARGET"
        echo "Mode    : pre-prod (Layers 1-6)"
        echo
        echo "LAYER RESULTS"
        echo "-------------"
        echo "Layer 1  RAPTOR agentic scan        : $L1_STATUS"
        echo "Layer 2  Dependency audit           : $L2_STATUS"
        echo "           npm audit                : $NPM_STATUS"
        echo "           pip-audit                : $PIP_STATUS"
        echo "Layer 3  Secret sweep (truffleHog)  : $L3_STATUS (actionable findings: $L3_COUNT)"
        echo "Layer 4  STRIDE threat model        : $L4_STATUS"
        echo "Layer 5  Architecture review        : $L5_STATUS"
        echo "Layer 6  ZAP DAST reminder          : $L6_STATUS"
        echo
        echo "LAYER 4 — STRIDE CHECKLIST"
        echo "--------------------------"
        for i in "${!STRIDE_Q[@]}"; do
            printf '  [%s] %s\n' "${STRIDE_A[$i]}" "${STRIDE_Q[$i]}"
        done
        echo
        echo "LAYER 5 — ARCHITECTURE CHECKLIST"
        echo "--------------------------------"
        for i in "${!ARCH_Q[@]}"; do
            printf '  [%s] %s\n' "${ARCH_A[$i]}" "${ARCH_Q[$i]}"
        done
        echo
        echo "LAYER 6 — ZAP DAST"
        echo "------------------"
        echo "  ZAP scan completed & reviewed: $ZAP_ANSWER"
        echo
        echo "Generated by las-security-review.sh"
    } >"$RECORD"
    echo " Review record : $RECORD"
fi
echo "=========================================================="

# --------------------------------------------------------------------------
# Exit code: 3 if any layer FAILED, 1 if any FINDINGS, else 0
# --------------------------------------------------------------------------
ALL_STATUSES="$L1_STATUS $L2_STATUS $L3_STATUS $L4_STATUS $L5_STATUS $L6_STATUS"
case "$ALL_STATUSES" in
    *FAILED*)   exit 3 ;;
    *FINDINGS*) exit 1 ;;
    *)          exit 0 ;;
esac
