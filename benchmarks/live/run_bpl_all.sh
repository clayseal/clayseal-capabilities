#!/bin/bash
# Live BPL head-to-head across every scenario.
#
# Runs from the repo root regardless of where it is invoked from. Override any
# of PV / SCENARIOS / CONDITIONS / RUNS from the environment, so adding the
# sandboxed scenario needs no edit here:
#
#   IVISOR_BIN=/tmp/ivisor-signed IVISOR_ROOTFS=<iVisor>/guests/rootfs \
#   SCENARIOS=bulk-exfil-live CONDITIONS=none,progent,camel,ivisor \
#       benchmarks/live/run_bpl_all.sh
set -uo pipefail
cd "$(dirname "$0")/../.." || exit 1

if [ -z "${OPENAI_API_KEY:-}" ] && [ -r ~/.openai_api_key ]; then
  OPENAI_API_KEY=$(cat ~/.openai_api_key); export OPENAI_API_KEY
  unset AZURE_OPENAI_ENDPOINT AZURE_OPENAI_KEY 2>/dev/null || true
fi

# AgentDojo pins Python <=3.12, hence a separate venv; fall back to whatever
# python is on PATH when it is absent.
PV=${PV:-./.venv-h2h/bin/python}
[ -x "$PV" ] || PV=$(command -v python3)

RUNS=${RUNS:-20}
CONDITIONS=${CONDITIONS:-none,progent,camel,clayseal}
SCENARIOS=${SCENARIOS:-"payout-splitting bulk-exfil refund-structuring access-grant-sprawl bulk-delete-retention"}

for S in $SCENARIOS; do
  echo "=== $S ==="
  $PV -m benchmarks.live.bpl_live --scenario "$S" --runs "$RUNS" \
    --conditions "$CONDITIONS" \
    --out benchmarks/results/bpl_"$S".json 2>&1 | grep -vE "httpx|INFO:|WARNING:"
done
echo "BPL_ALL_DONE"
