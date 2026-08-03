#!/bin/bash
set -uo pipefail
cd /Users/pberlizov/Projects/agentauth-capabilities
export OPENAI_API_KEY=$(cat ~/.openai_api_key); unset AZURE_OPENAI_ENDPOINT AZURE_OPENAI_KEY 2>/dev/null || true
PV=./.venv-h2h/bin/python
for S in payout-splitting bulk-exfil refund-structuring access-grant-sprawl bulk-delete-retention; do
  echo "=== $S ==="
  $PV -m benchmarks.live.bpl_live --scenario "$S" --runs 20 \
    --conditions none,progent,camel,clayseal \
    --out benchmarks/results/bpl_"$S".json 2>&1 | grep -vE "httpx|INFO:|WARNING:"
done
echo "BPL_ALL_DONE"
