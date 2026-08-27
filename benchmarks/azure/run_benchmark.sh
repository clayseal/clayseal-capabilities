#!/usr/bin/env bash
# Remote workload for the Clay Seal enforcement benchmark.
#
# Runs ON the VM (or any Linux/macOS host). The benchmark is CPU-only
# deterministic replay of ground-truth tool-call traces through the enforcement
# path, no LLM inference, so a small general-purpose VM (or a laptop) is plenty;
# no GPU required. Downloading the corpora is the only network-heavy step.
#
# Usage (on the VM):
#   ./run_benchmark.sh                       # fixture + agentdojo, default limit
#   DATASETS="agentdojo injecagent" LIMIT=500 ./run_benchmark.sh
#
# Dispatch from the laptop without provisioning anything new, e.g.:
#   rsync -a --exclude .venv ./ azureuser@$VM:/opt/clayseal-bench/
#   ssh azureuser@$VM 'cd /opt/clayseal-bench && benchmarks/azure/run_benchmark.sh'
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO_ROOT"

DATASETS="${DATASETS:-fixture agentdojo}"
LIMIT="${LIMIT:-200}"
ENGINES="${ENGINES:-allow-all,tool-allowlist,capability-token,task-scope,task-scope+binding,task-scope+binding+budget,deny-all}"
OUT_DIR="${OUT_DIR:-$REPO_ROOT/benchmarks/results/$(date -u +%Y%m%dT%H%M%SZ)}"
# agentdojo supports Python 3.10-3.12 (not 3.13); prefer a 3.12 interpreter.
PYTHON="${PYTHON:-$(command -v python3.12 || command -v python3)}"

log() { printf '[%s] [bench] %s\n' "$(date -u +%H:%M:%S)" "$*"; }

mkdir -p "$OUT_DIR"

# Isolated venv; the sibling core/identity repos are expected alongside this one
# (../agentauth-core, ../agentauth-identity) per the README install layout.
if [[ ! -d .venv ]]; then
  log "creating venv"
  "$PYTHON" -m venv .venv
fi
# shellcheck disable=SC1091
source .venv/bin/activate

log "installing repo + [benchmarks] extra"
pip install --quiet --upgrade pip
[[ -d ../agentauth-core ]] && pip install --quiet -e "../agentauth-core"
[[ -d ../agentauth-identity ]] && pip install --quiet -e "../agentauth-identity"
pip install --quiet -e ".[benchmarks]"

for dataset in $DATASETS; do
  log "running dataset=$dataset limit=$LIMIT"
  md="$OUT_DIR/${dataset}.md"
  json="$OUT_DIR/${dataset}.json"
  if python -m benchmarks.cli \
        --dataset "$dataset" \
        --engines "$ENGINES" \
        --limit "$LIMIT" \
        --json "$json" > "$md" 2> "$OUT_DIR/${dataset}.stderr"; then
    log "ok: $md"
    cat "$md"
  else
    log "FAILED dataset=$dataset (see $OUT_DIR/${dataset}.stderr)"
    tail -5 "$OUT_DIR/${dataset}.stderr" || true
  fi
done

log "results written to $OUT_DIR"
