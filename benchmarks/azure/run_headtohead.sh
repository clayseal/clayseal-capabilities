#!/usr/bin/env bash
# Remote workload for the Clay Seal LIVE head-to-head matrix.
#
# Unlike run_benchmark.sh (CPU-only trace replay), this drives a real LLM agent
# under real injection attacks, so it needs OPENAI_API_KEY and the AgentDojo
# package, which supports Python 3.10-3.12 (NOT 3.13). It is API-bound, not
# CPU/GPU-bound: a small VM is fine; the cost and wall-clock come from the model
# calls. Run it unattended on a VM rather than the laptop.
#
# Usage (on the VM):
#   OPENAI_API_KEY=... ./run_headtohead.sh                 # pilot first (cheap)
#   OPENAI_API_KEY=... MODE=full ./run_headtohead.sh       # full matrix (long)
#
# Dispatch from the laptop:
#   rsync -a --exclude .venv --exclude .git ./ azureuser@$VM:/opt/clayseal-bench/
#   ssh azureuser@$VM 'cd /opt/clayseal-bench && OPENAI_API_KEY=sk-... benchmarks/azure/run_headtohead.sh'
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO_ROOT"

: "${OPENAI_API_KEY:?set OPENAI_API_KEY (the live matrix calls the model)}"
MODE="${MODE:-pilot}"                    # pilot | full
OUT_DIR="${OUT_DIR:-$REPO_ROOT/benchmarks/results/matrix-$(date -u +%Y%m%dT%H%M%SZ)}"
# AgentDojo needs py3.10-3.12; prefer 3.12.
PYTHON="${PYTHON:-$(command -v python3.12 || command -v python3.11 || command -v python3.10)}"

log() { printf '[%s] [h2h] %s\n' "$(date -u +%H:%M:%S)" "$*"; }

if [[ -z "${PYTHON:-}" ]]; then
  echo "error: need python3.10-3.12 for agentdojo (found none); install one." >&2
  exit 1
fi
log "python: $PYTHON ($("$PYTHON" --version 2>&1))"

VENV="${VENV:-$REPO_ROOT/.venv-h2h}"
if [[ ! -d "$VENV" ]]; then
  log "creating venv $VENV"
  "$PYTHON" -m venv "$VENV"
fi
# shellcheck disable=SC1091
source "$VENV/bin/activate"
python -m pip install -q --upgrade pip
# Install this package with the benchmark extra (pulls agentdojo + openai), plus
# the sibling core/identity repos per the README install layout.
log "installing benchmark deps (agentdojo, openai)"
python -m pip install -q -e '.[benchmarks]' openai 2>&1 | tail -2 || {
  echo "error: '.[benchmarks]' install failed; check pyproject extras." >&2; exit 1; }

# Validate the plan before spending any tokens (azure-verify discipline).
log "dry-run validation (no API calls)"
python -m benchmarks.live.run_matrix --dry-run

ARGS=(--out "$OUT_DIR")
if [[ "$MODE" == "pilot" ]]; then
  log "PILOT: 1 model x 4 suites x 2 attacks, n_user=2 n_inj=1 repeats=1"
  ARGS+=(--pilot)
else
  log "FULL matrix: this is long and costs real tokens"
fi

log "launching matrix -> $OUT_DIR"
python -m benchmarks.live.run_matrix "${ARGS[@]}"
log "done. summary at $OUT_DIR/summary.md"
