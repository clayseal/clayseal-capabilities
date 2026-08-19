#!/usr/bin/env bash
# Run frozen BPL-v1.0 Core-12 live head-to-head.
# Requires Azure OpenAI (or OpenAI) credentials via the project provider helper.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"
# shellcheck disable=SC1091
source .venv/bin/activate 2>/dev/null || true

MODEL="${MODEL:-gpt-4o-mini-2024-07-18}"
RUNS="${RUNS:-8}"
CONDITIONS="${CONDITIONS:-none,progent,camel,drift,authgraph,clayseal}"
OUT="${OUT:-benchmarks/results/bpl_core_h2h_${MODEL//\//_}_r${RUNS}.json}"

echo "BPL Core-12 H2H model=$MODEL runs=$RUNS conditions=$CONDITIONS -> $OUT"
python -m benchmarks.live.bpl_live \
  --suite core \
  --model "$MODEL" \
  --runs "$RUNS" \
  --conditions "$CONDITIONS" \
  --out "$OUT"
