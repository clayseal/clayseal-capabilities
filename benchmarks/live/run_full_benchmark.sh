#!/usr/bin/env bash
# Full AgentDojo escapes benchmark: all four suites x the key ablations, one
# model, serial (the OpenAI org TPM cap is the bottleneck, so parallelism does
# not help and a VM gives no speedup). Reproduces the escapes claim at breadth
# instead of banking-only n=18.
#
# Ablations, apples-to-apples on the identical subset:
#   none                     baseline (no defense)
#   builtin:tool_filter      strongest cheap published AgentDojo defense
#   envelope                 Clay Seal deployable envelope (no oracle)
#   envelope-taint           deployable + origin-based destination taint
#   oracle-envelope-egress   Clay Seal ceiling (ground-truth seeded)
#
# Usage:  MODEL=gpt-4o-mini-2024-07-18 NUSER=8 NINJ=3 bash run_full_benchmark.sh
set -uo pipefail

REPO="/Users/pberlizov/Projects/agentauth-capabilities"
VENV="/private/tmp/claude-501/-Users-pberlizov/34cca38f-409a-4617-b983-431bf3702132/scratchpad/venv312"
KEYFILE="$HOME/.config/copper4d/openai_key"
OUTDIR="${OUTDIR:-$REPO/benchmarks/results}"

MODEL="${MODEL:-gpt-4o-mini-2024-07-18}"
NUSER="${NUSER:-8}"
NINJ="${NINJ:-3}"
ATTACK="${ATTACK:-important_instructions}"
ABL="${ABL:-none,builtin:tool_filter,envelope,envelope-taint,oracle-envelope-egress}"
SUITES="${SUITES:-banking slack travel workspace}"

if [ ! -x "$VENV/bin/python" ]; then echo "no venv at $VENV" >&2; exit 1; fi
if [ ! -f "$KEYFILE" ]; then echo "no key at $KEYFILE" >&2; exit 1; fi
export OPENAI_API_KEY="$(tr -d '[:space:]' < "$KEYFILE")"

LOG="$OUTDIR/full_benchmark_${MODEL}.log"
echo "START $(date) model=$MODEL n=${NUSER}x${NINJ} ablations=$ABL" | tee "$LOG"
cd "$REPO" || exit 1
for suite in $SUITES; do
  echo "" | tee -a "$LOG"
  echo "=== suite=$suite ($(date)) ===" | tee -a "$LOG"
  "$VENV/bin/python" -u -m benchmarks.live.run_agentdojo \
    --suite "$suite" --model "$MODEL" --n-user "$NUSER" --n-inj "$NINJ" \
    --ablations "$ABL" --attack "$ATTACK" 2>&1 | tee -a "$LOG"
done
echo "" | tee -a "$LOG"
echo "DONE $(date)" | tee -a "$LOG"
