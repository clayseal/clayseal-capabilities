#!/usr/bin/env bash
# Runtime replanning, measured on both instruments, serially.
#
#   benchmarks/live/run_replan_matrix.sh [n_user] [n_inj]
#
# Two questions, and they have to be answered together or the result means
# nothing:
#
#   AgentDyn: does replanning recover the utility that plan conformance destroyed?
#   AgentDojo: does it cost ASR on the suites where the layer already held at 0%?
#
# Serial by construction. Two concurrent cells saturate the 200k TPM ceiling and
# every request comes back 429, which reads as a hung run rather than a failed
# one. Full logs land in benchmarks/results/replan/ because the failure mode
# here is a truncated tail hiding the ablation you actually care about.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${ROOT}"
PY="${ROOT}/.venv-h2h/bin/python"
AGENTDYN="${ROOT}/.benchmark-corpus/AgentDyn/src"
OUT="benchmarks/results/replan"
mkdir -p "${OUT}"

N_USER="${1:-6}"
N_INJ="${2:-3}"
MODEL="gpt-4o-mini-2024-07-18"
ABL="envelope-taint,envelope-taint-replan"

export OPENAI_API_KEY="${OPENAI_API_KEY:-$(cat ~/.openai_api_key)}"
unset AZURE_OPENAI_ENDPOINT AZURE_OPENAI_KEY AZURE_OPENAI_API_KEY || true

run_cell() {           # run_cell <instrument> <suite> <extra-pythonpath>
  local instrument="$1" suite="$2" extra="${3:-}"
  local log="${OUT}/${instrument}-${suite}.log"
  echo "######## ${instrument} ${suite}  -> ${log}"
  ( if [ -n "${extra}" ]; then export PYTHONPATH="${extra}${PYTHONPATH:+:${PYTHONPATH}}"; fi
    "${PY}" -m benchmarks.live.run_agentdojo \
      --suite "${suite}" --model "${MODEL}" \
      --n-user "${N_USER}" --n-inj "${N_INJ}" \
      --ablations "${ABL}" --attack important_instructions
  ) >"${log}" 2>&1
  grep -E "clean-utility|SKIPPED" "${log}" || echo "  (no result line; see ${log})"
}

for suite in shopping github dailylife; do
  run_cell agentdyn "${suite}" "${AGENTDYN}"
done

for suite in banking slack travel workspace; do
  run_cell agentdojo "${suite}" ""
done

echo
echo "=== summary ==="
grep -H "clean-utility" "${OUT}"/*.log
