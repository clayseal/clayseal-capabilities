#!/usr/bin/env bash
# AgentDyn (arXiv:2602.03117, 2026): the current instrument, and the hard one.
#
#   benchmarks/live/run_agentdyn.sh [n_user] [n_inj] [suites]
#
# AgentDojo is 2024 and its published critiques are specific: mean trajectory
# length around three, heavy repetition, and evaluation bugs. AgentDyn is the
# 2026 replacement from the DRIFT authors, and it is deliberately harder in the
# two ways that hurt a system like ours:
#
#   Open-ended tasks requiring dynamic planning. Our intent envelope judges
#   against a plan generated up front, and the rule that fires when the agent
#   deviates causes 100% of our hard false blocks on AgentDojo. A benchmark that
#   *requires* the agent to plan at runtime should cost us more, and if it does
#   we would rather publish that than not know it.
#
#   Helpful third-party instructions embedded in tool output. Benign content
#   that looks like an injection. This measures over-defense directly, and the
#   paper's finding is that of ten state-of-the-art defenses almost all are
#   either insufficiently secure or over-defend badly.
#
# It is an AgentDojo fork, so the harness runs unchanged; only the import path
# and the suite names differ.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${ROOT}"
PY="${ROOT}/.venv-h2h/bin/python"
AGENTDYN="${ROOT}/.benchmark-corpus/AgentDyn/src"
OUT="benchmarks/results/agentdyn"
mkdir -p "${OUT}"

N_USER="${1:-6}"
N_INJ="${2:-3}"
SUITES="${3:-shopping,github,dailylife}"

if [ ! -d "${AGENTDYN}/agentdojo" ]; then
  echo "AgentDyn not present. Run: git clone https://github.com/leolee99/AgentDyn.git \\"
  echo "  ${ROOT}/.benchmark-corpus/AgentDyn"
  exit 2
fi

export OPENAI_API_KEY="${OPENAI_API_KEY:-$(cat ~/.openai_api_key)}"
# Azure stays unset for the same reason as the model ladder: `<aoai-resource>`
# deployment is named gpt-4o-mini and serves gpt-5-mini.
unset AZURE_OPENAI_ENDPOINT AZURE_OPENAI_KEY AZURE_OPENAI_API_KEY || true

# AgentDyn's package shadows the installed agentdojo, so it goes first.
export PYTHONPATH="${AGENTDYN}${PYTHONPATH:+:${PYTHONPATH}}"

for suite in ${SUITES//,/ }; do
  echo "############ AgentDyn ${suite} (${N_USER} user x ${N_INJ} injection)"
  "${PY}" -m benchmarks.live.run_agentdojo \
    --suite "${suite}" --model gpt-4o-mini-2024-07-18 \
    --n-user "${N_USER}" --n-inj "${N_INJ}" \
    --ablations none,envelope-taint,envelope-taint-graduated \
    --attack important_instructions \
    2>&1 | tee "${OUT}/${suite}.log"
done

echo
echo "AgentDyn results in ${OUT}/."
echo "Expect a worse utility number than AgentDojo. The suites require runtime"
echo "planning, which is exactly what our plan-conformance gate penalises."
