#!/usr/bin/env bash
# Live tier: the same protocol across a ladder of models.
#
#   benchmarks/live/run_model_ladder.sh [suite] [n_user]
#
# Swapping one model for a newer one trades the objection "that's a small 2024
# model" for "you picked the model that flatters you". Running a ladder and
# reporting the spread answers both, and it tests something real: injectability
# varies enormously by model, so containment that holds across tiers is a much
# stronger claim than containment on any single one.
#
# The ladder, weakest-to-resist-injection first:
#
#   gpt-4o-mini   public OpenAI, the injectable floor (61-89% undefended ASR).
#                 Kept precisely BECAUSE it is easy to inject: a defense that
#                 only works on a model that already resists injection has
#                 proven nothing.
#   llama-4-maverick  open weights, Azure AI Foundry. The representative case,
#                 what a company actually self-hosts.
#   grok-4        Azure AI Foundry. The strong-model end of the ladder.
#
# Llama-3.3-70B was the first choice and is NOT usable here: Foundry's serving
# of it rejects any request defining more than one tool (verified directly, not
# inferred from a failure), and AgentDojo's banking suite defines eight. That is
# a serving limitation rather than a model one, and no client-side shim can work
# around it. Llama-4-Maverick passes the same probe cleanly.
#
# Costs real money and takes real time. Every run writes its provider line and
# model label into the output so a result can never be attributed to the wrong
# model.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${ROOT}"
PY="${ROOT}/.venv-h2h/bin/python"   # AgentDojo needs py3.12
SUITE="${1:-banking}"
N_USER="${2:-8}"
OUT="benchmarks/results/model-ladder"
mkdir -p "${OUT}"

FOUNDRY_BASE="https://clayseal-foundry.services.ai.azure.com/models"
FOUNDRY_KEY="$(az cognitiveservices account keys list -n clayseal-foundry \
  -g clayseal-bench-rg --query key1 -o tsv)"

# AgentDojo validates the model id against its own enum, so every run passes the
# same recognized id while the client underneath is pointed at a different
# backend. LABEL is what actually answered, and it is what gets published.
AGENTDOJO_ID="gpt-4o-mini-2024-07-18"

run_one() {
  local label="$1" base="$2" key="$3" model="$4" no_parallel="${5:-0}" min_tokens="${6:-0}"
  echo "############ ${label} — ${SUITE}, n_user=${N_USER}"
  if [ -n "${base}" ]; then
    export OPENAI_COMPAT_BASE_URL="${base}" OPENAI_COMPAT_KEY="${key}" \
           OPENAI_COMPAT_MODEL="${model}" OPENAI_COMPAT_LABEL="${label}" \
           OPENAI_COMPAT_NO_PARALLEL_TOOLS="${no_parallel}" \
           OPENAI_COMPAT_MIN_MAX_TOKENS="${min_tokens}"
  else
    unset OPENAI_COMPAT_BASE_URL OPENAI_COMPAT_KEY OPENAI_COMPAT_MODEL \
          OPENAI_COMPAT_LABEL OPENAI_COMPAT_NO_PARALLEL_TOOLS \
          OPENAI_COMPAT_MIN_MAX_TOKENS
  fi
  "${PY}" -m benchmarks.live.diagnose_methodology \
    --suite "${SUITE}" --model "${AGENTDOJO_ID}" --n-user "${N_USER}" \
    --ablations envelope,envelope-taint,oracle-envelope-egress \
    --out "${OUT}/${SUITE}-${label}-trace.json" \
    2>&1 | tee "${OUT}/${SUITE}-${label}.log"
}

export OPENAI_API_KEY="${OPENAI_API_KEY:-$(cat ~/.openai_api_key)}"
# Azure OpenAI is unset here on purpose: the clayseal-aoai deployment is NAMED
# gpt-4o-mini-2024-07-18 but SERVES gpt-5-mini, so leaving it configured would
# silently make the "gpt-4o-mini" rung a gpt-5-mini run.
unset AZURE_OPENAI_ENDPOINT AZURE_OPENAI_KEY AZURE_OPENAI_API_KEY || true

run_one "gpt-4o-mini"      ""                ""               ""                 0 || true
run_one "llama-4-maverick" "${FOUNDRY_BASE}" "${FOUNDRY_KEY}" "llama-4-maverick" 0 || true
# grok-4 is a reasoning model: it spends the completion budget thinking before
# it emits anything, so it needs a much higher token floor or every turn comes
# back empty and reads as task failure.
run_one "grok-4"           "${FOUNDRY_BASE}" "${FOUNDRY_KEY}" "grok-4"           0 16000 || true

echo
echo "Traces in ${OUT}/. Summarize with:"
echo "  ${PY} -m benchmarks.live.summarize_ladder --suite ${SUITE}"
