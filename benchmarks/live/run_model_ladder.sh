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
# Optional comma-separated filter, so a single rung can be retried after an
# upstream failure without paying for the whole ladder again.
ONLY="${3:-}"
OUT="benchmarks/results/model-ladder"
mkdir -p "${OUT}"

FOUNDRY_BASE="https://clayseal-foundry.services.ai.azure.com/models"
# The resource group is a deployment detail, not a constant, and redacting it
# to a placeholder left this line unrunnable: `-g <aoai-resource-group>` is not
# a shell variable, it is a syntax error waiting for whoever tried to reproduce
# the ladder. It comes from the environment now, with a message that says what
# to set rather than failing inside `az`.
FOUNDRY_RG="${CLAYSEAL_FOUNDRY_RG:?set CLAYSEAL_FOUNDRY_RG to the resource group holding the Foundry account}"
FOUNDRY_KEY="$(az cognitiveservices account keys list -n clayseal-foundry \
  -g "${FOUNDRY_RG}" --query key1 -o tsv)"

# AgentDojo validates the model id against its own enum, so every run passes the
# same recognized id while the client underneath is pointed at a different
# backend. LABEL is what actually answered, and it is what gets published.
AGENTDOJO_ID="gpt-4o-mini-2024-07-18"

run_one() {
  local label="$1" base="$2" key="$3" model="$4" no_parallel="${5:-0}" min_tokens="${6:-0}"
  if [ -n "${ONLY}" ] && [[ ",${ONLY}," != *",${label},"* ]]; then
    echo "---- skipping ${label} (filtered)"
    return 0
  fi
  echo "############ ${label}, ${SUITE}, n_user=${N_USER}"
  if [ -n "${base}" ]; then
    export OPENAI_COMPAT_BASE_URL="${base}" OPENAI_COMPAT_KEY="${key}" \
           OPENAI_COMPAT_MODEL="${model}" OPENAI_COMPAT_LABEL="${label}" \
           OPENAI_COMPAT_NO_PARALLEL_TOOLS="${no_parallel}" \
           OPENAI_COMPAT_MIN_MAX_TOKENS OPENAI_COMPAT_RETRIES="${min_tokens}" \
           OPENAI_COMPAT_RETRIES="${OPENAI_COMPAT_RETRIES:-4}"
  else
    unset OPENAI_COMPAT_BASE_URL OPENAI_COMPAT_KEY OPENAI_COMPAT_MODEL \
          OPENAI_COMPAT_LABEL OPENAI_COMPAT_NO_PARALLEL_TOOLS \
          OPENAI_COMPAT_MIN_MAX_TOKENS OPENAI_COMPAT_RETRIES
  fi
  "${PY}" -m benchmarks.live.diagnose_methodology \
    --suite "${SUITE}" --model "${AGENTDOJO_ID}" --n-user "${N_USER}" \
    --ablations envelope,envelope-taint,oracle-envelope-egress \
    --out "${OUT}/${SUITE}-${label}-trace.json" \
    2>&1 | tee "${OUT}/${SUITE}-${label}.log"
}

export OPENAI_API_KEY="${OPENAI_API_KEY:-$(cat ~/.openai_api_key)}"
# Azure OpenAI is unset here on purpose: `<aoai-resource>` is NAMED
# gpt-4o-mini-2024-07-18 but SERVES gpt-5-mini, so leaving it configured would
# silently make the "gpt-4o-mini" rung a gpt-5-mini run.
unset AZURE_OPENAI_ENDPOINT AZURE_OPENAI_KEY AZURE_OPENAI_API_KEY || true

run_one "gpt-4o-mini"      ""                ""               ""                 0 || true
run_one "llama-4-maverick" "${FOUNDRY_BASE}" "${FOUNDRY_KEY}" "llama-4-maverick" 0 || true
# gpt-oss-120b rejects a history containing a multi-call assistant turn, so it
# runs with the sequential-tool shim.
run_one "gpt-oss-120b"     "${FOUNDRY_BASE}" "${FOUNDRY_KEY}" "gpt-oss-120b"     1 || true
# grok-4-1-fast replaces plain grok-4 as the strong rung. grok-4 is a heavy
# reasoning model and, on top of Foundry returning 424/503 for roughly one
# request in three, a single suite ran five hours without completing. That is
# not a usable measurement loop. The fast variant passes the same tool-use
# probe and is not deprecated (grok-4-fast-reasoning is, as of 2026-05-01).
run_one "grok-4-1-fast"    "${FOUNDRY_BASE}" "${FOUNDRY_KEY}" "grok-4-1-fast"    0 || true

echo
echo "Traces in ${OUT}/. Summarize with:"
echo "  ${PY} -m benchmarks.live.summarize_ladder --suite ${SUITE}"
