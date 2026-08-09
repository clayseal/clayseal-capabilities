#!/usr/bin/env bash
# Fetch the external corpora the RedCode / AgentHarm / ASB suites replay.
#
# All three ship static labeled ground truth, so this is a plain download — no
# LLM, no environment, no GPU. Total ~4 MB. Everything lands in
# .benchmark-corpus/ at the repo root, which is gitignored.
#
#   benchmarks/fetch_corpora.sh
#   python -m benchmarks.cli --dataset redcode
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CORPUS="${ROOT}/.benchmark-corpus"
mkdir -p "${CORPUS}"

# --------------------------------------------------------------------------- #
# RedCode-Exec — 1,410 risky code-execution cases (Apache-2.0)
# Sparse checkout: the dataset dir only, not the Docker environment.
# --------------------------------------------------------------------------- #
if [ ! -d "${CORPUS}/RedCode/dataset" ]; then
  echo "==> RedCode"
  rm -rf "${CORPUS}/RedCode"
  git clone --depth 1 --filter=blob:none --sparse \
    https://github.com/AI-secure/RedCode.git "${CORPUS}/RedCode"
  git -C "${CORPUS}/RedCode" sparse-checkout set dataset
else
  echo "==> RedCode already present"
fi

# --------------------------------------------------------------------------- #
# AgentHarm — 176 harmful + 176 matched benign behaviors (UK AISI, MIT license)
# --------------------------------------------------------------------------- #
echo "==> AgentHarm"
AH="${CORPUS}/AgentHarm/benchmark"
mkdir -p "${AH}"
AH_URL="https://huggingface.co/datasets/ai-safety-institute/AgentHarm/resolve/main/benchmark"
for f in harmful_behaviors_test_public.json benign_behaviors_test_public.json \
         harmful_behaviors_validation.json benign_behaviors_validation.json; do
  [ -s "${AH}/${f}" ] || curl -fsSL "${AH_URL}/${f}" -o "${AH}/${f}"
done

# --------------------------------------------------------------------------- #
# Agent Security Bench — 400 attacker tools across 10 domain agents
# --------------------------------------------------------------------------- #
echo "==> ASB"
ASB="${CORPUS}/ASB/data"
mkdir -p "${ASB}"
ASB_URL="https://raw.githubusercontent.com/agiresearch/ASB/main/data"
for f in agent_task.jsonl all_attack_tools.jsonl all_normal_tools.jsonl; do
  [ -s "${ASB}/${f}" ] || curl -fsSL "${ASB_URL}/${f}" -o "${ASB}/${f}"
done

# --------------------------------------------------------------------------- #
# Gorilla BFCL multi-turn ground truth — the benign file-system trajectories
# RedCode is scored against (Apache-2.0).
# --------------------------------------------------------------------------- #
echo "==> BFCL multi-turn"
BF="${CORPUS}/bfcl/data"
mkdir -p "${BF}/possible_answer" "${BF}/multi_turn_func_doc"
BF_URL="https://raw.githubusercontent.com/ShishirPatil/gorilla/main/berkeley-function-call-leaderboard/bfcl_eval/data"
for f in BFCL_v4_multi_turn_base.json BFCL_v4_multi_turn_long_context.json; do
  [ -s "${BF}/${f}" ] || curl -fsSL "${BF_URL}/${f}" -o "${BF}/${f}"
  [ -s "${BF}/possible_answer/${f}" ] || \
    curl -fsSL "${BF_URL}/possible_answer/${f}" -o "${BF}/possible_answer/${f}"
done
[ -s "${BF}/multi_turn_func_doc/gorilla_file_system.json" ] || \
  curl -fsSL "${BF_URL}/multi_turn_func_doc/gorilla_file_system.json" \
    -o "${BF}/multi_turn_func_doc/gorilla_file_system.json"

echo
echo "Corpora ready in ${CORPUS}"
du -sh "${CORPUS}"/* 2>/dev/null || true

# --------------------------------------------------------------------------- #
# SLEIGHT-Bench (arXiv:2605.16626, 2026) — 44 covert-harm coding-agent
# transcripts across 12 evasion categories, each with a benign pair.
#
# Canary-protected: the transcripts carry an explicit opt-out string and ship
# encrypted so they stay out of training corpora. The key is published in the
# upstream README on purpose, since the encryption stops automated scraping
# rather than human access.
# --------------------------------------------------------------------------- #
SLEIGHT_KEY="8Od5ksQZ8pCPpxKSE9WA0MeBL2R_zL1MTz6C5pJFZmo="
if [ ! -d "${CORPUS}/sleight-bench/attacks" ]; then
  echo "==> SLEIGHT-Bench"
  git clone --depth 1 https://github.com/safety-research/sleight-bench.git \
    "${CORPUS}/sleight-bench"
fi
if [ -z "$(find "${CORPUS}/sleight-bench/attacks" -name '*.jsonl' -print -quit 2>/dev/null)" ]; then
  echo "==> decrypting SLEIGHT-Bench"
  (cd "${CORPUS}/sleight-bench" && python decrypt.py --key "${SLEIGHT_KEY}" >/dev/null)
else
  echo "==> SLEIGHT-Bench already decrypted"
fi
