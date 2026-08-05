#!/usr/bin/env bash
# One command to reproduce every published deterministic benchmark result.
#
#   benchmarks/run_all.sh              # full pass, writes benchmarks/results/
#   benchmarks/run_all.sh --quick      # smaller limits, for a smoke check
#
# Everything here is CPU-only replay with no LLM in the loop and no network
# access after the corpus fetch, so a full pass runs in well under a minute and
# reproduces bit-for-bit given the same pinned corpus. The live-agent
# measurements are deliberately NOT in this script: they cost money, need API
# credentials, and carry sampling noise, so they are run and reported
# separately rather than being mixed into a "run everything" number.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT}"
PY="${PYTHON:-${ROOT}/.venv/bin/python}"
RESULTS="benchmarks/results"
QUICK=""
[ "${1:-}" = "--quick" ] && QUICK=1

LIMIT=$([ -n "${QUICK}" ] && echo 50 || echo 400)
SEEDS=$([ -n "${QUICK}" ] && echo "0-2" || echo "0-9")
ROUNDS=$([ -n "${QUICK}" ] && echo 3 || echo 6)

echo "==> verifying corpus pinning"
"${PY}" -m benchmarks.verify_corpus

echo "==> invariant + harness tests"
"${PY}" -m pytest benchmarks/tests -q

for dataset in redcode agentharm asb; do
  echo "==> ${dataset}: enforcement ladder (with confidence intervals)"
  "${PY}" -m benchmarks.cli --dataset "${dataset}" --ci \
    --json "${RESULTS}/new-suites/${dataset}.json" \
    | tee "${RESULTS}/new-suites/${dataset}.md"

  echo "==> ${dataset}: adversarial leaderboard (${SEEDS} seeds)"
  "${PY}" -m benchmarks.leaderboard --dataset "${dataset}" --seeds "${SEEDS}" \
    | tee "${RESULTS}/new-suites/${dataset}_leaderboard.md"
done

echo "==> adaptive red-team (all three knowledge levels)"
for objective in exfiltration persistence destruction; do
  "${PY}" -m benchmarks.adaptive --dataset redcode --limit "${LIMIT}" \
    --rounds "${ROUNDS}" --objective "${objective}" \
    --json "${RESULTS}/adaptive_${objective}.json" \
    | tee "${RESULTS}/adaptive_${objective}.md"
done

echo "==> enforcement latency"
"${PY}" -m benchmarks.latency --dataset redcode --limit 200 --repeats 20 \
  --json "${RESULTS}/latency_redcode.json" \
  | tee "${RESULTS}/latency_redcode.md"

echo
echo "All deterministic benchmarks complete. Results in ${RESULTS}/."
echo "Live-agent utility and false-block numbers are NOT included here; see"
echo "docs/benchmark_program.md for why they are reported separately."
