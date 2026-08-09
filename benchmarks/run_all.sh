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

for dataset in redcode agentharm asb sleight agent_threat_bench ipi_coding; do
  echo "==> ${dataset}: enforcement ladder (with confidence intervals)"
  "${PY}" -m benchmarks.cli --dataset "${dataset}" --ci \
    --json "${RESULTS}/new-suites/${dataset}.json" \
    | tee "${RESULTS}/new-suites/${dataset}.md"

  echo "==> ${dataset}: adversarial leaderboard (${SEEDS} seeds)"
  "${PY}" -m benchmarks.leaderboard --dataset "${dataset}" --seeds "${SEEDS}" \
    | tee "${RESULTS}/new-suites/${dataset}_leaderboard.md"
done

echo "==> attack-class coverage (what the layer can and cannot decide)"
"${PY}" -m benchmarks.coverage --datasets redcode,agentharm,asb,sleight,agent_threat_bench,ipi_coding \
  --json "${RESULTS}/coverage.json" | tee "${RESULTS}/coverage.md"

echo "==> adaptive red-team (all three knowledge levels)"
for objective in exfiltration persistence destruction; do
  "${PY}" -m benchmarks.adaptive --dataset redcode --limit "${LIMIT}" \
    --rounds "${ROUNDS}" --objective "${objective}" \
    --json "${RESULTS}/adaptive_${objective}.json" \
    | tee "${RESULTS}/adaptive_${objective}.md"
done

echo "==> long-trajectory needle (deployability: alarms per session)"
"${PY}" -m benchmarks.trajectory --length 500 --trajectories "$([ -n "${QUICK}" ] && echo 40 || echo 200)" \
  --json "${RESULTS}/trajectory.json" | tee "${RESULTS}/trajectory.md"

echo "==> cross-session structuring (principal-scoped aggregates)"
"${PY}" -m benchmarks.structuring --json "${RESULTS}/structuring.json" \
  | tee "${RESULTS}/structuring.md"

echo "==> slow drift (does the DEFENSE's baseline move?)"
"${PY}" -m benchmarks.drift --actions "$([ -n "${QUICK}" ] && echo 2000 || echo 10000)" \
  --json "${RESULTS}/drift.json" | tee "${RESULTS}/drift.md"

echo "==> enforcement latency"
"${PY}" -m benchmarks.latency --dataset redcode --limit 200 --repeats 20 \
  --json "${RESULTS}/latency_redcode.json" \
  | tee "${RESULTS}/latency_redcode.md"

echo "==> new product-shaped loaders (mcp_attack, advbench_agent, toolemu fixture)"
for dataset in mcp_attack advbench_agent toolemu; do
  echo "==> ${dataset}: enforcement ladder"
  "${PY}" -m benchmarks.cli --dataset "${dataset}" --ci \
    --json "${RESULTS}/new-suites/${dataset}.json" \
    | tee "${RESULTS}/new-suites/${dataset}.md" || true
done

echo "==> Tier 4 syscall boundary (iVisor sample-trace replay)"
"${PY}" -m benchmarks.syscall_tier \
  --out "${RESULTS}/syscall_tier.md" || true

echo "==> scoreboard rollup (excludes saturated suites from pooled headline)"
"${PY}" -m benchmarks.scoreboard $([ -n "${QUICK}" ] && echo --quick) \
  --json "${RESULTS}/scoreboard.json" | tee "${RESULTS}/scoreboard.md"

echo
echo "All deterministic benchmarks complete. Results in ${RESULTS}/."
echo "Live-agent utility and false-block numbers are NOT included here; see"
echo "docs/benchmark_program.md for why they are reported separately."
echo "Buyer packet checklist: benchmarks/SEND_PACKET.md"
