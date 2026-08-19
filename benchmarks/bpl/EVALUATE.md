# Evaluating a defense on BPL

## Commands

```bash
# Pack integrity (no LLM)
pytest benchmarks/tests/test_bpl_scenarios.py -q

# Frozen Core-12 membership
python -m benchmarks.live.bpl_live --list --suite core

# Live Core head-to-head (Azure or OpenAI credentials)
./scripts/paper/run_bpl_core_h2h.sh
```

Default conditions include published baselines (Progent, CaMeL) plus 2026
mechanism reproductions (**DRIFT**, **AuthGraph**) and ClaySeal:

```bash
python -m benchmarks.live.bpl_live --suite core \
  --conditions none,progent,camel,drift,authgraph,clayseal --runs 8
```

`drift` / `authgraph` are mechanism reproductions of arXiv:2506.12104 and
arXiv:2605.26497 (same fidelity class as the existing Progent/CaMeL branches;
AuthGraph upstream was not open at integration time). See
`benchmarks/live/baselines/`.

## What to report

For each condition:

| Metric | Meaning |
|--------|---------|
| **V** | Fraction of episodes where `violated(env)` is true |
| **P** | Mean `progress(env)` |
| **U** | `P * (1 - V)` (suite macro printed by the runner) |

Cite **suite=core**, **version=BPL-v1.0** from `benchmarks/bpl/SUITES.yaml`, the
model id (and true Azure deployment model if different), `runs`, and the git
commit of this repo.

## Adding another defense

Hook a new branch in `benchmarks/live/bpl_live.py` `run_episode` (same pattern as
`clayseal` / `progent` / `camel`). Keep tools, prompts, and predicates fixed.
Only the authorization gate changes. Then pass it in `--conditions`.

## Fairness

Violating trajectories must stay Progent-blind (every tool on the path is in the
OpenAI tool list) and CaMeL-untainted when the user prompt fully specifies the
task. Do not add prompt-injection strings to help your gate.
