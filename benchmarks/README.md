# Clay Seal capability-enforcement benchmarks

A dataset-agnostic harness for evaluating **architectural approaches to agent
authorization** on external agent-security data. It replays labeled tool-call
traces, benign (the user's own task steps) vs attack (prompt-injection /
compromised-tool steps), through Clay Seal's real decision path and scores each
engine on two axes:

- **Containment**, fraction of *attack* events blocked (higher is better).
- **Friction**, fraction of *benign* events wrongly blocked, the false-block
  rate (lower is better).

No LLM inference is involved: each dataset provides ground-truth call sequences,
so the benchmark is a deterministic replay. That makes runs cheap, reproducible,
and CPU-only.

## The enforcement ladder

Each engine wraps a real primitive from `clayseal.core` / `clayseal.capabilities`
(no reimplemented policy). The rungs add authority granularity; on a sound
system containment is monotone up the ladder at flat, near-zero false-block:

| Engine | Real primitive | Catches |
| --- | --- | --- |
| `allow-all` | — | nothing (containment floor) |
| `tool-allowlist` | tool-name set membership | ungranted tools |
| `capability-token` | `core.operations.capability_allows` (Biscuit `resource:action`) | + action escalation |
| `task-scope` | `core.task_scope.task_scope_allows_path` | + path exfiltration |
| `task-scope+binding` | commit-token `arguments_hash` (`verify_commit_token`) | + argument tampering |
| `task-scope+binding+budget` | `SessionValueBudget` / `SessionCallBudget` | + fragmented over-budget (aggregate volume) |
| `deny-all` | — | everything (friction ceiling) |

Two rows are **controls, not rungs**. They live in `CONTROLS` rather than
`LADDER` so the monotone-ablation invariants stay valid, and both are printed in
every table because a containment number that does not beat its controls is not
a measurement:

| Control | Reads | Bounds |
| --- | --- | --- |
| `deny-all` | nothing | the containment column: refuse everything and you win it |
| `position-only-control` | an event's index in its task, and nothing else | the **order** column: a corpus that replays a benign prefix then an attack suffix can be "contained" by counting |

The second one exists because four of fourteen corpora turned out to be
ordering-exposed: `agent_threat_bench`, `asb`, `injecagent` and `ipi_coding` each
report 100% containment that a pure position cut also reaches at the same zero
false-block. That is a statement about those corpora, not about the rungs, and
it is measured for every registered corpus by
`python -m benchmarks.ordering_exposure`
([results/ordering_exposure.md](results/ordering_exposure.md)).

The budget rung is stateful: it threads a task's events through the real
session ledgers in event order, catching aggregate volume (many individually
valid calls that together cross a requester-inherited ceiling) that every
per-call rung below it structurally cannot see.

Monotonicity is enforced as a per-event test on every corpus
([tests/test_ladder_invariants.py](tests/test_ladder_invariants.py)), not
asserted in prose. It has to be per-event: two rungs can report the same
containment percentage while disagreeing about which events they caught, and
that disagreement is the defect class worth hunting. It found one on the first
run, now fixed, under a path-scoped mandate `compile_task_scope` leaves
`allowed_resources` empty, so `task-scope` was skipping the resource check that
`capability-token`, a *lower* rung, enforces. `TaskScopeEngine` now composes the
rung below instead of replacing it.

Every rate carries a task-clustered bootstrap interval with `--ci`. Events
inside a task share a template, so an event-level interval is roughly
sqrt(events-per-task) too narrow; see [core/stats.py](core/stats.py).

**Engine-integration family**, `opa`, `cedar`, `openfga` carry the *same*
compiled policy across the pluggable `clayseal.capabilities.authorizers` seam.
Holding policy fixed isolates the engine integration (decision parity + overhead)
and answers "which external authz engine should we adopt?" separately from
"which scoping strategy wins?".

Fixture result (offline, `python -m benchmarks.cli --dataset fixture`):

```
| Engine                    | Attack prevented | False-block | Benign utility |
| allow-all                 |             0.0% |        0.0% |         100.0% |
| tool-allowlist            |            20.0% |        0.0% |         100.0% |
| capability-token          |            40.0% |        0.0% |         100.0% |
| task-scope                |            60.0% |        0.0% |         100.0% |
| task-scope+binding        |            80.0% |        0.0% |         100.0% |
| task-scope+binding+budget |           100.0% |        0.0% |         100.0% |
| deny-all                  |           100.0% |      100.0% |           0.0% |
```

## Datasets

| Name | Source | Status |
| --- | --- | --- |
| `fixture` | bundled, offline | ready — drives the smoke test |
| `agentdojo` | [AgentDojo](https://github.com/ethz-spylab/agentdojo) suites (banking/slack/travel/workspace) | ready — tracks the 0.1.35 API (`get_suites` → `load_and_inject_default_environment` → `task.ground_truth`), benchmark version `v1.2.2` newest-first. Needs Python 3.10–3.12 (not 3.13). |
| `injecagent` | [InjecAgent](https://github.com/uiuc-kang-lab/InjecAgent) JSON corpus | reads `test_cases_*.json`; point `data_root` at a checkout |
| `toolemu` | [ToolEmu](https://github.com/ryoungj/ToolEmu) curated cases | preferred: a normalized `clayseal_traces.jsonl`; best-effort raw-case parsing otherwise |
| `atif` | ATIF-v1.2 MCP agent trajectories (in `agentauth-receipts/benchmarks/corpus`) | **real long benign trajectories** (38 sessions, up to 32 tool-calls); ideal for the detector and adversarial synthesis |
| `redcode` | [RedCode-Exec](https://github.com/AI-secure/RedCode) + BFCL benign | ready — 718 risky ops on *granted* tools vs out-of-scope targets; the suite's sharpest ladder separator |
| `agentharm` | [AgentHarm](https://huggingface.co/datasets/ai-safety-institute/AgentHarm) (UK AISI) | ready — 176 harmful/benign twins; 81% share an identical tool set, so it maps the authorization *ceiling* |
| `asb` | [Agent Security Bench](https://github.com/agiresearch/ASB) | ready — 400 attacker tools x 10 domains; saturated at the allowlist rung (breadth, not discrimination) |

Fetch the last three (and the BFCL benign trajectories RedCode scores against)
with `benchmarks/fetch_corpora.sh`, ~4 MB total, static JSON, no LLM or
container needed. See [results/new_suites.md](results/new_suites.md) for what
each one does and does not prove.

More corpora already in `agentauth-receipts/benchmarks/corpus` (surveyed, not yet
wired): Gorilla BFCL function-call tasks, τ²-bench, MCP-Bench, and the fraud
datasets used for AML-style workloads; plus `devin-fusion-redteam` coding-agent
scenarios (which motivate the `delegated-trust-laundering` typology).

All loaders normalize to the same `BenchmarkTask` (see `core/events.py`). Wired
selective suites beyond the surface-leaving set:

| Loader | Role |
| --- | --- |
| `toolemu` | Prefers `clayseal_traces.jsonl`; ships fixture under `fixtures/toolemu/` |
| `advbench_agent` | Harmful-instruction breadth / content-ceiling marker (not an authz win) |
| `mcp_attack` | Product-shaped poisoned-tool / confused-deputy / arg-mutation fixture |

Buyer packet + forbidden claims: [`SEND_PACKET.md`](SEND_PACKET.md). Tier-4
syscall replay: `python -m benchmarks.syscall_tier`. Saturated suites (`asb`,
`injecagent`) are excluded from pooled headlines in `scoreboard.py`.

ToolEmu normalized traces:

```jsonl
{"task_id": "...", "summary": "...", "allowed_tools": ["ReadFile"],
 "benign": [{"tool": "ReadFile", "action": "read", "args": {...}, "path": "..."}],
 "attack": [{"tool": "DeleteFile", "action": "delete", "args": {...}, "path": "..."}]}
```

Drop that at `<data_root>/clayseal_traces.jsonl` (or use the shipped fixture);
the loader prefers it and falls back to coarse raw-case parsing when absent.

## Layout

```
benchmarks/
  core/      events.py  engines.py  runner.py  report.py
  datasets/  base.py  fixture.py  agentdojo.py  injecagent.py
  azure/     run_benchmark.sh        # remote workload (CPU-only)
  tests/     test_fixture_benchmark.py
  cli.py
```

## Run

Locally (offline):

```bash
python -m benchmarks.cli --dataset fixture
pytest benchmarks/tests -q
```

Full external data (installs the `[benchmarks]` extra):

```bash
pip install -e ".[benchmarks]"
python -m benchmarks.cli --dataset agentdojo --limit 200 --json results/agentdojo.json
```

On a VM, the workload is CPU-only, so a small general-purpose instance or a
laptop is sufficient; no GPU:

```bash
DATASETS="fixture agentdojo" LIMIT=500 benchmarks/azure/run_benchmark.sh
```

## Adversarial synthesis + leaderboard

Any benign corpus becomes a labeled adversarial benchmark: `benchmarks/adversarial`
transforms each benign task into attack variants across the memo's threat
taxonomy (argument-tampering, path-exfiltration, unauthorized-tool,
action-escalation, connector-substitution, fragmented-overspend, goal-drift).
`benchmarks/core/leaderboard.py` then reports containment *per attack class* for
every engine, so the table shows which architecture is blind to which shape, not
just an aggregate.

```bash
python -m benchmarks.leaderboard --dataset agentdojo --limit 500
python -m benchmarks.leaderboard --dataset fixture --classes path-exfiltration,goal-drift
```

## Behavioral detector mode

`--mode detector` scores the trajectory-level behavioral layer
(`clayseal.capabilities.monitor`): it fits the goal-conditioned detector on
benign trajectories and reports containment vs a conformally-bounded false-block
rate. See `clayseal/capabilities/monitor/README.md`.

```bash
python -m benchmarks.build_corpus --dataset agentdojo --limit 3000 --out benign.jsonl
python -m benchmarks.cli --dataset agentdojo --mode detector --scorer ngram
```

## Extending

- **New attack class**: add a transform to `benchmarks/adversarial/attacks.py`
  and register it in `ATTACKS`.
- **New engine** (architecture): add a class with `name` + `decide(task, event)`
  in `core/engines.py`, register it in `build_engines`, add it to `LADDER` if it
  belongs on the containment ladder.
- **New dataset**: implement a loader returning `list[BenchmarkTask]` and
  `register_loader` it in `datasets/base.py`.
- **New metric**: `EngineResult` in `core/runner.py` already feeds the
  library's `ScopingMetrics` schema; add derived properties there.
