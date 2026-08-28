# What is wired into the product, and what is not

STATUS: current

```bash
python -m benchmarks.integration_audit
```

This repository ships 172 library modules. Not all of them are reachable from
the gateway, and until this audit nobody had checked which. The question matters
because several published results are produced by code the shipped
`DeployableStack` never executes, and a reader has no way to tell from the
result file.

## Method

Two passes, because either alone gives a wrong answer.

**Static reachability.** Transitive import closure from the product entry points
(`DeployableStack`, `SessionBroker`) and from the public front doors (CLI,
`Guardrail`, MCP proxy, HTTP gateway, policy loader, async, integration, layer).
A module outside that closure cannot run in the product under any configuration.

**Runtime execution.** `sys.settrace` over `run_broker_benchmark` on five
corpora, recording which modules actually enter. This catches the opposite
error: a module that is imported and still never runs.

Static reachability alone would have called the budget machinery integrated
because it is imported; runtime tracing alone would have called it dead because
these corpora configure no budgets. Only the pair separates *unwired* from
*unexercised by this workload*.

## Result

| | count |
| --- | ---: |
| library modules | 161 |
| reachable from `DeployableStack` / `SessionBroker` | 124 |
| reachable from any public entry point | 130 |
| **orphaned, no entry point reaches them** | **31** |

The first run of this audit reported 172 modules and 42 orphans. Two of those
numbers moved for good reasons and one of them was my error, all recorded in
"What changed" below.

Most of the 31 are legitimately off the decision path and are listed here so
that stays a decision rather than an accident: the `sandbox/` subtree (10) is
the syscall tier that runs beside the gateway rather than inside it, and
`monitor/training/` plus `monitor/scoring/transformer` (5) are fit-time code.

## What changed since the first run

**`deputy.py` was never an orphan; the audit was wrong.** `SessionBroker` takes
it as `delegation: Any | None`, duck-typed so a caller can swap the boundary,
which means no `import` statement points at it and a static closure cannot see
the edge. The delegation rung has been wired since before this audit. Any
component injected through one of the broker's `Any` fields will read as
unreachable, and that is a limitation of the method rather than a finding.

**`velocity.py` is now wired.** It was the one genuine gap among the harm-class
detectors: 100% containment at burst >= 10 with 0.00% clean false alarms on
tau2 and BFCL ([burst.md](../benchmarks/results/burst.md)), and nothing on the
product path constructed it. `SessionBroker.velocity` now runs after the budget
reservation and before the behavioural layer, releasing any reservation it
refuses. Absent means unpaced, so no existing number moves. Pinned by
[`test_broker_velocity.py`](../python/tests/test_broker_velocity.py), including
the pass-through and the reservation-leak case.

**2,300 lines were deleted rather than wired.** `reidentification.py` (677) and
`staleness.py` (577) each defined a harm class, had a benchmark harness, and had
**no results file, no README or docs mention, and no caller**. `scoping/tools/`
(1,043) had unit tests and nothing else. Speculative code on a security library's
public surface is a liability, not an asset, so it is gone; the history has it if
a measurement ever justifies bringing one back.

Two orphans still back claims we publish, and those are the ones that matter.

## The behavioural tier is not what its numbers say it is

**`monitor/scoring/target.py` is not wired into the gateway.**
`monitor/__init__.py` exports `NGramScorer` and `SequenceScorer`;
`TargetDensityScorer` is imported only by `benchmarks/opeval.py`,
`benchmarks/adequacy.py`, `benchmarks/concentration.py` and
`benchmarks/core/engines.py`. So the channel that reaches 100% detection at a 1%
false-alarm rate on RedCode and `ipi_coding`
([opeval.md](../benchmarks/results/opeval.md)) is a research scorer, and the
scorer the product would run scores **0.0% at the same operating point, at an
AUC of 0.425, below chance.**

**The scorer slot contributes nothing to the detector's published result.**
Measured on SLEIGHT trajectories, holding everything else fixed:

| scorer | twin corridor on | twin corridor off |
| --- | ---: | ---: |
| `ngram` (the default) | 17/18 | 2/18 |
| `target` | 17/18 | 2/18 |
| **random, carries no information** | **17/18** | **2/18** |

A scorer emitting uniform noise scores exactly what the fitted n-gram scores, in
both configurations. The 94.4% in
[sleight_detector.md](../benchmarks/results/sleight_detector.md) and in the
`sleight[detector]` scoreboard row is a **twin-corridor** result: turning that
one structural tier off drops containment to 11.1% no matter which scorer is
installed.

Two controls were needed to establish that, and the first was wrong. A scorer
returning a *constant* surprise is inert by construction under conformal
calibration, because nothing is unusual relative to a distribution of identical
values, so "constant scorer changes nothing" proves only that the calibrator
works. The finding rests on the random and monotone scorers, which vary and
still change nothing.

**What this does not say.** It does not say the detector is worthless: 17 of 18
covert-intent trajectories are contained at zero false blocks, and that is a
real result from a real mechanism. It says the mechanism is the twin corridor,
and any sentence attributing it to goal-conditioned behavioural scoring is
wrong.

## The other one

**`ledger_backends.py`** (shared and Redis principal ledgers) is reachable only
by importing it directly. [THREAT_MODEL.md](THREAT_MODEL.md) §5 lists
`SharedPrincipalLedger` and `RedisPrincipalLedger` against spend split across
processes or hosts, which is accurate, but a deployment gets them by
constructing one, not by configuring the stack.

## What follows

Nothing here is fixed by editing a results file. Wiring `TargetDensityScorer`
into `monitor/__init__.py` is a one-line change and the wrong one to make
blind: the same table shows it at chance on the content-defined corpora, so the
default has to be chosen against a measurement, not against RedCode. Making the
scorer slot load-bearing is a change to `detector.py`'s tier combination and
belongs with its own before-and-after.

Both are open. They are recorded here rather than in a backlog because the
claims they touch are already published.
