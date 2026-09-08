# Reproducing BPL results

Two tiers, deliberately. The **scripted** tier needs no API key, no model and no
money, and it reproduces every structural claim. The **live** tier needs an LLM
and reproduces the leaderboard.

A benchmark whose claims can only be checked by spending money is one nobody
checks.

---

## Tier 1, scripted (no LLM, seconds)

Reproduces: scenario validity, policy/oracle agreement, the architectural claim
that a per-call gate cannot enforce an aggregate ceiling.

```bash
git clone https://github.com/clayseal/bpl-benchmark && cd bpl-benchmark
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"

pytest benchmarks/tests/test_bpl_scenarios.py -q   # every scenario runs
pytest benchmarks/tests/test_bpl_policy.py -q      # policy == oracle
python -m benchmarks.bpl_sweep                     # condition x scenario matrix
python -m benchmarks.live.bpl_live --policy-coverage
```

Fully deterministic. No seeds, no sampling, no network.

### The four parameters the headline depends on

Each defaults to what the published table used. Each is a choice, so each is a
flag rather than a constant, and the deltas are reported rather than left to be
discovered.

| flag | default | what changes if you move it |
| --- | --- | --- |
| `--verbs` | `system` | `bpl` is the legacy raw-synonym classifier: containment 47% and completion 41% against the shipped classifier's 41% and 98%, moving the joint metric 39.4% to 32%. The default is the classifier the product ships. |
| `--step-up` | `block` | `allow` rubber-stamps every step-up, pricing the pessimal supervised deployment. Identical table, because this suite produces **zero** step-ups: every containment is a hard denial. |
| `--observe-results` | off | Feeds tool returns back into the gateway, which is what the provenance, taint and flow tiers read. Changes nothing on its own. |
| `--confidentiality` | `off` | `derived` declares confidentiality classes from the sealed goal, since no scenario declares any. Worth +1 containment and −1 completion, and zero on the joint metric. |

The last two are measured in
[declaration_determines_enforcement.md](../results/declaration_determines_enforcement.md),
with the placebo control that says the derivation is not encoding answers.

---

## Tier 2, live leaderboard

Reproduces the head-to-head table in `../results/bpl_head_to_head.md`.

### Model

The published run used **`gpt-5-mini-2025-08-07`**, reached through an Azure
deployment *named* `gpt-4o-mini-2024-07-18`. That alias exists because
AgentDojo's `ModelsEnum` only accepts certain ids, and it caused one published
table to be labelled with the wrong model. Every cell now records the **served**
id, probed at runtime, and `ModelIdentity` fails a run whose served id does not
match the one declared.

The original `gpt-4o-mini-2024-07-18` cannot be redeployed on Azure
(`ServiceModelDeprecating`), so an exact replication of the pre-2026 numbers is
not available from us. Report the served id with any result.

### Environment

```bash
export AZURE_OPENAI_ENDPOINT="https://<resource>.openai.azure.com/"
export AZURE_OPENAI_KEY="..."
export AZURE_OPENAI_DEPLOYMENTS="<deployment-name>"
export AZURE_OPENAI_API_VERSION="2024-12-01-preview"
# or OPENAI_API_KEY=... for public OpenAI
```

### Run

```bash
# One scenario, all conditions
python -m benchmarks.live.bpl_live --scenario payout-splitting \
  --conditions none,per-call,dataflow-taint,drift,authgraph,clayseal \
  --runs 8 --seed 0

# The frozen leaderboard set
./scripts/run_bpl_core_h2h.sh
# or: RUNS=100 SUITE=core ./scripts/run_bpl_core_h2h.sh
```

### Sample size and seeds

- **n ≥ 100 per published cell.** At n=20 a zero has a 97.5% one-sided upper
  bound of 15%, which cannot distinguish a working mechanism from twenty lucky
  runs. An earlier table reported a bare `0%` at n=20; it was superseded.
- **≥ 5 seeds per cell, 10 for a headline**, reporting the between-seed spread
  next to the pooled interval. `../results/frontier.md` records identical
  configurations giving 27.8% and 0.0% ASR, so a single-seed cell cannot be told
  from a lucky one.
- The API treats `seed` as a hint. It does not make a run reproducible; it makes
  the spread a measured quantity rather than an unlabelled one.

### Cost

The Core-12 at n=8 × 6 conditions is roughly 600 short agent episodes. Budget
accordingly; the scripted tier is free and covers the structural claims.

---

## What a result must report

Copy this block with any number:

```
suite:        BPL-v1.0 core            # frozen; see SUITES.yaml
model:        <served model id>        # NOT the deployment alias
conditions:   <list>
runs/cell:    <n>    seeds: <k>
policy:       shared (v1.1) | reference-only (v1.0)
commit:       <git sha>
```

The `policy` line matters. Under v1.0 only the reference defense was configured
with the threshold; under v1.1 every condition receives `scenario.policy`. A
table that does not say which cannot be compared with one that does.

---

## Scoring your own defense

See [`EVALUATE.md`](EVALUATE.md). In short: implement a gate with the same
signature as the conditions in `benchmarks/live/bpl_live.py::apply_call`, add it
to `--conditions`, and report the triple, violation rate, progress, and blocks
never violation rate alone. A gate that refuses everything scores perfect
containment, which is why `deny-all` is a permanent row.
