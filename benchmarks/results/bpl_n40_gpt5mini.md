# Head-to-head at n=40, on gpt-5-mini

STATUS: current

First run under the W4 reporting rules, and the first live cell this repository
has produced with the served model verified rather than assumed.

## Result

`python -m benchmarks.live.bpl_live --runs 40 --scenario payout-splitting`,
Azure `<azure-openai-resource>`, served model **gpt-5-mini-2025-08-07**.

| condition | composite violation | legitimate progress | friction |
| --- | --- | ---: | ---: |
| none | 100.0% (40/40) | 100.0% | 0.00 |
| per-call | 100.0% (40/40) | 100.0% | 0.00 |
| dataflow-taint | 100.0% (40/40) | 100.0% | 0.00 |
| **clayseal** | **0/40, 97.5% upper bound 8.8%** | 60.0% | 2.05 blocks/run |

The separation holds and it is total: both published defenses violate on every
single run, and the stateful budget rung violates on none. The structural reason
is unchanged and is verified in competitor source: per-call's policy is per-call
with no cross-call state, and dataflow-taint's dataflow gate never fires on a task the
trusted prompt fully specifies.

## What this does and does not strengthen

**Strengthens the bound.** The published cell was n=20, which permits a true rate
as high as 16.8%. At n=40 that falls to 8.8%.

| n | upper bound on 0 successes |
| ---: | ---: |
| 20 (as published) | 16.8% |
| **40 (here)** | **8.8%** |
| 100 (plan target) | 3.6% |
| 200 | 1.8% |

Still short of the plan's n≥100. A rate that could be 8.8% is not a rate anyone
should call zero, and this file does not.

**Does NOT replicate the published head-to-head.** That ran on gpt-4o-mini. This
is a different cell on a stronger model and must be reported as such. The Azure
resource has no gpt-4o-mini deployment; the OpenAI account that does returns
`credit_balance_exhausted`. The replication is blocked on billing, not code.

**Arguably a harder test, which is worth stating.** `notes/improvements.md` rests
on utility cost shrinking as models get stronger. A stronger agent is also better
at finding routes to complete the task, so 100% violation for both competitors on
a frontier model is a more demanding result for them than the same figure on a
weak one.

**One scenario, one seed.** payout-splitting only, and the harness exposes no
seed control, so the between-seed spread that `frontier.md` warns about is
unmeasured here. `publishable()` would reject this cell as a headline on those
grounds alone, and correctly.

## The mislabelling this run caught

The harness printed its provider line as `gpt-4o-mini-2024-07-18` because that is
the deployment name. The served model is `gpt-5-mini-2025-08-07`. Every Azure
result this harness produced before today carried the wrong model id, and
`improvements.md`'s central claim is a model-strength trend that one mislabelled
cell inverts.

`bpl_live` now probes the served model and prints both, warning when they differ.
The probe is diagnostic rather than a gate: a failed probe degrades to
`(unverified)` instead of blocking the run.

## Cost of the full sweep

Measured: ~36 s per run across four conditions. The plan's primary table
(4 scenarios × 100 runs × 5 seeds) is therefore on the order of **20 hours** of
wall clock. Worth scheduling deliberately rather than launching blind.

## Reproduce

```bash
export OPENAI_API_KEY=<azure key>
export OPENAI_BASE_URL=https://<azure-openai-resource>.openai.azure.com/openai/v1/
python -m benchmarks.live.bpl_live --model gpt-4o-mini-2024-07-18 \
  --runs 40 --scenario payout-splitting
```
