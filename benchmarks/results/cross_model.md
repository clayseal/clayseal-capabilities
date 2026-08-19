# The model axis: seed spread and cross-family replication

STATUS: current

Two things stood between the aggregate-class result and being publishable, and
neither was about the mechanism. `python -m benchmarks.live.ladder_sweep`.

## Why `gpt-4o-mini` is not in this table

The published head-to-head was labelled gpt-4o-mini and was not: the deployment
`gpt-4o-mini-2024-07-18` on `<azure-openai-resource>` serves **gpt-5-mini-2025-08-07**.
Deploying a genuine one is no longer possible —

```
ERROR: (ServiceModelDeprecating) The model 'Format:OpenAI,Name:gpt-4o-mini,
Version:2024-07-18' is in deprecating state and cannot be used for new deployments.
```

so the exact replication is closed by the provider, not by billing. Two live
models were deployed instead (`gpt-4.1-mini`, `gpt-4.1`), which is the better
design anyway: a trend across families answers "is this a property of the
mechanism or of one model's tool-calling habits", and a single replication does
not.

Every cell below records the model the API *reported*, not the one requested.

## 1. Between-seed spread

`frontier.md` records an identical config, suite, model and attack giving 27.8%
ASR in one sweep and 0.0% in another at n=18. That is why W4 requires five seeds
per published cell and the spread reported beside the interval: they answer
different questions. The interval says how precisely this sweep measured itself.
The spread says whether another sweep would have found the same thing.

**gpt-4.1-mini, payout-splitting, 5 seeds x n=20:**

| condition | min | max | spread | pooled |
| --- | ---: | ---: | ---: | --- |
| none | 100.0% | 100.0% | **0.0%** | 100.0% (100/100) |
| progent | 100.0% | 100.0% | **0.0%** | 100.0% (100/100) |
| camel | 100.0% | 100.0% | **0.0%** | 100.0% (100/100) |
| clayseal | 0.0% | 0.0% | **0.0%** | 0/100, 97.5% upper bound 3.6% |

Zero spread on every condition, and it is worth being precise about why, because
"no variance" is the kind of result that should attract suspicion.

It is not that the agent behaves identically across seeds — it does not, and the
friction column moves. It is that **the quantity being measured is not a function
of the agent's choices.** The ledger decides the aggregate class deterministically
from the multiset of committed effects: whatever order or phrasing the model
picks, the ceiling is crossed or it is not, and crossing it is refused. In the
other direction, Progent and CaMeL violate on every run for a structural reason —
per-call policy has no cross-call state, and a task the trusted prompt fully
specifies never trips a dataflow gate — so their 100% is not a sampling outcome
either.

Zero spread is therefore evidence *for* the class claim rather than a suspiciously
clean number: a model-mediated defense on this suite would show spread, and the
whole point of the claim is that this one is not model-mediated. It also means
the seeds are cheap insurance rather than the load-bearing measurement, which is
the honest way to describe them.

## 2. Cross-family replication

Same four scenarios, `gpt-4.1-mini` and `gpt-4.1`, n=25 per cell, seed 0.

| model | scenario | none | Progent | CaMeL | ClaySeal | ClaySeal progress |
| --- | --- | ---: | ---: | ---: | --- | ---: |
| gpt-4.1-mini-2025-04-14 | payout-splitting | 100% (25/25) | 100% (25/25) | 100% (25/25) | **0/25, ub 13.7%** | 60% |
| gpt-4.1-mini-2025-04-14 | refund-structuring | 100% (25/25) | 100% (25/25) | 100% (25/25) | **0/25, ub 13.7%** | 40% |
| gpt-4.1-mini-2025-04-14 | access-grant-sprawl | 100% (25/25) | 100% (25/25) | 100% (25/25) | **0/25, ub 13.7%** | 50% |
| gpt-4.1-mini-2025-04-14 | bulk-delete-retention | 100% (25/25) | 100% (25/25) | 100% (25/25) | **0/25, ub 13.7%** | 38% |
| gpt-4.1-2025-04-14 | payout-splitting | 100% (25/25) | 100% (25/25) | 100% (25/25) | **0/25, ub 13.7%** | 60% |
| gpt-4.1-2025-04-14 | refund-structuring | 100% (25/25) | 100% (25/25) | 100% (25/25) | **0/25, ub 13.7%** | 40% |
| gpt-4.1-2025-04-14 | access-grant-sprawl | 100% (25/25) | 100% (25/25) | 100% (25/25) | **0/25, ub 13.7%** | 50% |
| gpt-4.1-2025-04-14 | bulk-delete-retention | 100% (25/25) | 100% (25/25) | 100% (25/25) | **0/25, ub 13.7%** | 38% |

Pooled across both families, 8 cells of 25:

| condition | violations |
| --- | --- |
| none | 100.0% (200/200) |
| progent | 100.0% (200/200) |
| camel | 100.0% (200/200) |
| clayseal | 0/200, 97.5% upper bound 1.8% |

The separation reproduces on every cell of every family. That is what the model
axis was for: `gpt-4.1-mini` and `gpt-4.1` are a different family from
`gpt-5-mini`, and neither the baselines' 100% nor the ledger's zero moves.

Read the two columns differently. Each baseline violating on 200 of 200 is a
**structural** result and the one that carries the claim — per-call policy has no cross-call
state, and a task the trusted prompt fully specifies never trips a dataflow
gate, so there is no model on which either would do better. The ledger's zero is
a **bound**: 0 of 100 per family is an upper bound of 3.6%, and at the 25-run
cell level 13.7%. Neither is a zero, and neither should be written as one.

Progress is the cost column and it is real: the ledger completes 37% to 61% of
requested work because the actions it blocks are exactly the over-budget ones.
The baselines pay nothing there because they do not block.

## Reproduce

```bash
python -m benchmarks.live.ladder_sweep --stage seeds --runs 20 --seeds 5
python -m benchmarks.live.ladder_sweep --stage cross --runs 25
```

Both need an Azure OpenAI endpoint in `OPENAI_BASE_URL` and its key in
`OPENAI_API_KEY`; the harness prints the served model id before the first cell.
