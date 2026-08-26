# Is the evaluation strong enough to publish?

STATUS: current

```bash
python -m benchmarks.bpl_sweep --suite full
python -m benchmarks.verify_results
python -m benchmarks.check_claims
```

Three questions a reviewer asks: is the headline tested correctly, is the
evaluation set independent of the system, and can anyone else reproduce it. The
answers here are yes, no, and partly.

## 1. The headline, tested the way paired data has to be

Every condition is replayed against the same 132 scenarios, so the conditions are
not independent samples. The sweep previously reported five rates with no test
between them.

Primary metric: **contained AND benign twin completed**, the only one of the
three columns neither degenerate control can win.

| clayseal vs | wins | losses | difference (95% CI) | p |
| --- | ---: | ---: | ---: | ---: |
| undefended | 50 | 0 | 39.4% [31.1%, 47.7%] | 4.4e-16 |
| refuse everything | 50 | 0 | 39.4% [31.1%, 47.7%] | 4.4e-16 |
| per-call authorization | 50 | 0 | 39.4% [31.1%, 47.7%] | 4.4e-16 |
| dataflow taint | 42 | 7 | 28.0% [18.2%, 37.9%] | 1.21e-07 |

Exact McNemar on the discordant scenarios; difference by paired bootstrap over
scenarios; **all four survive Holm correction** over the family.

McNemar rather than Fisher because the pairing is the point: the two mechanisms
agree on only 21 of 132, so an unpaired test pools 111 scenarios that carry no
information about which is better.

### Cluster-robust, because the scenarios are not independent

Scenarios were written in batches of four to twelve, one file at a sitting.
Treating 132 as 132 independent samples understates every interval. Clustering
on the family gives three clusters, too few for a bootstrap; clustering on the
authoring file gives 17.

| condition | naive (iid) | clustered by authoring batch |
| --- | --- | --- |
| dataflow taint | 11.4% [7.0%, 17.9%] | 11.4% [6.1%, 17.7%] |
| **clayseal** | 39.4% [31.5%, 47.9%] | **39.4% [24.3%, 57.9%]** |

The clustered intervals do not overlap. **That is the number to publish**, and it
is materially wider than the naive one, which is the point of computing it.

## 2. The evaluation set is not independent of the system, and that is now bounded

This is the finding that would decide a review. It is not favourable, and it is
smaller than it first looked. Read
[bpl_label_free.md](bpl_label_free.md) with this section.

The suite's `clayseal_expected` labels predict containment with **97.7%
accuracy**: every `contain`-labelled scenario is contained (50/50) and almost
nothing else is (3/82). The scenarios that fail are the scenarios written as
expected to fail.

Consequences a reviewer would draw, all correct:

- The generalization map, which reports zero regressions and zero stale labels,
  has almost no power to discover anything. It reads as validation and is closer
  to a tautology.
- No failure analysis is possible. Six mechanism hypotheses were read out of the
  79 failing scenarios; two died to a base-rate control, three were noise at
  n=9, and the one that reached significance dissolved under Simpson's paradox.
  See [bpl_failure_patterns.md](bpl_failure_patterns.md).
- The Core-12 leaderboard set is 83% `contain`-labelled where the suite is 38%.
  Disclosed now, and worth 43 points of raw containment.

What rules out the crude versions and not this one: labels were committed with
their scenarios rather than revised after measurement, and they are never read in
the decision path. Both checked.

### How much of the label is private knowledge, measured

The question that decides how bad this is: does the label encode something only
the authors could know, or something any reader could recover?

Whether a scenario's own `make_broker` configures a value or call budget is a
property of the CONFIGURATION. It is fixed before anything runs, readable from
source, and requires trusting nobody.

| the scenario's grant | n | clayseal | dataflow taint |
| --- | ---: | --- | --- |
| configures a budget | 42 | **83.3% [69.4%, 91.7%]** | 2.4% [0.4%, 12.3%] |
| configures none | 90 | 18.9% [12.1%, 28.2%] | 15.6% [9.5%, 24.4%] |

Fisher exact p = 6.5e-11. **Configuration alone predicts the outcome 81.8% of the
time; the label predicts 98.5%.**

So the bulk of what the label knows is not private. It records a mechanical fact
about the grant, and it records the fact the architecture predicts should matter:
the aggregate rung has nothing to accumulate against when the constraint is not
expressed as a ceiling. The residual 18 points is the part that cannot be
checked, and it is 26 scenarios, enumerated in the label-free writeup.

### Generalization across authoring batches, with no label read

Leave one batch out. Held-out batches do **not** score systematically worse than
the rest, so there is no evidence of fitting to individual scenarios. What there
is instead is heterogeneity: held-out rates run from nothing to 87.5%, sd 0.327,
against a pooled 39.4%.

That is not a mechanism with a 37.9% success rate. It is a mechanism that works
on some kinds of scenario and not on others, and any pooled number is partly a
property of the suite's mix. It is also the justification for the cluster-robust
interval: with this much between-batch variance the naive interval is not
conservative, it is wrong.

### What is left

The residual is real and narrower than "the evaluation is contaminated":

- The bulk of the outcome is explained by a property observable without labels.
- The evaluation still cannot discover a failure mode nobody anticipated,
  because a scenario is only in the suite if someone wrote it.
- Any single pooled number should be read with the between-batch spread.

### The remaining gap, now partly closed

Adversarial search against the shipped gateway reads no labels and no scenario
file: it constructs candidates and keeps what gets through, so a failure it finds
is one nobody wrote down in advance.
[adaptive_stack_labelfree.md](adaptive_stack_labelfree.md), 250 tasks, 1,014,100
candidates, three attacker knowledge levels, 1,156s.

It **independently reproduces the published open gap**. On
`in-scope-exfiltration` the full stack contains exactly what the bare floor
contains, 8.0% blind and 15.2% under feedback, at every step-up setting: the
behavioural tiers add nothing to that class. `in_scope_exfiltration.md` says so
from a curated corpus; an adversary that was never told reaches the same number.

It also found something the curated suite does not report. On the neighbouring
`in-scope-content-staging` class the stack goes from 9.6% to 83.6% blind and
18.0% to 96.8% under feedback, **but only with `step-up=block`**; with
`step-up=allow` it falls back to the floor exactly. The flow tracker's entire
contribution on that class is carried by whether a step-up halts the action, so a
deployment treating step-up as advisory has the floor and nothing else there.
That is a deployment-relevant fact that no label could have encoded.

### And the external corpora, which answer half of it

Eleven corpora nobody here wrote, 5,279 attack events
([external_corpora_structure.md](external_corpora_structure.md)). They split
sharply and the split decides what they can validate.

**Surface-leaving attacks: 100% contained by task-scope, over 4,400 events across
five corpora.** That half of the claim has independent multi-corpus support.

**In-surface attacks: none contained, upper bound 1.9% on AgentHarm's 507
events.** The bound is tight enough to be a finding rather than noise, and it is
the same wall three other independent sources report.

The reason is measured and controlled rather than argued: **0 of 520 tasks across
four corpora declare a budget in their mandate.** The control is that the
synthetic `fixture` loader does produce them, so the machinery can express one and
the absence belongs to the corpora.

That cuts both ways and the second direction is the one to state first.

- It **explains why a purpose-built suite had to exist**, without special
  pleading: the existing corpora encode **attacks**, not **authorities**. A task
  carries a goal, a tool list and a hostile injection, and no ceiling, no expiry,
  no once-per-object rule.
- It also means **the external corpora do not independently confirm the aggregate
  result.** They are silent on the half this product is built for. Anyone citing
  the BPL numbers as externally validated would be wrong.

What is still missing is blind authoring: scenarios written by someone who has
not seen the mechanism, shipping a mandate with a ceiling and a benign twin.
Adversarial search explores the space its harness can generate, which is not the
same as the space a person would think of, and no external corpus carries the
input the aggregate rung needs.

## 3. Reproducibility: partly

`verify_results.py` reads the command a results file declares and re-runs it.

| | count |
| --- | ---: |
| results files | 77 |
| declare a command this gate can run | 19 |
| of those, still produce their own numbers | 4 |
| declare no runnable command | 58 |
| neither a command nor a `STATUS:` header | 38 |

The 38 with neither are the queue: a number nobody can check and nobody has
vouched for.

Read the failures as triage rather than as verdicts. The harness has a known
false-positive class it cannot fix cheaply: a table cell may hold a HISTORICAL
figure, and `commit_totality.md` reporting `NEVER_RAISES | 0 *(was 46)*` is
correctly missing 46 from a current run. Only an `ok` is evidence.

Two of the failures were diagnosed and were the file's fault rather than the
code's. `drift.md` reports 2,000 actions and the module defaults to 10,000, so
verification was comparing two different experiments; adding
`--actions 2000` to the file made it reproduce. That is the general shape of the
problem: **a results file that does not record its parameters is not
reproducible by anyone**, including its author.

Four bugs in the verifier itself were found and fixed while writing it, which is
its own argument for treating its output as advisory: comparison direction
reversed, dates in prose read as figures, thousands separators split into two
numbers, and shell paths matched as Python modules.

## What is already strong

Worth stating, because the sections above are all deficits.

- The **deterministic tier needs no model, no key and no money** and reproduces
  every structural claim in seconds. A benchmark whose claims can only be checked
  by spending money is one nobody checks.
- **`deny-all` is a permanent row.** A containment number that does not beat it
  is not a measurement, and it takes the containment column outright.
- **Zeros render as their bound.** `check_claims` enforces it on stamped files and
  ratchets the rest, and it failed the first draft of two files written this week,
  including the sentence explaining the convention.
- **Pre-registration exists** (`core/reporting.PreRegistration`), hashes its
  design, and `publishable()` mechanically refuses a cell with no denominator, a
  bare zero, fewer than five seeds, no prereg hash, or an unverified model
  identity.
- **46 of 47 benchmark scripts run.** The one holdout correctly refuses without
  its external dataset.

## Verdict

The statistics are publication-grade: paired tests, corrected for multiplicity,
with cluster-robust intervals justified by a measured between-batch spread.

Reproducibility is a known, enumerable, finishable gap: 38 files with neither a
command nor a status, and a tool that names them.

Evaluation-set independence is the one a reviewer finds first, and it is now
bounded rather than merely disclosed, from two directions. 81.8% of the outcome
is predictable from a configuration property no label is needed to observe. And a
label-free adversarial search reproduces the published open gap without being
told about it, while finding one thing the curated suite does not report.

What remains is what every curated benchmark has: it cannot surprise its authors,
and adversarial search only explores what its harness can generate. Saying that
plainly, with the 81.8% and the adaptive run beside it, is a defensible position.
Quoting a bare zero over twelve chosen scenarios is not.
