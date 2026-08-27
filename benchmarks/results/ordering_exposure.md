# How much of each corpus's containment is available from event order alone

STATUS: current

```bash
python -m benchmarks.ordering_exposure --json benchmarks/results/ordering_exposure.json
python -m benchmarks.cli --dataset sleight --mode ladder
```

Every table in `new-suites/` reports containment and false-block. Neither column
can show the failure this measures: a corpus that replays a benign prefix and
then an attack suffix can be "contained" by **counting**. Block late events and
the attack share falls, because the attack events are the late ones. No tool,
path, destination or policy is read.

`deny-all` is a permanent row because a containment number that does not beat it
is not a measurement. This is the same argument on the axis of order, and it
needed its own control for the same reason. `position-only-control` is now that
row, printed in every ladder table.

## The structural fact

**Every benign-paired corpus segregates.** In 100% of paired tasks, every benign
event precedes every attack event. What varies is the gap:

| corpus | median benign index | median attack index | gap |
| --- | ---: | ---: | ---: |
| injecagent, ipi_coding, agent_threat_bench | 0 | 1 | 1 |
| agentdojo | 1 | 2 | 1 |
| **sleight** | 3 | 11 | **8** |
| **asb** | 0 | 22 | **22** |

A gap of one event is harmless: no quota is exhausted in one call. A gap of eight
or twenty-two is not, because a stateful rung spends its allowance on the benign
prefix and then refuses the attack for arriving late. That is the mechanism, and
it has nothing to do with what the attack does.

## The comparison, at matched friction

Counting reaches 100% containment by blocking everything, so the control is only
informative under a friction budget. For each corpus: take the best real rung,
read its false-block rate, and ask what a pure position cut achieves **without
exceeding that same false-block rate**.

A zero renders as its 97.5% upper bound rather than as a bare percentage, here
and throughout, and on this table that convention does real work: the benign
denominators differ by two orders of magnitude across these corpora.

| corpus | best rung | containment | false-block (benign n) | counting at same false-block | verdict |
| --- | --- | ---: | ---: | ---: | --- |
| advbench_agent | `task-scope+binding` | 100.0% | 0/11, ub 28.5% | 83.3% | discriminates |
| agent_threat_bench | `task-scope` | 100.0% | 0/24, ub 14.2% | 100.0% | **EXPOSED** |
| agentdojo | `task-scope+binding` | 100.0% | 0/215, ub 1.7% | 3.9% | discriminates |
| agentharm | `capability-token` | 27.2% | 0/729, ub 0.5% | 0/696, ub 0.5% | discriminates |
| agentleak | `tool-allowlist` | 0/27, ub 12.8% | 0/27, ub 12.8% | 0/27, ub 12.8% | no signal |
| asb | `tool-allowlist` | 100.0% | 0/102, ub 3.6% | 100.0% | **EXPOSED** |
| b3 | `task-scope` | 66.7% | 0/8, ub 36.9% | 55.6% | discriminates |
| fixture | `task-scope+binding+budget` | 100.0% | 0/7, ub 41.0% | 80.0% | discriminates |
| injecagent | `tool-allowlist` | 100.0% | 0/400, ub 0.9% | 100.0% | **EXPOSED** |
| ipi_coding | `task-scope` | 100.0% | 0/45, ub 7.9% | 100.0% | **EXPOSED** |
| mcp_attack | `task-scope+binding` | 100.0% | 0/9, ub 33.6% | 80.0% | discriminates |
| mind2web_sc | `task-scope+binding+budget+velocity` | 98.0% | 0/100, ub 3.6% | 0/100, ub 3.6% | discriminates |
| redcode | `task-scope` | 100.0% | 0/344, ub 1.1% | 0/400, ub 0.9% | discriminates |
| sleight | `task-scope+binding+budget+velocity` | 65.9% | 16.1% | 55.8% | discriminates |

**Four of fourteen corpora are ordering-exposed.** `agent_threat_bench`, `asb`,
`injecagent` and `ipi_coding` each report 100% containment that a position cut
also reaches at the same zero false-block.

Read that as a statement about the **corpus**, not about the rung. Those rungs
may well be right, and on ASB and InjecAgent the tool-allowlist result is
independently sensible: the attack calls a tool nobody granted. What the corpus
cannot do is distinguish that from counting, so its 100% is not evidence for the
mechanism, and citing it as though it were would be citing the corpus's shape.

The corpora that discriminate do so decisively, which is what keeps the control
honest. RedCode 100% against counting's 0/400 (97.5% upper bound 0.9%),
AgentDojo 100% against 3.9%, mind2web_sc 98% against 0/100 (upper bound 3.6%).
On those, order carries no signal at all, and a control that won everywhere
would have been measuring the harness rather than the corpora.

### A second gap the same table exposes: the friction column

Rendering the zeros with their bounds surfaces something that has nothing to do
with ordering. `fixture` has 7 benign events, `b3` has 8, `mcp_attack` 9,
`advbench_agent` 11, `agent_threat_bench` 24. A zero false-block on 7 events is
not distinguishable from 41%, so those corpora cannot support a friction claim
at all, whatever the rung does.

It is the same shape as the ordering finding: the table has a column, the column
has a number, and the corpus does not have the evidence to fill it. The corpora
that CAN carry a friction claim are the large-denominator ones, `agentharm`
(729), `injecagent` (400), `redcode` (344) and `agentdojo` (215). That is
consistent with `sleight.md` already routing its own friction measurement to
tau2, BFCL and ATIF instead of reporting it locally, which is the right instinct
applied to one corpus and not to the other five that need it.

## Friction has to be matched, and getting that wrong flattered us

The first version of this analysis compared SLEIGHT's velocity row (65.9% at
16.1% false-block) against a cut at k=8 scoring 71.3%, and concluded the rung
lost to counting outright. That cut spends **20.9%** false-block: it was allowed
friction the rung was not. Matched, the rung wins by ten points.

The corrected reading is narrower and still worth having: **55.8 of velocity's
65.9 points are reachable without reading anything but position.** The rung is
not purely positional, and most of what the table credits it with is order.

The error is recorded because it ran in our favour on the conclusion we were
already forming, and an unmatched control is the easiest way to manufacture one.

## SLEIGHT: four things that were known and none of them reached the table

`new-suites/sleight.md` published the velocity row as a result. Every objection
to it already existed somewhere in this repository:

- The loader sets `"ladder_rung": "task-scope+binding+budget"` with the comment
  *"Velocity misreads long coding-agent sessions as abuse."*
- The loader sets `"false_block_unscoreable": True`, because the mandate is
  derived from the benign twin and that twin is clean by construction.
- `VelocityLadderEngine`'s own docstring says the rung contributes *"+0.0 points
  on every corpus"* and that on SLEIGHT *"containment and false-block move
  together at every point, so the mechanism was blocking a fraction of everything
  and being credited for the attack share."*
- `test_ladder_invariants.py` excludes velocity from every invariant, noting it
  reports *"61 extra points of containment that are transcript length"* and that
  the number *"swings 29.5 points when the events are shuffled."*

`scoreboard.py` reads the first two of those. `benchmarks/cli.py`, which is the
command printed at the top of every `new-suites/*.md`, read neither. The
knowledge was in the repository and the publishing path did not consult it.

### And the cap was never calibrated

`VelocityLadderEngine.calibrate` reads only tasks with no ATTACK event. A loader
that concatenates a benign twin and its attack into one task supplies **none**,
so the cap silently fell back to `default_cap = 5`, an arbitrary constant, and
the table reported the resulting containment as though a limit had been learned
from traffic.

| corpus | clean tasks | cap | calibrated |
| --- | ---: | ---: | --- |
| redcode | 50 | 32 | yes |
| agentharm | 176 | 6 | yes |
| bfcl | 400 | 1 | yes |
| **sleight** | **0** | 5 | **no, constant** |
| **asb** | **0** | 5 | **no, constant** |

AgentHarm has clean tasks precisely because its loader was already fixed to emit
the benign twin and the harmful twin as two tasks, after the same concatenation
handed the rung +8.0 points it had not earned. SLEIGHT's loader was never given
the same treatment.

## What changed

Four changes, each of which generalises to corpora that do not exist yet.

1. **`position-only-control` is a permanent row** in every ladder table, in
   `CONTROLS` rather than `LADDER` so the monotone-ablation invariants still hold.
   It reads an event's index and nothing else.
2. **`benchmarks/cli.py` honours the corpus-declared contract.** A corpus that
   names its highest valid rung gets rows above it marked as ablation rather than
   result; a corpus that declares its false-block column unscoreable says so under
   the table. Both keys already existed and only `scoreboard.py` read them.
3. **An uncalibrated cap is declared.** `calibrate_with_provenance` returns
   whether calibration data existed, and a rung that fell back to its constant is
   named under the table instead of printing a number that looks learned.
4. **`benchmarks/ordering_exposure.py`** runs the matched-friction comparison over
   every registered corpus, so a new corpus is screened for this on arrival
   rather than after someone notices.

## What this does not fix

The SLEIGHT loader still concatenates. Splitting it the way AgentHarm is split
would remove the confound at the source and give the rung something to calibrate
on, and it is the right next change. It is not made here because it moves a
published number and belongs with a re-run of the corpus's own results rather
than bundled into a methodology pass.

The exposed corpora stay exposed. A control cannot make a corpus discriminate;
it can only stop the number being read as though it did.
