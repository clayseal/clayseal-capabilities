# What the external corpora can and cannot measure

STATUS: superseded in part

## Correction

The in-surface containment figures for the shipped stack below, 24.9% on
AgentHarm and 20.5% on sleight, were measured with a membership tier that
refused actions whose resource vocabulary the goal surface could not express,
and with a detector that was never wired in at all. Both are fixed. The current
figures are **31.6% on AgentHarm and 37.7% on sleight**, at 6.3% and 14.1%
benign cost respectively, and the composed detector arm adds an operating curve
on top. See [composed_detector.md](composed_detector.md).

The structural finding this file exists for is unchanged and now rests on
better numbers: the surface-leaving population is contained at 100% and the
in-surface population is the wall.

```bash
python -m benchmarks.coverage --datasets redcode,agentharm,asb,injecagent,agentleak,mcp_attack,sleight,advbench_agent,agent_threat_bench,ipi_coding,b3 --limit 4000
```

Eleven corpora, none of them written here, 5,279 attack events. They are the
independent evaluation the BPL suite cannot be
([bpl_label_free.md](bpl_label_free.md)), so the question is what they say about
where the mechanism structurally fails.

The answer has two halves and the second one is about the corpora rather than
about the gateway.

## The structural split

`coverage.py` partitions attacks **without consulting any engine**.
`surface-leaving` means at least one field (tool, resource, action, target) falls
outside what the task's own mandate and benign trajectory establish.
`in-surface` means every field is one the task legitimately uses.

| corpus | attack events | surface-leaving | in-surface |
| --- | --: | --: | --: |
| asb | 2040 | 2040 (100%) | 0 |
| injecagent | 1598 | 1597 (100%) | 1 |
| redcode | 718 | 717 (100%) | 1 |
| agentharm | 696 | 189 (27%) | **507 (73%)** |
| sleight | 129 | 7 (5%) | **122 (95%)** |
| ipi_coding | 50 | 50 (100%) | 0 |
| agentleak | 22 | 0 | **22 (100%)** |
| b3 | 9 | 6 (67%) | 3 (33%) |
| advbench_agent | 6 | 4 (67%) | 2 (33%) |
| agent_threat_bench | 6 | 6 (100%) | 0 |
| mcp_attack | 5 | 2 (40%) | 3 (60%) |

Two populations, and they barely overlap. Five corpora are essentially all
surface-leaving; three are essentially all in-surface.

Containment splits the same way. **The first version of this file reported the
in-surface column as nothing across the board, and that was wrong**: the
structural analysis went through `build_engines`, which had every ablation rung
registered and not the shipped product. It measured the ladder and called it the
system. `deployable-stack` is registered now.

| corpus | engine | surface-leaving | in-surface |
| --- | --- | --- | --- |
| agentharm | ladder top | 100.0% [97.0%, 100.0%] | **0.0% [0.0%, 1.9%]** |
| agentharm | **shipped stack** | 100.0% [97.0%, 100.0%] | **24.9% [18.8%, 30.8%]** |
| sleight | ladder top | 100.0% [25.0%, 100.0%] | 0.0% [0.0%, 7.3%] |
| sleight | **shipped stack** | 100.0% [25.0%, 100.0%] | **20.5% [13.8%, 28.4%]** |
| agentleak | shipped stack | n/a | 0.0% [0.0%, 13.6%] |

**Every point of that comes from the step-up path.** The same stack with
`treat_step_up="allow"`, the pessimistic supervised reading where a human
approves everything, scores 0.0% [0.0%, 1.9%] on AgentHarm: identical to the
ladder. That is the third independent measurement of the same thing, after
`adaptive_stack_labelfree.md` found the whole `in-scope-content-staging`
contribution carried by whether a step-up halts the action. A deployment that
treats step-up as advisory has the floor and nothing else on this class.

**507 in-surface attack events in AgentHarm, of which the ladder contains none,
upper bound 1.9%.**
That bound is what makes this a finding rather than small-sample noise, and it is
the same wall four independent sources now report: `in_scope_exfiltration.md` from
a curated corpus, the BPL `in-scope` family, the label-free adversarial search
([adaptive_stack_labelfree.md](adaptive_stack_labelfree.md)), and this.

## The in-surface population is not one class

A budget can only see a violation that is a property of a SEQUENCE. Counting
attack actions per task separates two very different things:

| corpus | tasks with attacks | attack events | tasks whose attack is a SINGLE action |
| --- | --: | --: | --: |
| agentharm | 176 | 696 | **0 of 176** |
| sleight | 43 | 129 | 8 of 43 (19%) |
| agentleak | 22 | 22 | **22 of 22 (100%)** |

- **AgentLeak is entirely single-action.** One authorized call is itself the harm.
  No aggregate rung can ever see it, because there is no aggregate. Zero
  containment there is structural and not a gap.
- **AgentHarm has no single-action tasks at all**, 0 of 176, 2 to 7 actions each. It is
  sequence-shaped, so zero containment is *not* structurally forced. Something
  else explains it.

## What explains it, controlled

Zero of 520 tasks across `agentharm`, `sleight`, `agentleak` and `redcode`
declare a budget in their mandate. Not one.

The control that matters: **the synthetic `fixture` loader does produce budgets**,
1 of 4 tasks, so the loader machinery can express them and the absence is a
property of the corpora rather than a harness bug.

So the absence of containment is the deployment rule, reproduced on
independently-authored data at its limit. `bpl_label_free.md` measures 83.3% [69.4%, 91.7%] containment where the
grant expresses the constraint as a budget against 18.9% [12.1%, 28.2%] where it
does not. These corpora declare none at all, 0 of 520, and the aggregate rung has
nothing to accumulate against.

## What this means, in both directions

**It explains why the BPL suite had to be written**, without special pleading.
The existing corpora are prompt-injection and harm-refusal corpora: they encode
**attacks**, not **authorities**. A task carries a goal, a tool list and a
hostile injection, and no ceiling, no expiry, no once-per-object rule. An
authorization layer measured on them can only be measured on the half of its job
they describe.

**And it means these corpora do not independently confirm the aggregate result.**
They confirm the surface-leaving half decisively, 100% containment by task-scope
over more than 4,400 events across five corpora, and they are silent on the half
this product is actually built for. Anyone quoting the BPL numbers as
externally validated would be wrong, and this file is the reason.

The honest position: the surface-leaving claim has independent multi-corpus
support; the aggregate claim has a purpose-built suite, a label-free
configuration split, and an adversarial search, and no external corpus that
carries the input it needs.

**Half of that changed.** `tau2_policy_enforcement.md` compiles each tau2 domain's
own `policy.md` into a grant and replays that domain's own ground-truth action
sequences through it: **13,906 of 13,907 pass**. The rules are theirs, the
traffic is theirs, the state comes from their `db.json`, and nobody here chose a
scenario or labelled an outcome. That is external validation of FRICTION, and it
is what was impossible before `policy_draft` could read a rule out of prose and
`tools.when` could express the shapes prose actually uses.

The aggregate CONTAINMENT claim is still unvalidated externally, and for the
reason stated above rather than a new one: tau2 scores whether the AGENT refuses,
16 of its 50 airline tasks test exactly that, and a gateway needs a corpus
carrying the attempted violation as a CALL. Constructing that call here would be
this objection arriving one level down.

## What was built in response, and where it stands

The in-surface population splits into two things and only one of them is fixable
by an authorization layer.

**AgentLeak, single-action, 22 of 22.** One authorized call is the harm. No
aggregate rung can ever see it and none should be built to pretend otherwise.
Content judgement is the only instrument, which in this layer means the
entailment judge, advisory and step-up only.

**AgentHarm, sequence-shaped, 0 of 176 single-action, and no budget declared.**
This one is fixable, and the fix is not "ask operators to declare budgets",
because 0 of 520 tasks do and a rung that waits for a declaration is inert
exactly where it is needed. The bound has to be **derived**.

`monitor/multiplicity.py` derives it from the sealed goal. The envelope could
already say which tools a plan uses and whether a phase repeats at all, never how
many times, so "email a summary" admitted one send and fifty identically. A phase
now carries `max`, `Deviation.OVER_COUNT` names the miss, and the broker turns it
into a **step-up rather than a denial**: the bound came from reading a sentence,
so "you said one and this is the second" is a reason to ask, not to refuse. A
retry after a failed send looks identical.

It is deliberately conservative and most goals get no bound at all. Three signals
produce one, any iteration marker suppresses it, and a clause supporting two
different readings yields none, because a bound nobody clearly stated must not
exist.

**Measured on these corpora: 52 of 200 AgentHarm goals yield a bound, 3 of 43 on
sleight, 0 of 27 on AgentLeak.** The last is correct and the first is the useful
number.

**What is NOT yet measured is whether that moves containment**, and it is worth
being exact about why. `benchmarks/core/stack_factory.py` builds the benchmark's
stack without an intent envelope at all, so the capability cannot be exercised on
this corpus without changing the harness, and changing the harness at the end of
the session that built the capability is the sequence problem
`grant_changes_2026_08.md` already had to disclose once. The mechanism is
demonstrated end to end in `python/tests/test_multiplicity.py`, on a bare goal
with no budget declared anywhere, and the corpus measurement is the next step
rather than a claim made here.

## What would change that

A corpus of **authorities**, not attacks: tasks that ship a mandate with a
ceiling, a window, an expiry or an once-per-object rule, and a benign twin.
`benchmarks/bpl` is one, written here, which is exactly the objection. The
useful version is authored elsewhere.

Short of that, the closest external instrument is `tau-bench`/`tau2-bench`, which
measure policy adherence and do carry declarative rules. They are diagnostics
rather than defenses and do not ship the rule in a machine-readable grant, so a
loader would have to compile their prose policies into mandates, and that
compilation would be ours.

## One hypothesis that died on the way

The verb vocabulary looked like a candidate gap. `broker._WRITE_ACTIONS` and
`_EGRESS_ACTIONS` list eight and four verbs, and 14 verbs that
`monitor.consequence.is_consequential` calls consequential appear in neither:
`execute`, `run`, `install`, `exec`, `invoke`, `apply`, `deploy`, `commit`,
`publish`, `upload`, `grant`, `revoke`, `approve`, `call`. Sleight's in-surface
population is 60/129 `execute`, which made it look load-bearing.

It is not. Both the path scope and the egress check are **verb-independent**,
verified by driving ten verbs including invented ones (`exfil`, `sync`, `export`)
at an off-allow-list destination and getting a denial from every one. The two sets
gate only an optional soft rung (`require_declaration_for_egress`) and the
protected-zone read/write label. Recorded because the next person to read those
two constants will have the same idea.
