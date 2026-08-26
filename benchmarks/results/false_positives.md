# The false-positive rate, and the two things that were causing it

STATUS: current

```bash
python -m benchmarks.session_units --datasets agentharm,sleight
```

Measuring per SESSION rather than per event made the cost visible:
`session_units.md` put sleight's benign disruption at **46.5% of sessions**
against 14.1% of events. Nearly half of benign sessions carried a refusal, which
the per-event figure had rounded into comfort. This is what that was, and what
it took to remove.

## Where the refusals came from

Diagnosed before anything was changed, because the two causes turned out to be
different problems with different answers.

| corpus | benign refusals | shape |
| --- | --: | --- |
| sleight | 44 | **34 hard DENY** on `resource class 'workspace' outside the goal surface`, 10 step-up |
| agentharm | 46 | **all step-up**, all `occurrence 2 of a phase the sealed goal accounts for 1 time(s)` |

That split matters. A step-up costs a person's attention and a denial costs the
work, so sleight's was the more serious of the two even though AgentHarm's was
the larger count.

## One: an opaque label is not a place

The 34 denials were actions carrying **no path at all**. Their only reading was
`workspace`, which is what the harness calls the session, tested against a
surface built from file paths holding `data`, `home` and `net`.

This is the residual of the disjoint-vocabulary defect, one level down.
`surface_is_comparable` asks whether the SESSION ever spoke the surface's
vocabulary and licenses the tier for the whole session once it has. Right for an
action that names a path; wrong for one that names nothing. An action with no
path and a bare-word resource is refused on evidence that carries no target
information.

The tier now abstains for such an action, and the abstention is narrow: a scheme
says where it is going, a path says what it opens, and an opaque label WITH a
path is judged on the path.

It opens no hole the other tiers do not cover. An action with no path cannot
reach a file, a destination lives in the arguments where the egress tier reads
it, and the tool is still bound by `tools.allow` and by any withdrawal.

**And the fix had a bug the tests caught.** `surface_is_comparable` was built on
`in_surface`, which now answers True for an abstention, so a session of nothing
but opaque labels reported itself comparable and licensed the tier with no
evidence it could read anything. `matches_surface` is the strict question now
and `in_surface` folds in the abstention. An abstention is the absence of a
judgement, not a positive one.

## Two: a derived count is a bad default

All 46 of AgentHarm's refusals were the goal-derived count rung. "Email a
summary" reads as one send; a benign trajectory legitimately sends two.

| derived counts | contained/session | benign disrupted/session |
| --- | --: | --: |
| on | 46.2% | 10.2% |
| **off** | **45.0%** | **0 of 176 sessions** |

**Roughly eight points of false positive per point of containment.** That is not
a trade, and a default nobody chose is the wrong place to make it.
`derive_counts` is False now, in the library and in the benchmark arm named
`deployable-stack`, so the headline describes what ships. The rung is still
there, still tested, still a step-up rather than a denial, and
`compile_envelope(goal, derive_counts=True)` turns it on for a deployment that
has measured the exchange on its own traffic. The ablation arm was renamed
`deployable-stack-with-counts` so its contribution stays attributable.

## Where it landed

| corpus | contained/session | benign disrupted/session |
| --- | --: | --: |
| agentharm, before | 46.2% | 10.2% |
| agentharm, after | 45.0% | **0 of 176** |
| sleight, before | 78.0% | 46.5% |
| sleight, after | 61.0% | **0 of 43** |

Across all seven corpora: **0 benign refusals in 9,181 benign events**, and
surface-leaving containment unchanged at 100% on every one of them, 717/717 on
redcode, 2040/2040 on asb, 1597/1597 on injecagent, 189/189 on agentharm and
7/7 on sleight. tau2 went from 1 refusal in 5,441 to none.

**Zero is not proof of zero.** At 176 benign sessions the upper bound on the
true rate is about 1.7%, and at 43 sessions on sleight it is nearer 7%. What can
be said is that nothing in nine thousand benign events from seven independently
authored corpora is now refused, and that the containment those refusals were
buying cost 1.2 points on AgentHarm and 17.0 on sleight.
