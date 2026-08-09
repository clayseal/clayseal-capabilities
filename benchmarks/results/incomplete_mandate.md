# What an incomplete mandate costs, and what it takes to fix

Our headline friction number, 0.00% false-block across 18,356 benign events, is
conditional on a mandate that names everything the task will touch. Rebuild the
grant from half a task's benign events and score the other half, and it becomes:

| corpus | FB, complete grant | FB, held-out grant |
| --- | --: | --: |
| tau2 | 0.03% | **47.91%** |
| ToolEmu | 0.00% | 54.74% |
| AgentHarm | 0.00% | 58.44% |
| ASB | 0.00% | 50.00% |
| ATIF | 1.94% | 21.29% |
| BFCL | 0.00% | 19.65% |

**A mandate that misses half the resources blocks about half the work.** That is
the operational risk a buyer carries, and it is invisible in the left column.

## What is actually being refused

Every refused resource on tau2 and ToolEmu is an `mcp:tool:` identifier. The grant
lists specific tools; the held-out events call tools it never saw. tau2 averages
3.4 distinct benign resources across 6 events per task, so holding out half grants
about two and leaves about one and a half unseen.

This is not a pathological construction. It is the shape of a planner-derived
scope, which is what the live path has: the LLM planner guesses the tools a task
needs, and on an open-ended task it cannot know. AgentDyn made that concrete, with
zero clean utility and 254 of 281 actions blocked before runtime replanning
existed.

## Three ways to widen the grant, measured

Each admits an ungranted resource under a different rule.

| corpus | no extension | any verb class | reversible only | goal-conditioned |
| --- | --- | --- | --- | --- |
| tau2 | -/48.1% | -/**8.5%** | -/34.3% | -/48.1% |
| BFCL | -/18.0% | -/6.5% | -/8.6% | -/18.0% |
| ATIF | -/27.0% | -/2.8% | -/3.5% | -/26.6% |
| ToolEmu | 100%/54.7% | 100%/**0.0%** | 100%/0.0% | 100%/54.7% |
| ASB | 100%/50.0% | **5.8%**/9.8% | **5.8%**/9.8% | 100%/50.0% |
| AgentHarm | 6.3%/57.7% | 3.1%/25.4% | 3.7%/36.0% | 6.3%/57.1% |

Cells are containment / false-block.

**The headroom is real.** Verb-class extension takes tau2 from 48.1% to 8.5% and
ToolEmu to 0.0%, so most of the friction is recoverable in principle.

**The naive rule is unsafe.** It collapses ASB containment from 100% to 5.8%. ASB
is the canary here: its containment is entirely the tool allowlist, so any rule
that admits ungranted tools destroys it by construction. That is the same failure
shape as `defer_allows_bound`, which took AgentDojo travel from 5.6% to 27.8% ASR,
and as un-interlocked replanning, which took it from 11.1% to 22.2%.

**Restricting to reversible actions does not save it.** ASB stays at 5.8%, because
its attack verbs classify as reads and calls rather than effects, so the
reversibility gate never fires on them. It costs most of the recovery too, leaving
tau2 at 34.3%.

**Goal-conditioned matching does nothing deterministically.** Requiring the sealed
goal to name the tool changes tau2 by 0.0 points, because tau2's summaries are
natural language and never contain tool identifiers. The rule is right and the
corpora cannot express it without a model.

## The conclusion

The friction is recoverable and no deterministic rule tested here recovers it
safely. The safe version needs a judge that reads the sealed goal, and an
interlock so that a consequential action still needs its destination validated by
the floor.

That is precisely what the live path runs, and there it works:

| suite | clean utility | ASR |
| --- | --- | --- |
| AgentDojo banking | 16.7% to **50.0%** | 0.0% throughout |
| AgentDojo workspace | 83.3% to **100.0%** | 0.0% throughout |
| AgentDyn shopping | 0.0% to **50.0%** | 16.7% undefended, 5.6% defended |
| AgentDyn github | 0.0% to **16.7%** | 61.1% undefended, 0.0% defended |

So the honest product statement is that the deterministic tier measures the
enforcement floor, and the mechanism that makes an incomplete mandate survivable
lives above it and is only measurable on the live path. Reporting the 0.00% from
the left column without this document attached would overstate what the floor does
on its own.

## Reproduce

```bash
.venv/bin/python -m benchmarks.scoreboard        # both false-block columns
```

The extension sweep is a research probe rather than shipped behaviour; the shipped
mechanism is `agentauth/capabilities/replan.py` with the destination interlock in
`agentauth/capabilities/broker.py`.
