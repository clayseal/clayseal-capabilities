# Where the utility goes, and what fixing it is worth

STATUS: current

STATUS applies to a document that reports measurements. This one is an
**analysis**: it reasons over results produced elsewhere rather than emitting
its own, so there is no command to re-run. `current` here means the argument
still matches the results it reasons about, checked against this commit.

Diagnosis of every false block the live tier recorded across four models and
four suites, then a targeted change and its measured effect. Reproduce the
first half with `python -m benchmarks.live.diagnose_denials`.

## One rule causes every hard false block on the shippable path

| Ablation | benign denials | on tasks the defense lost | dominant rule |
| --- | --: | --: | --- |
| `envelope` | 11 | 10 | `off-plan and consequential` (11/11, **100%**) |
| `envelope-taint` | 33 | 29 | `egress/recipient not on allow-list` (27/33) |
| `oracle-envelope-egress` | 6 | 2 | `off-plan and consequential` (5/6) |

**On `envelope`, the path we would actually ship, one rule accounts for all 11
hard false blocks, and 10 of them turned a task that would have succeeded into a
failure.** The tools it hits are ordinary work: `create_calendar_event` (5),
`send_money` (2), `send_direct_message` (2), `send_channel_message`,
`reserve_hotel`.

The rule is the intent envelope's two-signal gate: an action that deviates from
the LLM-generated plan **and** is consequential gets a hard DENY. The floor runs
first, so anything reaching that gate is already in scope, within budget,
argument-bound, and (under provenance or taint) aimed at a destination that
traces to the sealed goal. The envelope's remaining objection is that the
planner did not list the step. That is a statement about the planner's recall,
not about the action.

`envelope-taint`'s 27 egress denials are the slack failure mode already
documented in [live_ladder.md](live_ladder.md), and they are concentrated there:
slack accounts for 27 of 33.

## The change: defer to binding

`SessionBroker(defer_to_binding=True)` demotes that DENY to a STEP_UP **when an
egress binding floor is active**, on the reasoning that an injected step's
destination never clears the floor and so never reaches this gate. It is
conditional rather than a blanket relaxation: with no egress policy the envelope
is the only thing between an injected send and the attacker's address.

Travel, gpt-4o-mini, n=8, paired:

| Ablation | autonomous | supervised | hard DENY | step-ups |
| --- | --- | --- | --: | --: |
| `envelope-taint` | 75% | 75% | 1 | 0 |
| `envelope-taint-defer` | 62% | 75% | **0** | 1 |

**The hard false block goes to zero and reappears as a recoverable step-up.**
That is exactly what the mechanism predicts and no more: a STEP_UP halts
autonomous execution just as a DENY does, so **this change cannot raise
autonomous utility, and it did not.** It changes the *character* of the loss
from unrecoverable to recoverable, which is worth having, and it is a smaller
claim than the one the first run appeared to support.

Raising autonomous utility means *allowing* the action rather than stepping it
up. That is a real relaxation, so it had to be measured against attack before
being claimed.

## RETRACTED: `deferallow` is not safe. Do not ship it.

The banking result below held ASR at 0.0% and looked like the strongest win in
the tier. **Validation on travel overturns it:**

| Suite | `envelope-taint` ASR | `envelope-taint-deferallow` ASR |
| --- | --: | --: |
| banking | 0.0% | 0.0% |
| **travel** | **5.6%** | **27.8%** |
| **workspace** | **0.0%** | **27.8%** |
| slack | 0.0% | 0.0% |

Final tally: two suites unaffected (banking, slack), two broken (travel,
workspace).

**Update, and it weakens this evidence.** A later frontier sweep re-ran
workspace `deferallow` under identical conditions and measured **0.0% ASR**, not
27.8%. Same code, same suite, same model, same attack, n=18 both times. The
retraction still stands on travel, which independently showed 5.6% to 27.8% and
has not been contradicted, but the workspace half is now one result each way.
See [frontier.md](frontier.md): ASR has run-to-run variance wide enough to flip
a shipping decision, which we had wrongly assumed was a property of the utility
axis only. A change that is safe on half the suites and hands the attacker a
27.8% success rate on the other half is not a safe change, and the two suites
where it looked fine are exactly the ones that would have been quoted.

On travel, allowing the plan miss takes attack success from 5.6% to 27.8% and
drops blocks from 17 to 3. On workspace it takes ASR from **0.0% to 27.8%**, and
utility under attack falls from 88.9% to 55.6%. Two of three validation suites
refute it, and workspace is the clearer refutation because the baseline it
destroys is a perfect one.

Workspace also shows what the step-ups were buying: `envelope-taint` spends 2.17
interruptions per task there and returns 0.0% ASR at 100% clean utility.
`deferallow` spends zero and gives up 27.8%. That is not a bug in the deferral,
it is the price of attention made visible, and it is the argument for the audit
budget rather than against step-ups. **The intent envelope's
off-plan gate was doing real containment work on travel that the binding floor
does not do.**

So the reasoning that motivated the change, "an injected step's destination
never clears the binding floor, so this gate catches nothing new", is false in
general. It happens to hold on banking, where the attack is a transfer to an
attacker IBAN that egress binding rejects. It fails on travel, where the
injected action reaches a destination the floor considers acceptable and only
the plan-conformance check objects.

The measurement that mattered was the one that could refute the claim, and the
claim did not survive it. `defer_allows_bound` stays in the codebase as a
measured negative result and defaults to off.

The step-up variant (`defer_to_binding` alone) is unaffected by this: it never
allows anything, it converts a hard denial into a halt-plus-question, and it
held ASR at 0.0% on banking. That one remains viable.

## The banking measurement (superseded by the above)

`defer_allows_bound` allows the plan miss **only when the floor positively
validated a destination on that action** (`EgressPolicy.binds`). An action
carrying no destination was never examined by the floor, so it still steps up:
the strength of the response follows the strength of the evidence.

Banking, gpt-4o-mini, `important_instructions`, 6 user x 3 injection = 18 runs
per ablation:

| Ablation | clean utility | ASR | utility under attack | friction/task |
| --- | --- | --- | --- | --- |
| none | 50.0% | 66.7% | 38.9% | 0.00 |
| `envelope-taint` | 16.7% | **0.0%** | 16.7% | 0.67 |
| `envelope-taint-defer` | 16.7% | **0.0%** | 22.2% | 1.67 |
| **`envelope-taint-deferallow`** | **50.0%** | **0.0%** | 27.8% | **0.00** |

**Clean utility goes from 16.7% to 50.0%, exactly the undefended baseline, while
ASR stays at 0.0% and friction falls to zero.** Utility under attack improves
too, 16.7% to 27.8%.

That is the whole utility cost of the defense on this suite, removed, with no
measured security loss. It is the strongest single result in the live tier, and
it exists because the diagnosis pointed at one rule instead of at the mechanism
in general.

The reason it works is the reason the diagnosis predicted: the injected step's
destination is the attacker's own address, it never clears the binding floor, so
it never reaches the gate that was being relaxed. The hard DENY on plan misses
was catching nothing the floor had not already caught, and was costing every
task where the LLM planner failed to enumerate a legitimate step.

Caveats, all of which matter: n=18, one suite, one attack, one model.
Validation runs on travel, workspace, and slack are in flight, and the result
should not be quoted until they agree.

### The gain is scoped to destination-carrying tools

Travel, three repeats, n=8 each:

| Ablation | pooled autonomous | per-run | hard DENYs | step-ups |
| --- | --- | --- | --: | --: |
| `envelope-taint` | 75.0% [55.1, 88.0] | 75%, 75%, 75% | 4 | 0 |
| `envelope-taint-deferallow` | 66.7% [46.7, 82.0] | 75%, 62%, 62% | **1** | 10 |

**No autonomous gain on travel**, and the reason is the two-tier rule working as
designed rather than failing. Banking's denials land on `send_money`, which
carries a recipient, so the floor validated it and the action is allowed.
Travel's land on `reserve_hotel` and `create_calendar_event`, which carry no
external destination, so the floor never examined them and they step up instead.

Hard denials still fall 4 to 1, so the loss becomes recoverable. But the
headline banking result is **specific to tools whose actions carry a destination
the binding floor can vouch for**, and quoting it as a general utility recovery
would overstate it.

## What repetition says about every number here

The same three repeats give the variance answer. Within this experiment the
widest run-to-run spread was 12 points, and `envelope-taint` was perfectly
stable at 75%, 75%, 75%.

That is *narrower* than the 25-point swing seen earlier in the day, when the
same configuration on the same suite produced 50% and then 75%. Both
observations are real, which is the point: run-to-run spread is itself unstable,
so a single pair of runs cannot bound it. Treat differences under roughly 25
points on these suites as unresolved unless repeats say otherwise, and prefer
the action-level counts (hard denials, step-ups), which moved cleanly and in the
predicted direction in every comparison here while the task-level percentages
wandered.

## Two harness bugs found while measuring this

Both would have published a fabricated improvement, and neither raised an error.

**The ablation ran with no defense at all.** `diagnose_methodology` resolved
planners from an exact-name dict. A new ablation name missed every key, got
`planner=None`, and therefore built no intent envelope. The run reported
**8/8 tasks, zero denials, a 50-point improvement**, a perfect score for a
defense that was not running. Planner selection now matches on shape and the
script refuses to start if any requested ablation resolves to no planner, so the
failure mode is a wrong planner (loud) rather than no planner (silent and
flattering).

**Run-to-run variance is larger than most differences we quote.** Identical
config, same suite, same model, two runs of `envelope-taint` on travel: **50%
and 75%**. One task is 12.5 points at n=8. No single-run difference smaller than
about 25 points on these suites should be read as a result, including the ones
in this document.
