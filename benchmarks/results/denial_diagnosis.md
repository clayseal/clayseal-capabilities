# Where the utility goes, and what fixing it is worth

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

## The measured answer: full baseline utility at unchanged ASR

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

## Two harness bugs found while measuring this

Both would have published a fabricated improvement, and neither raised an error.

**The ablation ran with no defense at all.** `diagnose_methodology` resolved
planners from an exact-name dict. A new ablation name missed every key, got
`planner=None`, and therefore built no intent envelope. The run reported
**8/8 tasks, zero denials, a 50-point improvement** — a perfect score for a
defense that was not running. Planner selection now matches on shape and the
script refuses to start if any requested ablation resolves to no planner, so the
failure mode is a wrong planner (loud) rather than no planner (silent and
flattering).

**Run-to-run variance is larger than most differences we quote.** Identical
config, same suite, same model, two runs of `envelope-taint` on travel: **50%
and 75%**. One task is 12.5 points at n=8. No single-run difference smaller than
about 25 points on these suites should be read as a result, including the ones
in this document.
