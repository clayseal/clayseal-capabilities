# Bounding the session trajectory

**Status: designed, not implemented.** This is the write-up of a change that was
scoped for 0.6 and deliberately left out of it. It is here so the next attempt
starts from the analysis rather than repeating it.

## The problem

A session grows by ~1,194 bytes per decision and never shrinks, so a session of
100,000 actions holds roughly 120 MB. `benchmarks/results/session_scaling.md` has
published this as a known limit for several releases.

Four structures grow per call. One was fixed in 0.6:

| structure | site | state |
| --- | --- | --- |
| `_trajectory.actions` | `SessionBroker._observe` in `broker.py`, `self._trajectory.actions.append` | open |
| `_trajectory.context` | `SessionBroker` in `broker.py`, `self._trajectory.context = [*self._trajectory.context, item]` — rebuilt by **copy** each observation, so O(N) time too | open |
| the envelope phase memo | the memo key in `intent_envelope.py` built from `tuple(steps)`, one entry per action, re-allocated per call | open |
| `ScopingMetrics._overhead_samples` | `scoping/metrics.py` | **fixed in 0.6** — bounded deque + exact counters |

`DecisionLog` is already bounded (`decision_log.py:102-155`, `max_records=10_000`
with an `evicted` counter so sequence numbers stay right) and is the precedent
this design follows.

## Why it is not simply a `deque(maxlen=...)`

The trajectory is not telemetry. It feeds the behavioural layers, and their reads
are not all suffix reads. Every consumer is one of: per-action (safe under any
window), a monotone existential or counter, or a left fold with carried state.
The last two must be lifted into an aggregate that survives eviction, or the
window changes verdicts.

The failure directions differ, which is what makes a naive window dangerous
rather than merely lossy:

- **Fails open.** `check_secret_flow`'s taint bit in `sealed_plan.py` — evict
  the `.env` read and the session is silently un-tainted. A phase `max` count
  resets, so `Deviation.OVER_COUNT` stops being raised and the step-up at
  the `Deviation.OVER_COUNT` check in `broker.py` never fires.
- **Fails closed.** A phase `min` landmark goes unmet, so everything after it
  raises `Deviation.OUT_OF_ORDER` — a wave of false denials on precisely the long
  sessions the window exists to serve.

### The memo hazard

`intent_envelope`'s incremental prefix-resume (`_memo_key` / `_resume` /
`_remember`, `:488-521`) validates with `actions[length - 1] is last`, where
`length` is a **positional index**. Evicting *k* from the front shifts every
position by *k*. Either the check fails and the window is re-assessed with
`satisfied` zeroed (both failure modes above), or — if an `Action` instance is
ever reused — it passes at the wrong offset and steps are silently duplicated or
dropped.

That module's own comment is the right standard to hold this to: *"an
optimization inside an enforcement path that is subtly wrong is worse than the
cost it saves."*

## The design

1. **Absolute coordinates.** Store `covered = evicted + len(actions)`, never a
   bare index. This is the `seq = self.evicted + len(self._records)` line from
   `decision_log.py:149`, translated.
2. **Eviction is a pull with a watermark, not a push.** Consumers register a
   cursor carrying their `covered`; `compact()` may drop only below
   `min(cursor.covered)`. Called from exactly one place, the top of
   `SessionBroker.authorize` — **not** inside `_finalize`'s bookkeeping block,
   which is explicitly where failures are swallowed.
3. **A `TrajectoryPrefix` aggregate** carrying what eviction would otherwise
   destroy: per-tool and per-verb counts, read count, distinct targets (bounded,
   with an explicit `truncated` flag), the `surface_is_comparable` latch, the
   secret-taint bit, the ngram `prev` carry, the `feasible` fold's `(world, dead)`
   checkpoint, and the per-memo-key `satisfied` vector at the eviction frontier.
   Nothing in it decreases; anything that must decrease is a fold checkpoint
   applied at eviction in original order.
4. **Fail closed on abstention.** Where an aggregate cannot be exact, it says so
   and the consumer takes the conservative branch.
5. **`tree_conformance` gets no window** in a first version:
   `behavior_tree.py:242-263` carries NFA state across the whole trace with no
   memo, so windowing it re-opens the plan from the beginning. Make `compact()` a
   no-op when `plan_tree` is set, and say so.

## Two hazards to fix first

Both are invisible until something is actually evicted:

- `sandbox/monitor_feed.py:96` computes `start_step=len(trajectory.actions)`.
  After eviction the resident length shrinks, so synthesized step numbers restart
  and **collide** with earlier ones. `detector.py:172` keys scores by step and
  `twin_corridor.py:217` looks actions up by it, so scores get mis-attributed.
  Must become `evicted + len(actions)`. Same defect in
  `benchmarks/live/broker_defense.py:487,526`.
- `session_state.restore` (`session_state.py:169-172`) reassigns
  `broker._trajectory.actions` to a plain list, which defeats any bounded
  container, and `snapshot` serialises no aggregate. A snapshot/restore of a
  windowed session would **fail open** on taint, phase counts and the surface
  latch.

## How to choose the window, and why BPL cannot

Of the 132 BPL scenarios, the longest script is 44 calls
(`chronicle-then-blast`), then 42 (`marathon-micro-drip`), then 39; median 16,
mean 18.2. **Any window ≥ 44 evicts nothing**, so a sweep returns identical
numbers for W ∈ {44, 64, 512, ∞}. Reading that as "windowing is safe" would be
reading a mechanism that never fired.

The suite is therefore a **falsifier over W ∈ [1, 44]**, not a chooser. Note also
that `marathon-micro-drip` is contained by the value budget, a running scalar, so
it is window-immune at any W.

Choosing a default needs an arm the suite does not have: take the long scenarios
and insert benign filler between setup and payload at 200 / 1,000 / 5,000 calls.
Under a correct aggregate, containment is **invariant in the amount of filler**.
Under a naive window it collapses once filler exceeds W. That is the experiment
that distinguishes the two designs, and neither is visible in the BPL headline at
any window ≥ 44.

Acceptance for the sweep half: the smallest W where, for **every** scenario,
`contained`, `completed`, `blocks` and `outcomes` are identical to W = ∞. Equal
outcomes with different `blocks` means the scenario was contained for a different
reason, which is a silent semantic change and must be reported rather than
averaged. Hold all five conditions, the verb source, `derive_counts`, the
`clayseal_expected` labels and `detector=None` constant, and prove determinism by
running W = ∞ twice.

Suggested default if the breakpoint lands where the scenario lengths suggest:
`max_actions: int | None = 256`, with `None` for benchmark harnesses — the exact
shape of `decision_log.py:117`.

## Why it was deferred

It is a correctness change to the enforcement path wearing the clothes of a
performance fix. It needs a cursor protocol, absolute coordinates through the
memo, a per-consumer aggregate, two pre-existing hazards fixed first, and a new
benchmark arm to choose its one tuning constant — and the existing suite cannot
tell a correct implementation from a broken one.

The honest end state for 0.6 is the limit documented with its analysis, which is
what this file is.
