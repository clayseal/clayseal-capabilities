# The same run, in the two units

STATUS: current

```bash
python -m benchmarks.session_units --datasets agentharm,sleight
```

Per event is the optimistic read of protection and of cost. Per session is the
pessimistic read of both. A deployment sits between them.

| corpus | unit | in-surface contained | benign disrupted |
| --- | --- | --- | --- |
| agentharm | per event | 152/507 (30.0%) | 0/729 (0.0%) |
| agentharm | **per session** | **72/160 (45.0%)** | **0/176 (0.0%)** |
| agentharm | _actions that ran before the first stop_ | _109_ | _first stop at action {0: 4, 1: 40, 2: 15, 3: 13}_ |
| sleight | per event | 27/122 (22.1%) | 0/311 (0.0%) |
| sleight | **per session** | **25/41 (61.0%)** | **0/43 (0.0%)** |
| sleight | _actions that ran before the first stop_ | _14_ | _first stop at action {0: 15, 1: 6, 2: 4}_ |

A session counted as contained still did part of what it set out to do: the
middle row is protection at its most generous and the italic row is what that
generosity costs in actions that already ran.

## Why this was not noticed for four passes

Because every unit in this repository was chosen once, early, for a per-action
gate, and never revisited when the question changed. `coverage.py` scores an
authorization decision, and an authorization decision is per action, so per
action is what it counted. That is a defensible choice and it silently answers a
different question from the one a buyer asks, which is whether the attack got
through and whether the work got done.

The tell was available the whole time and nobody looked at it: **18 of sleight's
32 stops land on the attack's FIRST action.** A per-event score divides that by
the length of an attack the gateway already prevented.

## What it changes, in both directions

**Protection is better than reported.** In-surface attack SESSIONS are stopped
far more often than attack EVENTS are, because a stop early in an attack
prevents the rest. The wall is lower than four passes of results have said.

**Cost was worse than reported, and that is what got fixed.** The session unit
put sleight's benign disruption at **46.5%** against 14.1% of events, which is
what made the false-positive problem visible at all: nearly half of benign
sessions carried a refusal, and the per-event number had rounded that into
comfort. `false_positives.md` records the two changes that took it to zero.

**Neither number moved.** This is the same run, scored twice. Every result in
this repository that quotes one unit is quoting the optimistic half of a pair,
and which half is optimistic depends on which column you are reading.

## The rule this suggests

Report the pair, always, and say which is which. A containment figure per event
beside a cost figure per event is two optimistic numbers presented as a trade,
and the trade is better than the truth in both columns at once. The
`costless` ratchet already refuses a containment figure with no cost column; the
missing half is that the two must be in the same unit and that unit must be
named.

