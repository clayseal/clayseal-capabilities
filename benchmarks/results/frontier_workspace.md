# Safety/usefulness frontier, workspace, gpt-4o-mini-2024-07-18, 6x3 runs per config

STATUS: superseded

> **STATUS: superseded.** Retired on 2026-08-29. The figures below were never
> re-derived, carry no reproduce command, and are cited by no document in this
> repository. The frontier across suites rather than one cell of it is now in
> [frontier.md](frontier.md), which is stamped `current`.
>
> Kept rather than deleted, because a number that was once published should stay
> readable with its correction attached.

> No command was recorded for this file, so its numbers cannot be
> re-derived from it. `unverified` says that nobody has checked them, which
> is the honest claim; `current` would be vouching for a run nobody can
> reproduce. See the provenance section of [README.md](README.md).


| Configuration | ASR | clean utility | utility under attack | friction/task | |
| --- | --: | --: | --: | --: | --- |
| none | 83.3% | 100.0% | 27.8% | 0.00 | **frontier** |
| floor | 0.0% | 100.0% | 88.9% | 4.17 | dominated (by envelope-taint) |
| envelope | 0.0% | 100.0% | 88.9% | 4.50 | dominated (by floor) |
| envelope-taint | 0.0% | 100.0% | 83.3% | 1.50 | **frontier** |
| envelope-taint-graduated | 0.0% | 100.0% | 94.4% | 6.00 | dominated (by floor) |
| envelope-taint-defer | 0.0% | 100.0% | 88.9% | 2.00 | dominated (by envelope-taint) |
| envelope-taint-deferallow | 0.0% | 100.0% | 88.9% | 2.33 | dominated (by envelope-taint) |
| envelope-taint-graduated-audit1 | 0.0% | 100.0% | 88.9% | 2.50 | dominated (by envelope-taint) |
| envelope-taint-graduated-audit3 | 0.0% | 100.0% | 88.9% | 4.17 | dominated (by envelope-taint) |

```
  utility
1.0 |       a                                     *
    |                                              
    |                                              
    |                                              
    |                                              
    |                                              
    |                                              
    |                                              
    |                                              
    |                                              
    |                                              
    |                                              
    |                                              
0.0 |                                              
    +----------------------------------------------
     0.0                                safety (1-ASR) 1.0

  a = none
  b = floor
  c = envelope
  d = envelope-taint
  e = envelope-taint-graduated
  f = envelope-taint-defer
  g = envelope-taint-deferallow
  h = envelope-taint-graduated-audit1
  i = envelope-taint-graduated-audit3

  * = several configurations at the same point: bcdefghi
```

2 of 9 configurations are on the frontier. A dominated configuration is one another beats on safety, utility, AND attention simultaneously, so shipping one is strictly a mistake. They are listed rather than dropped, because a frontier that hides its losers is a marketing chart.

Lowest ASR: **envelope-taint** at 0.0% ASR, 100.0% clean utility, 1.50 interruptions per task. Read those three together: the third number is what the first two cost a human.
