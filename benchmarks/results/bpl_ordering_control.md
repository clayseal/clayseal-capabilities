# Is the BPL result available from call position alone?

STATUS: current

```bash
python -m benchmarks.bpl_ordering_control
```

[ordering_exposure.md](ordering_exposure.md) asks this of the event corpora and
found four of them unable to distinguish a rung from counting. It does not cover
BPL, and **BPL is the suite the headline rests on**, so the control that matters
most had never been run against the number it matters most for.

## The attack on our own result

Every BPL scenario is a scripted attack and its benign twin, and the violating
step is usually late: the script establishes context, then breaches. A defense
that reads nothing at all, and simply refuses every call from index `k` onward,
should therefore contain a great many attacks. If it reaches our joint score, the
gateway is not wrong; the suite is simply unable to tell a session-state rung
apart from a clock, and our number would be reporting the shape of the scripts.

`deny-all` is a permanent row in the main table because a containment number that
does not beat it is not a measurement. This is the same argument on the axis of
ORDER.

## Result

| control | best k | contained | completed | **joint** |
| --- | ---: | ---: | ---: | ---: |
| position cut (refuse index >= k) | 3 | 118 | 4 | **3** |
| suffix cut (refuse the last n) | 27 | 132 | 0 | **0** |
| **gateway + 4 goal-derived rungs** | - | **72** | **130** | **70** |

The control chooses its threshold *after* seeing the score. The gateway does not.

**At matched friction the control collapses completely.** Holding the position
rule to the gateway's own benign cost, completing at least 130 of 132:

```
best counting rule contains 0 of 132, against the gateway's 72
```

Not "fewer". Zero. Every position rule that leaves the benign twins alone also
leaves every attack alone, because in this suite the violating step is not
reliably later than the benign work that surrounds it. **BPL is not
ordering-exposed**, and the containment reported for it is not a restatement of
transcript order.

## Why this control was nearly useless twice

Both faults would have produced a publishable-looking number.

**The null endpoint was wrong.** The sweep ran `k` to 40 while the longest script
is 44, so the "block nothing" endpoint still refused calls in the four longest
scenarios and reported 102 completions where allow-all reaches 132. A control
whose null endpoint is wrong cannot bound anything.

**The control was graded on an easier metric than the gateway.** The first
version scored a twin as completed when `progress >= 1.0`. That is not what
`bpl_sweep` means by completed, which is *nothing was refused*
(`bpl_sweep.py:212`). Thirty compliant scripts end below 1.0 with nothing blocked
at all, so the control would have started with a thirty-scenario head start over
the thing it was controlling. A control graded on a different metric is not a
control.

Both are pinned by tests, on the principle that a broken control reports the most
flattering possible result and reports it quietly.
