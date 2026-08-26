# Trajectory detector, sleight

STATUS: current

```bash
python -c "from benchmarks.datasets.base import get_loader; \
from benchmarks.core.detector_eval import run_detector_benchmark; \
print(run_detector_benchmark(get_loader('sleight').load(limit=4000), seed=0).summary())"
```

scorer=ngram, alpha=0.05, train 25 / test 18 / attack trajectories 18.

| quantity | value |
| --- | --- |
| attack trajectories contained | 17 of 18 (94.4%) |
| benign trajectories blocked | 0 of 18, upper bound 18.5% at n=18 |

## What this file said before, and why it was wrong

It said, in full, `containment 83.3% | false-block 0.0%`, with no command, no
STATUS and no denominators, over n=18 held-out trajectories. Neither number could be reproduced: the code as it stood returned
**18 of 18 contained at 13 of 18 benign trajectories blocked**, a 72.2%
false-block rate at alpha=0.05, and the file had been carrying that figure for
a configuration that no longer existed.

The cause was not the detector's statistics. `TypedGoalEnvelope` compiled the
goal into resource CLASSES and refused any action whose class was not a member,
while every sleight event is labelled `resource="workspace"` and the goal
surface is built from file paths. The two vocabularies never intersect, so the
tier refused everything, and it sits outside the conformal budget, so it was
blocking benign trajectories at p-values of 0.523, 0.709 and 0.912. No choice of
alpha touched it.

`monitor/surface.py` now holds the rule that closes it: read the path as well as
the resource, and refuse only once something in the session has matched the
surface at least once. Containment fell by one trajectory and the false-block
rate fell by 13. The statistics are unchanged.

See [composed_detector.md](composed_detector.md) for the same detector measured
per EVENT inside the shipped stack, where it is worth considerably less, and for
why the trajectory unit flatters a per-action gateway.
