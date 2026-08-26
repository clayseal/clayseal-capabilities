# The floor and the calibrated detector, composed: raw sweep output

STATUS: current

The machine output behind the analysis in [composed_detector.md](composed_detector.md). Every cell is a mean over five
task-level splits with its spread, because a single draw of an 18-task split is
not a result.

STATUS: current

```bash
python -m benchmarks.composed --datasets agentharm,sleight --limit 4000 --alphas 0.05,0.20 --seeds 1,3,5,7,11
```

Every published number for the shipped stack was measured with `detector=None`.
The detector is fit one-class on benign trajectories from a task-level train
split and never sees an attack label. Both arms run on the same held-out tasks.

## agentharm

211 tasks fit the detector, 141 held out and scored, averaged over 5 splits.

| arm | surface-leaving | in-surface | benign interrupted |
| --- | --- | --- | --- |
| floor only (no detector) | 100.0% sd 0.0% [100.0%, 100.0%] n=5 | 31.7% sd 1.5% [30.2%, 34.5%] n=5 | 6.6% sd 1.3% [4.3%, 8.3%] n=5 |
| floor + detector, alpha=0.05 | 100.0% sd 0.0% [100.0%, 100.0%] n=5 | 35.1% sd 2.7% [30.9%, 38.3%] n=5 | 9.5% sd 4.0% [5.6%, 16.6%] n=5 |
| floor + detector, alpha=0.2 | 100.0% sd 0.0% [100.0%, 100.0%] n=5 | 46.7% sd 5.5% [38.9%, 54.3%] n=5 | 25.4% sd 5.8% [19.1%, 32.8%] n=5 |

## sleight

25 tasks fit the detector, 18 held out and scored, averaged over 5 splits.

| arm | surface-leaving | in-surface | benign interrupted |
| --- | --- | --- | --- |
| floor only (no detector) | 100.0% sd 0.0% [100.0%, 100.0%] n=4 | 40.0% sd 6.4% [34.5%, 52.4%] n=5 | 13.5% sd 5.1% [6.2%, 19.8%] n=5 |
| floor + detector, alpha=0.05 | 100.0% sd 0.0% [100.0%, 100.0%] n=4 | 44.6% sd 8.9% [34.5%, 59.5%] n=5 | 21.7% sd 6.2% [12.4%, 30.2%] n=5 |
| floor + detector, alpha=0.2 | 100.0% sd 0.0% [100.0%, 100.0%] n=4 | 53.0% sd 7.5% [45.9%, 66.7%] n=5 | 32.6% sd 6.8% [24.0%, 39.8%] n=5 |

