# Slow drift over 2000 actions

The adversary raises the mean by 0.00400 sigma per action, from 10.0 to 14.0. A single action at 14.0 would be 4 sigma out at t=0 and refused outright. No single step is ever more than a fraction of a sigma above the last. The objective is reached at 50% of the run, after which the agent simply operates there.

| Monitor | baseline moved | displacement | alarms at objective |
| --- | --: | --: | --: |
| rolling | 9.995 -> 14.027 | 4.15 sigma | 5/1000 (0.5%) |
| anchored | 9.995 -> 9.995 | 0.0 sigma | 821/1000 (82.1%) |

The rolling monitor's notion of normal moved **4.15 sigma** while it was watching. That is the finding: it did not fail to detect an anomaly, it stopped considering the behaviour anomalous, having been retrained by traffic it had already permitted.

Once the attacker is operating openly at 14.0, the rolling monitor alarms on 0.5% of actions and the anchored one on 82.1%. The anchored monitor is judging against what a human signed off; the rolling one is judging against what the agent talked it into.

The cost is stated rather than hidden: an anchored monitor also alarms on legitimate business change, because drift and growth are the same signal. The answer is not to tell them apart automatically, it is to force the question to a human on a schedule, which is what re-anchoring is.
