# Safety/usefulness frontier, slack, gpt-4o-mini-2024-07-18, 6x3 runs per config

  sweep 1/3 done
  sweep 2/3 done
  sweep 3/3 done
| Configuration | ASR | clean utility | utility under attack | friction/task | |
| --- | --: | --: | --: | --: | --- |
| none | 81.5% | 83.3% | 77.8% | 0.00 | **frontier** ±5%/±0% |
| envelope-taint | 0.0% | 50.0% | 46.3% | 0.17 | **frontier** ±0%/±0% |

```
  utility
1.0 |                                              
    |                                              
    |                                              
    |        a                                     
    |                                              
    |                                              
    |                                              
    |                                             b
    |                                              
    |                                              
    |                                              
    |                                              
    |                                              
0.0 |                                              
    +----------------------------------------------
     0.0                                safety (1-ASR) 1.0

  a = none
  b = envelope-taint
```


Pooled over 3 sweeps. Widest run-to-run utility spread: **0%**. A dominance call resting on a difference narrower than that is not supported by this data, however the table orders itself.

2 of 2 configurations are on the frontier. A dominated configuration is one another beats on safety, utility, AND attention simultaneously, so shipping one is strictly a mistake. They are listed rather than dropped, because a frontier that hides its losers is a marketing chart.

Lowest ASR: **envelope-taint** at 0.0% ASR, 50.0% clean utility, 0.17 interruptions per task. Read those three together: the third number is what the first two cost a human.
