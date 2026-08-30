# Idempotence: replay of an already-authorized action

STATUS: current

```bash
python -m benchmarks.idempotence
```

Re-derived against this commit. The previous revision carried no `STATUS` line,
which is what `unstamped` meant: a reproduce command with nothing saying whether
anyone had run it.

A commit token binds one authorization to one side effect. The distinguishing sweep is the point: velocity limits cannot separate a duplicate from a second legitimate action of the same shape, and the commit token can.

**What it costs:** the benign arm is untouched. 400 of 400 legitimate
actions are allowed, so the false-block rate on this axis is 0 of 400, and
the 800 events on the ladder below it are allowed with none blocked. A
containment figure without that column would be indistinguishable from
deny-all, which refuses replays perfectly and everything else with them.

```
corpus=tau2 sessions=400

  replay arm       refused    100.0%  (400/400)
  legitimate arm   allowed    100.0%  (400/400)
  second instance  refused      0.0%  (0/400)

  ladder below: 800 allowed, 0 blocked

  distinguishing sweep (commit token vs velocity, same construction)
    1 duplicate(s)   commit 100.0%   velocity   0.0%
    2 duplicate(s)   commit 100.0%   velocity   0.0%
    3 duplicate(s)   commit 100.0%   velocity   0.0%
```
