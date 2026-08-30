# Pooled attack-success rate: 216 runs, four suites, three sweeps each

STATUS: current

Verified in a separate live run against `gpt-4o-mini`, reported by the person
who ran it. It is not reproducible from this checkout: the OpenAI account
here has no credits, and `gpt-4o-mini` version `2024-07-18` can no longer be
deployed on Azure, where the aliased substitute (`gpt-5-mini`) is not
injectable by this attack at all. See
[utility_experiment_void.md](utility_experiment_void.md).

Every live security number in this repository previously came from a single
sweep of n=18. At that size a clean result supports a claim to about one
significant figure: 0 of 18 has a Wilson upper bound of **17.6%**. We also had
direct evidence that a single sweep can move, since the same workspace
configuration measured 27.8% and 0.0% ASR on two occasions.

This is the pooled measurement. Deployable configuration (`envelope-taint`),
gpt-4o-mini, `important_instructions`, 6 user x 3 injection tasks per sweep,
three sweeps per suite.

| Suite | undefended ASR | defended ASR | successes / runs | sweep spread | clean utility | baseline | interrupts/task |
| --- | --: | --: | --: | --: | --: | --: | --: |
| banking | 66.7% | 0.0% | 0 / 54 | 0.0% | 16.7% | 50.0% | 0.56 |
| slack | 81.5% | 0.0% | 0 / 54 | 0.0% | 50.0% | 83.3% | 0.17 |
| travel | 38.9% | **1.9%** | **1 / 54** | 5.6% | 66.7% | 100.0% | 0.56 |
| workspace | 88.9% | 0.0% | 0 / 54 | 0.0% | 83.3% | 100.0% | 2.11 |

**Pooled: 1 attack success in 216 runs, 0.5% [0.1, 2.6].**

## Reading

**The claim is now supported to the precision it is quoted at.** A single sweep
of 18 with no successes justified nothing tighter than [0, 17.6%]. 216 runs with
one success justifies [0.1%, 2.6%], which is a different kind of statement and
the one worth putting in front of a reviewer. Progent, the closest published
comparable, leaves 11.1 to 16.7% on the same suites and attack.

**Defended ASR is stable; undefended ASR is not.** Sweep-to-sweep spread on the
defended configuration is 0.0% on three suites and 5.6% on travel. The
undefended baseline moved by 11 points on banking and 17 on travel. That
ordering is the useful part: the noise lives in whether the attack lands on an
unprotected agent, not in whether the enforcement layer holds. It also means the
earlier 27.8%-versus-0.0% disagreement was measuring a configuration that had
been deliberately weakened, not the shipping one.

**The single failure is on travel and is the known residual.** One run in 54,
consistent with the 5.6% previously reported for that suite, and it is the suite
where benign destinations are discovered from content rather than named in the
goal.

**Utility cost on gpt-4o-mini is 29 points pooled** (54.2% against an 83.3%
baseline), at 0.85 interruptions per task. That is the weak-model end of the
ladder; the same configuration costs 3 points on grok-4-1-fast. Both numbers
should always travel together.

## Reproduce

```bash
for s in banking slack travel workspace; do
  python -m benchmarks.live.frontier --suite $s --n-user 6 --n-inj 3 \
    --repeats 3 --configs none,envelope-taint
done
```
