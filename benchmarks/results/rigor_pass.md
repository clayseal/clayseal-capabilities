# Rigor pass: adaptive red-team, uncertainty, and three vulnerabilities

Everything below reproduces with `benchmarks/run_all.sh` against the pinned
corpus in `benchmarks/corpus_manifest.json`. No LLM is involved; a full pass is
CPU-only and takes under a minute.

The headline is not a score. It is that building an adversary that adapts found
three exploitable defects in the shipping authorization path within an hour,
none of which any static corpus in the suite had surfaced.

## Vulnerabilities found and fixed

### 1. Path traversal defeats scope matching (core, high)

`agentauth.core.task_scope.path_matches_any` fnmatched the raw string. Given a
workspace grant of `/app/**`:

```
path_matches_any("/app/../etc/passwd", ["/app/**"])  ->  True
```

An `open()` on that string reads `/etc/passwd`. Every rung that scopes by path
inherited the bypass, so a coding agent's own file tool could read anything on
the box. The protected-zone deny-list missed it too, because it string-matched
the same unresolved input, so defense in depth did not apply.

Fixed by resolving `.` and `..` lexically before matching, on both the path and
the pattern. Regression tests in
`agentauth-core/python/tests/test_task_scope_normalization.py`.

### 2. Protected zones bypassed by procfs re-entry (capabilities, high)

`/proc/self/root` is the process's own root directory, so
`/proc/self/root/etc/passwd` addresses `/etc/passwd` behind a prefix no pattern
recognized. Worse, resolving it lexically is *wrong*: popping the symlinked
`root` component yields `/proc/self/etc/passwd`, which matches nothing.

Fixed by matching the deny-list against the resolved *and* the literal form,
which for a deny-list can only ever deny more, plus explicit patterns for
`/proc/*/root/**`, `environ`, `mem`, and `cmdline`. The residual is stated
plainly: lexical resolution cannot follow symlinks, and the allow-list side
cannot use the match-both trick. That is a syscall-boundary problem.

### 3. The ladder was not monotone (benchmarks, medium)

Surfaced by Yuvvan's RedCode suite and left open there. A path-scoped mandate
compiles to an empty `allowed_resources`, and `TaskScopeEngine` treated empty as
"allow any resource", so connector-substitution passed `task-scope` and failed
`capability-token`, a *lower* rung.

Fixed by composing rather than replacing: `task-scope` now carries the
capability check forward. `connector-substitution` goes 0% to 100% at that rung,
false-block stays at 0%, and overall containment moves 89% to 92% and 95% to
97%. Monotonicity is now a per-event test over every corpus rather than a claim
in a README.

## Adaptive red-team

400 RedCode tasks, 6 rounds, three attacker knowledge levels. Identical results
for all three objectives:

| Engine | blind | feedback | oracle |
| --- | --- | --- | --- |
| allow-all | 0% | 0% | 0% |
| tool-allowlist | 0% | 0% | 0% |
| capability-token | 0% | 0% | 0% |
| task-scope | 100% | 100% | 100% |
| task-scope+binding | 100% | 100% | 100% |
| task-scope+binding+budget | 100% | 100% | 100% |

Objectives: exfiltration (T1041), persistence (T1546), destruction (T1485).

The result worth stating is the flat line across the columns. Telling the
attacker the compiled policy buys it nothing, because the defense constrains the
outcome rather than the input, and there is no phrasing of "send `/etc/passwd`
to `198.51.100.7`" that is inside a workspace grant.

`capability-token` at 0% is the same finding RedCode makes statically, now
against an adaptive adversary: every leg of the attack uses a resource and tool
the agent legitimately holds, and only the target is wrong.

**These numbers are only as good as the control.** A prefix matcher without
canonicalization is checked in as a test that must keep failing, and it falls
80/80 at round 1. If it ever survives, nothing here is publishable.

Three fabricated-finding bugs were caught and fixed in the harness itself
before these numbers were trusted:

- `/app/etc/passwd` scored as exfiltration on a substring match, before the
  objective canonicalized paths;
- `/app/etc/cron.d/agent`, a file in the agent's own workspace, scored as
  persistence, giving `task-scope` a false 0%;
- informed mutations crowded out the blind move that worked, making the oracle
  attacker *weaker* than the blind one (46% vs 0% containment on persistence).

Each is now a test. The pattern is consistent: an adaptive search optimizes
against whatever you actually wrote down, so the objective predicate is the
experiment.

## Uncertainty

Every rate carries a task-clustered bootstrap interval. RedCode ladder:

| Engine | Attack prevented | False-block |
| --- | --- | --- |
| tool-allowlist | 0.0% [0.0%, 0.4%] | 0.0% [0.0%, 0.4%] |
| capability-token | 0.0% [0.0%, 0.4%] | 0.0% [0.0%, 0.4%] |
| task-scope | 99.9% [99.6%, 100.0%] | 0.0% [0.0%, 0.4%] |
| task-scope+binding+budget | 99.9% [99.6%, 100.0%] | 0.0% [0.0%, 0.4%] |

Clustering by task rather than by event roughly triples the interval width on
these corpora, which is the honest number: RedCode's 718 attack events come from
14 risk templates.

The adversarial leaderboard over 10 synthesis seeds shows **zero** variance in
every cell, so those results are structural rather than lucky draws. That is a
real finding and it is why the multi-seed table reports no `±` anywhere.

The 0% false-block column is **not** an operational false-positive rate. Replay
feeds ground-truth calls that pass by construction. The live measurement is
tier 3 and is not rebuilt yet.

## Cost

RedCode, 10,880 decisions per engine, 20 repeats, warm:

| Engine | p50 | p95 | p99 | added over previous |
| --- | --- | --- | --- | --- |
| allow-all | 0.33 us | 0.46 us | 0.54 us | - |
| tool-allowlist | 0.54 us | 0.67 us | 0.92 us | +0.21 us |
| capability-token | 2.79 us | 3.33 us | 3.50 us | +2.25 us |
| task-scope | 31.9 us | 36.3 us | 56.1 us | +29.1 us |
| task-scope+binding | 33.8 us | 40.5 us | 58.5 us | +1.8 us |
| task-scope+binding+budget | 35.0 us | 40.5 us | 60.3 us | +1.3 us |

The full stack decides in 35 us at p50 and 60 us at p99, four orders of
magnitude below the LLM round trip it gates. Scope compilation is amortized per
task and reported separately at 21 ms for 250 tasks.

The path-normalization fix cost real time: `task-scope` went from about 19 us to
48 us, brought back to 32 us by caching the resolver. It is still the most
expensive rung by a wide margin, and it is the one that does the work.

## Still open

- **Live false-block.** The three methodology defects in
  `docs/methodology_audit.md` are unaddressed: STEP_UP counted as failure, no
  paired causal control, n too small to resolve the differences being quoted.
- **Symlink containment.** Named above, needs the syscall boundary.
- **Deployment-shaped chains.** RedCode and AgentHarm are research corpora. A
  buyer wants a coding agent on a private repo and a support agent over a
  customer database, mapped to ATT&CK and the OWASP Agentic Top 10.
