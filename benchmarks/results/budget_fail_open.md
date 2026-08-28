# The budget rungs failed open on malformed input

STATUS: current

**This is a defect report, not a measurement.** It reports four bugs and their
fixes; it makes no containment claim, so it has no cost column to put beside one.
The rungs it describes are priced where they are measured, in
`bpl_sweep --suite full` (2 benign twins refused of 132, no work lost) and in
`burst.md` (clean false alarms 0 of 200 tau2 sessions).

Four defects in the enforcement floor, found by fuzzing rather than by corpus
evaluation, all of the same shape: **a control that stops applying precisely when
its input is absurd, while reporting that it passed.** All four are fixed; all
four are pinned by tests.

This matters more than the behavioural-layer work that preceded it. The budget
rungs are not experimental, they ship, they are what `SEND_PACKET.md` cites for
"Volume / burst containment 100%", and they are the only rungs carrying state
across a session, so a bug compounds instead of being confined to one decision.

## How they were found

`benchmarks/stress_budget.py` throws randomized reserve/commit/release
interleavings at the real `SessionValueBudget` and asserts conservation, ceiling,
release-is-free, no-double-settle and remaining-consistency after every operation.

**The sequence fuzzing found nothing.** All properties held across 200,000
operations, which is a genuine positive result for the ledger's locking and
settlement logic. Every defect below was in *input handling*, the half a
sequence fuzzer never reaches, and surfaced only when the amount and ceiling
fields were fuzzed with values an attacker or a malformed mandate would supply.

## Defect 1, an unparseable amount was treated as untracked (critical)

`SessionValueBudget._amount` returned `None` for two different situations: "this
tool has no money spec" and "the amount is garbage". Callers read the single
`None` as *untracked*, so `reserve()` returned `allowed=True` with reason
`ok_untracked` and **no ceiling check ran at all.**

Measured against a ceiling of 10, every one of these was allowed and booked
nothing:

```
'1e999'   'Infinity'   '-Infinity'   'sNaN'   '0x10'   ''   10**30
None      [5]          {'a': 1}      True
```

`1e999` is not an exotic input: it is what an injected agent writes for
"transfer everything". `10**30` is an ordinary Python int that merely overflows
cent-quantization. The mechanism: `_money` calls
`Decimal(str(v)).quantize(Decimal('0.01'))`, which raises `InvalidOperation` (an
`ArithmeticError`) for non-finite or over-long values; `_amount` caught
`ArithmeticError` and returned `None`.

**Fixed** by making `_amount` tri-state, `None` for genuinely untracked,
`(budget_id, None)` for tracked-but-unusable, `(budget_id, Decimal)` for usable
and denying the middle state as `value_budget_unparseable_amount` in `reserve`,
`would_allow` and `commit`.

## Defect 2, `NaN` raised out of the authorization gate

`Decimal('NaN')` quantizes without complaint, so `_money` returned it happily.
The next line, `if amount < 0:`, raises `InvalidOperation` on a NaN comparison
which escaped `reserve()` unhandled and would take the whole `authorize()` call
with it. An authorization gate may deny; it may not crash.

**Fixed** by rejecting non-finite amounts explicitly in `_amount` rather than
letting them reach a comparison.

## Defect 3, a non-finite *ceiling* silently disabled the compute budget

`ComputeBudgetConfig.ceiling_for` coerced with a bare `float(raw)`:

| configured ceiling | became | effect |
| --- | --- | --- |
| `'Infinity'`, `'1e999'` | `inf` | no limit |
| `'NaN'` | `nan` | **every** `projected > ceiling` is False, so nothing is ever refused |

Measured: with a NaN ceiling, a **1,000,000-second** request returned
`allowed=True`, reason `'ok'`, not even `ok_clamped`. With a valid ceiling of 10
the same request is correctly clamped to 0 remaining. A NaN ceiling is the worst
case of the three because it defeats the comparison rather than merely widening
it.

## Defect 4, malformed ceilings raised from the hot path

`ValueBudgetConfig.ceiling_for` raised `InvalidOperation` out of `reserve()` for
every one of `'Infinity'`, `'NaN'`, `'1e999'`, `'abc'`, `[1]`.
`CallBudgetConfig.ceiling_for` raised `ValueError`/`TypeError` similarly. Better
than fail-open, but still an unhandled exception in the authorization path,
triggered by configuration rather than by traffic.

**Fixed** for all three rungs by validating in `__post_init__`: a ceiling that is
not finite, not numeric, or negative raises `ValueError` at construction with a
message naming the budget. Note that returning `None` ("no ceiling") would itself
be fail-open, so refusing to build the config is the only honest option, **a
budget that cannot be enforced must not be constructible.**

## Why the whole class is worth naming

Each defect is the same decision made four times: *when input is unusable,
proceed*. For a parser that is often right. For an authorization control it is
always wrong, and it is invisible from above, the broker records that the budget
rung passed, the scoreboard counts it as enforced, and the ladder reports
containment it did not perform.

The corpora could never have found these. Every corpus in the repo carries
well-formed amounts, because corpora are written by people modelling *agents*,
not people modelling *malformed input*. That is the argument for keeping a fuzzer
alongside the benchmarks rather than choosing between them.

## Residual, stated

- **An absent amount argument on a tracked tool is still untracked-allowed.**
  This is deliberate, genuinely absent differs from present-and-garbage, and
  denying the first would refuse legitimate calls, but it remains a way to reach
  a money tool without a ceiling check if a downstream tool defaults the amount.
  Closing it requires knowing which arguments are mandatory, which the mandate
  does not currently express.
- **Only the three budget rungs were audited this way.** The same
  fail-open-on-unparseable question applies to egress policy, path scoping and
  the identity adapters, and has not been asked there yet.


## Follow-up: the class, removed rather than the sites

Fixing four sites does not remove a bug class. `benchmarks/stress_gates.py` runs
one hostile corpus against **every** gate the broker composes and asserts two
properties, so the next rung someone adds is audited without anyone remembering
to. `benchmarks/tests/test_gate_totality.py` runs it in CI.

| gate | raises | fails open | verdict |
| --- | ---: | ---: | --- |
| value-budget | 0 | 0 | ok |
| call-budget | 0 | 0 | ok |
| compute-budget | 0 | 0 | ok |
| protected-zones | 0 | 0 | ok |
| egress-policy | 0 | 0 | ok |
| task-scope | **5** | 0 | external — see below |

Two more defects were fixed getting there, both public API and both unreachable
through the shipped broker (`broker._action_path` filters with
`isinstance(v, str)`) but reachable by the integration path the README actually
sells, "bring verified claims from your IdP and build your own gateway":

- **`is_protected_path`** raised `AttributeError` on a `list`, `dict` or `bool`.
  It now treats a non-string path as protected. A deny-list is allow-by-default,
  which makes an unreadable path the dangerous direction: "I cannot parse this,
  therefore it is not protected" is the fail-open in its purest form.
- **`SessionComputeBudget.reserve`** raised `TypeError` from the `< 0` comparison
  for any string estimate, and *granted* `float('nan')` as `ok_clamped`, which
  then poisons every later comparison on the ledger, since NaN compares False
  against everything. Both now deny as `compute_budget_unusable_estimate`.
  `bool` is excluded explicitly, because `True` is an `int` and would otherwise
  book one second and report `ok`.

### One finding referred rather than patched

`clayseal.core.task_scope_allows_path` raises `TypeError` / `AttributeError` on
`None`, `0`, `[1]`, `{}` and `True`. It lives in the sibling **clay-seal-core**
repository, so it is reported here rather than edited from this one. The fix is
the same shape as the two above: a non-string path is malformed, never
legitimate, so return `False` rather than raise. `test_gate_totality.py` carries
it as a `strict=True` xfail, which will flip to a failure the moment core is
fixed and the stale expectation needs removing.

### What the harness got wrong before it got anything right

Worth recording, because a harness that cries wolf is worse than none. Its first
three runs reported 16 egress "fail-opens", 5 task-scope "fail-opens" and 19
compute "raises" that were all correct behaviour:

- `''`, `net:`, `@`, `None`, `0` yield **no extractable destination**, so
  "within policy" is right: there is nothing to egress to.
- `/app//data` and `/app/./data` normalise to `/app/data`, which is in scope.
- `evil.test.trusted.test` is a genuine **subdomain** of the allow-listed domain.
  The matcher was verified sound separately: `trusted.test.evil.com`,
  `nottrusted.test` and `xtrusted.test` are all denied, and matching is
  case-insensitive.
- A negative compute estimate raises `ValueError` **by documented design**; a
  typed validation error is a denial mechanism, not a crash.
- `10**30` seconds clamped to the ceiling is the rung *working*.

Each gate now declares its own remit predicate and its own legitimate denial
exceptions, so the report contains only things that are actually wrong. The
egress policy in particular came out of this with a clean bill of health, which
is a result worth stating as plainly as the defects.

### Still unfuzzed

The identity adapters (SPIFFE, OIDC, Auth0, STS, Entra, Azure, GCP), the commit
token verifier, the replay-defense stores, and the sandbox lowering path. Same
two properties apply to all of them and none has been asked.

## Reproduce

```bash
python -m benchmarks.stress_budget --sessions 5000
python -m benchmarks.stress_gates
pytest python/tests/test_value_budget_fail_closed.py benchmarks/tests/test_gate_totality.py -q
```
