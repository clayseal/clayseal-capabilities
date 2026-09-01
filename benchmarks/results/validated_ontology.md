# Validating the compiled ontology removes the review, and the regressions

STATUS: current

```bash
python -m benchmarks.compile_ontology     # once per catalogue, offline
python -m benchmarks.validate_ontology    # once per catalogue, offline
python -m benchmarks.precondition_rung    # deterministic, no model
```

[compiled_ontology.md](compiled_ontology.md) established the split, compile once
per catalogue and enforce deterministically per call, and found that an
**unreviewed** artifact is a wash: +9 attacks contained against 8 benign tasks
broken. Every regression was a precondition the compiler invented, always of one
kind:

```
staged_count     requires delete_staged        a count, gated on the delete
whoami           requires persona_active       a read
trade_log        requires invoice_paid         a read
pay_vendor       requires open_payments_listed workflow habit, not a requirement
```

The design answered that with "a person reviews it once per catalogue". That is
still a person. This removes them from the common case.

## The rule

**A precondition that legitimate traffic violates is not a precondition.**

Replay known-good traces against the compiled operators. Wherever a trace runs a
tool whose declared precondition is unmet, the declaration is contradicted by
evidence and is dropped. What survives is the subset of the compiler's guesses
that no legitimate run disagrees with.

This is a compile-time pass over historical traffic, at the same trust tier and
the same moment as the compile. It is not a decision-time read of a live task's
output.

## Result

| | contained | completed | joint | vs baseline |
| --- | ---: | ---: | ---: | --- |
| goal-derived rungs | 75 | 130 | 73 | |
| + raw compiled ontology | 87 | 115 | 74 | +9 -8, p = 1.0 |
| + one review rule | 87 | 120 | 76 | +9 -6, p = 0.61 |
| **+ validated ontology** | **85** | **130** | **83** | **+10 -0, p = 0.002** |

Ten scenarios gained, none lost, and completion returns to its unmoved 130.

**The validation is surgical, which is the load-bearing check.** It drops 25 of
511 compiled preconditions and keeps 486, or 95%. An artifact tuned until it
stopped disagreeing with the benign trace would have lost far more; the
containment comes from the 95% that legitimate traffic never contradicted.

## What is measured and what is guaranteed

Say plainly which column is which.

**Containment (85) is measured.** Validation never sees an attack. The traces it
reads are the benign ones, and the 85 is scored on violating scripts it has no
knowledge of.

**Completion (130) is guaranteed by construction, and is not a result.** On this
benchmark the only known-good trace for a catalogue is that scenario's own benign
twin, so validating on it and then scoring it can only return 130. Reporting that
as evidence would be circular.

In deployment the two come apart usefully: the validating traffic is historical
and the judged session is new, so the guarantee becomes *traffic resembling what
you validated on cannot be refused*, which is real but partial. Traffic of a shape
never seen at compile time can still be refused, and this benchmark cannot
estimate how often, because each catalogue ships exactly one benign trace.

## Automatic severity, and a caveat on it

Severity needs no lexicon: an operator whose effects no tool in the catalogue can
undo is the costly one, and the compiler emits `reversible` per tool. That is
declared structure rather than a name-based prior, which
[tool_risk.md](tool_risk.md) showed is fit on the evaluation set.

**The compiler over-marks it.** 415 of 600 operators come back irreversible, 69%,
which is implausible for a catalogue containing this many reads and logs. Severity
therefore separates less than it should, and the same validation idea would
sharpen it: an effect that a later tool in some known-good trace demonstrably
undoes is reversible, whatever the compiler said. That is not built.

## Cost

One model call per catalogue at compile time, cached and versioned with the
schema. Zero per prompt. At decision time the rung is a set-membership test
against the session's own history, with no model and no network.
