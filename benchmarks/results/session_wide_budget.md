# One number, set once: the configuration a deployment can actually supply

STATUS: current

```bash
python -m benchmarks.bpl_sweep --suite full --confidentiality scoped --observe-results \
    --budgets session+refuted --conditions product,product+all
python -m benchmarks.bpl_sweep --suite full --confidentiality scoped --observe-results \
    --budgets none --conditions product,product+all      # the state a grant arrives in
```

## The objection this answers

The aggregate rung is the strongest thing here and it has always rested on a
field nobody writes. Containment is 83.3% where a grant configures a budget and
18.9% where it does not, and across **520 external tasks not one configures a
budget of any kind** ([external_corpora_structure.md](external_corpora_structure.md)).
A reviewer is entitled to say that a mechanism whose best half is inert on every
real task anyone has measured is not deployable, and they would be right.

`budgets.tracked` is the field in question: which tool debits which ceiling, and
through which argument. It reads like an N-tools-by-M-ceilings assignment that
somebody has to maintain as the catalogue changes.

## It is not that decision, because there is only ever one ceiling

Across every scenario in this suite that budgets value at all there is **exactly
one ceiling: 34 of 34** ([derived_budget_binding.md](derived_budget_binding.md)).
With one ceiling there is nothing to disambiguate. The operator is not choosing
which limit a tool debits; they are restating which of their tools spend, and the
schema already says that in the shape of an argument.

So the whole field collapses to a single number set when the session opens. Every
tool whose schema carries a quantity debits it. No per-tool map, no ceiling ids,
no maintenance.

## Result

132 paired scenarios, scoped flow tier, every arm through
`DeployableStack.from_goal`.

| `budgets` | arm | contained | completed | joint |
| --- | --- | ---: | ---: | ---: |
| `none`, the state a grant arrives in | product | 48 | 130 | 46 |
| | product+all | 60 | 130 | 58 |
| `session`, one ceiling, no refutation | product | 76 | 128 | 72 |
| | product+all | 88 | 128 | 84 |
| **`session+refuted`** | product | 76 | **130** | **74** |
| | **product+all** | **88** | **130** | **86** |
| `session-identity+refuted` | product+all | 90 | 128 | 87 |
| `declared`, hand-written per-tool map | product | 78 | 130 | 76 |
| | product+all | 90 | 130 | 88 |

**`session+refuted` against `none`: +28 gains, 0 regressions, exact McNemar
p = 7.4e-09.**

**`declared` against `session+refuted`: +2 gains, 0 regressions, p = 0.5.** A
hand-written per-tool map, the configuration no real deployment has, is not
distinguishable on this suite from one number set once.

## What refutation buys, and it is specific

Without it a single session-wide counter costs two benign completions,
`layering-hop-chain` and `round-trip-spend-wash`. Both are scenarios where value
legitimately moves in a circle or through hops, so one running total counts the
same money more than once and refuses the operator's own work. That is the
genuine conceptual cost of collapsing to one counter, and replaying the
operator's own known-good traffic is what tells the ceiling which hops to stop
counting. Completion returns to 130.

## What the identity variant does, and why it is not the default

`session-identity+refuted` recovers containment to 90, matching `declared`,
by binding an idempotency key alongside the amount. It costs the same two
completions back, for a joint of 87 against 86. The two scenarios it recovers are
`idempotent-double-pay` and `retry-storm-double-effect`, which need to tell a
retry from a second payment. Offered, not defaulted: it trades a benign
completion for a containment and this suite cannot say which a deployment wants.

## What may not be quoted

**The completion column on any `+refuted` arm is guaranteed by construction
here.** A scenario's only known-good trace is its own benign twin, so the traffic
that refutes the bindings is then the traffic scored. Containment is honest,
because refutation never sees an attack. A deployment refutes against its own
logs and afterwards serves different traffic, so it does not inherit this, but
this suite cannot measure that and does not claim to.

**`session` mode declines when a grant states more than one ceiling.** That is
not a limitation dodged, it is the case where the operator genuinely expressed
something a single counter throws away, and scoring it would report a number for
a configuration nobody chose. It never fires on this suite, because 34 of 34
state one ceiling.
