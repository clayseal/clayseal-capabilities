## What this changes

<!-- One or two sentences. -->

## Does it change a decision the gateway makes?

<!--
The question that matters most here. If an action that was allowed is now
denied, or one that was denied is now allowed, say so and show the measurement.
"No" is a perfectly good answer for a docs or refactor change.
-->

- [ ] No, this cannot change any authorization outcome
- [ ] Yes, and the effect is measured below

<!-- If yes: -->
```
python -m benchmarks.bpl_sweep --suite full
before:
after:
```

## Checks

- [ ] `pytest python/tests -q`
- [ ] `ruff check clayseal agentauth`
- [ ] New behaviour has a test that **fails without the change**
- [ ] If this closes a bypass, there is a control asserting the mechanism is not
      silently inert (a test that only ever asserts "denied" also passes when
      the checker stops running)

## Notes for the reviewer

<!-- What you are unsure about; where you want the argument. -->
