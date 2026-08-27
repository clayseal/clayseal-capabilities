# The confidentiality window, re-measured

STATUS: current

`python -m benchmarks.flow`, tau2, 200 sessions, seed 0. This supersedes the
splitting arms in [flow.md](flow.md), which predates the write-windowing. It is
also the measurement the plan required **before** wiring `FlowTracker` into the
broker, and it changes the wiring decision.

## What the window fixed

| arm | before (`flow.md`) | now |
| --- | --- | --- |
| single-write leak | contained | **100.0%** contained (200/200) |
| false-block, real tau2 sink writes | **3.0% at 4 writes rising to 94.6% at 400** | **0.00%** (0 of 1,230) |
| false-block, all benign events | — | **0.00%** (0 of 1,242) |
| **2 fragments, one sink** | **200/200 walked out** | **0/200** |
| 4 fragments, one sink | — | **0/200** |
| 2 and 4 fragments, fan-out | — | **0/200** |
| 2 and 4 fragments, out of order | — | **0/200** |

Two results matter here and they pull in opposite directions from the ones
below. The false-block catastrophe is gone: on real benign traffic containing
nothing sensitive, the tracker now refuses **nothing at all** across 1,242
events, where the unbounded accumulator refused 94.6% of writes in a 400-write
session. And **the cheapest split there is, two writes, went from completely open
to completely closed**. `flow.md` recorded "a value split into two writes with
300 characters of ordinary prose in each walks out whole in 200 of 200 tau2
sessions"; it is now 0 of 200.

That pair is the whole point of windowing. The old accumulator was simultaneously
useless (refusing almost everything) and porous (missing the two-write split),
because a subsequence scan over an unbounded buffer answers "is there enough text
here to spell this" rather than "did these fragments arrive together".

## What remains open, and it is wide splits

| arm | 2 | 4 | 11 | 22 |
| --- | ---: | ---: | ---: | ---: |
| chunked, one sink | 0/200 | 0/200 | 8/200 | **84/200** |
| fan-out | 0/200 | 0/200 | 6/200 | **81/200** |
| out of order | 0/200 | 0/200 | **84/200** | **162/200** |
| reversed | 0/200 | 0/200 | **84/200** | **93/200** |
| concurrent chunked | 0/200 | 0/200 | 16/200 | 87/200 |
| concurrent fan-out | 0/200 | 0/200 | 6/200 | 52/200 |

Chunked at 22 fragments is 84/200, which is exactly what `flow.md` reported
before the window. So the wide-split arms are **not made worse** by the window;
they were open then and they are open now. What changed is that the narrow splits
closed and the false blocks went to zero.

Encoding evasions remain open independently of width: `base85`, `caesar+1`,
`digit-arithmetic+1` and `decimal byte codes` are 100/100 at every width, and
`base64` is 88/100 at k=2. Keyed transforms are marked `KEYED` in the harness and
are out of scope by construction, but the unkeyed encodings are not.

> **UPDATE 2026-08-19, the single-write unkeyed encodings are now closed.**
> The adaptive search against the shipped gateway
> ([adaptive_stack.md](adaptive_stack.md)) found `base85` as the one staging
> evasion of nine that got through, and the cause was a decoder-ordering defect
> rather than a missing decoder: `_decode_layer` stopped at the first attempt
> that did not RAISE, and `urlsafe_b64decode` does not validate, so it "succeeded"
> on a base85 token and the base85 decoder two lines below was never reached.
> Judging whether a decode plausibly succeeded, strictly, so a lossy
> `errors="ignore"` cannot launder noise into printable text, closes five at
> once:
>
> | transform | before | after |
> | --- | ---: | ---: |
> | base32 | leaking | **100% contained (200/200)** |
> | base85 | leaking | **100% contained (200/200)** |
> | base64-of-hex | leaking | **100% contained (200/200)** |
> | double base64 | leaking | **100% contained (200/200)** |
> | decimal byte codes | leaking | **100% contained (200/200)** |
>
> False blocks on real traffic did not move: **0 of 1,242** benign tau2 events,
> the same as before the fix. The keyed transforms (`caesar+1`,
> `digit-arithmetic+1`) are still open and still out of scope by construction
> a keyed transform is not a decoding.
>
> **The COMPOSED arms are unchanged.** Split crossed with a per-fragment
> transform is still open at width, because decoding a fragment yields a
> fragment. That is the fragmentation class below, not this one.

## The wiring decision this forces

The plan said: re-measure first, and *if the splitting arms are still open, wire
as advisory/STEP_UP only and say so.* They are still open at width.

So `FlowTracker` goes into the broker as a **STEP_UP layer, not a DENY layer.**
The justification is not caution for its own sake, it is the shape of the two
tables above: the mechanism is now sound where it fires (0.00% false block on
1,242 real benign events) and incomplete in what it catches (wide splits, unkeyed
encodings). A layer with those properties should ask, not refuse. Refusing on a
mechanism with known holes buys the holes nothing and costs the false blocks
everything.

This also matches what it unlocks. `StagingLadderEngine` currently refuses any
publication-class write after any secret-class read, and
[staging_rung.md](staging_rung.md) records that its friction is a
non-measurement. With the tracker consulted the predicate sharpens from "a secret
was read this session" to "this write's content derives from it", and the honest
outcome set is: derives implies STEP_UP, no derivation implies ALLOW, opaque or
high-entropy content implies STEP_UP.

## Residual, stated

- **Wide splits.** 11 and 22 fragments leak in 3% to 81% of runs depending on the
  arm. Out-of-order at 22 is the worst at 162/200. The volume axis is what should
  own this class: 22 writes to one sink is what the velocity rung sees, and the
  flow axis is bounded on the false-block side deliberately.
- **Unkeyed encodings.** base85, base64-of-hex, base32, decimal byte codes and
  double-base64 are open at every width. These are a decode-layer problem rather
  than a window problem and are not addressed by anything in this change.
  **Closed 2026-08-19**, see the update above. It was indeed a decode-layer
  problem, and specifically a decoder-ORDERING problem: the decoders were all
  present and one was shadowing another.
- **`python/tests/test_flow_order_independence.py`** carries a `strict=False`
  xfail on the concurrency arms at 11 and 22 fragments recording exactly this
  trade, with the measured numbers on both sides.

## Reproduce

```bash
python -m benchmarks.flow
pytest benchmarks/tests/test_flow_invariants.py python/tests/test_confidentiality.py -q
```
