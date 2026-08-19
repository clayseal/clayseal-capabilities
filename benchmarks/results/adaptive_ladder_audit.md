# The adaptive red-team: a calibration defect, and a saturated ladder

STATUS: current

Two findings from running `benchmarks/adaptive.py` against the density rung. The
first is a bug in the harness. The second is about what the existing published
adaptive tables actually show, and it is the more consequential of the two.

## 1. The harness never calibrated the engines it attacked

`run_benchmark` gives a calibrated engine one look at clean traffic through
`observe_corpus`, using a split where attack-bearing tasks never calibrate
anything. The adaptive path did not call it at all — `observe_corpus` appears
only in `benchmarks/core/runner.py`.

The omission was invisible because an uncalibrated engine does not fail, it
defaults:

| rung | uncalibrated | calibrated on RedCode |
| --- | --- | --- |
| `…+velocity` | `default_cap = 5` | `_cap = 32` |
| `…+velocity+density` | no baseline → abstains on every event | fitted, threshold 10.49 bits |

So every adaptive result for the velocity rung was produced with a cap **6.4×
tighter** than the one an operator would set from their own logs, which biases
containment upward — the direction that flatters the system. The density rung was
worse off: with no baseline it abstains on every event, so its row is a verbatim
copy of its parent's, and a row that cannot differ from the one above it is not a
measurement.

Fixed by `benchmarks/adaptive.calibrate()`, which reuses the runner's own
`_calibration_split` so the discipline is identical in both harnesses. Pinned by
[../tests/test_adaptive_calibration.py](../tests/test_adaptive_calibration.py),
including the invariant that no attack-bearing task ever reaches the calibration
set.

## 2. The ladder is a step function, and one rung does all the work

With calibration wired, the full ladder against an oracle attacker on RedCode:

| Engine | blind | feedback | oracle |
| --- | --- | --- | --- |
| allow-all | 0% | 0% | 0% |
| tool-allowlist | 0% | 0% | 0% |
| capability-token | 0% | 0% | 0% |
| **task-scope** | **100%** | **100%** | **100%** |
| task-scope+binding | 100% | 100% | 100% |
| task-scope+binding+budget | 100% | 100% | 100% |
| …+velocity+density | 100% | 100% | 100% |

77,078 candidates tried across five rounds, zero escapes above `task-scope`.

**Everything above `task-scope` contributes exactly zero on this test.** The
headline that the stack holds 100% against an attacker who reads the compiled
policy is true, and it is a `task-scope` result. Binding, budget, velocity and
the new density rung are indistinguishable from it and from each other.

The same step function appears in all three already-published tables —
`adaptive_exfiltration.md`, `adaptive_persistence.md`, `adaptive_destruction.md`.
So the calibration defect above never changed a published number: those tables
were saturated, and a 6.4×-too-tight velocity cap lands on the same 100% as a
correct one. The defect was real, latent, and would have surfaced the first time
the harness was pointed at a corpus where velocity discriminates.

### Why it saturates, and why that is partly good news

The `AttackObjective` predicate is doing its job. Exfiltration requires reaching
a credential-bearing file *and* sending it to an external host; `task-scope`
denies the path by definition, and every mutation that stays in scope stops
achieving the objective and is discarded as a failed attack rather than counted
as an escape. There is no in-scope route to an out-of-scope outcome, so the
result is a tautology in the good sense — the mechanism is sound and the test
confirms it can't be talked around.

But it means this test cannot rank the ladder, and the ladder is what the
scoreboard sells. A benchmark where rungs 4 through 7 are identical measures rung
4.

## What should change

- **`SEND_PACKET.md` should attribute the adaptive result to `task-scope`**, not
  to the stack. The current framing invites a reader to credit the top rung.
- **The adaptive suite needs an objective the lower rungs do not already
  contain** if it is to discriminate at all. Candidates: an objective achievable
  entirely *within* scope (in-workspace credential exfiltration, which is exactly
  what the density's L1 mimicry failure was about), or aggregate-volume
  objectives that only the budget and velocity rungs can see.
- **Do not add the density rung to `LADDER`** on the strength of this table. It
  scores 100% here, and so does every rung below it; the number carries no
  information about the rung.

## Reproduce

```bash
python -m benchmarks.adaptive --dataset redcode --limit 80 --rounds 5 \
  --engines "allow-all,tool-allowlist,capability-token,task-scope,\
task-scope+binding,task-scope+binding+budget,task-scope+binding+budget+velocity+density"
pytest benchmarks/tests/test_adaptive_calibration.py -q
```
