# What enforcement costs

STATUS: current

This is the one place performance numbers live. Every other document links here
rather than restating a figure, because restating them is how this repository
came to publish four different p50 latencies for "the full stack".

## The four numbers that disagreed

They were all produced honestly and they measure different things. Nothing was
wrong except that none of them said which:

| figure | source | what it actually measured |
| --- | --- | --- |
| 18.9 µs p50 / 180.8 µs p99 | `latency_redcode.md` | `engine.decide()` on the `task-scope+binding+budget` rung, redcode, 10,880 decisions |
| 35 µs p50 / 60 µs p99 | `docs/METHODOLOGY_MEMO.md` | quoted from an earlier run of the above |
| 94 µs p50, 10,000/sec | `full_stack_benchmark.md` | `broker.authorize()` including receipt emission |
| "approx 200 µs, n=3000" | `head_to_head_injection.md` | a live AgentDojo run, so it includes harness overhead |

`baselines_audit.md` flagged this against itself before this file existed:
*"Our own figure is inconsistent across files… Pick one, name the stack and n."*
The resolution is not to pick a favourite. It is to name the measurement point
beside every number, which is what the table below does.

## The measurement points

Three, and they are not interchangeable. Quote the one that matches what you are
deploying.

| point | what it includes | p50 | reproduce |
| --- | --- | ---: | --- |
| engine floor | one ladder rung, no session | 0.7 µs | `python -m benchmarks.latency --dataset redcode --repeats 20` |
| full ladder | scope + binding + budget | 18.9 µs | same command, bottom row |
| **`Guardrail`** | **the wrapper the README documents, policy compiled from a document, all default layers** | **34.1 µs** | `python -m benchmarks.gateway_cost` |

**Quote the `Guardrail` row** unless you know you mean otherwise. It is the only
one that corresponds to something a reader installs.

## The gateway boundary, in full

`python -m benchmarks.gateway_cost` — full output in
[gateway_cost.md](gateway_cost.md).

| measurement | value |
| --- | --- |
| decision, small argument | **34.1 µs** (29,331/sec, n=20,000) |
| decision, 16 KB argument | 206.5 µs (4,842/sec, n=2,000) |
| cost at call 3,500+ vs call 0-500 | **ratio 1.0** |
| import `clayseal.capabilities` | 2.5 ms above a 19.4 ms interpreter |
| policy compile, warm | 0.24 ms |
| memory, idle session | 11.7 KB |
| memory, per decision | 1,182 bytes, **unbounded** |

An agent acts at roughly 1 to 10 actions per second and an LLM tool-call round
trip is hundreds of milliseconds, so the median is about four orders of magnitude
below the thing it gates. The median is not the interesting number.

## The three numbers that are

### Cost depends on the argument, and the argument is attacker-influenced

The egress floor scans argument text for destinations, so a 16 KB body costs 6×
a short one. That is by design and it is bounded (`MAX_SCAN_CHARS = 16_384`), but
it means "34 µs" is a statement about payloads, not just policies.

0.6 replaced the per-character scan with a translation table, which is 24 to 42×
faster on that step for byte-identical output:

| | before | after |
| --- | ---: | ---: |
| `EgressPolicy.check`, 16 KB body | 1.244 ms | 0.868 ms |
| `EgressPolicy.check`, 16 KB of `@` | 3.600 ms | 2.204 ms |

### The tail, which has an attacker on it

`confidentiality._subsequence_coverage` is the one place a single call can stall
the gateway. From [flow.md](flow.md): tau2 p99 **2.1 ms** against its own 27 µs
median; BFCL at the full 64-write accumulator p50 **2.1 ms**, p99 **10.7 ms**;
one run of the same command on the same machine peaked at **219 ms**. Under
cProfile over 120 writes it is 11.35 s of 11.48 s.

flow.md's own words: *"The tail also has an attacker on it… one write can hold
the tracker lock for seconds."*

This is enabled by default (`enable_flow=True`) and its expensive path switches on
once a session has read something sensitive — that is, on exactly the sessions
the feature exists to protect. **It is the open performance problem.** Bounding
it is not a tuning change: the search is what produces the verdict.

### Memory is unbounded per session

1,182 bytes per decision, so roughly 120 MB at 100,000 actions in one session.
0.6 bounded one of the four sources; the other three need a windowed trajectory
with an aggregate that survives eviction, and the analysis for that —
including why the BPL suite **cannot** choose the window size — is
[docs/TRAJECTORY_WINDOW.md](../../docs/TRAJECTORY_WINDOW.md).

## What 0.6 changed

| change | effect |
| --- | --- |
| `str.translate` for the egress scan | 24-42× on that step, byte-identical output |
| `CSafeLoader` when libyaml is present | policy compile 4.5 ms → 0.24 ms |
| PEP 562 lazy exports | import 85 ms → 2.5 ms of package cost |
| bounded overhead samples | `summary()` no longer sorts a growing list; one leak of four closed |

None of it moved containment: BPL stays at 39.4% (52/132) with friction
unchanged at 2 benign scripts refused and 0 work lost.

## What is not measured here

- **Throughput under contention.** Every number above is single-threaded. The
  broker takes a lock per authorization; the contended shape is not measured.
- **The `flow` tail as a distribution.** [flow.md](flow.md) has it, and its own
  warning applies: *"read the shape rather than any single cell"* — an earlier run
  gave a max of 219 ms where the current one gives 33 ms.
- **Cross-process ledger cost.** `SharedPrincipalLedger` takes a file lock per
  reservation; correctness is tested, cost is not.
