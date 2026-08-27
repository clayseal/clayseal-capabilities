"""CLI: what one authorization costs at the gateway boundary.

    python -m benchmarks.gateway_cost

`benchmarks.latency` measures `engine.decide()` per ladder rung, which is the
floor. This measures the other end: `Guardrail`, the wrapper the README tells
people to use, with a policy compiled from a real document. The two are different
numbers for different questions, and publishing either without saying which is
how this repository ended up with four contradictory latency figures (see
`benchmarks/results/performance.md`).

Four things, because each answers a question the others cannot:

* **throughput** at two argument sizes, since the egress floor scans argument
  text and cost therefore depends on the payload, not only on the policy
* **scaling with session length**, which is the O(N^2) that a session-scoped
  gateway is always one mistake away from
* **cold start**, which dominates for a CLI or a serverless invocation and is
  invisible in any per-call number
* **memory per session**, because a gateway holds sessions open

Deliberately not a wall-clock gate. It reports, and `--check` asserts only the
properties that must hold on any machine: that per-call cost does not grow with
session length, and that memory per session stays bounded.
"""
from __future__ import annotations

import argparse
import gc
import json
import statistics
import subprocess
import sys
import textwrap
import time
import tracemalloc
from pathlib import Path

POLICY = textwrap.dedent("""
    version: 1
    goal: {id: cost-probe, summary: Take notes about the tickets.}
    expires_at: 2030-01-01T00:00:00Z
    tools: {allow: [note], harmless: [note], effects: {note: read}}
    paths: {pathless: [note]}
""")


def _guard(tmp: Path):
    from clayseal.capabilities import Guardrail

    path = tmp / "cost_probe.yaml"
    path.write_text(POLICY)
    guard = Guardrail.from_policy_file(str(path))
    return guard.wrap_all({"note": lambda text=None: "ok"})


def throughput(tmp: Path, *, n: int = 20_000) -> dict:
    """Decisions per second at a small and a large argument."""
    out = {}
    for label, arg in (("small", "a short observation"), ("16kb", "x" * 16_000)):
        tools = _guard(tmp)
        count = n if label == "small" else max(n // 10, 200)
        for _ in range(200):
            tools["note"](text=arg)
        start = time.perf_counter()
        for _ in range(count):
            tools["note"](text=arg)
        elapsed = time.perf_counter() - start
        out[label] = {"n": count,
                      "per_call_us": round(elapsed / count * 1e6, 1),
                      "per_second": round(count / elapsed)}
    return out


def scaling(tmp: Path, *, calls: int = 4000, buckets: int = 8) -> dict:
    """Per-call cost in equal buckets across one long session.

    Flat means no per-call term that walks the session. The ratio of the last
    bucket to the first is the number that matters; the absolute values are
    machine-specific.
    """
    tools = _guard(tmp)
    size = calls // buckets
    medians = []
    for b in range(buckets):
        samples = []
        for i in range(size):
            start = time.perf_counter()
            tools["note"](text=f"observation {b * size + i}")
            samples.append((time.perf_counter() - start) * 1e6)
        medians.append(round(statistics.median(samples), 2))
    return {"calls": calls, "bucket_size": size, "median_us_per_bucket": medians,
            "last_over_first": round(medians[-1] / medians[0], 3) if medians[0] else None}


def cold_start() -> dict:
    """Interpreter-to-usable, which no per-call number can show."""
    def timed(code: str) -> float:
        best = min(
            (lambda t0: (subprocess.run([sys.executable, "-c", code], check=True,
                                        capture_output=True), time.perf_counter() - t0)[1])(
                time.perf_counter())
            for _ in range(5))
        return round(best * 1000, 1)

    bare = timed("pass")
    imported = timed("import clayseal.capabilities")
    return {"bare_interpreter_ms": bare, "import_ms": imported,
            "package_cost_ms": round(imported - bare, 1)}


def memory(tmp: Path, *, calls: int = 2000) -> dict:
    """Bytes retained per idle session, and per decision within one."""
    from clayseal.capabilities import Guardrail

    path = tmp / "cost_probe.yaml"
    path.write_text(POLICY)
    Guardrail.from_policy_file(str(path))          # warm the module caches
    gc.collect()
    tracemalloc.start()

    base = tracemalloc.take_snapshot()
    guards = [Guardrail.from_policy_file(str(path)) for _ in range(50)]
    idle = sum(s.size_diff for s in tracemalloc.take_snapshot().compare_to(base, "filename"))

    tools = guards[0].wrap_all({"note": lambda text=None: "ok"})
    for _ in range(200):
        tools["note"](text="warm")
    before = tracemalloc.take_snapshot()
    for i in range(calls):
        tools["note"](text=f"observation {i}")
    grew = sum(s.size_diff for s in tracemalloc.take_snapshot().compare_to(before, "filename"))
    tracemalloc.stop()
    return {"per_idle_session_kb": round(idle / 50 / 1024, 1),
            "calls": calls, "bytes_per_call": round(grew / calls)}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--json", type=Path, help="write the raw numbers here")
    ap.add_argument("--quick", action="store_true", help="fewer iterations")
    ap.add_argument("--check", action="store_true",
                    help="exit non-zero if a scaling or memory property fails")
    args = ap.parse_args(argv)

    import tempfile
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        n = 2000 if args.quick else 20_000
        calls = 1000 if args.quick else 4000
        report = {
            "throughput": throughput(tmp, n=n),
            "scaling": scaling(tmp, calls=calls),
            "cold_start": cold_start(),
            "memory": memory(tmp, calls=min(calls, 2000)),
        }

    t, s, c, m = (report["throughput"], report["scaling"],
                  report["cold_start"], report["memory"])
    print("# What one authorization costs\n")
    print("STATUS: current\n")
    print("```bash\npython -m benchmarks.gateway_cost\n```\n")
    print("Measured at the `Guardrail` boundary, the wrapper the README documents,")
    print("against a policy compiled from a document. `benchmarks.latency` measures")
    print("the engine floor instead; the two are different questions.\n")
    print("| measurement | value |")
    print("| --- | --- |")
    print(f"| decision, small argument | **{t['small']['per_call_us']} us** "
          f"({t['small']['per_second']:,}/sec, n={t['small']['n']:,}) |")
    print(f"| decision, 16 KB argument | {t['16kb']['per_call_us']} us "
          f"({t['16kb']['per_second']:,}/sec, n={t['16kb']['n']:,}) |")
    print(f"| cost at call {s['calls'] - s['bucket_size']}+ vs call 0-{s['bucket_size']} "
          f"| ratio **{s['last_over_first']}** |")
    print(f"| import `clayseal.capabilities` | {c['package_cost_ms']} ms "
          f"above a {c['bare_interpreter_ms']} ms interpreter |")
    print(f"| memory, idle session | {m['per_idle_session_kb']} KB |")
    print(f"| memory, per decision | {m['bytes_per_call']} bytes "
          f"(**unbounded**, see docs/TRAJECTORY_WINDOW.md) |")
    print(f"\nPer-call medians across the session, in buckets of {s['bucket_size']}: "
          f"{s['median_us_per_bucket']} us.")
    print("\nA ratio near 1.0 is the claim: per-call cost does not grow with session")
    print("length. The absolute microseconds are machine-specific and the ratio is not.")

    if args.json:
        args.json.write_text(json.dumps(report, indent=2))

    if args.check:
        failures = []
        if s["last_over_first"] is not None and s["last_over_first"] > 1.5:
            failures.append(
                f"per-call cost grew {s['last_over_first']}x across the session; "
                "something on the decision path is walking it")
        if m["bytes_per_call"] > 4096:
            failures.append(
                f"{m['bytes_per_call']} bytes retained per decision, over the 4096 ceiling")
        for f in failures:
            print(f"FAIL: {f}", file=sys.stderr)
        return 1 if failures else 0
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
