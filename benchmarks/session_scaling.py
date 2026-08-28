"""What a long session costs, which `latency.py` cannot see.

    python -m benchmarks.session_scaling
    python -m benchmarks.session_scaling --lengths 100,500,1000,2000,4000

`latency.py` reports per-decision cost on the ladder rungs, which are stateless
per event, so its numbers are flat in session length by construction. The
shipped stack is not stateless: the intent envelope re-assesses the WHOLE
trajectory on every decision, so the cost of the thousandth tool call is not the
cost of the first.

That is invisible to every other measurement in this repository, because the
corpora have short tasks. `agentharm` averages a handful of actions and the
longest is well under a hundred. An agent that runs for an hour is a different
regime and nothing here was measuring it.

## What this reports

Total wall time and mean per-decision cost at several session lengths, on the
real `DeployableStack` with an intent envelope attached, plus the growth
exponent fitted across them. An exponent near 1 means per-decision cost is flat
and the session is linear; near 2 means the session is quadratic and the last
decision is much dearer than the first.
"""
from __future__ import annotations

import argparse
import math
import sys
import time

from clayseal.capabilities.deployable_stack import DeployableStack
from clayseal.capabilities.monitor.action import Action
from clayseal.capabilities.monitor.generation import compile_envelope
from clayseal.capabilities.scoping.goal import GoalSpec

DEFAULT_LENGTHS = (100, 250, 500, 1000, 2000)


def _goal() -> GoalSpec:
    return GoalSpec(
        query_id="scaling",
        summary="Read each invoice under /finance/ap and write a summary",
        allow_resources=["/finance/ap/**", "/finance/out/**"],
        structured_intent={"kind": "ap", "verbs": ["read", "write"],
                           "tools": ["read_file", "write_file"]})


def _action(step: int) -> Action:
    path = f"/finance/ap/inv-{step}.json"
    return Action(step=step, tool="read_file", resource=path, verb="read",
                  args={"path": path}, meta={"path": path})


def run(length: int, *, envelope) -> float:
    stack = DeployableStack.from_goal(_goal(), intent_envelope=envelope)
    start = time.perf_counter()
    for step in range(1, length + 1):
        stack.authorize(_action(step))
    return time.perf_counter() - start


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--lengths", default=",".join(str(n) for n in DEFAULT_LENGTHS))
    args = p.parse_args(argv if argv is not None else sys.argv[1:])
    lengths = [int(n) for n in args.lengths.split(",") if n.strip()]

    envelope = compile_envelope(_goal(), derive_counts=False).envelope
    warm = DeployableStack.from_goal(_goal(), intent_envelope=envelope)
    for step in range(30):
        warm.authorize(_action(step))

    print("# What a long session costs\n")
    print("STATUS: current\n")
    print("```bash")
    print(f"python -m benchmarks.session_scaling --lengths {args.lengths}")
    print("```\n")
    print("`DeployableStack` with an intent envelope, one session, no attacks.\n")
    print("| actions in the session | total | mean per decision |")
    print("| --: | --: | --: |")
    points: list[tuple[int, float]] = []
    for length in lengths:
        elapsed = run(length, envelope=envelope)
        points.append((length, elapsed))
        print(f"| {length} | {elapsed:.2f} s | {elapsed / length * 1e6:.0f} us |")

    if len(points) >= 2:
        (n0, t0), (n1, t1) = points[0], points[-1]
        exponent = math.log(t1 / t0) / math.log(n1 / n0)
        print(f"\nFitted growth exponent across the range: **{exponent:.2f}**. "
              f"An exponent near 1\nmeans per-decision cost is flat; near 2 "
              f"means the session is quadratic and the\nlast decision costs "
              f"far more than the first.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
