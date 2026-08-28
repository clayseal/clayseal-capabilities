"""What it costs to treat an observed grant as advisory rather than as authority.

Thirteen loaders build a task's grant from the tools its own benign events use,
and a deployment that derives a policy from a recorded session does the same.
Every tool the recording missed is then refused, even where the same mandate
already authorizes that verb class. This measures both sides of relaxing that:
the benign traffic it recovers, and the containment it costs.

Utility is measured on HELD-OUT mandates (grant built from half a task's benign
events, scored on the other half), because a grant scored against the events it
was built from cannot fail. Security is measured on every attack corpus, and
the report prints how many extensions actually fired, since "containment
unchanged" on a corpus where nothing was admitted is not evidence.
"""

from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path

from benchmarks.core import broker_eval as BE
from benchmarks.core.heldout import hold_out_corpus
from benchmarks.datasets.base import get_loader

ATTACK_CORPORA = ("redcode", "agentharm", "sleight", "ipi_coding", "mcp_attack",
                  "advbench_agent", "agent_threat_bench", "asb", "injecagent")
UTILITY_CORPORA = ("tau2", "bfcl")
_ORIG = BE.stack_from_benchmark_task


def _run(tasks, catalog, cap, *, count=False):
    """Score `tasks`; cap=None runs the shipped default (extension off)."""
    counts: Counter = Counter()
    if cap is None:
        BE.stack_from_benchmark_task = _ORIG
    else:
        def patched(task, **kw):
            stack = _ORIG(task, **kw)
            broker = stack.broker
            broker.tools_are_advisory = True
            broker.tool_catalog = catalog
            broker.scope_is_advisory = True
            broker.max_scope_extensions = cap
            if broker.plan_extender is not None:
                broker.plan_extender.catalog = sorted(catalog)
                broker.plan_extender.max_extensions = cap
            if count:
                real = broker._consider_tool

                def spy(action):
                    ok, why = real(action)
                    counts["considered"] += 1
                    counts["admitted"] += bool(ok)
                    return ok, why

                broker._consider_tool = spy
            return stack
        BE.stack_from_benchmark_task = patched
    try:
        return BE.run_broker_benchmark(tasks, entailment_judge=None), counts
    finally:
        BE.stack_from_benchmark_task = _ORIG


def _catalog(tasks) -> frozenset[str]:
    return frozenset(e.tool_name for t in tasks for e in t.events)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--limit", type=int, default=1200)
    ap.add_argument("--cap", type=int, default=8,
                    help="max distinct tools admitted per session")
    ap.add_argument("--sweep", action="store_true", help="sweep the cap")
    ap.add_argument("--json", type=Path, default=None)
    args = ap.parse_args(argv)
    report: dict = {"cap": args.cap, "utility": {}, "security": {}}

    print("UTILITY, held-out mandates (grant built from half the benign events)\n")
    print(f"  {'corpus':<10} {'n benign':>9} {'FB off':>8} {'FB on':>8}")
    for name in UTILITY_CORPORA:
        try:
            tasks = list(get_loader(name).load(limit=args.limit))
        except Exception:
            continue
        cat = _catalog(tasks)
        held, corrected = hold_out_corpus(tasks, seed=0)
        if not corrected:
            print(f"  {name:<10} {'-':>9} {'':>8} {'':>8}  (grant not observed-derived)")
            continue
        off, _ = _run(held, cat, None)
        on, _ = _run(held, cat, args.cap)
        print(f"  {name:<10} {off.n_benign:>9} {100*off.false_block_rate:7.2f}% "
              f"{100*on.false_block_rate:7.2f}%")
        report["utility"][name] = {"n": off.n_benign,
                                   "off": off.false_block_rate,
                                   "on": on.false_block_rate}

    print("\nSECURITY, every attack corpus. `admitted` is the control: a corpus")
    print("where nothing was admitted says nothing about the cost.\n")
    print(f"  {'corpus':<19} {'contained off':>13} {'on':>8} {'admitted':>9}")
    for name in ATTACK_CORPORA:
        try:
            tasks = list(get_loader(name).load(limit=400))
        except Exception:
            continue
        cat = _catalog(tasks)
        off, _ = _run(tasks, cat, None)
        on, counts = _run(tasks, cat, args.cap, count=True)
        print(f"  {name:<19} {100*off.attack_prevention_rate:12.1f}% "
              f"{100*on.attack_prevention_rate:7.1f}% {counts['admitted']:>9}")
        report["security"][name] = {"off": off.attack_prevention_rate,
                                    "on": on.attack_prevention_rate,
                                    "admitted": counts["admitted"]}

    if args.sweep:
        print("\nCAP SWEEP, tau2 held-out false-block\n")
        tasks = list(get_loader("tau2").load(limit=args.limit))
        cat = _catalog(tasks)
        held, _c = hold_out_corpus(tasks, seed=0)
        for cap in (None, 2, 4, 8, 16, 32, 64):
            r, _ = _run(held, cat, cap)
            print(f"  cap {'off' if cap is None else cap:>4}   "
                  f"{100*r.false_block_rate:6.2f}%")

    if args.json:
        args.json.write_text(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
