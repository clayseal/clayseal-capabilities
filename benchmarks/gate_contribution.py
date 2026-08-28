"""What each gate contributes, and what it costs, measured by removing it.

The observed-grant finding generalises: a gate can refuse a lot of benign
traffic while catching nothing that the gates around it would not have caught
anyway. Reading the code cannot tell you which ones those are, because every
gate looks load-bearing in isolation. Removing it and re-running can.

For each gate this reports:

* **unique catch**, attacks contained with the full stack that escape when only
  this gate is removed. Not "attacks this gate denied": a gate that denies an
  attack three other gates also deny contributes nothing, and the denial reason
  would still credit it.
* **benign cost**, held-out benign events it refuses.

A gate with a benign cost and no unique catch is pure friction on the corpora
measured. That is a finding about these corpora, not a theorem, and the report
prints the denominators so the difference is visible.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from benchmarks.core import broker_eval as BE
from benchmarks.core.events import EventLabel
from benchmarks.core.heldout import hold_out_corpus
from benchmarks.datasets.base import get_loader

_ORIG = BE.stack_from_benchmark_task

#: gate name -> (attribute, disabled value). Every one is a field a deployment
#: can genuinely leave unset, so "removed" means "not configured", not "patched".
GATES: dict[str, tuple[str, object]] = {
    "tool allow-list": ("allowed_tools", None),
    "capability list": ("capabilities", None),
    "resource scope": ("scope", None),
    "egress": ("egress", None),
    "value budget": ("value_budget", None),
    "call budget": ("call_budget", None),
    "intent envelope": ("intent_envelope", None),
    "detector": ("detector", None),
    "flow tracker": ("flow", None),
    "provenance": ("provenance", None),
    "conditional tools": ("conditional_tools", None),
    "credential payloads": ("refuse_credential_payloads", False),
}

ATTACK = ("redcode", "agentharm", "sleight", "ipi_coding", "mcp_attack",
          "advbench_agent", "agent_threat_bench", "asb", "injecagent")


def _run(tasks, ablate: str | None):
    """Score with one gate removed. `ablate=None` is the full stack."""
    if ablate is None:
        BE.stack_from_benchmark_task = _ORIG
    else:
        attr, off = GATES[ablate]

        def patched(task, **kw):
            stack = _ORIG(task, **kw)
            setattr(stack.broker, attr, off)
            return stack
        BE.stack_from_benchmark_task = patched
    try:
        return BE.run_broker_benchmark(tasks, entailment_judge=None)
    finally:
        BE.stack_from_benchmark_task = _ORIG


def _contained_ids(tasks, ablate: str | None) -> set[str]:
    """Which attack events were contained, by event id."""
    ids: set[str] = set()
    rec0 = BE._record

    def rec(result, event, decision, ms):
        if getattr(event, "label", None) is EventLabel.ATTACK and not decision.allowed:
            ids.add(event.event_id)
        return rec0(result, event, decision, ms)

    BE._record = rec
    try:
        _run(tasks, ablate)
    finally:
        BE._record = rec0
    return ids


#: denial-reason substring -> gate, for first-refuser attribution.
_REASON_TO_GATE = (
    ("not granted", "tool allow-list"),
    ("no capability for", "capability list"),
    ("out of scope", "resource scope"),
    ("not on the egress", "egress"),
    ("egress to", "egress"),
    ("budget", "value budget"),
    ("call allowance", "call budget"),
    ("not in the goal's plan", "intent envelope"),
    ("off-plan", "intent envelope"),
    ("withdrawn", "conditional tools"),
    ("credential", "credential payloads"),
)


def _attack_refusers(corpora) -> dict[str, int]:
    """How often each gate was the first to refuse an ATTACK event.

    This separates the two reasons a gate can show zero unique catch. A gate
    that fired and was merely redundant is a finding. A gate that never fired
    at all was not tested, and reading its zero as "contributes nothing" is how
    someone deletes the budget rung, which carries the 83.3% headline on a suite
    this scan does not load.
    """
    counts: dict[str, int] = {}
    rec0 = BE._record

    def rec(result, event, decision, ms):
        if getattr(event, "label", None) is EventLabel.ATTACK and not decision.allowed:
            reason = str((getattr(decision, "reasons", ()) or ("?",))[0]).lower()
            gate = next((g for frag, g in _REASON_TO_GATE if frag in reason), "other")
            counts[gate] = counts.get(gate, 0) + 1
        return rec0(result, event, decision, ms)

    BE._record = rec
    try:
        for tasks in corpora.values():
            _run(tasks, None)
    finally:
        BE._record = rec0
    return counts


def _first_refuser(tasks) -> dict[str, int]:
    """Which gate produced the denial, per refused benign event.

    A gate can be the first to refuse a large share of benign traffic and still
    show zero *unique* cost, because another gate behind it refuses the same
    events. That pair is the finding: removing one changes nothing, removing
    the set changes everything. See results/observed_grant.md.
    """
    counts: dict[str, int] = {}
    rec0 = BE._record

    def rec(result, event, decision, ms):
        if getattr(event, "label", None) is EventLabel.BENIGN and not decision.allowed:
            reason = str((getattr(decision, "reasons", ()) or ("?",))[0]).lower()
            gate = next((g for frag, g in _REASON_TO_GATE if frag in reason), "other")
            counts[gate] = counts.get(gate, 0) + 1
        return rec0(result, event, decision, ms)

    BE._record = rec
    try:
        _run(tasks, None)
    finally:
        BE._record = rec0
    return counts


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--limit", type=int, default=300)
    ap.add_argument("--json", type=Path, default=None)
    args = ap.parse_args(argv)

    corpora = {}
    for name in ATTACK:
        try:
            corpora[name] = list(get_loader(name).load(limit=args.limit))
        except Exception:
            continue
    tau2 = list(get_loader("tau2").load(limit=800))
    held, _ = hold_out_corpus(tau2, seed=0)

    base_ids = {n: _contained_ids(t, None) for n, t in corpora.items()}
    base_fb = _run(held, None).false_block_rate
    total_contained = sum(len(v) for v in base_ids.values())
    print(f"full stack: {total_contained} attack events contained across "
          f"{len(corpora)} corpora; held-out benign false-block "
          f"{100*base_fb:.2f}% of {len(held)} tau2 tasks\n")
    refusers = _first_refuser(held)
    fired = _attack_refusers(corpora)
    n_refused = sum(refusers.values()) or 1
    print(f"  {'gate':<21} {'unique catch':>13} {'unique cost':>12} "
          f"{'first to refuse':>16}   where")
    rows = []
    for gate in GATES:
        lost: dict[str, int] = {}
        for name, tasks in corpora.items():
            missing = base_ids[name] - _contained_ids(tasks, gate)
            if missing:
                lost[name] = len(missing)
        fb = _run(held, gate).false_block_rate
        cost = base_fb - fb          # benign events this gate refuses
        unique = sum(lost.values())
        where = ", ".join(f"{k} {v}" for k, v in sorted(
            lost.items(), key=lambda x: -x[1])[:3]) or "-"
        first = refusers.get(gate, 0)
        exercised = unique > 0 or fired.get(gate, 0) > 0
        note = where if exercised else "NOT EXERCISED by these corpora"
        print(f"  {gate:<21} {unique:>13} {100*cost:>11.2f}% "
              f"{first:>9} ({100*first/n_refused:4.1f}%)   {note}")
        rows.append({"gate": gate, "unique_catch": unique, "benign_cost": cost,
                     "first_to_refuse": first, "exercised": exercised,
                     "where": lost})

    friction = [r for r in rows
                if r["unique_catch"] == 0 and r["exercised"]
                and (r["benign_cost"] > 0 or r["first_to_refuse"] > 0)]
    unexercised = [r["gate"] for r in rows if not r["exercised"]]
    if friction:
        print("\nGATES THAT COST BENIGN TRAFFIC AND CATCH NOTHING UNIQUELY:")
        for r in friction:
            print(f"  {r['gate']}: refuses {r['first_to_refuse']} held-out benign "
                  f"events first, catches nothing the rest of the stack misses")
        print("  On these corpora. Another corpus may need them; the point is")
        print("  that these ones do not, and that was not visible from the code.")
    if unexercised:
        print("\nNOT EXERCISED, so their zero says nothing either way:")
        print("  " + ", ".join(unexercised))
        print("  These need a corpus that provokes them. The budget rungs carry")
        print("  the 83.3% in the README and are measured by bpl_sweep, which")
        print("  this scan does not load.")
    if args.json:
        args.json.write_text(json.dumps(rows, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
