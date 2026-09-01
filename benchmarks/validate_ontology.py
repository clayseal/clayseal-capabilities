"""Validate a compiled ontology against known-good traffic, at compile time.

    python -m benchmarks.validate_ontology

`compiled_ontology.md` showed the split works and that an UNREVIEWED artifact is
a wash: +9 attacks contained against 8 benign tasks broken, every regression a
precondition the compiler invented. `staged_count requires delete_staged`.
`whoami requires persona_active`. Looking at what you are about to do is never
gated on having done it.

The design answered that with "a person reviews it once per catalogue". That is
still a person, and the objection to per-prompt effort applies with less force
but does apply. So this removes the person from the common case.

## The rule

**A precondition that legitimate traffic violates is not a precondition.**

Replay known-good traces for a catalogue against its compiled operators. Every
time a trace runs a tool whose declared precondition is unmet, that declaration
is contradicted by evidence, and it is dropped. What survives is the subset of
the compiler's guesses that no legitimate run disagrees with.

This is a compile-time step over historical traffic, not a decision-time read of
a live task's output. It is the same trust tier and the same moment as the
compile itself.

## What it guarantees, and the honest limit of measuring it here

Validation makes the artifact **safe by construction against traffic of the shape
it validated on**: those runs cannot be refused, because every precondition they
contradict has been removed. So benign completion is not an interesting
measurement afterwards, it is an identity, and the only open question is how much
containment survives.

In deployment the validating traffic is historical and the traffic being judged
is new, so the guarantee is real but partial. In this benchmark the only
known-good trace for a catalogue is that scenario's own benign twin, so the
completion column is guaranteed by construction and is reported as such rather
than as a result. Containment is measured on the attack, which validation never
saw.
"""
from __future__ import annotations

import argparse
import json

from benchmarks.bpl.registry import get_scenario
from benchmarks.precondition_rung import PreconditionLedger, _replay, specs_for


def validate(specs: dict, good_traces: list[list[str]]) -> tuple[dict, int]:
    """Drop every precondition that a known-good trace contradicts."""
    dropped = 0
    specs = {t: {"pre": set(v["pre"]), "add": set(v["add"]),
                 "del": set(v["del"]), "rev": v["rev"]}
             for t, v in specs.items()}
    for trace in good_traces:
        led = PreconditionLedger(specs)
        for tool in trace:
            spec = specs.get(tool)
            if spec is not None:
                unmet = {f for f in spec["pre"]
                         if f in led.producible and f not in led.world}
                if unmet:
                    spec["pre"] -= unmet     # contradicted by legitimate work
                    dropped += len(unmet)
            led.observe(tool)
    return specs, dropped


def severity_report(specs: dict) -> dict:
    """Automatic severity: an operator no tool can undo is the costly one."""
    irr = [t for t, v in specs.items() if not v["rev"]]
    return {"tools": len(specs), "irreversible": len(irr)}


def run() -> dict:
    rows = {r["scenario"]: r for r in json.load(open("/tmp/base.json"))}
    A = "clayseal+identity"
    contained = completed = joint = 0
    gains, regs = [], []
    dropped_total = irr_total = tool_total = 0
    for n, r in rows.items():
        s = get_scenario(n)
        raw = specs_for(s) or {}
        good = [[t for t, _ in s.compliant_script]] if s.compliant_script else []
        specs, dropped = validate(raw, good)
        dropped_total += dropped
        sr = severity_report(specs)
        irr_total += sr["irreversible"]
        tool_total += sr["tools"]
        pv, _ = _replay(s, s.violating_script,
                        lambda q=specs: PreconditionLedger(q), False)
        _, pb = _replay(s, s.compliant_script,
                        lambda q=specs: PreconditionLedger(q), False)
        c = r["cells"][A]["contained"] or (pv is False)
        m = r["cells"][A]["completed"] and (pb == 0)
        bj = r["cells"][A]["contained"] and r["cells"][A]["completed"]
        contained += c
        completed += m
        joint += c and m
        if (c and m) and not bj:
            gains.append(n)
        if bj and not (c and m):
            regs.append(n)
    return {"contained": contained, "completed": completed, "joint": joint,
            "gains": gains, "regressions": regs, "dropped": dropped_total,
            "irreversible": irr_total, "tools": tool_total}


def main(argv=None) -> int:
    from math import comb
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--json", type=str, default=None)
    args = p.parse_args(argv)
    r = run()
    b, x = len(r["gains"]), len(r["regressions"])
    pv = 2*sum(comb(b+x, k)*0.5**(b+x) for k in range(0, min(b, x)+1)) if b+x else 1.0
    print("\nCompiled ontology, validated against known-good traffic\n")
    print(f"  preconditions dropped as contradicted : {r['dropped']}")
    print(f"  severity: irreversible operators      : {r['irreversible']} "
          f"of {r['tools']} tools")
    print("\n  combined with the goal-derived rungs:")
    print(f"    contained {r['contained']}   completed {r['completed']}   "
          f"joint {r['joint']}")
    print(f"    +{b} -{x}   exact McNemar p = {min(1.0, pv):.4g}")
    if r["regressions"]:
        print(f"    regressions: {r['regressions']}")
    print("\n  Completion is guaranteed by construction on validated traffic and")
    print("  is not a result. Containment is measured on attacks validation")
    print("  never saw.")
    if args.json:
        with open(args.json, "w") as fh:
            json.dump(r, fh, indent=2)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
