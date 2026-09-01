"""Precedence and severity from a compiled ontology, with no goal text at all.

    python -m benchmarks.precondition_rung

`compile_ontology.py` produces, once per catalogue and offline, a planning
operator per tool: what it requires, what it establishes, what it destroys, and
whether that can be undone. This is the runtime half, and it is **deterministic**:
no model, no network, no nondeterminism. It reads the compiled artifact and the
session's own history.

## The rule

A fact that some tool in the catalogue ESTABLISHES is a fact this session can
produce. A precondition over such a fact is therefore an ordering constraint: the
producer must run before the consumer. A precondition over a fact no tool
establishes is a statement about the world before the session opened, and is
assumed to hold, because refusing it would refuse the first action of every task.

That is precedence derived from the catalogue rather than from the goal, which is
the limitation the lexical rungs could not escape. Nothing here reads the goal
sentence.

Severity comes from the same artifact. An operator marked irreversible is one
whose effects no tool in the catalogue can undo, which is the property that makes
an action worth stopping.

## Posture

The compiled artifact is a DERIVED ARTIFACT a person reviews once, so a
precondition that is merely unmet escalates, and only an unmet precondition on an
irreversible action denies. A compiler's guess should not silently become a hard
refusal.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os

from benchmarks.bpl.registry import SCENARIOS, get_scenario
from benchmarks.compile_ontology import _schema_only, load_cache

DEPLOYMENT = os.environ.get("CLAYSEAL_MONITOR_DEPLOYMENT", "gpt-4.1-mini")


def specs_for(scen) -> dict | None:
    """The compiled operators for this scenario's catalogue, or None."""
    schema = _schema_only(scen.tools)
    if not schema:
        return None
    digest = hashlib.sha256(
        (DEPLOYMENT + json.dumps(schema, sort_keys=True)).encode()).hexdigest()
    raw = load_cache().get(digest)
    if not raw:
        return None
    out = {}
    for s in raw:
        if isinstance(s, dict) and s.get("tool"):
            out[str(s["tool"])] = {
                "pre": {str(x) for x in s.get("preconditions") or ()},
                "add": {str(x) for x in s.get("establishes") or ()},
                "del": {str(x) for x in s.get("destroys") or ()},
                "rev": bool(s.get("reversible", True)),
            }
    return out or None


class PreconditionLedger:
    """Deterministic. Reads the compiled artifact and this session's history."""

    def __init__(self, specs: dict):
        self.specs = specs
        # A fact SOME tool establishes is session-producible; anything else is a
        # property of the world before the session and is assumed to hold.
        self.producible = set()
        for s in specs.values():
            self.producible |= s["add"]
        self.world: set[str] = set()

    def check(self, tool: str) -> tuple[bool, bool, str]:
        """(allowed, severe, reason). `severe` picks DENY over STEP_UP."""
        spec = self.specs.get(tool)
        if spec is None:
            return True, False, ""
        missing = {f for f in spec["pre"]
                   if f in self.producible and f not in self.world}
        if not missing:
            return True, False, ""
        severe = not spec["rev"]
        return False, severe, (
            f"{tool!r} requires {sorted(missing)}, which nothing in this session "
            f"has established; the catalogue declares those facts producible")

    def observe(self, tool: str) -> None:
        spec = self.specs.get(tool)
        if spec is None:
            return
        self.world |= spec["add"]
        self.world -= spec["del"]


def _replay(scen, script, ledger_factory, step_up_blocks: bool):
    led = ledger_factory()
    env = scen.make_env()
    if scen.configure is not None:
        scen.configure(env, "none")
    refused = 0
    for name, args in script or ():
        ok, severe, _ = led.check(name)
        blocked = (not ok) and (severe or step_up_blocks)
        if blocked:
            refused += 1
            continue
        try:
            scen.handler(env, name, dict(args or {}))
        except Exception:
            return None, refused
        led.observe(name)
    return bool(scen.violated(env)), refused


def run(step_up_blocks: bool = True) -> dict:
    names = [n for n in SCENARIOS
             if (s := get_scenario(n)).violating_script and s.compliant_script]
    c = m = j = 0
    armed = 0
    for n in names:
        scen = get_scenario(n)
        specs = specs_for(scen)
        if specs is None:
            # No compiled artifact: the rung is inert and the scenario is scored
            # exactly as the undefended run, never as a containment.
            v, _, = _replay(scen, scen.violating_script,
                            lambda: PreconditionLedger({}), step_up_blocks)
            _, bref = _replay(scen, scen.compliant_script,
                              lambda: PreconditionLedger({}), step_up_blocks)
        else:
            armed += 1
            v, _ = _replay(scen, scen.violating_script,
                           lambda s=specs: PreconditionLedger(s), step_up_blocks)
            _, bref = _replay(scen, scen.compliant_script,
                              lambda s=specs: PreconditionLedger(s), step_up_blocks)
        ok_c, ok_m = v is False, bref == 0
        c += ok_c; m += ok_m; j += ok_c and ok_m
    return {"n": len(names), "armed": armed, "contained": c,
            "completed": m, "joint": j}


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--json", type=str, default=None)
    args = p.parse_args(argv)
    rows = []
    print("\nPrecondition rung, compiled once per catalogue, enforced "
          "deterministically\n")
    print(f"{'posture':>24} {'armed':>6} {'contained':>10} {'completed':>10} {'joint':>7}")
    for label, sub in (("step-up blocks", True), ("only severe denies", False)):
        r = run(sub); r["posture"] = label; rows.append(r)
        print(f"{label:>24} {r['armed']:>6} {r['contained']:>10} "
              f"{r['completed']:>10} {r['joint']:>7}")
    print("\nNothing here reads the goal sentence.")
    if args.json:
        with open(args.json, "w") as fh:
            json.dump(rows, fh, indent=2)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
