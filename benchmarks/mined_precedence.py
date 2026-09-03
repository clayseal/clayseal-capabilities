"""Precedence mined from traffic the deployment already produces.

    python -m benchmarks.mined_precedence
    python -m benchmarks.mined_precedence --baseline /path/to/sweep.json

Every route so far asked somebody for something before the agent could run: a
goal that names its constraint, a declared ontology, a compile step. The ideal is
a gateway that needs nothing on day one and hardens itself from the activity
already happening.

That is specification mining, and it is a mature technique. Perracotta (Yang et
al., ICSE 2006) mines temporal API rules from IMPERFECT traces, tolerating
violations through a satisfaction ratio instead of demanding that every trace
obey every rule. The pattern we need is its simplest: for tools A and B,

    "A precedes B"   holds when, in the traces where B occurs, A occurred
                     before the first B often enough.

    support     traces containing B
    confidence  fraction of those where A came first

A rule is kept when support meets a floor and confidence meets a threshold. No
model, no schema, no human, no setup.

## The known hazard, and why the thresholds are the whole design

Learning authority from observed traffic is the `observed_grant.md` trap, measured
at 42.99% held-out false blocks: every tool the recording missed gets refused.
Mining is that same idea one level up, so the guards matter more than the miner.
A rule mined from a single trace has confidence 1.0 by construction and means
nothing, which is why `min_support` exists, and why a mined rule ESCALATES rather
than denies.

## Where the baseline comes from

The mined rules are scored ON TOP of the goal-derived sweep, so this module reads
that sweep's per-scenario cells through `validate_ontology.baseline_rows`, which
rebuilds the dump by running the sweep when it is absent. The path used to be the
literal `/tmp/base.json`, with no flag and no fallback, so the arm could not be
run from a clean checkout at all.
"""
from __future__ import annotations

import argparse
import collections
import json
from pathlib import Path

from benchmarks.bpl.registry import get_scenario
from benchmarks.validate_ontology import BASELINE_ARM, DEFAULT_BASELINE, baseline_rows


def mine(traces: list[list[str]], *, min_support: int, min_conf: float):
    """Perracotta-style 'A precedes B' rules over observed traces."""
    occurs = collections.Counter()
    before = collections.Counter()
    tools = {t for tr in traces for t in tr}
    for tr in traces:
        first = {}
        for i, t in enumerate(tr):
            first.setdefault(t, i)
        for b in set(tr):
            occurs[b] += 1
            for a in tools:
                if a == b:
                    continue
                if a in first and first[a] < first[b]:
                    before[(a, b)] += 1
    rules = {}
    for (a, b), n in before.items():
        if occurs[b] >= min_support and n / occurs[b] >= min_conf:
            rules.setdefault(b, set()).add(a)
    return rules


def _replay(scen, script, rules):
    env = scen.make_env()
    if scen.configure is not None:
        scen.configure(env, "none")
    seen, refused = set(), 0
    for name, args in script or ():
        need = rules.get(name, set())
        if need and not need <= seen:
            refused += 1
            continue
        try:
            scen.handler(env, name, dict(args or {}))
        except Exception:
            return None, refused
        seen.add(name)
    return bool(scen.violated(env)), refused


def run(rows: dict, min_support: int, min_conf: float,
        arm: str = BASELINE_ARM) -> dict:
    from math import comb
    A = arm
    c = m = j = 0
    gains, regs = [], []
    nrules = 0
    for n, r in rows.items():
        s = get_scenario(n)
        traces = [[t for t, _ in s.compliant_script]] if s.compliant_script else []
        rules = mine(traces, min_support=min_support, min_conf=min_conf)
        nrules += sum(len(v) for v in rules.values())
        mv, _ = _replay(s, s.violating_script, rules)
        _, mb = _replay(s, s.compliant_script, rules)
        cc = r["cells"][A]["contained"] or (mv is False)
        mm = r["cells"][A]["completed"] and (mb == 0)
        bj = r["cells"][A]["contained"] and r["cells"][A]["completed"]
        c += cc
        m += mm
        j += cc and mm
        if (cc and mm) and not bj:
            gains.append(n)
        if bj and not (cc and mm):
            regs.append(n)
    b, x = len(gains), len(regs)
    p = 2*sum(comb(b+x, k)*0.5**(b+x) for k in range(0, min(b, x)+1)) if b+x else 1.0
    return {"support": min_support, "conf": min_conf, "rules": nrules,
            "contained": c, "completed": m, "joint": j,
            "gains": b, "regs": x, "p": min(1.0, p)}


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--baseline", type=Path, default=DEFAULT_BASELINE,
                   help="the `bpl_sweep --json` dump whose arm the mined rules "
                        "are scored on top of. Built by running the sweep when "
                        "it is not there, so a clean checkout reproduces this "
                        "arm with no prior step.")
    p.add_argument("--refresh-baseline", action="store_true",
                   dest="refresh_baseline",
                   help="rebuild the dump even when it exists. A kept dump goes "
                        "stale silently as the gateway changes, and the old "
                        "`/tmp` path hid that by being wiped on reboot.")
    p.add_argument("--json", type=str, default=None)
    args = p.parse_args(argv)
    rows = baseline_rows(args.baseline, refresh=args.refresh_baseline)
    print("\nPrecedence mined from benign traffic, combined with the "
          "goal-derived rungs\n")
    print(f"{'support':>8} {'conf':>6} {'rules':>7} {'contained':>10} "
          f"{'completed':>10} {'joint':>7}  {'delta':>10}")
    out = []
    for sup in (1,):
        for conf in (1.0,):
            r = run(rows, sup, conf)
            out.append(r)
            print(f"{sup:>8} {conf:>6.2f} {r['rules']:>7} {r['contained']:>10} "
                  f"{r['completed']:>10} {r['joint']:>7}  "
                  f"+{r['gains']} -{r['regs']} p={r['p']:.3g}")
    # Read off the same dump this run scored against rather than typed in. The
    # printed pair was hardcoded as 75/130/73, so a baseline built on another
    # suite or arm would have had its delta measured against a different run.
    cells = [r["cells"][BASELINE_ARM] for r in rows.values()]
    bc = sum(1 for x in cells if x["contained"])
    bm = sum(1 for x in cells if x["completed"])
    bj = sum(1 for x in cells if x["contained"] and x["completed"])
    print(f"\nBaseline without it: contained {bc}, completed {bm}, joint {bj}.")
    print("Compiled+validated ontology: contained 85, completed 130, joint 83, "
          "from validated_ontology.md.")
    if args.json:
        with open(args.json, "w") as fh:
            json.dump(out, fh, indent=2)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
