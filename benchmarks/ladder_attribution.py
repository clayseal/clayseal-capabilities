"""Where the live tier's utility cost actually comes from, per task.

`live_ladder.md` reports utility as four aggregate percentages per model. Four
points cannot support a claim about a trend, and they discard the fact that
every model runs the SAME tasks, which makes the comparison paired.

This reads the per-task traces instead and answers three questions the aggregate
table cannot:

* which layer denies the benign tasks that fail, and how concentrated that is;
* how many "defense-caused losses" record no denial at all, which bounds how
  much of the cost is attributable to the gateway rather than to run-to-run
  variance in the agent;
* whether the cost differs between models, tested pairwise with exact McNemar
  over tasks eligible under both, rather than by ranking four percentages.
"""

from __future__ import annotations

import argparse
import collections
import json
import pathlib
from math import comb

TRACES = pathlib.Path(__file__).resolve().parent / "results" / "model-ladder"


def load(arm: str = "envelope"):
    """(suite, task) -> model -> (succeeded undefended, succeeded defended)."""
    out: dict[tuple[str, str], dict[str, tuple[bool, bool]]] = (
        collections.defaultdict(dict))
    denials: collections.Counter = collections.Counter()
    losses = with_reason = 0
    for f in sorted(TRACES.glob("*-trace.json")):
        suite, model = f.stem[:-6].split("-", 1)
        for task, arms in json.loads(f.read_text()).items():
            base, defended = arms.get("none"), arms.get(arm)
            if not base or not defended:
                continue
            out[(suite, task)][model] = (bool(base.get("success")),
                                         bool(defended.get("success")))
            if base.get("success") and not defended.get("success"):
                losses += 1
                entries = defended.get("deny") or []
                if entries:
                    with_reason += 1
                for e in entries:
                    layer = e.get("layer") if isinstance(e, dict) else e
                    denials[str(layer)[:48]] += 1
    return out, denials, losses, with_reason


def mcnemar(a_only: int, b_only: int) -> float:
    """Exact two-sided McNemar on the discordant pairs."""
    n = a_only + b_only
    if n == 0:
        return 1.0
    k = min(a_only, b_only)
    return min(1.0, 2 * sum(comb(n, i) for i in range(k + 1)) / 2 ** n)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--arm", default="envelope")
    args = ap.parse_args(argv)
    tasks, denials, losses, with_reason = load(args.arm)

    print(f"ATTRIBUTION, arm={args.arm}\n")
    print(f"  defense-caused losses (succeeded undefended, failed defended): {losses}")
    print(f"  of those, recording a denial:                                 {with_reason}")
    print(f"  recording NO denial, so not attributable to a rule:           {losses - with_reason}\n")
    print("  denials behind the attributable half:")
    for layer, n in denials.most_common():
        print(f"    {n:>3}  {layer}")

    models = sorted({m for per in tasks.values() for m in per})
    print("\nPAIRWISE, exact McNemar over tasks eligible under BOTH models.")
    print("  Eligible means the task succeeded undefended for both, so the only")
    print("  thing being compared is what the gateway cost.\n")
    print(f"  {'A':<18}{'B':<18}{'A lost':>7}{'B lost':>7}{'n':>5}{'p':>9}")
    for i, a in enumerate(models):
        for b in models[i + 1:]:
            a_only = b_only = 0
            for per in tasks.values():
                if a not in per or b not in per:
                    continue
                (ba, da), (bb, db) = per[a], per[b]
                if not (ba and bb):
                    continue
                la, lb = (not da), (not db)
                a_only += la and not lb
                b_only += lb and not la
            n = a_only + b_only
            if n:
                print(f"  {a:<18}{b:<18}{a_only:>7}{b_only:>7}{n:>5}"
                      f"{mcnemar(a_only, b_only):>9.3f}")
    print("\n  An unpaired test on this data returns a smaller p by discarding the")
    print("  pairing, which is not a stronger result; it is the wrong test.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
