"""Where does the utility go? Aggregate every recorded false block.

    python -m benchmarks.live.diagnose_denials

The live tier now has traces across four models and four suites, and each one
records the tool, layer, and reason for every hard DENY of a *benign* call. That
is a corpus of our own false positives, and it is the only direct evidence we
have about which enforcement rule costs the most utility.

Two things this is careful about:

* **Only defense-caused denials count.** A denial on a task that also failed
  with no defense present costs nothing, because the task was lost anyway.
  Counting those would send us optimizing rules that are not actually losing us
  anything.
* **Denials are weighted by whether they flipped a task.** Ten denials inside
  one already-doomed task matter less than one denial that turned a success into
  a failure. Both are reported, because the first predicts friction a user
  notices and the second predicts lost work.
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

RESULTS = Path(__file__).resolve().parent.parent / "results" / "model-ladder"


def collect(directory: Path, ablation: str) -> dict:
    by_layer = Counter()
    by_tool = Counter()
    by_reason = Counter()
    flipping = Counter()          # denials on tasks the defense actually lost
    harmless = Counter()          # denials on tasks that failed anyway
    per_cell = defaultdict(Counter)
    examples: dict[str, str] = {}

    for path in sorted(directory.glob("*-trace.json")):
        stem = path.stem.removesuffix("-trace")
        try:
            trace = json.loads(path.read_text())
        except json.JSONDecodeError:
            continue
        for task in trace.values():
            rec = task.get(ablation)
            if not rec or not rec.get("deny"):
                continue
            baseline_ok = task.get("none", {}).get("success", False)
            lost = baseline_ok and not rec.get("success")
            for d in rec["deny"]:
                layer, tool = d.get("layer", "?"), d.get("tool", "?")
                reason = _normalize(d.get("reason", ""))
                by_layer[layer] += 1
                by_tool[tool] += 1
                by_reason[reason] += 1
                per_cell[stem][reason] += 1
                (flipping if lost else harmless)[reason] += 1
                examples.setdefault(reason, d.get("reason", ""))

    return {
        "by_layer": by_layer, "by_tool": by_tool, "by_reason": by_reason,
        "flipping": flipping, "harmless": harmless,
        "per_cell": per_cell, "examples": examples,
    }


def _normalize(reason: str) -> str:
    """Collapse a reason to its rule, dropping the specific value.

    'recipient Alice not on allow-list' and 'recipient Bob not on allow-list'
    are one rule firing twice, not two problems.
    """
    text = reason.lower()
    for pattern, label in [
        ("not on allow-list", "egress/recipient not on allow-list"),
        ("off-plan", "off-plan consequential action"),
        ("before required earlier phase", "phase ordering violation"),
        ("protected zone", "protected zone"),
        ("outside path scope", "path outside scope"),
        ("budget", "budget exceeded"),
        ("arguments not authorized", "argument binding"),
        ("not in plan", "tool not in plan"),
    ]:
        if pattern in text:
            return label
    return text[:60] or "(no reason recorded)"


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Aggregate live-tier false blocks")
    p.add_argument("--dir", type=Path, default=RESULTS)
    p.add_argument("--ablations", default="envelope,envelope-taint,oracle-envelope-egress")
    args = p.parse_args(argv if argv is not None else sys.argv[1:])

    print("# Where the utility goes: every recorded false block\n")
    for ablation in [a.strip() for a in args.ablations.split(",") if a.strip()]:
        data = collect(args.dir, ablation)
        total = sum(data["by_reason"].values())
        if not total:
            continue
        lost = sum(data["flipping"].values())
        print(f"## `{ablation}`, {total} benign denials, {lost} on tasks the defense lost\n")

        print("| Rule | denials | of which flipped a task | layer |")
        print("| --- | --: | --: | --- |")
        layer_of = {}
        for path in sorted(args.dir.glob("*-trace.json")):
            try:
                trace = json.loads(path.read_text())
            except json.JSONDecodeError:
                continue
            for task in trace.values():
                for d in (task.get(ablation) or {}).get("deny", []):
                    layer_of[_normalize(d.get("reason", ""))] = d.get("layer", "?")
        for reason, n in data["by_reason"].most_common():
            print(f"| {reason} | {n} | {data['flipping'][reason]} | {layer_of.get(reason,'?')} |")

        print("\nBy tool: " + ", ".join(f"{t} ({n})" for t, n in data["by_tool"].most_common(6)))
        print("\nWorst cells:")
        for cell, counter in sorted(data["per_cell"].items(),
                                    key=lambda kv: -sum(kv[1].values()))[:5]:
            top = counter.most_common(1)[0]
            print(f"  {cell:32} {sum(counter.values()):>3} denials   (mostly: {top[0]})")
        print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
