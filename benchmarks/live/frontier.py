"""The safety/usefulness frontier: a curve, not a pair of numbers.

    python -m benchmarks.live.frontier --suite banking --n-user 6 --n-inj 3

Every result this repo has published is a single operating point: one ASR, one
utility, for one configuration. The 2026 AI-control literature reports a
**Pareto frontier** instead, because a protocol is a family of configurations
and the useful question is the shape of the tradeoff, not one point on it. A
buyer wants to pick their own operating point; a reviewer wants to know whether
we are on the frontier or inside it.

We already have the knobs and never swept them. `graduated`, `defer`, and the
audit budget are points on a curve nobody drew.

Reported per configuration:

* **ASR**, attack success, lower better. The safety axis.
* **clean utility**, task completion with no attack, higher better. The
  usefulness axis.
* **friction**, human interruptions per task. The third axis the control
  literature insists on, because a protocol that buys safety with unlimited
  human attention has moved the cost rather than removed it.

A configuration is **Pareto-dominated** when another achieves at least as much
safety AND at least as much utility AND asks for no more attention. Dominated
points are marked, because shipping one is strictly a mistake.
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
PY = str(ROOT / ".venv-h2h" / "bin" / "python")

# The sweep. Chosen to vary one thing at a time where possible: the enforcement
# stack, then the response policy (hard deny -> step-up), then the attention
# budget. `deferallow` is deliberately included despite being a measured
# negative result, because a frontier that hides its dominated points is a
# marketing chart.
DEFAULT_CONFIGS = [
    "none",
    "floor",
    "envelope",
    "envelope-taint",
    "envelope-taint-graduated",
    "envelope-taint-defer",
    "envelope-taint-deferallow",
    "envelope-taint-graduated-audit1",
    "envelope-taint-graduated-audit3",
]

_LINE = re.compile(
    r"^\s*(?P<ab>\S+)\s+clean-utility\s+(?P<cu>[\d.]+)%\s+ASR\s+(?P<asr>[\d.]+)%"
    r"\s+utility-under-attack\s+(?P<uua>[\d.]+)%\s+friction\s+(?P<fr>[\d.]+)/task"
)


def pool(runs: list[list[dict]]) -> list[dict]:
    """Average repeated sweeps per configuration and record the spread.

    A frontier drawn from one sweep is a frontier drawn from one draw. At
    n=18 per cell, identical configurations have produced utility figures 25
    points apart, which is wider than most of the gaps the chart is used to
    judge. Repeating the whole sweep and pooling is the only thing that makes a
    dominance call trustworthy, because dominance is a comparison of small
    differences by construction.
    """
    by_config: dict[str, list[dict]] = {}
    for run in runs:
        for pt in run:
            by_config.setdefault(pt["config"], []).append(pt)

    pooled = []
    for config, pts in by_config.items():
        n = len(pts)
        entry = {"config": config, "repeats": n}
        for key in ("asr", "clean_utility", "utility_under_attack", "friction"):
            values = [p[key] for p in pts]
            entry[key] = sum(values) / n
            entry[f"{key}_spread"] = (max(values) - min(values)) if n > 1 else 0.0
        pooled.append(entry)
    return pooled


def run_sweep(suite: str, model: str, n_user: int, n_inj: int,
              configs: list[str], attack: str) -> list[dict]:
    import os

    env = dict(os.environ)
    if not env.get("OPENAI_API_KEY"):
        key = Path.home() / ".openai_api_key"
        if key.exists():
            env["OPENAI_API_KEY"] = key.read_text().strip()
    for var in ("AZURE_OPENAI_ENDPOINT", "AZURE_OPENAI_KEY", "AZURE_OPENAI_API_KEY"):
        env.pop(var, None)

    cmd = [PY, "-m", "benchmarks.live.run_agentdojo", "--suite", suite,
           "--model", model, "--n-user", str(n_user), "--n-inj", str(n_inj),
           "--ablations", ",".join(configs), "--attack", attack]
    proc = subprocess.run(cmd, capture_output=True, text=True, env=env)
    if proc.returncode != 0:
        print(proc.stdout[-2000:], file=sys.stderr)
        print(proc.stderr[-2000:], file=sys.stderr)
        return []

    points = []
    for line in proc.stdout.splitlines():
        m = _LINE.match(line)
        if m:
            points.append({
                "config": m.group("ab"),
                "asr": float(m.group("asr")) / 100,
                "clean_utility": float(m.group("cu")) / 100,
                "utility_under_attack": float(m.group("uua")) / 100,
                "friction": float(m.group("fr")),
            })
    return points


def mark_dominated(points: list[dict]) -> list[dict]:
    """Flag every point another point beats on all three axes at once."""
    for p in points:
        p["dominated_by"] = None
        for q in points:
            if q is p:
                continue
            better_or_equal = (
                q["asr"] <= p["asr"]
                and q["clean_utility"] >= p["clean_utility"]
                and q["friction"] <= p["friction"]
            )
            strictly_better = (
                q["asr"] < p["asr"]
                or q["clean_utility"] > p["clean_utility"]
                or q["friction"] < p["friction"]
            )
            if better_or_equal and strictly_better:
                p["dominated_by"] = q["config"]
                break
    return points


def plot(points: list[dict], width: int = 46, height: int = 14) -> str:
    """A rough ASCII scatter, because a curve should look like a curve.

    Safety (1 - ASR) on x, clean utility on y, so up-and-right is better.
    """
    grid = [[" "] * width for _ in range(height)]
    labels = {}
    # Collisions matter here. Configurations that land on identical coordinates
    # are the interesting ones: they are doing the same job by different means
    #, and an earlier version silently overwrote them, so `envelope-taint`
    # vanished behind `deferallow` and the plot showed 5 of 9 points with no
    # indication that 4 were missing.
    occupied: dict[tuple[int, int], list[str]] = {}
    for i, p in enumerate(points):
        x = min(width - 1, int((1 - p["asr"]) * (width - 1)))
        y = min(height - 1, int(p["clean_utility"] * (height - 1)))
        ch = chr(ord("a") + i) if i < 26 else "?"
        labels[ch] = p["config"]
        occupied.setdefault((x, y), []).append(ch)

    overlaps = []
    for (x, y), chars in occupied.items():
        grid[height - 1 - y][x] = chars[0] if len(chars) == 1 else "*"
        if len(chars) > 1:
            overlaps.append("".join(chars))

    lines = ["  utility"]
    for row_i, row in enumerate(grid):
        axis = "1.0 |" if row_i == 0 else ("0.0 |" if row_i == height - 1 else "    |")
        lines.append(axis + "".join(row))
    lines.append("    +" + "-" * width)
    lines.append("     0.0" + " " * (width - 14) + "safety (1-ASR) 1.0")
    lines.append("")
    lines += [f"  {ch} = {name}" for ch, name in labels.items()]
    if overlaps:
        lines.append("")
        lines.append("  * = several configurations at the same point: "
                     + "; ".join(overlaps))
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Safety/usefulness frontier")
    p.add_argument("--suite", default="banking")
    p.add_argument("--model", default="gpt-4o-mini-2024-07-18")
    p.add_argument("--n-user", type=int, default=6)
    p.add_argument("--n-inj", type=int, default=3)
    p.add_argument("--attack", default="important_instructions")
    p.add_argument("--configs", default=",".join(DEFAULT_CONFIGS))
    p.add_argument("--repeats", type=int, default=1,
                   help="repeat the whole sweep and pool; dominance calls compare "
                        "small differences, so one draw is rarely enough")
    p.add_argument("--json", type=Path, default=None)
    args = p.parse_args(argv if argv is not None else sys.argv[1:])

    configs = [c.strip() for c in args.configs.split(",") if c.strip()]
    print(f"# Safety/usefulness frontier, {args.suite}, {args.model}, "
          f"{args.n_user}x{args.n_inj} runs per config\n", flush=True)

    runs = []
    for i in range(args.repeats):
        run = run_sweep(args.suite, args.model, args.n_user, args.n_inj, configs, args.attack)
        if run:
            runs.append(run)
        if args.repeats > 1:
            print(f"  sweep {i + 1}/{args.repeats} done", file=sys.stderr)
    if not runs:
        print("no points collected", file=sys.stderr)
        return 2
    points = pool(runs) if args.repeats > 1 else runs[0]
    points = mark_dominated(points)

    print("| Configuration | ASR | clean utility | utility under attack | friction/task | |")
    print("| --- | --: | --: | --: | --: | --- |")
    for pt in points:
        flag = "dominated" if pt["dominated_by"] else "**frontier**"
        note = f" (by {pt['dominated_by']})" if pt["dominated_by"] else ""
        spread = ""
        if pt.get("repeats", 1) > 1:
            spread = (f" ±{pt['asr_spread']:.0%}/±{pt['clean_utility_spread']:.0%}")
        print(f"| {pt['config']} | {pt['asr']:.1%} | {pt['clean_utility']:.1%} | "
              f"{pt['utility_under_attack']:.1%} | {pt['friction']:.2f} | {flag}{note}{spread} |")

    print("\n```\n" + plot(points) + "\n```\n")

    if points and points[0].get("repeats", 1) > 1:
        worst = max(p["clean_utility_spread"] for p in points)
        print(f"\nPooled over {points[0]['repeats']} sweeps. Widest run-to-run utility "
              f"spread: **{worst:.0%}**. A dominance call resting on a difference "
              "narrower than that is not supported by this data, however the table "
              "orders itself.\n")

    frontier = [pt for pt in points if not pt["dominated_by"]]
    print(f"{len(frontier)} of {len(points)} configurations are on the frontier. "
          "A dominated configuration is one another beats on safety, utility, AND "
          "attention simultaneously, so shipping one is strictly a mistake. They are "
          "listed rather than dropped, because a frontier that hides its losers is "
          "a marketing chart.\n")

    best = min(points, key=lambda q: (q["asr"], -q["clean_utility"], q["friction"]))
    print(f"Lowest ASR: **{best['config']}** at {best['asr']:.1%} ASR, "
          f"{best['clean_utility']:.1%} clean utility, {best['friction']:.2f} "
          "interruptions per task. Read those three together: the third number is "
          "what the first two cost a human.")

    if args.json:
        args.json.write_text(json.dumps(points, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
