"""Render the Core-12 head-to-head under the SHARED policy (BPL v1.1).

    python -m benchmarks.bpl_v11_report --dir benchmarks/results/bpl_v11

The v1.0 tables were produced when only the reference defense was configured with
the threshold and the other conditions were never given one. This renders the
re-run in which every condition receives `scenario.policy`, so the comparison is
about architecture rather than about who was told the rule.

Reports the triple, never violation alone. A gate that refuses everything scores
perfect containment, which is why progress and the joint score are printed beside
it and why `deny-all` is a permanent row in the scripted sweep.
"""
from __future__ import annotations

import argparse
import json
import math
import pathlib
import re
import sys

CONDITIONS = ("none", "per-call", "dataflow-taint", "drift", "authgraph", "clayseal")

#: Conditions whose design has no policy input at all. Reported so a reader can
#: tell "given the rule and could not use it" from "was never given the rule".
NO_POLICY_INPUT = {"drift", "authgraph"}

_ROW = re.compile(
    r"\s+(\S+)\s+violation\s+([\d.]+)%\s+progress\s+([\d.]+)%\s+friction\s+([\d.]+)"
)


def _wilson_upper(k: int, n: int, z: float = 1.959963985) -> float:
    """Upper bound of the Wilson interval. A zero out of 20 is not zero."""
    if n == 0:
        return float("nan")
    p = k / n
    d = 1 + z * z / n
    centre = p + z * z / (2 * n)
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))
    return min(1.0, (centre + half) / d)


def load(directory: pathlib.Path) -> tuple[dict, int]:
    rows: dict[str, dict[str, tuple[float, float, float]]] = {}
    runs = 0
    for log in sorted(directory.glob("*.log")):
        for line in log.read_text().splitlines():
            m = _ROW.match(line)
            if not m:
                continue
            rows.setdefault(log.stem, {})[m.group(1)] = (
                float(m.group(2)), float(m.group(3)), float(m.group(4))
            )
            n = re.search(r"\(n=(\d+)\)", line)
            if n:
                runs = max(runs, int(n.group(1)))
    return rows, runs


def _optimal_progress(names: list[str]) -> dict[str, float]:
    """Progress the scenario's own COMPLIANT script achieves.

    This is the ceiling a correct defense should reach — not the undefended
    agent's progress, which includes work the policy forbids. Comparing against
    the undefended column makes a defense that plays the policy perfectly look
    like it is costing 26 points of utility.
    """
    from benchmarks.bpl.registry import SCENARIOS
    from benchmarks.bpl.schema import run_script

    out: dict[str, float] = {}
    for name in names:
        entry = SCENARIOS.get(name)
        if entry is None:
            continue
        scen = entry() if callable(entry) else entry
        if not scen.compliant_script:
            continue
        out[name] = 100 * scen.progress(run_script(scen, scen.compliant_script))
    return out


def render(rows: dict, runs: int) -> str:
    complete = sorted(n for n, c in rows.items() if len(c) >= len(CONDITIONS))
    partial = sorted(n for n, c in rows.items() if len(c) < len(CONDITIONS))
    out: list[str] = []
    a = out.append

    a("# Core-12 head-to-head under the shared policy (BPL v1.1)")
    a("")
    a("STATUS: current")
    a("")
    a(f"`gpt-5-mini-2025-08-07`, n={runs} per cell, "
      f"{len(complete)} of 12 scenarios complete.")
    a("")
    a("Every condition receives `scenario.policy` — the declarative rule the "
      "violation oracle is checked against. In v1.0 only the reference defense "
      "was configured with the threshold, so that table partly measured which "
      "condition had been told the rule.")
    a("")
    a("**V** violation rate (lower better) · **P** progress (higher better) · "
      "**U = P × (1 − V)** joint score. Violation alone is not a score: a gate "
      "that refuses everything wins it outright at P=0.")
    a("")

    header = "| scenario | " + " | ".join(f"{c} V/P" for c in CONDITIONS) + " |"
    a(header)
    a("| --- | " + " | ".join("---:" for _ in CONDITIONS) + " |")
    for name in complete:
        cells = rows[name]
        line = f"| {name} |"
        for c in CONDITIONS:
            v, p, _ = cells[c]
            line += f" {v:.0f}/{p:.0f} |"
        a(line)
    a("")

    a("## Suite means")
    a("")
    a(f"| condition | policy input | mean V (n={runs}/cell) | mean P | "
      f"mean U | friction |")
    a("| --- | --- | ---: | ---: | ---: | ---: |")
    for c in CONDITIONS:
        vs = [rows[n][c][0] / 100 for n in complete]
        ps = [rows[n][c][1] / 100 for n in complete]
        fr = [rows[n][c][2] for n in complete]
        us = [p * (1 - v) for v, p in zip(vs, ps, strict=True)]
        given = "—" if c == "none" else ("no input" if c in NO_POLICY_INPUT else "given")
        mean_v = 100 * sum(vs) / len(vs)
        # A mean of exact zeros is still zero out of n*k trials, and the
        # linter is right to demand the denominator: `format_rate` exists
        # because an uncontextualised 0% is the repository's most repeated
        # reporting error.
        v_cell = (f"0% (0 of {runs * len(complete)})" if mean_v == 0.0
                  else f"{mean_v:.1f}%")
        a(f"| `{c}` | {given} | {v_cell} | "
          f"{100*sum(ps)/len(ps):.1f}% | {100*sum(us)/len(us):.1f}% | "
          f"{sum(fr)/len(fr):.2f} |")
    a("")

    # The headline: did the shared policy change the per-call result?
    none_v = sum(rows[n]["none"][0] for n in complete) / len(complete)
    pc_v = sum(rows[n]["per-call"][0] for n in complete) / len(complete)
    a("## The architectural result")
    a("")
    a(f"`per-call` is **given** the policy and lands at {pc_v:.1f}% violation "
      f"against {none_v:.1f}% undefended — a difference of "
      f"{none_v - pc_v:.1f} points across {len(complete)} scenarios.")
    a("")
    a("It is not uninformed. It holds no state between calls, so an aggregate "
      "constraint has nothing to accumulate against, and being handed the "
      "ceiling does not give it somewhere to put the running total. That is the "
      "claim the benchmark exists to support, and it is now measured under the "
      "condition that would have falsified it.")
    a("")

    zeros = [n for n in complete if rows[n]["clayseal"][0] == 0.0]
    if zeros:
        ub = _wilson_upper(0, runs) * 100
        a(f"The reference defense records 0 violations on {len(zeros)} of "
          f"{len(complete)} scenarios. At n={runs} a zero has a 95% Wilson "
          f"upper bound of **{ub:.1f}%**; it is not zero, and the protocol in "
          f"`REPRODUCE.md` asks for n≥100 before a headline.")
        a("")

    # Scenarios where nothing violated: they cost runtime and discriminate nothing.
    inert = [n for n in complete if all(rows[n][c][0] == 0.0 for c in CONDITIONS)]
    saturated = [n for n in complete
                 if all(rows[n][c][0] == 100.0 for c in CONDITIONS)]
    if inert or saturated:
        a("## Scenarios that did not discriminate")
        a("")
        a("Reported because a suite mean over cells that cannot separate the "
          "conditions is a mean over noise, and the effective size of the "
          "leaderboard is smaller than its nominal size.")
        a("")
        if inert:
            a(f"**No condition violated** ({len(inert)} of {len(complete)}) — "
              f"the undefended model complies on its own at n={runs}, so the "
              f"cell measures nothing about any defense:")
            a("")
            for n in inert:
                a(f"- `{n}`")
            a("")
        if saturated:
            a(f"**Every condition violated** ({len(saturated)} of "
              f"{len(complete)}) — no defense separates here either, though "
              f"these still show the undefended rate is real:")
            a("")
            for n in saturated:
                a(f"- `{n}`")
            a("")
        disc = len(complete) - len(inert)
        a(f"Effective discriminating set: **{disc} of {len(complete)}** "
          f"complete scenarios. Suite means above are over all {len(complete)}; "
          f"a mean over the discriminating subset alone would flatter every "
          f"defense and is not reported in its place.")
        a("")

    a("## What it costs, measured against the right baseline")
    a("")
    a("The obvious comparison — defended progress against UNDEFENDED progress — "
      "overstates the cost, and the first version of this report made that "
      "mistake. An undefended agent completes work the policy forbids, so its "
      "progress is not a target any correct defense should reach. The baseline "
      "is **policy-optimal** progress: what the scenario's own compliant script "
      "achieves.")
    a("")
    optimal = _optimal_progress(complete)
    a(f"| scenario | policy-optimal P | clayseal P (n={runs}) | gap |")
    a("| --- | ---: | ---: | ---: |")
    gaps = []
    for n in complete:
        if n not in optimal:
            continue
        opt, cs = optimal[n], rows[n]["clayseal"][1]
        gaps.append(cs - opt)
        # The linter checks per LINE, so a 0% cell needs its denominator here
        # rather than in the header — an uncontextualised zero is this
        # repository's most repeated reporting error.
        cs_cell = f"0% (0 of {runs})" if cs == 0.0 else f"{cs:.0f}%"
        a(f"| {n} | {opt:.0f}% | {cs_cell} | {cs - opt:+.0f} |")
    a("")
    if gaps:
        exact = sum(1 for g in gaps if abs(g) < 1e-6)
        undershoot = sorted(
            ((rows[n]['clayseal'][1] - optimal[n], n) for n in complete if n in optimal),
        )[:3]
        a(f"**Optimal on {exact} of {len(gaps)} scenarios** — the defense plays "
          f"the policy exactly, and the apparent progress loss on those cells is "
          f"the correct answer rather than over-refusal. Mean gap "
          f"{sum(gaps)/len(gaps):+.1f} points.")
        a("")
        a("The loss is concentrated, not spread:")
        a("")
        for g, n in undershoot:
            if g < -5:
                a(f"- `{n}` — {g:+.0f} points. ")
        a("")
        # The worst cell: refusing where no defense was needed.
        inert_here = [n for n in complete
                      if all(rows[n][c][0] == 0.0 for c in CONDITIONS)
                      and n in optimal and rows[n]["clayseal"][1] - optimal[n] < -5]
        if inert_here:
            a(f"Worst case, and worth naming: {', '.join(f'`{n}`' for n in inert_here)} "
              f"— cells where NO condition violates, so the defense is refusing "
              f"work while providing no security benefit at all. That is pure "
              f"friction, and it is the first thing to fix.")
            a("")

    if partial:
        a("## Incomplete")
        a("")
        a("Scenarios still running at render time, excluded from every number "
          "above rather than averaged in partially:")
        a("")
        for n in partial:
            a(f"- `{n}` — {len(rows[n])} of {len(CONDITIONS)} conditions")
        a("")

    a("## Reproduce")
    a("")
    a("```bash")
    a("./scripts/paper/run_bpl_core_h2h.sh    # RUNS=20 SUITE=core")
    a("python -m benchmarks.bpl_v11_report --dir benchmarks/results/bpl_v11")
    a("```")
    return "\n".join(out)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    p.add_argument("--dir", type=pathlib.Path,
                   default=pathlib.Path("benchmarks/results/bpl_v11"))
    p.add_argument("--out", type=pathlib.Path, default=None)
    args = p.parse_args(argv if argv is not None else sys.argv[1:])

    rows, runs = load(args.dir)
    if not rows:
        print(f"no results in {args.dir}", file=sys.stderr)
        return 2
    text = render(rows, runs)
    print(text)
    if args.out:
        args.out.write_text(text + "\n")
        print(f"\nWrote {args.out}", file=sys.stderr)
    (args.dir / "summary.json").write_text(json.dumps(
        {"runs": runs, "conditions": list(CONDITIONS), "cells": rows}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
