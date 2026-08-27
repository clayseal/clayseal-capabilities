"""Is target diffuseness a property of agents, or of synthetic benchmarks?

    python -m benchmarks.concentration
    python -m benchmarks.concentration --corpora atif tau2 redcode

`density_sweep.py` found that the target-density channel on RedCode learned
exactly one bit, the workspace root, because benign traffic below it is nearly
all-distinct: 99 paths over 314 events, escape mass 0.317 at the `app` node. A
node that diffuse reserves so much probability for unseen children that novelty
there carries no information, and an adversary who relocates inside a known root
pays nothing.

That result is only actionable if we know **why** the traffic is diffuse. Two
explanations with opposite consequences:

  (a) Agents genuinely touch fresh resources constantly. Then the channel is
      close to worthless and further investment is wasted.

  (b) These corpora are synthetic. RedCode generates a plausible-looking filename
      per test case, so no file is ever visited twice by construction, and the
      diffuseness is an artifact of corpus authorship rather than of agent
      behaviour. Real repositories concentrate hard, an agent edits the same
      handful of files over and over.

This module measures the difference, because the repo contains both kinds of
data. ATIF is **real MCP agent trajectories** (38 sessions, up to 32 tool-calls);
tau2 and BFCL are real task suites; RedCode and the fixtures are synthetic.

The statistic is deliberately simple and pre-registered here so it cannot be
chosen after seeing the numbers:

    repeat rate     1 - (distinct targets / target observations)
                    0.0 = every action visits somewhere new
    top-10 share    fraction of observations landing on the 10 commonest targets
    root escape     d*U/N at the trie root      (low = concentrated)
    depth-1 escape  median d*U/N one level down (the level mimicry exploits)

Nothing here reads an attack label; concentration is a property of benign
traffic, which is the point: it can be measured on a tenant's own logs before
any decision to deploy the channel.
"""
from __future__ import annotations

import argparse
import json
import statistics
import sys
from collections import Counter
from pathlib import Path

from benchmarks.core.detector_eval import task_to_trajectories
from benchmarks.datasets.base import get_loader
from clayseal.capabilities.monitor.scoring.target import (
    TargetDensityScorer,
    action_target,
    segments,
)

# Labelled by how the benign side was produced, declared before measuring.
PROVENANCE = {
    "atif": "real agent sessions",
    "tau2": "real task suite",
    "bfcl": "real task suite",
    "toolemu": "curated cases",
    "agentharm": "curated cases",
    "redcode": "synthetic per-case",
    "ipi_coding": "synthetic per-case",
    "agent_threat_bench": "synthetic per-case",
    "sleight": "synthetic per-case",
}

DEFAULT_CORPORA = ["atif", "tau2", "bfcl", "toolemu", "agentharm", "redcode",
                   "sleight"]


def benign_targets(tasks) -> list[str]:
    """Targets of benign actions only, in the shape the density would see."""
    out: list[str] = []
    for task in tasks:
        try:
            benign, _ = task_to_trajectories(task)
        except Exception:
            continue
        for action in benign.actions:
            target = action_target(action)
            if target:
                out.append(target)
    return out


def escape_profile(tasks) -> tuple[float | None, float | None]:
    """(root escape, median depth-1 escape) from a density fit on benign only."""
    trajectories = []
    for task in tasks:
        try:
            benign, _ = task_to_trajectories(task)
        except Exception:
            continue
        if benign.actions:
            trajectories.append(benign)
    if not trajectories:
        return None, None
    scorer = TargetDensityScorer().fit(trajectories)
    rows = [r for r in scorer.concentration(max_depth=1)
            if r["key"].count("|") == 0]
    root = [r["escape"] for r in rows if r["depth"] == 0 and r["n"] >= 3]
    depth1 = [r["escape"] for r in rows if r["depth"] == 1 and r["n"] >= 3]
    return (statistics.median(root) if root else None,
            statistics.median(depth1) if depth1 else None)


def measure(corpus: str) -> dict | None:
    tasks = list(get_loader(corpus).load())
    targets = benign_targets(tasks)
    if not targets:
        return None
    counts = Counter(targets)
    total = len(targets)
    top10 = sum(c for _, c in counts.most_common(10))
    root, depth1 = escape_profile(tasks)
    # Depth is reported because a corpus of one-segment targets cannot exhibit
    # depth concentration at all, and reading its depth-1 cell as evidence would
    # be reading an absence.
    depths = [len(segments(t)) for t in targets]
    return {
        "corpus": corpus,
        "provenance": PROVENANCE.get(corpus, "unknown"),
        "observations": total,
        "distinct": len(counts),
        "repeat_rate": 1 - len(counts) / total,
        "top10_share": top10 / total,
        "median_depth": statistics.median(depths) if depths else 0,
        "root_escape": root,
        "depth1_escape": depth1,
    }


def render(rows: list[dict]) -> str:
    head = (f"{'corpus':<20}{'benign side':<20}{'obs':>7}{'distinct':>10}"
            f"{'repeat':>9}{'top10':>8}{'depth':>7}{'esc(root)':>11}{'esc(d1)':>9}")
    lines = ["target concentration in benign traffic", "=" * len(head), "",
             head, "-" * len(head)]
    for r in rows:
        lines.append(
            f"{r['corpus']:<20}{r['provenance']:<20}"
            f"{r['observations']:>7}{r['distinct']:>10}"
            f"{r['repeat_rate']:>8.1%}{r['top10_share']:>8.1%}"
            f"{r['median_depth']:>7.0f}"
            f"{_num(r['root_escape']):>11}{_num(r['depth1_escape']):>9}"
        )
    return "\n".join(lines)


def _num(value) -> str:
    return "-" if value is None else f"{value:.3f}"


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--corpora", nargs="*", default=DEFAULT_CORPORA)
    p.add_argument("--curve", nargs="*", type=int, default=None,
                   help="calibration sizes for the learning curve")
    p.add_argument("--json", type=Path, default=None)
    args = p.parse_args(argv)

    if args.curve is not None:
        sizes = args.curve or [100, 300, 1000, 3000, 10000]
        rows = []
        for corpus in args.corpora:
            try:
                rows.extend(learning_curve(corpus, sizes))
            except Exception as exc:
                print(f"{corpus}: {str(exc)[:70]}", file=sys.stderr)
        print(render_curve(rows))
        if args.json:
            args.json.parent.mkdir(parents=True, exist_ok=True)
            args.json.write_text(json.dumps(rows, indent=2))
        return 0

    rows = []
    for corpus in args.corpora:
        try:
            row = measure(corpus)
        except Exception as exc:
            print(f"{corpus}: unavailable ({str(exc)[:70]})", file=sys.stderr)
            continue
        if row:
            rows.append(row)
    rows.sort(key=lambda r: -r["repeat_rate"])
    print(render(rows))
    print("\nrepeat = 1 - distinct/observations. 0.0% means every benign action")
    print("visited a target no other action ever visited, which is the shape a")
    print("per-case corpus generator produces and the shape a density cannot learn.")
    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(json.dumps(rows, indent=2))
        print(f"\nwrote {args.json}")
    return 0


# --------------------------------------------------------------------------- #
# Learning curve: how much clean traffic before the channel discriminates?
# --------------------------------------------------------------------------- #
def learning_curve(corpus: str, sizes: list[int], seed: int = 0) -> list[dict]:
    """Escape mass as a function of calibration volume.

    The cross-corpus table shows concentration tracking neither "synthetic vs
    real" nor "tool catalog vs filesystem" but simply **observations per distinct
    target**: tau2 has 285, ATIF has 1.8. If that is the whole story then the
    channel is not weak, it is *starved*, and the operational question changes
    from "does this work" to "how much traffic until it does".

    This measures it directly by subsampling a corpus's own benign trajectories.
    A monotone curve turns the precondition into a deployment readiness number a
    tenant can be quoted in advance.
    """
    import random as _random

    tasks = list(get_loader(corpus).load())
    trajectories = []
    for task in tasks:
        try:
            benign, _ = task_to_trajectories(task)
        except Exception:
            continue
        if benign.actions:
            trajectories.append(benign)
    rng = _random.Random(seed)
    rng.shuffle(trajectories)

    rows = []
    for size in sizes:
        subset, actions = [], 0
        for traj in trajectories:
            if actions >= size:
                break
            subset.append(traj)
            actions += len(traj.actions)
        if actions < size * 0.8:
            continue  # corpus cannot supply this volume; do not extrapolate
        scorer = TargetDensityScorer().fit(subset)
        prof = [r for r in scorer.concentration(max_depth=1)
                if r["key"].count("|") == 0]
        root = [r["escape"] for r in prof if r["depth"] == 0 and r["n"] >= 3]
        d1 = [r["escape"] for r in prof if r["depth"] == 1 and r["n"] >= 3]
        distinct = len({action_target(a) for t in subset for a in t.actions})
        rows.append({
            "corpus": corpus, "actions": actions, "distinct": distinct,
            "obs_per_target": actions / distinct if distinct else 0,
            "root_escape": statistics.median(root) if root else None,
            "depth1_escape": statistics.median(d1) if d1 else None,
            # Bits a novel child earns from escape alone. Below ~3 the channel
            # cannot separate anything; the conformal gate will simply never fire.
            "novel_bits": (-__import__("math").log2(statistics.median(d1))
                           if d1 and statistics.median(d1) > 0 else None),
        })
    return rows


def render_curve(rows: list[dict]) -> str:
    head = (f"{'corpus':<12}{'actions':>9}{'distinct':>10}{'obs/target':>12}"
            f"{'esc(root)':>11}{'esc(d1)':>10}{'novel bits(d1)':>16}")
    lines = ["density learning curve", "=" * len(head), "", head, "-" * len(head)]
    for r in rows:
        bits = "-" if r["novel_bits"] is None else f"{r['novel_bits']:.1f}"
        lines.append(
            f"{r['corpus']:<12}{r['actions']:>9}{r['distinct']:>10}"
            f"{r['obs_per_target']:>12.1f}"
            f"{_num(r['root_escape']):>11}{_num(r['depth1_escape']):>10}{bits:>16}"
        )
    return "\n".join(lines)

if __name__ == "__main__":
    sys.exit(main())
