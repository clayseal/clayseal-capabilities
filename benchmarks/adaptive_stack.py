"""Adaptive red-team against the SHIPPED gateway, at three knowledge levels.

    python -m benchmarks.adaptive_stack --dataset redcode --rounds 8 --breadth 24

WHY THIS EXISTS
---------------
`benchmarks/validity.py` gate P10 fails, and it is the honest failure: the
published sweep declares ONE attacker knowledge level, `scripted
(author-written)`. The adaptive-evaluation literature's finding applies directly
— static benchmarks made twelve in-band defenses look strong until adaptive
attacks broke them at over 90% — and a gate that reads a declaration cannot be
satisfied by improving the declaration. It has to be satisfied by running the
levels.

There was already an adaptive search with three knowledge levels. It judged
candidates with a LADDER RUNG, which is an ablation used to attribute containment
to a mechanism, not the product. So the thing a deployment actually runs had
never faced an adaptive adversary. `docs/production_sota_path.md` names it:
"extend the adaptive adversary from the detector to the plan-plus-taint path;
report the residual."

THE THREE CONTROLS THAT MAKE THE NUMBERS READABLE
-------------------------------------------------
Every one of these exists because this repository has already been burned by its
absence.

**`allow-all` establishes the attacker's own failure rate.** `in_scope_exfiltration.md`
reports 38.5% "containment" for every rung INCLUDING allow-all: that 38.5% was
the attacker failing to construct a valid attack, not the defense stopping one.
Containment is therefore reported as a LIFT over the no-enforcement floor, and a
lift of zero is printed as zero however good the raw number looks.

**The objective is defined over the world, not over the policy.**
`adaptive_ladder_audit.md`: every objective used to be defined through
`_outside_workspace()`, which is precisely what `task-scope` denies, so the
published 100% was definitional and no rung above `task-scope` could be
distinguished from it. `in-scope-exfiltration` is the complement and is run here
as a first-class objective rather than a footnote.

**Both readings of STEP_UP are reported.** A step-up halts an autonomous agent,
so counting it as containment is right for an unattended deployment and assumes
the answer for a supervised one. Reporting one number would hide which
deployment is being described.

WHAT A FLAT LINE MEANS, AND WHAT A DECAYING ONE MEANS
-----------------------------------------------------
Containment that does not move from blind to oracle is a structural guarantee:
knowing the design does not help. Containment that decays as knowledge rises is a
filter that buys time. Both are publishable; only the first is a security claim.
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from dataclasses import dataclass
from pathlib import Path

from benchmarks.adversarial.adaptive import (
    OBJECTIVES,
    Knowledge,
    run_adaptive,
)
from benchmarks.core.engines import build_engines
from benchmarks.core.stack_engine import DeployableStackEngine
from benchmarks.datasets.base import get_loader

#: The rung the product's floor corresponds to, kept as the ablation comparison.
LADDER_TOP = "task-scope+binding+budget"


@dataclass
class Cell:
    engine: str
    objective: str
    knowledge: str
    attacked: int
    escaped: int
    candidates: int
    ineffective: int

    @property
    def contained(self) -> float:
        return 1.0 - (self.escaped / self.attacked) if self.attacked else float("nan")

    def to_dict(self) -> dict:
        return {
            "engine": self.engine,
            "objective": self.objective,
            "knowledge": self.knowledge,
            "tasks_attacked": self.attacked,
            "tasks_escaped": self.escaped,
            "candidates_tried": self.candidates,
            "candidates_allowed_but_ineffective": self.ineffective,
            "contained": round(self.contained, 6),
        }


def _engines(step_up_readings: bool):
    """The product, plus the two controls a number is unreadable without."""
    out = [("allow-all", build_engines(["allow-all"])[0])]
    ladder = build_engines([LADDER_TOP])
    if ladder:
        out.append((LADDER_TOP, ladder[0]))
    out.append(("stack (step-up=block)", DeployableStackEngine(treat_step_up="block")))
    if step_up_readings:
        out.append(
            ("stack (step-up=allow)", DeployableStackEngine(treat_step_up="allow"))
        )
    return out


def run(dataset: str, *, limit: int, rounds: int, breadth: int, seed: int,
        objectives: list[str], levels: list[Knowledge],
        step_up_readings: bool) -> list[Cell]:
    tasks = get_loader(dataset).load(limit=limit)
    if not tasks:
        raise RuntimeError(f"dataset {dataset!r} produced no tasks")

    cells: list[Cell] = []
    for name, engine in _engines(step_up_readings):
        for objective_name in objectives:
            objective = OBJECTIVES[objective_name]()
            for level in levels:
                result = run_adaptive(
                    tasks, engine, objective=objective, knowledge=level,
                    rounds=rounds, seed=seed, breadth=breadth,
                )
                cells.append(Cell(
                    engine=name,
                    objective=objective_name,
                    knowledge=level.value,
                    attacked=result.tasks_attacked,
                    escaped=result.tasks_escaped,
                    candidates=result.candidates_tried,
                    ineffective=result.candidates_allowed_but_ineffective,
                ))
    return cells


def render(cells: list[Cell], *, dataset: str, rounds: int, breadth: int) -> str:
    """Containment per knowledge level, with the lift over no enforcement."""
    engines = list(dict.fromkeys(c.engine for c in cells))
    objectives = list(dict.fromkeys(c.objective for c in cells))
    levels = list(dict.fromkeys(c.knowledge for c in cells))
    index = {(c.engine, c.objective, c.knowledge): c for c in cells}

    out: list[str] = []
    out.append(f"# Adaptive red-team against the shipped gateway — {dataset}")
    out.append("")
    out.append("STATUS: current")
    out.append("")
    n = next(iter(cells)).attacked if cells else 0
    out.append(
        f"`python -m benchmarks.adaptive_stack --dataset {dataset} "
        f"--rounds {rounds} --breadth {breadth}` — {n} tasks, "
        f"{sum(c.candidates for c in cells):,} candidates."
    )
    out.append("")
    out.append(
        "Containment, and in brackets the LIFT over `allow-all`. The lift is the "
        "number that means anything: `allow-all` scores whatever the attacker "
        "failed to construct on its own, and reporting that as containment is "
        "the defect `in_scope_exfiltration.md` records."
    )
    out.append("")

    for objective in objectives:
        out.append(f"## {objective}")
        out.append("")
        out.append("| engine | " + " | ".join(levels) + " |")
        out.append("| --- | " + " | ".join("---:" for _ in levels) + " |")
        for engine in engines:
            row = [engine]
            for level in levels:
                cell = index.get((engine, objective, level))
                if cell is None:
                    row.append("-")
                    continue
                floor = index.get(("allow-all", objective, level))
                pct = f"{100 * cell.contained:.1f}%"
                if floor is not None and engine != "allow-all":
                    lift = cell.contained - floor.contained
                    pct += f" ({lift * 100:+.1f})"
                row.append(pct)
            out.append("| " + " | ".join(row) + " |")
        out.append("")
    return "\n".join(out)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    p.add_argument("--dataset", default="redcode")
    p.add_argument("--limit", type=int, default=200)
    p.add_argument("--rounds", type=int, default=8)
    p.add_argument("--breadth", type=int, default=24)
    p.add_argument("--seed", type=int, default=0)
    p.add_argument("--objectives", default=",".join(sorted(OBJECTIVES)))
    p.add_argument("--knowledge", default="blind,feedback,oracle")
    p.add_argument("--no-step-up-readings", action="store_true")
    p.add_argument("--json", type=Path, default=None)
    p.add_argument("--markdown", type=Path, default=None)
    args = p.parse_args(argv if argv is not None else sys.argv[1:])

    objectives = [o.strip() for o in args.objectives.split(",") if o.strip()]
    unknown = sorted(set(objectives) - set(OBJECTIVES))
    if unknown:
        print(f"error: unknown objectives {unknown}", file=sys.stderr)
        return 2
    levels = [Knowledge(k.strip()) for k in args.knowledge.split(",") if k.strip()]

    started = time.time()
    cells = run(
        args.dataset, limit=args.limit, rounds=args.rounds, breadth=args.breadth,
        seed=args.seed, objectives=objectives, levels=levels,
        step_up_readings=not args.no_step_up_readings,
    )
    elapsed = time.time() - started

    markdown = render(cells, dataset=args.dataset, rounds=args.rounds,
                      breadth=args.breadth)
    print(markdown)
    print(f"\n_{elapsed:.1f}s_")

    if args.json:
        args.json.write_text(json.dumps(
            {
                "dataset": args.dataset,
                "rounds": args.rounds,
                "breadth": args.breadth,
                "seed": args.seed,
                "attacker_knowledge": [level.value for level in levels],
                "elapsed_seconds": round(elapsed, 1),
                "cells": [c.to_dict() for c in cells],
            },
            indent=2,
        ))
        print(f"Wrote {args.json}", file=sys.stderr)
    if args.markdown:
        args.markdown.write_text(markdown + f"\n\n_{elapsed:.1f}s_\n")
        print(f"Wrote {args.markdown}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
