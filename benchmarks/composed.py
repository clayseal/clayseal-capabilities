"""The floor and the calibrated detector, composed, measured on one split.

WHY THIS EXISTS

This repository has carried two evaluations that never met.

`coverage.py` measures the **authorization stack**: per-action, deterministic,
and it partitions attacks into `surface-leaving` (some field left the task's own
surface) and `in-surface` (every field is one the task legitimately uses). It
reports 100% containment on the first and a wall on the second, over more than
4,400 events.

`core/detector_eval.py` measures the **behavioural detector**: per-trajectory,
statistical, conformally calibrated on benign traffic, and it reports 83.3%
containment at a 0.0% false-block rate on sleight and 100% at 0.0% on bfcl's
fully-authorized aggregate class.

`SessionBroker` composes them already and has since it was written: the floor
decides first, an allowed action is appended to the running trajectory, and the
detector re-assesses. But `DeployableStack.from_goal` takes `detector=None`, and
`stack_factory.py` never passed one, so **every published number for the shipped
stack describes a stack with the behavioural layer switched off**. That is the
same defect as the intent envelope, which was missing from the same factory and
worth 62 points on sleight when it was wired.

So the wall this repository reports on in-surface attacks has never been
measured against the one instrument built for it. This module measures it.

WHAT MAKES THE MEASUREMENT HONEST

**The detector never sees an attack label.** It is fit one-class on benign
trajectories only, which is both the threat model and the data situation a real
deployment is in: plenty of benign traffic, no labelled attacks.

**The split is at the task level.** A task whose benign trajectory trained the
detector is not scored, so a task's own normal behaviour can never be the reason
its attack looks surprising.

**Both arms run on the same held-out tasks**, so the difference between them is
attributable to the detector and to nothing else.

**Benign interruption is measured on the same events**, because containment
reported without its cost is not a measurement. `deny-all` contains everything.

**Alpha is swept.** A conformal alpha is a false-alarm dial with a proof behind
it, so the composed system has an operating curve rather than an operating
point, and a deployment can choose where to sit on it.

**Several splits, not one.** The first version of this reported a single seed.
On `sleight` the held-out split is 18 tasks and the between-seed standard
deviation is 6.4 points of containment and 5.1 of benign cost, so a single draw
put the published figure near the bottom of a range it never showed, and the
detector's apparent contribution swung from nothing to seven points depending on
which draw it was. Every cell below is a mean over seeds with its spread, and a
single-seed run has to be asked for.
"""
from __future__ import annotations

import argparse
import random
import sys
from dataclasses import dataclass, field
from pathlib import Path

from benchmarks.core.events import BenchmarkTask, EventLabel
from benchmarks.core.reporting import format_rate
from benchmarks.core.stats import cluster_bootstrap_ci
from benchmarks.coverage import IN_SURFACE, SURFACE_LEAVING, TaskSurface

#: Alphas swept to produce the operating curve. 0.0 is the arm with no detector
#: at all, reported as the baseline every other row is a difference from.
DEFAULT_ALPHAS = (0.01, 0.05, 0.10, 0.20)


@dataclass
class Cell:
    """One (arm, population) cell: how many events, how many were stopped."""

    events: int = 0
    blocked: int = 0
    clusters: dict[str, list[int]] = field(default_factory=dict)

    def record(self, task_id: str, blocked: bool) -> None:
        self.events += 1
        self.blocked += int(blocked)
        c = self.clusters.setdefault(task_id, [0, 0])
        c[0] += int(blocked)
        c[1] += 1

    @property
    def rate(self) -> float:
        return self.blocked / self.events if self.events else 0.0

    def interval(self):
        return cluster_bootstrap_ci([tuple(v) for v in self.clusters.values()])

    def rendered(self) -> str:
        if not self.events:
            return "n/a"
        ci = self.interval()
        return (f"{format_rate(self.blocked, self.events)} "
                f"[{ci.low:.1%}, {ci.high:.1%}]")


@dataclass
class ArmResult:
    label: str
    surface_leaving: Cell = field(default_factory=Cell)
    in_surface: Cell = field(default_factory=Cell)
    benign: Cell = field(default_factory=Cell)

    def cell(self, population: str) -> Cell:
        return {SURFACE_LEAVING: self.surface_leaving,
                IN_SURFACE: self.in_surface,
                "benign": self.benign}[population]


def fit_detector(train_tasks: list[BenchmarkTask], *, alpha: float):
    """A detector fit one-class on benign trajectories, and nothing else.

    Returns None when there is too little benign traffic to calibrate on. A
    conformal calibrator with no calibration set returns p=1.0 for everything
    and never flags, so an uncalibrated detector is not a conservative detector,
    it is an absent one, and reporting it as an arm would be reporting a
    configuration that does no work.
    """
    from clayseal.capabilities.monitor import TrajectoryDetector
    from benchmarks.core.detector_eval import task_to_trajectories

    benign = [b for b, _ in map(task_to_trajectories, train_tasks) if b.actions]
    if len(benign) < 8:
        return None
    detector = TrajectoryDetector(alpha=alpha)
    detector.fit(benign)
    return detector


def run_arm(test_tasks: list[BenchmarkTask], *, label: str, detector) -> ArmResult:
    """Replay every test task through one configuration of the shipped stack."""
    from benchmarks.core.stack_engine import DeployableStackEngine

    engine = DeployableStackEngine(name=label, treat_step_up="block")
    result = ArmResult(label=label)

    for task in test_tasks:
        surface = TaskSurface.of(task)
        engine.reset()
        stack = engine._stack_for(task)
        # The detector is a per-session sensor and the engine builds one stack
        # per task, so it is attached after the stack exists rather than through
        # the factory. `detector_advisory=False` lets the two-signal rule stand:
        # the broker still demotes a flag on a non-consequential action, so this
        # is not a licence to hard-block on a statistic alone.
        stack.broker.detector = detector
        stack.broker.detector_advisory = False

        for event in task.events:
            blocked = not engine.decide(task, event).allowed
            if event.label is EventLabel.ATTACK:
                population, _ = surface.classify(event)
            elif event.label is EventLabel.BENIGN:
                population = "benign"
            else:
                continue
            result.cell(population).record(task.task_id, blocked)
    return result


@dataclass
class Spread:
    """One cell across seeds: what it averages, and how far it moves."""

    values: list[float] = field(default_factory=list)
    blocked: int = 0
    events: int = 0

    def add(self, cell: Cell) -> None:
        if cell.events:
            self.values.append(cell.rate)
            self.blocked += cell.blocked
            self.events += cell.events

    def rendered(self) -> str:
        if not self.values:
            return "n/a"
        mean = sum(self.values) / len(self.values)
        if len(self.values) == 1:
            return f"{format_rate(self.blocked, self.events)}"
        var = sum((v - mean) ** 2 for v in self.values) / len(self.values)
        # The seed count travels with the cell. A standard deviation is not a
        # rate and `sd 0.0%` is a real reading, but a number with no idea how
        # many draws are behind it is not one a reader can weigh.
        return (f"{mean:.1%} sd {var ** 0.5:.1%} "
                f"[{min(self.values):.1%}, {max(self.values):.1%}] "
                f"n={len(self.values)}")


def measure_seeds(tasks: list[BenchmarkTask], *, alphas=DEFAULT_ALPHAS,
                  train_frac: float = 0.6, seeds=(1, 3, 5, 7, 11)):
    """Run `measure` on every seed and collect each cell's spread.

    Reporting one draw of an 18-task split is not reporting a result. The mean
    is the estimate and the spread is how much the split choice is doing.
    """
    order: list[str] = []
    cells: dict[str, dict[str, Spread]] = {}
    meta: dict = {}
    for seed in seeds:
        arms, meta = measure(tasks, alphas=alphas, train_frac=train_frac, seed=seed)
        for arm in arms:
            if arm.label not in cells:
                order.append(arm.label)
                cells[arm.label] = {k: Spread() for k in
                                    (SURFACE_LEAVING, IN_SURFACE, "benign")}
            for key in (SURFACE_LEAVING, IN_SURFACE, "benign"):
                cells[arm.label][key].add(arm.cell(key))
    meta["seeds"] = list(seeds)
    return [(label, cells[label]) for label in order], meta


def measure(tasks: list[BenchmarkTask], *, alphas=DEFAULT_ALPHAS,
            train_frac: float = 0.6, seed: int = 7) -> tuple[list[ArmResult], dict]:
    order = list(tasks)
    # Seeded shuffle for a reproducible split, not for anything secret.
    random.Random(seed).shuffle(order)  # noqa: S311
    split = max(1, int(len(order) * train_frac))
    train_tasks, test_tasks = order[:split], order[split:]

    arms = [run_arm(test_tasks, label="floor only (no detector)", detector=None)]
    fitted = 0
    for alpha in alphas:
        detector = fit_detector(train_tasks, alpha=alpha)
        if detector is None:
            continue
        fitted += 1
        arms.append(run_arm(test_tasks, label=f"floor + detector, alpha={alpha}",
                            detector=detector))
    meta = {"n_train": len(train_tasks), "n_test": len(test_tasks),
            "alphas_fitted": fitted, "seed": seed}
    return arms, meta


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        description="The floor and the calibrated detector, composed")
    p.add_argument("--datasets", default="agentharm,sleight,agentleak")
    p.add_argument("--limit", type=int, default=None)
    p.add_argument("--alphas", default=",".join(str(a) for a in DEFAULT_ALPHAS))
    p.add_argument("--train-frac", type=float, default=0.6)
    p.add_argument("--seeds", default="1,3,5,7,11",
                   help="splits to average over; one seed reports a single draw")
    p.add_argument("--out", type=Path, default=None)
    args = p.parse_args(argv if argv is not None else sys.argv[1:])

    from benchmarks.datasets.base import get_loader

    alphas = tuple(float(a) for a in args.alphas.split(",") if a.strip())
    seeds = tuple(int(x) for x in args.seeds.split(",") if x.strip())
    lines: list[str] = []

    def say(text: str = "") -> None:
        print(text)
        lines.append(text)

    say("# The floor and the calibrated detector, composed")
    say()
    say("STATUS: current")
    say()
    say("```bash")
    say(f"python -m benchmarks.composed --datasets {args.datasets} "
        f"--limit {args.limit} --alphas {args.alphas} --seeds {args.seeds}")
    say("```")
    say()
    say("Every published number for the shipped stack was measured with "
        "`detector=None`.")
    say("The detector is fit one-class on benign trajectories from a "
        "task-level train")
    say("split and never sees an attack label. Both arms run on the same "
        "held-out tasks.")
    say()

    for name in [d.strip() for d in args.datasets.split(",") if d.strip()]:
        try:
            tasks = get_loader(name).load(limit=args.limit)
        except (KeyError, RuntimeError) as exc:
            say(f"## {name}: skipped ({str(exc).splitlines()[0][:60]})")
            say()
            continue
        rows, meta = measure_seeds(tasks, alphas=alphas,
                                   train_frac=args.train_frac, seeds=seeds)
        say(f"## {name}")
        say()
        say(f"{meta['n_train']} tasks fit the detector, "
            f"{meta['n_test']} held out and scored, "
            f"averaged over {len(seeds)} splits.")
        say()
        if meta["alphas_fitted"] == 0:
            say("Too little benign traffic to calibrate on, so there is no "
                "detector arm.")
            say("An uncalibrated conformal test flags nothing, so reporting "
                "one would be")
            say("reporting a configuration that does no work.")
            say()
            continue
        say("| arm | surface-leaving | in-surface | benign interrupted |")
        say("| --- | --- | --- | --- |")
        for label, cell in rows:
            say(f"| {label} | {cell[SURFACE_LEAVING].rendered()} "
                f"| {cell[IN_SURFACE].rendered()} | {cell['benign'].rendered()} |")
        say()

    if args.out:
        args.out.write_text("\n".join(lines) + "\n")
        print(f"\nwrote {args.out}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
