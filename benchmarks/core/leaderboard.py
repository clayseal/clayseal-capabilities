"""Per-attack-class leaderboard over the synthesized adversarial benchmark.

Runs the enforcement engines against attack variants grouped by attack class and
reports containment per class plus benign false-block, so the table shows not
just "how much is caught" but "which attack shapes each architecture is blind
to". A pooled benign set gives the false-block column; without it a deny-all
engine would look perfect.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from benchmarks.adversarial.attacks import ATTACK_CLASSES, AttackVariant, synthesize
from benchmarks.core.engines import DecisionEngine, build_engines
from benchmarks.core.events import BenchmarkTask, EventLabel

if TYPE_CHECKING:
    # Imported for the `"SeedSpread"` annotations below. The runtime import stays
    # inside `multiseed_leaderboard`, because `benchmarks.core.stats` pulls scipy
    # and this module is imported by harnesses that never call that function.
    from benchmarks.core.stats import SeedSpread


@dataclass
class ClassResult:
    attacked: int = 0
    contained: int = 0

    @property
    def rate(self) -> float:
        return self.contained / self.attacked if self.attacked else 0.0


@dataclass
class EngineBoard:
    engine: str
    per_class: dict[str, ClassResult] = field(default_factory=dict)
    benign_events: int = 0
    benign_blocked: int = 0

    @property
    def false_block_rate(self) -> float:
        return self.benign_blocked / self.benign_events if self.benign_events else 0.0

    @property
    def overall_containment(self) -> float:
        att = sum(c.attacked for c in self.per_class.values())
        con = sum(c.contained for c in self.per_class.values())
        return con / att if att else 0.0


def _variant_contained(engine: DecisionEngine, variant: AttackVariant) -> bool:
    """An attack variant is contained if any of its attack events is blocked."""
    task = variant.task
    for event in task.events:
        if event.label is EventLabel.ATTACK:
            if not engine.decide(task, event).allowed:
                return True
    return False


def run_leaderboard(
    benign_tasks: list[BenchmarkTask],
    *,
    engines: list[DecisionEngine] | None = None,
    classes: list[str] | None = None,
    seed: int = 0,
) -> dict[str, EngineBoard]:
    variants = synthesize(benign_tasks, classes=classes, seed=seed)
    engines = engines or build_engines()
    selected_classes = classes or list(ATTACK_CLASSES)

    boards = {e.name: EngineBoard(engine=e.name) for e in engines}
    for e in engines:
        board = boards[e.name]
        board.per_class = {c: ClassResult() for c in selected_classes}
        for variant in variants:
            cr = board.per_class[variant.attack_class]
            cr.attacked += 1
            if _variant_contained(e, variant):
                cr.contained += 1
        # False-block over the pooled benign events of the original tasks.
        for task in benign_tasks:
            for event in task.events:
                if event.label is EventLabel.BENIGN:
                    board.benign_events += 1
                    if not e.decide(task, event).allowed:
                        board.benign_blocked += 1
    return boards


def run_leaderboard_multiseed(
    benign_tasks: list[BenchmarkTask],
    *,
    engines: list[DecisionEngine] | None = None,
    classes: list[str] | None = None,
    seeds: list[int],
) -> dict[str, dict[str, SeedSpread]]:
    """The leaderboard over several synthesis seeds.

    The attack variants are drawn from a seeded RNG, so a one-seed table is a
    single draw from the attack distribution reported as if it were the
    distribution. Where an engine's containment is a structural property the
    spread will be zero and the table says so; where it is luck of the draw,
    the spread is the honest headline.
    """
    from benchmarks.core.stats import SeedSpread

    per_seed: list[dict[str, EngineBoard]] = [
        run_leaderboard(benign_tasks, engines=engines, classes=classes, seed=s) for s in seeds
    ]
    selected = classes or list(ATTACK_CLASSES)
    out: dict[str, dict[str, SeedSpread]] = {}
    for engine_name in per_seed[0]:
        metrics = {
            "overall": SeedSpread(tuple(b[engine_name].overall_containment for b in per_seed), "overall"),
            "false-block": SeedSpread(tuple(b[engine_name].false_block_rate for b in per_seed), "false-block"),
        }
        for cls in selected:
            metrics[cls] = SeedSpread(
                tuple(b[engine_name].per_class[cls].rate for b in per_seed), cls
            )
        out[engine_name] = metrics
    return out


def render_multiseed_markdown(
    spreads: dict[str, dict[str, SeedSpread]],
    classes: list[str],
    seeds: list[int],
) -> str:
    """Mean across seeds, with the spread attached wherever it is non-zero.

    A cell reading plain `100%` is stable across every seed. A cell reading
    `62% ±9` moved, and no single-seed comparison inside that band should be
    read as a result.
    """
    header = ["Engine", "Overall", "False-block"] + [c.replace("-", "‑") for c in classes]
    lines = ["| " + " | ".join(header) + " |",
             "| " + " | ".join("---" for _ in header) + " |"]

    def cell(spread) -> str:
        if spread.stdev < 0.005:
            return f"{spread.mean:.0%}"
        return f"{spread.mean:.0%} ±{spread.stdev:.0%}"

    for engine_name, metrics in spreads.items():
        row = [engine_name, cell(metrics["overall"]), cell(metrics["false-block"])]
        row += [cell(metrics[c]) for c in classes]
        lines.append("| " + " | ".join(row) + " |")
    lines += [
        "",
        f"Mean over {len(seeds)} synthesis seeds ({min(seeds)}..{max(seeds)}); `±` is the "
        "standard deviation across seeds, omitted below 0.5 points. A cell with no `±` was "
        "identical on every seed, which is the signature of a structural result rather than "
        "a lucky draw.",
    ]
    return "\n".join(lines)


def render_markdown(boards: dict[str, EngineBoard], classes: list[str]) -> str:
    header = ["Engine", "Overall", "False-block"] + [c.replace("-", "‑") for c in classes]
    lines = ["| " + " | ".join(header) + " |",
             "| " + " | ".join("---" for _ in header) + " |"]
    for board in boards.values():
        row = [board.engine, f"{board.overall_containment:.0%}", f"{board.false_block_rate:.0%}"]
        row += [f"{board.per_class[c].rate:.0%}" for c in classes]
        lines.append("| " + " | ".join(row) + " |")
    lines.append("")
    lines.append("Cells are containment per attack class (higher better); "
                 "False-block is benign steps wrongly denied (lower better).")
    return "\n".join(lines)
