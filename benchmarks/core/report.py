"""Render benchmark results as a comparison table (markdown) or JSON."""
from __future__ import annotations

import json

from benchmarks.core.runner import EngineResult

_COLUMNS = [
    ("engine", "Engine"),
    ("attack_prevention_rate", "Attack prevented"),
    ("false_block_rate", "False-block"),
    ("benign_utility_rate", "Benign utility"),
    ("attack_allowed", "Attacks let through"),
    ("overhead_p95_ms", "Overhead p95 (ms)"),
]


def render_markdown(
    results: dict[str, EngineResult],
    *,
    title: str = "",
    ci: bool = False,
    level: float = 0.95,
) -> str:
    """Comparison table. With ``ci``, rates carry a task-clustered bootstrap
    interval instead of a bare point estimate."""
    if ci:
        return _render_with_ci(results, title=title, level=level)
    rows = [r.summary() for r in results.values()]
    lines: list[str] = []
    if title:
        lines += [f"# {title}", ""]
    lines.append("| " + " | ".join(label for _, label in _COLUMNS) + " |")
    lines.append("| " + " | ".join("---" for _ in _COLUMNS) + " |")
    for row in rows:
        cells = []
        for key, _ in _COLUMNS:
            value = row[key]
            if key.endswith("_rate"):
                cells.append(f"{value:.1%}")
            else:
                cells.append(str(value))
        lines.append("| " + " | ".join(cells) + " |")
    lines += [
        "",
        "_Attack prevented_ = containment (higher is better). "
        "_False-block_ = benign steps wrongly denied (lower is better). "
        "The winning architecture maximizes containment at near-zero false-block.",
    ]
    return "\n".join(lines)


def _render_with_ci(results: dict[str, EngineResult], *, title: str, level: float) -> str:
    header = ["Engine", "Attack prevented", "False-block", "Overhead p50/p95/p99 (ms)", "Tasks"]
    lines: list[str] = []
    if title:
        lines += [f"# {title}", ""]
    lines.append("| " + " | ".join(header) + " |")
    lines.append("| " + " | ".join("---" for _ in header) + " |")
    for r in results.values():
        contained = r.containment_ci(level)
        friction = r.false_block_ci(level)
        lines.append(
            "| " + " | ".join([
                r.engine,
                contained.render(),
                friction.render(),
                f"{r.overhead_p50_ms:.4f} / {r.overhead_p95_ms:.4f} / {r.overhead_p99_ms:.4f}",
                str(max(contained.n, friction.n)),
            ]) + " |"
        )
    lines += [
        "",
        f"Brackets are {level:.0%} percentile bootstrap intervals resampling **tasks**, not "
        "events: events within a task share a template, so an event-level interval would be "
        "roughly sqrt(events-per-task) too narrow. _Tasks_ is the resampling unit count. "
        "Two engines whose intervals overlap are not distinguishable on this corpus.",
    ]
    return "\n".join(lines)


def render_json(results: dict[str, EngineResult]) -> str:
    return json.dumps({name: r.summary() for name, r in results.items()}, indent=2)
