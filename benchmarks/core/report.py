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


def render_markdown(results: dict[str, EngineResult], *, title: str = "") -> str:
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


def render_json(results: dict[str, EngineResult]) -> str:
    return json.dumps({name: r.summary() for name, r in results.items()}, indent=2)
