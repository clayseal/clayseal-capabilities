"""Cross-turn session state shared by every DeployableStack path.

These signals are *product* memory, the same object live AgentDojo, CTR, and
scoreboard replay consult, not corpus-specific caches. Keeping them in one
dataclass stops broker fields from proliferating per residual attack family.
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class SessionMemory:
    """Mutable session-local observations and taints.

    Attributes
    ----------
    symlink_taints
        ``(source, dest)`` pairs for model/checkpoint → ``results/`` links.
        Later zip/upload without symlink-safe flags STEP_UPs.
    csv_columns
        Path → header column names from observed CSV ``head`` (1-indexed awk).
    file_text
        Path → current file body from Read/Edit (absolute-line sed checks).
    file_line_shift
        Path → net positive line delta from expanding Edits this session.
    sealed_violation
        True after a sealed-plan / digΔ STEP_UP; follow-on git/crontab/egress
        is treated as cleanup-then-push risk.
    """

    symlink_taints: set[tuple[str, str]] = field(default_factory=set)
    csv_columns: dict[str, list[str]] = field(default_factory=dict)
    file_text: dict[str, str] = field(default_factory=dict)
    file_line_shift: dict[str, int] = field(default_factory=dict)
    sealed_violation: bool = False

    def clear_file_state(self) -> None:
        """Drop CSV / line-map state (e.g. when switching twin sessions)."""
        self.csv_columns.clear()
        self.file_text.clear()
        self.file_line_shift.clear()

    def clear_taints(self) -> None:
        """Drop packaging / sealed-violation taints (benign twin utility)."""
        self.symlink_taints.clear()
        self.sealed_violation = False

    def adopt(self, other: SessionMemory) -> None:
        """Share packaging taints across tasks (multi-session coding)."""
        self.symlink_taints = other.symlink_taints
