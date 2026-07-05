"""DP-21: Exploration budgets for read-only context discovery.

Tracks and enforces caps on read-scope auto-expansion:
- max unique files read
- max unique directories explored
- max total bytes read
- disable all exploration when in tightened mode

The budget is consumed via ``try_consume()`` which returns whether the
read is allowed.  The governor / broker calls this before granting
auto-expansion of read scope.
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class ExplorationBudgetConfig:
    max_files: int = 50
    max_dirs: int = 15
    max_bytes: int = 2_000_000
    tightened: bool = False


@dataclass
class ExplorationBudget:
    """Consumable budget for read-only context discovery (DP-21).

    Usage::

        budget = ExplorationBudget()
        allowed, reason = budget.try_consume("src/utils.py", byte_count=1200)
        if not allowed:
            # block or step-up
    """

    config: ExplorationBudgetConfig = field(default_factory=ExplorationBudgetConfig)
    files_read: set[str] = field(default_factory=set)
    dirs_read: set[str] = field(default_factory=set)
    bytes_read: int = 0

    def try_consume(
        self,
        file_path: str,
        *,
        byte_count: int = 0,
    ) -> tuple[bool, str]:
        """Attempt to consume budget for reading ``file_path``.

        Returns ``(allowed, reason)``.  When ``allowed`` is False, the
        read should be blocked or require a step-up.
        """
        if self.config.tightened:
            return False, "exploration_disabled_tightened"

        normalized = file_path.replace("\\", "/").strip("/")
        parts = normalized.rsplit("/", 1)
        dir_name = parts[0] if len(parts) > 1 else "."

        is_new_file = normalized not in self.files_read
        is_new_dir = dir_name not in self.dirs_read

        if is_new_file and len(self.files_read) >= self.config.max_files:
            return False, "file_budget_exhausted"

        if is_new_dir and len(self.dirs_read) >= self.config.max_dirs:
            return False, "dir_budget_exhausted"

        if byte_count > 0 and self.bytes_read + byte_count > self.config.max_bytes:
            return False, "byte_budget_exhausted"

        self.files_read.add(normalized)
        self.dirs_read.add(dir_name)
        self.bytes_read += byte_count
        return True, "ok"

    def enter_tightened_mode(self) -> None:
        self.config.tightened = True

    def exit_tightened_mode(self) -> None:
        self.config.tightened = False

    @property
    def remaining_files(self) -> int:
        return max(0, self.config.max_files - len(self.files_read))

    @property
    def remaining_dirs(self) -> int:
        return max(0, self.config.max_dirs - len(self.dirs_read))

    @property
    def remaining_bytes(self) -> int:
        return max(0, self.config.max_bytes - self.bytes_read)

    def to_dict(self) -> dict:
        return {
            "files_read": len(self.files_read),
            "dirs_read": len(self.dirs_read),
            "bytes_read": self.bytes_read,
            "remaining_files": self.remaining_files,
            "remaining_dirs": self.remaining_dirs,
            "remaining_bytes": self.remaining_bytes,
            "tightened": self.config.tightened,
        }
