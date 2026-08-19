"""Frozen BPL evaluation suites (Core / Hard / research quarantine)."""
from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

_SUITES_PATH = Path(__file__).resolve().parent / "SUITES.yaml"


@lru_cache(maxsize=1)
def load_suites() -> dict[str, Any]:
    data = yaml.safe_load(_SUITES_PATH.read_text())
    if not isinstance(data, dict):
        raise RuntimeError(f"invalid suites file: {_SUITES_PATH}")
    return data


def suite_names() -> list[str]:
    return ["core", "hard", "research_quarantine", "full"]


def scenarios_in_suite(suite: str, *, registry_keys: list[str] | None = None) -> list[str]:
    """Return ordered scenario names for a suite.

    ``full`` = all simulated registry keys except bulk-exfil-live.
    """
    data = load_suites()
    suite = suite.strip().lower()
    if suite == "full":
        keys = registry_keys or []
        return [k for k in keys if k != "bulk-exfil-live"]
    if suite in ("research", "research_quarantine"):
        return list(data["research_quarantine"]["scenarios"])
    if suite not in ("core", "hard"):
        raise KeyError(f"unknown suite {suite!r}; choose from {suite_names()}")
    return list(data[suite]["scenarios"])


def suite_meta(suite: str) -> dict[str, Any]:
    data = load_suites()
    if suite == "full":
        return {
            "description": "Entire simulated pack (not a frozen leaderboard).",
            "version": data.get("version"),
        }
    key = "research_quarantine" if suite in ("research", "research_quarantine") else suite
    block = data[key]
    return {
        "description": (block.get("description") or "").strip(),
        "version": data.get("version"),
        "frozen": data.get("frozen", False),
        "non_goals": data.get("non_goals", []),
    }


def assert_suite_subset_of_registry(registry_keys: set[str]) -> None:
    data = load_suites()
    for key in ("core", "hard", "research_quarantine"):
        for name in data[key]["scenarios"]:
            if name not in registry_keys:
                raise KeyError(f"suite {key!r} references unknown scenario {name!r}")
    core = set(data["core"]["scenarios"])
    hard = set(data["hard"]["scenarios"])
    research = set(data["research_quarantine"]["scenarios"])
    if core & research:
        raise RuntimeError(f"core overlaps research quarantine: {core & research}")
    if hard & research:
        raise RuntimeError(f"hard overlaps research quarantine: {hard & research}")
    if len(core) != 12:
        raise RuntimeError(f"core must have 12 scenarios, found {len(core)}")
    if len(hard) != 24:
        raise RuntimeError(f"hard must have 24 scenarios, found {len(hard)}")
