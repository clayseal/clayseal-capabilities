"""Velocity limits: the one signal that survives an action having no target.

Our authority binds to targets. `benchmarks/results/why_we_fail.md` measured the
consequence: 641 of 833 missed attacks carry no target at all, with tool,
resource and action all granted, so path scope and destination binding have
nothing to check and the action passes by construction.

The same document tested the naive answer, escalating any consequential action
with no bindable target, and it destroyed the system: 54.6% of legitimate
actions blocked on tau2, 14.3% on BFCL. Untargeted consequential actions are
most of normal agent work.

Velocity is the version of that idea that does not have the problem. It does not
ask whether an action is allowed, it asks whether the *rate* of such actions has
left the shape of the task. Sending an email is normal; sending the fiftieth
email in a minute is not, and the difference is visible without knowing anything
about the recipient or the content.

Two properties this design insists on:

**The baseline comes from the task, not from a constant.** A global "20 sends per
hour" ceiling is wrong for every task simultaneously: too tight for a mail-merge
agent, uselessly loose for one that answers a single ticket. The expected rate is
declared per mandate, alongside the other budgets, and defaults to unlimited so
adding this module changes no existing result.

**It is deliberately blind to the first occurrence.** A velocity limit cannot
stop the first harmful action and should not pretend to. It bounds the blast
radius of a compromise that is already underway, which is a different and more
achievable job than deciding intent.
"""
from __future__ import annotations

import threading
import time
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

# Verb classes that change external state. A read burst is a different concern
# (bulk collection, handled by the value budget) from a write burst.
EFFECT_VERBS = frozenset({
    "write", "send", "transfer", "post", "pay", "delete", "create", "update", "execute",
})


@dataclass(frozen=True)
class VelocityConfig:
    """Expected rate per action class, declared by the mandate.

    ``limits`` maps an action class to (max_actions, window_seconds). A class
    absent from the map is unlimited, which is the default for everything, so
    enabling this module is opt-in per mandate rather than a global behaviour
    change.
    """

    limits: Mapping[str, tuple[int, float]] = field(default_factory=dict)
    # Classes are derived from the verb by default. A caller with a richer
    # ontology can map tools to classes explicitly.
    tool_classes: Mapping[str, str] = field(default_factory=dict)

    def class_for(self, tool_name: str, action: str) -> str | None:
        explicit = self.tool_classes.get(tool_name)
        if explicit:
            return explicit
        return action if action in EFFECT_VERBS else None

    def limit_for(self, action_class: str) -> tuple[int, float] | None:
        return self.limits.get(action_class)


@dataclass
class VelocityVerdict:
    allowed: bool
    reason: str
    observed: int = 0
    limit: int | None = None
    window_seconds: float = 0.0


@dataclass
class SessionVelocity:
    """Sliding-window rate ledger for one principal or session.

    Timestamps rather than counters, because a counter reset on a fixed schedule
    lets an attacker align a burst to the boundary and get double the rate for
    free. A sliding window has no boundary to align to.
    """

    config: VelocityConfig = field(default_factory=VelocityConfig)
    _events: dict[str, list[float]] = field(default_factory=dict)
    _lock: Any = field(default_factory=threading.RLock, repr=False, compare=False)

    def _recent(self, action_class: str, window: float, now: float) -> list[float]:
        stamps = self._events.get(action_class)
        if not stamps:
            return []
        cutoff = now - window
        if stamps and stamps[0] < cutoff:
            stamps = [t for t in stamps if t >= cutoff]
            self._events[action_class] = stamps
        return stamps

    def check(self, tool_name: str, action: str, *, now: float | None = None) -> VelocityVerdict:
        """Would this action exceed the declared rate? Does not record it."""
        at = time.time() if now is None else now
        action_class = self.config.class_for(tool_name, action)
        if action_class is None:
            return VelocityVerdict(True, "not a rate-limited action class")
        limit = self.config.limit_for(action_class)
        if limit is None:
            return VelocityVerdict(True, f"no velocity limit for {action_class!r}")

        max_actions, window = limit
        with self._lock:
            observed = len(self._recent(action_class, window, at))
        if observed + 1 > max_actions:
            return VelocityVerdict(
                False,
                f"velocity: {observed + 1} {action_class} actions in {window:.0f}s "
                f"exceeds the {max_actions} this task declared",
                observed + 1, max_actions, window,
            )
        return VelocityVerdict(True, f"within {action_class} velocity",
                               observed + 1, max_actions, window)

    def record(self, tool_name: str, action: str, *, now: float | None = None) -> None:
        at = time.time() if now is None else now
        action_class = self.config.class_for(tool_name, action)
        if action_class is None or self.config.limit_for(action_class) is None:
            return
        with self._lock:
            self._events.setdefault(action_class, []).append(at)

    def observed(self, action_class: str, window: float, *, now: float | None = None) -> int:
        at = time.time() if now is None else now
        with self._lock:
            return len(self._recent(action_class, window, at))


def velocity_from_mandate(mandate: Mapping[str, Any]) -> SessionVelocity:
    """Build a limiter from ``mandate['velocity']``.

    Shape, all optional:

        "velocity": {"send": {"max": 20, "window_seconds": 3600}}

    Absent means unlimited, so a mandate written before this module existed
    behaves exactly as it did.
    """
    raw = (mandate or {}).get("velocity") or {}
    limits: dict[str, tuple[int, float]] = {}
    for action_class, spec in raw.items():
        if not isinstance(spec, Mapping):
            continue
        try:
            limits[str(action_class)] = (int(spec["max"]),
                                         float(spec.get("window_seconds", 3600)))
        except (KeyError, TypeError, ValueError):
            continue
    return SessionVelocity(config=VelocityConfig(limits=limits))
