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

import math
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

# The aggregate class. A mandate that declares a limit on `send` has bounded sends
# and nothing else: the other eight effect verbs stay unlimited through the same
# tool, which is a hole an operator writing "20 sends per hour" does not expect to
# have left open. `effect` bounds all of them at once, and per-verb limits compose
# with it (both must admit the action).
EFFECT_CLASS = "effect"

# Everything a mandate may name as a rate class. A limit on anything else was
# previously parsed, stored, and never applied, so the mandate said one thing and
# the enforcement did another.
KNOWN_CLASSES = frozenset(EFFECT_VERBS | {EFFECT_CLASS})


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
    # Entries the mandate declared that this config could not honour, with the
    # reason. A silently dropped limit is a gap the operator believes is closed.
    rejected: Mapping[str, str] = field(default_factory=dict)

    def classes_for(self, tool_name: str, action: str) -> tuple[str, ...]:
        """Every rate class this action counts against, tightest-first.

        Returns a tuple rather than one class, because an action belongs to both
        its verb class and the aggregate `effect` class, and a limit on either
        has to bind. Returning a single class is what let a limit on `send` leave
        the other eight effect verbs unlimited through the same tool.

        The action is normalised before lookup. It arrives from the agent's own
        tool call, and `SEND` used to miss a limit declared on `send` entirely:
        twenty calls passed a cap of two.
        """
        verb = (action or "").strip().casefold()
        out: list[str] = []
        explicit = self.tool_classes.get(tool_name)
        if explicit:
            out.append(str(explicit).strip().casefold())
        if verb in EFFECT_VERBS:
            if verb not in out:
                out.append(verb)
            if EFFECT_CLASS not in out:
                out.append(EFFECT_CLASS)
        return tuple(out)

    def class_for(self, tool_name: str, action: str) -> str | None:
        """First class only. Kept for callers that want a label, not a decision."""
        classes = self.classes_for(tool_name, action)
        return classes[0] if classes else None

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
        """Would this action exceed a declared rate? Read-only; records nothing.

        A projection for reporting. `try_acquire` is the enforcement entry point,
        because check-then-record is a race.
        """
        at = time.time() if now is None else now
        with self._lock:
            for action_class in self.config.classes_for(tool_name, action):
                limit = self.config.limit_for(action_class)
                if limit is None:
                    continue
                max_actions, window = limit
                observed = len(self._recent(action_class, window, at))
                if observed + 1 > max_actions:
                    return VelocityVerdict(
                        False,
                        f"velocity: {observed + 1} {action_class} actions in "
                        f"{window:.0f}s exceeds the {max_actions} this task declared",
                        observed + 1, max_actions, window,
                    )
        return VelocityVerdict(True, "within every declared velocity class")

    def try_acquire(self, tool_name: str, action: str, *,
                    now: float | None = None) -> VelocityVerdict:
        """Count and record under one lock. The only safe enforcement entry point.

        `check` followed by `record` is a check-then-act race, and not a
        theoretical one: forty concurrent sends passed a cap of five, because
        every thread counted before any thread recorded. A rate limit whose
        window can be entered concurrently is not a rate limit.

        Acquires against EVERY class the action belongs to, all or nothing. An
        action counts against its verb class and against the aggregate `effect`
        class, and a limit on either has to bind, so a partial acquisition would
        leave one bucket charged for an action that never happened.
        """
        at = time.time() if now is None else now
        classes = [c for c in self.config.classes_for(tool_name, action)
                   if self.config.limit_for(c) is not None]
        if not classes:
            return VelocityVerdict(True, "no velocity limit applies to this action")
        with self._lock:
            for action_class in classes:
                max_actions, window = self.config.limit_for(action_class)
                observed = len(self._recent(action_class, window, at))
                if observed + 1 > max_actions:
                    return VelocityVerdict(
                        False,
                        f"velocity: {observed + 1} {action_class} actions in "
                        f"{window:.0f}s exceeds the {max_actions} this task declared",
                        observed + 1, max_actions, window,
                    )
            for action_class in classes:
                self._events.setdefault(action_class, []).append(at)
            tightest = min(classes, key=lambda c: self.config.limit_for(c)[0])
            max_actions, window = self.config.limit_for(tightest)
            return VelocityVerdict(
                True, f"within {tightest} velocity",
                len(self._recent(tightest, window, at)), max_actions, window)

    def release(self, tool_name: str, action: str, *, now: float | None = None) -> None:
        """Give back the slots acquired for an action a later rung then refused."""
        with self._lock:
            for action_class in self.config.classes_for(tool_name, action):
                stamps = self._events.get(action_class)
                if not stamps:
                    continue
                if now is None:
                    stamps.pop()
                    continue
                for i in range(len(stamps) - 1, -1, -1):
                    if stamps[i] == now:
                        stamps.pop(i)
                        break

    def record(self, tool_name: str, action: str, *, now: float | None = None) -> None:
        at = time.time() if now is None else now
        with self._lock:
            for action_class in self.config.classes_for(tool_name, action):
                if self.config.limit_for(action_class) is None:
                    continue
                self._events.setdefault(action_class, []).append(at)

    def observed(self, action_class: str, window: float, *, now: float | None = None) -> int:
        at = time.time() if now is None else now
        with self._lock:
            return len(self._recent(action_class, window, at))


def velocity_from_mandate(mandate: Mapping[str, Any],
                          *, strict: bool = False) -> SessionVelocity:
    """Build a limiter from ``mandate['velocity']``.

    Shape, all optional::

        "velocity": {
            "effect": {"max": 40, "window_seconds": 3600},
            "send":   {"max": 20, "window_seconds": 3600},
            "tool_classes": {"mailer": "send"}
        }

    Absent means unlimited, so a mandate written before this module existed
    behaves exactly as it did.

    Every value here is validated, because each of these was silently accepted
    and each silently disabled the limit it appeared on:

    - ``window_seconds`` of ``0``, ``-1`` or ``-inf``: all ten of ten sends
      passed a declared cap of one, because the sliding window could never
      contain anything.
    - a class name that is not a known rate class: parsed, stored, and never
      applied, so the mandate said one thing and enforcement did another.
    - ``max`` of ``True``: ``bool`` is an ``int`` in Python, so a cap of one.

    ``strict`` raises on a bad entry instead of dropping it. The default drops
    and is what a live path wants, since a malformed mandate should not take the
    session down. Anything dropped is reported in ``VelocityConfig.rejected`` so
    a caller can log it rather than discover the gap in production.
    """
    raw = dict((mandate or {}).get("velocity") or {})
    tool_classes_raw = raw.pop("tool_classes", None) or {}
    tool_classes = {str(k): str(v).strip().casefold()
                    for k, v in tool_classes_raw.items()
                    if isinstance(k, str) and isinstance(v, str) and v.strip()}

    limits: dict[str, tuple[int, float]] = {}
    rejected: dict[str, str] = {}
    declarable = set(KNOWN_CLASSES) | set(tool_classes.values())
    for action_class, spec in raw.items():
        name = str(action_class).strip().casefold()
        if not isinstance(spec, Mapping):
            rejected[name] = "not an object"
            continue
        if name not in declarable:
            rejected[name] = (
                f"unknown rate class; declare it in tool_classes or use one of "
                f"{sorted(KNOWN_CLASSES)}")
            if strict:
                raise ValueError(f"velocity: {name!r} {rejected[name]}")
            continue
        max_raw = spec.get("max")
        if isinstance(max_raw, bool) or not isinstance(max_raw, (int, float, str)):
            rejected[name] = "max must be a number"
            if strict:
                raise ValueError(f"velocity: {name!r} {rejected[name]}")
            continue
        try:
            max_actions = int(max_raw)
            window = float(spec.get("window_seconds", 3600))
        except (TypeError, ValueError):
            rejected[name] = "max or window_seconds is not a number"
            if strict:
                raise ValueError(f"velocity: {name!r} {rejected[name]}")
            continue
        if max_actions < 1:
            rejected[name] = f"max must be at least 1, got {max_actions}"
        elif not math.isfinite(window) or window <= 0:
            rejected[name] = f"window_seconds must be finite and positive, got {window}"
        else:
            limits[name] = (max_actions, window)
            continue
        if strict:
            raise ValueError(f"velocity: {name!r} {rejected[name]}")
    return SessionVelocity(config=VelocityConfig(
        limits=limits, tool_classes=tool_classes, rejected=rejected))
