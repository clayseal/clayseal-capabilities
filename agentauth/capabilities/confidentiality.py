"""Confidentiality flow: harm defined by the SEQUENCE, not the target.

## The gap this closes

Our measurement splits agent harm three ways by what defines it.

**Target.** The action points somewhere it must not. Path escapes, unauthorized
egress destinations, protected zones. Scope and binding contain essentially all
of it: 99.9% on RedCode, 100% on IPI-Coding, across 2,808 attack events.

**Volume.** Each action is authorized and correctly targeted, and there are far
too many. Velocity contains it: 100% of bursts of ten or more, blast radius four
to five actions, no false alarms across 400 real sessions
(`benchmarks/results/burst.md`).

**Content.** The action is authorized, correctly targeted, normally paced, and
its *meaning* is harmful. Nobody contains this. We get 6.3% on AgentHarm; the
published frontier gets 32% of SLEIGHT at a 1% false-positive rate.

There is a fourth, and it is the one this module is for. **Sequence.** Read the
credentials file, then write to the log the task legitimately writes to. Read the
customer table, then post to the channel the goal named. Every action is granted,
every target is in scope, the pace is ordinary, and no single action is harmful.
Only the *pair* is. A per-action authorization layer cannot see a pair, so it
allows both.

Unlike content-defined harm, this one is decidable. It does not require guessing
intent. It requires remembering where a value came from.

## Why the textbook answer does not work

Bell-LaPadula says no write down: once a session reads at level HIGH, it may not
write at level LOW. Applied per session that is correct and unusable. An agent
that reads one secret at step 3 has every write blocked for the rest of the
session, which is the label-creep failure that has kept information-flow control
out of production systems for forty years.

So the check here is **per value, not per session**. A write is refused when its
arguments carry a value attributable to a sensitive read, and not otherwise. An
agent may read a secret and then write anything that does not contain it. That is
the difference between a mechanism and a compliance theatre.

The attribution index is `parameter_provenance.ParameterProvenance`, which
already records which observation supplied which token and is already wired into
the live path.

## Declassification, which is the other half

Some flows are the point of the task. "Email the quarterly numbers to the board"
reads sensitive data and sends it outward, and refusing that is refusing the job.

Declassification is bound to the **sealed goal**, the same trusted input the
replanner uses. A sink the goal named is an authorized destination for sensitive
data; every other sink is not. The goal is captured before any tool output could
contaminate it, so an injected instruction cannot nominate a sink.

That is the same structure as destination binding, one level up: binding asks
whether this recipient was authorized, and this asks whether this *class of data*
was authorized to reach that recipient.

## What it cannot do

If the goal names the sink, sensitive data may flow to it, and an attacker who
controls what the sealed goal says controls that. Sealing the goal is what makes
this safe, and this module must not be deployed where the goal is attacker-
reachable.

It attributes by token, so a value the agent transforms beyond recognition
(encrypted, encoded, summarised in prose) is not attributable and flows freely.
That is a real limit, it is shared by every practical taint system, and it is
measured rather than assumed: see `benchmarks/results/flow.md`.
"""
from __future__ import annotations

import fnmatch
import threading
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from agentauth.capabilities.parameter_provenance import ParameterProvenance

# Verbs that move data outward. A read cannot leak; a write, send or post can.
SINK_VERBS = frozenset({"write", "send", "post", "share", "create", "update", "pay"})

# Verbs that bring data in, and can therefore taint it.
SOURCE_VERBS = frozenset({"read", "search", "list", "get", "query"})


@dataclass(frozen=True)
class FlowVerdict:
    allowed: bool
    reason: str
    # The sensitive resources whose data this action would have carried.
    carried: tuple[str, ...] = ()
    declassified_by: str | None = None


@dataclass(frozen=True)
class SensitivityPolicy:
    """Which resources are sensitive, and which sinks the goal authorized.

    Both come from the mandate. Nothing here is inferred at runtime, because a
    policy an attacker can influence is not a policy.
    """

    # Glob patterns over resource identifiers or paths.
    sensitive: tuple[str, ...] = ()
    # Sinks the sealed goal named. Sensitive data may reach these and only these.
    declassified_sinks: tuple[str, ...] = ()

    @classmethod
    def from_mandate(cls, mandate: Mapping[str, Any] | None) -> "SensitivityPolicy":
        raw = (mandate or {}).get("confidentiality") or {}
        return cls(
            sensitive=tuple(str(p) for p in (raw.get("sensitive") or ())),
            declassified_sinks=tuple(str(p) for p in (raw.get("declassified_sinks") or ())),
        )

    @property
    def active(self) -> bool:
        """Absent policy means no flow control, so adding this module changes
        nothing for a mandate written before it existed."""
        return bool(self.sensitive)

    def is_sensitive(self, resource: str | None, path: str | None = None) -> bool:
        return any(_matches(c, pat)
                   for c in (resource, path) if c
                   for pat in self.sensitive)

    def is_declassified(self, resource: str | None, path: str | None = None) -> str | None:
        for candidate in (resource, path):
            if not candidate:
                continue
            for pat in self.declassified_sinks:
                if _matches(candidate, pat):
                    return pat
        return None


def _matches(candidate: str, pattern: str) -> bool:
    return fnmatch.fnmatch(candidate, pattern) or candidate == pattern


# A reconstruction has to clear a higher bar than an exact match, because
# stripping separators from an outgoing payload creates long strings that could
# coincidentally contain a short secret.
_MIN_RECONSTRUCTED = 12

_DECODE_TOKEN = __import__("re").compile(r"[A-Za-z0-9+/=]{16,}")


def _TOKENS_FOR_DECODE(blob: str) -> list[str]:
    return _DECODE_TOKEN.findall(blob)


def _flatten(value: Any) -> str:
    """Every string in a nested payload, joined. Structure does not hide a value."""
    if value is None:
        return ""
    if isinstance(value, Mapping):
        return " ".join(_flatten(v) for v in value.values())
    if isinstance(value, (list, tuple, set)):
        return " ".join(_flatten(v) for v in value)
    return str(value)


@dataclass
class FlowTracker:
    """Per-value confidentiality flow over one session.

    Holds no policy of its own: `check` is given the policy so the same tracker
    can serve a session whose mandate changes under delegation.
    """

    provenance: ParameterProvenance = field(default_factory=ParameterProvenance)
    # token -> the sensitive resources that emitted it.
    _sensitive_tokens: dict[str, set[str]] = field(default_factory=dict)
    _lock: Any = field(default_factory=threading.RLock, repr=False, compare=False)

    # ----------------------------------------------------------------- #
    # Observing
    # ----------------------------------------------------------------- #
    def observe(self, tool: str, resource: str, payload: Any, *,
                policy: SensitivityPolicy, path: str | None = None,
                structured_fields: Mapping[str, Any] | None = None) -> None:
        """Record what this observation returned, and whether it was sensitive."""
        self.provenance.record_observation(
            tool, payload, structured_fields=structured_fields)
        if not policy.is_sensitive(resource, path):
            return
        origin = path or resource
        with self._lock:
            for token in ParameterProvenance._tokens(payload):
                self._sensitive_tokens.setdefault(token, set()).add(origin)
            for value in (structured_fields or {}).values():
                for token in ParameterProvenance._tokens(value):
                    self._sensitive_tokens.setdefault(token, set()).add(origin)

    # ----------------------------------------------------------------- #
    # Deciding
    # ----------------------------------------------------------------- #
    def check(self, *, tool: str, verb: str, resource: str, args: Any,
              policy: SensitivityPolicy, path: str | None = None) -> FlowVerdict:
        """May this action carry what it is carrying, to where it is going?"""
        if not policy.active:
            return FlowVerdict(True, "no confidentiality policy declared")
        if verb not in SINK_VERBS:
            return FlowVerdict(True, f"{verb!r} does not move data outward")

        carried = self._carried(args)
        if not carried:
            return FlowVerdict(True, "carries no value from a sensitive read")

        # A sink the sealed goal named is authorized to receive this.
        sink = policy.is_declassified(resource, path)
        if sink is not None:
            return FlowVerdict(
                True, f"sensitive data to {sink}, which the sealed goal named",
                tuple(sorted(carried)), sink)

        # The destination is legitimate for this task and the DATA is not.
        origins = ", ".join(sorted(carried))
        return FlowVerdict(
            False,
            f"would carry data read from {origins} to {resource!r}, which the "
            f"sealed goal did not name as a destination for it",
            tuple(sorted(carried)),
        )

    def _carried(self, args: Any) -> set[str]:
        tokens = ParameterProvenance._tokens(args)
        with self._lock:
            found: set[str] = set()
            for token in tokens:
                found |= self._sensitive_tokens.get(token, set())
            if found:
                return found
            # Exact tokens missed. Try the reconstructions below, which cost a
            # normalisation of the outgoing payload and nothing else.
            return self._carried_after_normalisation(args)

    def _carried_after_normalisation(self, args: Any) -> set[str]:
        """Catch the cheap transforms, and be explicit about the rest.

        The confidentiality-flow benchmark measures which evasions work. Exact
        token matching alone caught a verbatim value and nothing else: chunking
        it, dotting it, base64ing it or hexing it all carried it out at 100%.
        Each of those is a mechanical transform with a mechanical inverse, so
        each is handled here.

        What is deliberately NOT handled is anything requiring semantics: a
        value the agent encrypts, paraphrases, or summarises out of existence.
        That is the standing limit of every practical taint system, it is
        published in `benchmarks/results/flow.md` rather than papered over, and
        the honest reading is that flow control raises the cost of exfiltration
        rather than making it impossible.
        """
        import base64
        import binascii

        blob = _flatten(args)
        if not blob:
            return set()

        candidates = [
            # Separator stripping recovers chunked and dotted values, since the
            # sensitive token was indexed in its unseparated form.
            "".join(ch for ch in blob if ch.isalnum()),
            blob[::-1],
        ]
        compact = candidates[0]
        candidates.append("".join(ch for ch in blob[::-1] if ch.isalnum()))

        # Encodings, decoded rather than pattern-matched, so a false positive
        # needs the payload to actually decode to the sensitive value.
        for chunk in _TOKENS_FOR_DECODE(blob):
            try:
                candidates.append(base64.b64decode(chunk + "=" * (-len(chunk) % 4),
                                                   validate=True).decode("utf-8", "ignore"))
            except (binascii.Error, ValueError):
                pass
            try:
                candidates.append(bytes.fromhex(chunk).decode("utf-8", "ignore"))
            except ValueError:
                pass

        with self._lock:
            found: set[str] = set()
            for cand in candidates:
                if not cand:
                    continue
                for token, origins in self._sensitive_tokens.items():
                    if len(token) < _MIN_RECONSTRUCTED:
                        continue
                    compact_token = "".join(ch for ch in token if ch.isalnum())
                    if (token in cand
                            or (compact_token and compact_token in
                                "".join(ch for ch in cand if ch.isalnum()))):
                        found |= origins
            _ = compact
            return found

    # ----------------------------------------------------------------- #
    # Introspection, so an operator can see why something was refused
    # ----------------------------------------------------------------- #
    @property
    def sensitive_origins(self) -> set[str]:
        with self._lock:
            return {o for origins in self._sensitive_tokens.values() for o in origins}


def declassified_sinks_from_goal(goal: str, candidates: Sequence[str]) -> tuple[str, ...]:
    """Which candidate sinks does the sealed goal name?

    Substring matching on the goal text, deliberately: the goal is trusted input
    fixed before execution, so a permissive match against it cannot be steered.
    The conservative direction is a sink the goal did not name, and that is the
    one that fails closed.
    """
    lowered = (goal or "").lower()
    return tuple(c for c in candidates if c and c.lower() in lowered)
