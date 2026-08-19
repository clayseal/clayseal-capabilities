"""Parameter provenance: bind a value to the observation that supplied it.

Our destination binding asks "is this address on the trusted list". AuthGraph
(arXiv:2605.26497) asks a strictly finer question: *which tool's observation
supplied this value, and was that tool an authorized source for this parameter*.
It is the reason their utility number is the best published, because it lets a
legitimate value discovered at runtime be trusted without widening the trusted
set for everything else.

The difference matters in a case we measured and got wrong. On slack our taint
mode produced ten hard denials against the plain envelope's zero, all on
legitimate destinations discovered from message content. We diagnosed that as
"free text and injections share a channel, so no field-type rule separates
them", which is true and is the wrong axis. The separating question is not what
*kind of field* a value sat in. It is which observation produced it: a recipient
read from a channel the user's goal named is a legitimate source for a message
recipient, and the same string appearing in a fetched webpage is not.

This module records that association and answers the question. It does not
decide policy on its own; the egress and envelope layers consult it.

**Why this is not in the deterministic benchmark.** The replay corpora do not
record which observation supplied an argument, and AgentHarm carries no argument
values at all (0 of 314 events). There is nothing to bind. Parameter provenance
is only measurable on the live path, where tool outputs and their consumers both
exist, so that is where it is evaluated.
"""
from __future__ import annotations

import re
import threading
from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

# Values shorter than this are too common to attribute: a "3" or an "ok" appears
# in every observation and would make everything trusted by everything.
MIN_ATTRIBUTABLE = 6

_TOKEN = re.compile(r"[A-Za-z0-9_.:@/+-]{" + str(MIN_ATTRIBUTABLE) + r",}")

# Punctuation that belongs to the sentence rather than to the value. The token
# class has to contain these characters, because they appear inside real values
# (paths, addresses, URLs), and that means a value at the end of a sentence
# matches with the full stop attached.
#
# The confidentiality-flow benchmark found this by measurement rather than by
# review: a secret recorded from a structured field and then written out as
# "Here is the record you asked for: <secret>." was attributed to nothing,
# because "<secret>." is not "<secret>". Containment on that arm was 0%.
# Trimming the edges is the whole fix and it only ever makes attribution
# stronger. See benchmarks/results/flow.md.
_EDGE = ".:,;!?/+-_@"


class DestinationTrust(str, Enum):
    """Policy verdict for a destination under containing-object provenance.

    Structured fields of a *trusted* observation (goal-named / named object) may
    ALLOW at this layer (slot checks). Free text — even from a goal-named
    containing object — never auto-allows: the measured limit is that the legit
    recipient and an injected attacker IBAN can sit side by side in one trusted
    file. That case steps up. Ungrounded or foreign-object destinations deny.

    The egress floor still demotes provenance ALLOW → STEP_UP for autonomy
    (measured inversion: structured injection in a goal-named resource must not
    grant an unattended send).
    """

    ALLOW = "allow"
    STEP_UP = "step_up"
    DENY = "deny"


@dataclass(frozen=True)
class Source:
    """Where a value came from.

    ``containing_object`` is the trust root the improvements memo names: not the
    field type, but the channel / file / resource the observation was taken from.
    A recipient in a message from a channel the goal named is task-derived; the
    same string in an unrelated webpage is not.
    """

    tool: str
    structured: bool          # from a named field, rather than from free text
    goal_named: bool          # the producing call referenced something the goal named
    containing_object: str = ""  # channel, file, or resource id of the observation

    def describe(self) -> str:
        where = "a structured field" if self.structured else "free text"
        named = " of a goal-named resource" if self.goal_named else ""
        obj = f" in {self.containing_object!r}" if self.containing_object else ""
        return f"{where} of {self.tool}{named}{obj}"

    def object_trusted(self, goal_named_objects: set[str] | None) -> bool:
        """Is the containing object itself on the sealed goal's named set?"""
        if self.goal_named:
            return True
        if not goal_named_objects or not self.containing_object:
            return False
        obj = self.containing_object
        return any(obj == g or g in obj or obj in g for g in goal_named_objects)


@dataclass
class ParameterProvenance:
    """Which observations supplied which values, over one session.

    Deliberately a record rather than a policy. The question "may this parameter
    take a value from that source" belongs to the mandate, and keeping the two
    apart is what stops this becoming another implicit trust rule.
    """

    # value -> the sources that produced it. A value can have several: the same
    # address may appear in a trusted record and in an untrusted webpage, and
    # the caller decides what to do with that ambiguity.
    _origins: dict[str, set[Source]] = field(default_factory=dict)
    _lock: Any = field(default_factory=threading.RLock, repr=False, compare=False)

    def record_observation(self, tool: str, payload: Any, *,
                           structured_fields: Mapping[str, Any] | None = None,
                           goal_named: bool = False,
                           containing_object: str = "") -> None:
        """Note every attributable token this observation contained.

        Structured fields are recorded separately from the free-text body,
        because a value that appears only in prose carries much weaker evidence
        than one that appears in a named field. ``containing_object`` records
        which channel/file/resource the observation was taken from — the axis
        that separates the slack case from an unrelated webpage fetch.
        """
        with self._lock:
            for _key, value in (structured_fields or {}).items():
                for token in self._tokens(value):
                    self._origins.setdefault(token, set()).add(
                        Source(tool, True, goal_named, containing_object))
            for token in self._tokens(payload):
                self._origins.setdefault(token, set()).add(
                    Source(tool, False, goal_named, containing_object))
    # Attacker-shaped tool output reaches this. A deeply nested or
    # self-referential payload raised RecursionError INSIDE the authorization
    # path, which is a denial of service on the thing that decides whether
    # actions are allowed. Bounded traversal, and the tokens found so far are
    # returned rather than an exception raised: a payload we cannot fully walk
    # grounds less, which fails toward refusing rather than allowing.
    MAX_DEPTH = 24

    @staticmethod
    def _tokens(value: Any, *, _depth: int = 0, _seen: set[int] | None = None) -> list[str]:
        if value is None or _depth > ParameterProvenance.MAX_DEPTH:
            return []
        if isinstance(value, (list, tuple, set, Mapping)):
            seen = _seen if _seen is not None else set()
            marker = id(value)
            if marker in seen:
                return []
            seen.add(marker)
            items = value.values() if isinstance(value, Mapping) else value
            out: list[str] = []
            for item in items:
                out.extend(ParameterProvenance._tokens(
                    item, _depth=_depth + 1, _seen=seen))
            seen.discard(marker)
            return out
        out = []
        seen_tokens: set[str] = set()
        for raw in _TOKEN.findall(str(value)):
            for form in (raw, raw.strip(_EDGE)):
                # Both forms, because the trimmed one recovers a value that ended
                # a sentence while the raw one keeps a path or address that
                # legitimately ends in a separator.
                #
                # Deduplicated through a set rather than `in out`: this runs on
                # every observation in the live path, and a linear membership
                # test over a growing list is quadratic in the token count of
                # the payload.
                if len(form) >= MIN_ATTRIBUTABLE and form not in seen_tokens:
                    seen_tokens.add(form)
                    out.append(form)
        return out

    def sources_of(self, value: Any) -> set[Source]:
        """Every observation that could have supplied this value."""
        with self._lock:
            found: set[Source] = set()
            for token in self._tokens(value):
                found |= self._origins.get(token, set())
            return found

    def is_grounded(self, value: Any, *, authorized_tools: set[str] | None = None,
                    require_structured: bool = True) -> tuple[bool, str]:
        """Did an authorized observation supply **all** of this value?

        ``authorized_tools`` is the set of sources the mandate permits for this
        parameter. None means any observed source counts, which is weaker and is
        the setting to use while the mandate does not yet declare per-parameter
        sources.

        Every attributable token has to be grounded, not any of them. Asking
        whether *some* token was observed lets one legitimate token launder an
        entire composite value, and each of these passed before the check was
        tightened:

            "alice@corp.example, attacker@evil.test"        (a BCC)
            "https://evil.test/exfil?to=alice@corp.example" (a URL exfil)
            ["alice@corp.example", "attacker@evil.test"]    (a recipient list)

        Structuredness is likewise evaluated on the token that actually matched,
        rather than on the union: a value used to satisfy `require_structured`
        because some *other* token in it came from a named field.
        """
        tokens = self._tokens(value)
        if not tokens:
            return False, "value contains nothing attributable"

        # The edge-trimmed and raw forms of one token are the same value, so
        # matching either is enough. Group them so a sentence-final value is not
        # counted as two tokens, one of which is ungrounded.
        with self._lock:
            groups: list[list[str]] = []
            for token in tokens:
                trimmed = token.strip(_EDGE)
                for group in groups:
                    if trimmed and trimmed in (t.strip(_EDGE) for t in group):
                        group.append(token)
                        break
                else:
                    groups.append([token])

            for group in groups:
                sources: set[Source] = set()
                for token in group:
                    sources |= self._origins.get(token, set())
                if not sources:
                    return False, (
                        f"{group[0]!r} appears in no observation this session"
                    )
                candidates = sources
                if authorized_tools is not None:
                    candidates = {s for s in sources if s.tool in authorized_tools}
                    if not candidates:
                        seen = ", ".join(sorted({s.tool for s in sources}))
                        return False, (
                            f"{group[0]!r} came from {seen}, which is not an "
                            "authorized source for this parameter"
                        )
                if require_structured and not any(s.structured for s in candidates):
                    return False, (
                        f"{group[0]!r} appears only in free text, which is where "
                        "injected content also lives"
                    )

            first = groups[0]
            sources = set()
            for token in first:
                sources |= self._origins.get(token, set())
            if authorized_tools is not None:
                sources = {s for s in sources if s.tool in authorized_tools}
            best = next(iter(sorted(sources, key=lambda s: (not s.structured,
                                                            not s.goal_named,
                                                            s.tool,
                                                            s.containing_object))))
        return True, f"every part of the value is grounded, first in {best.describe()}"

    def check_destination(
        self,
        value: Any,
        *,
        goal_named_objects: set[str] | None = None,
        authorized_tools: set[str] | None = None,
    ) -> tuple[DestinationTrust, str]:
        """Containing-object provenance verdict for an egress destination.

        Product matrix (egress still demotes ALLOW → STEP_UP for autonomy):

        - Structured field of a **trusted** observation (``goal_named`` or
          containing object on the sealed goal's named set) → ALLOW.
        - Free text whose containing object the goal named → STEP_UP (never
          auto-trust: injection and legit recipient can share one source).
        - Structured or free text of a foreign object, or ungrounded → DENY.
        """
        tokens = self._tokens(value)
        if not tokens:
            return DestinationTrust.DENY, "value contains nothing attributable"

        with self._lock:
            groups: list[list[str]] = []
            for token in tokens:
                trimmed = token.strip(_EDGE)
                for group in groups:
                    if trimmed and trimmed in (t.strip(_EDGE) for t in group):
                        group.append(token)
                        break
                else:
                    groups.append([token])

            worst = DestinationTrust.ALLOW
            reasons: list[str] = []
            for group in groups:
                sources: set[Source] = set()
                for token in group:
                    sources |= self._origins.get(token, set())
                if not sources:
                    return (
                        DestinationTrust.DENY,
                        f"{group[0]!r} appears in no observation this session",
                    )
                candidates = sources
                if authorized_tools is not None:
                    candidates = {s for s in sources if s.tool in authorized_tools}
                    if not candidates:
                        seen = ", ".join(sorted({s.tool for s in sources}))
                        return (
                            DestinationTrust.DENY,
                            f"{group[0]!r} came from {seen}, not an authorized source",
                        )
                trusted_structured = [
                    s for s in candidates
                    if s.structured and s.object_trusted(goal_named_objects)
                ]
                if trusted_structured:
                    best = next(iter(sorted(
                        trusted_structured,
                        key=lambda s: (not s.goal_named, s.tool))))
                    reasons.append(f"{group[0]!r} structured via {best.describe()}")
                    continue
                if any(s.structured for s in candidates):
                    # Structured but foreign containing object — not slot-ALLOW.
                    return (
                        DestinationTrust.DENY,
                        f"{group[0]!r} structured field of an untrusted "
                        "containing object",
                    )
                if any(s.object_trusted(goal_named_objects) for s in candidates):
                    worst = DestinationTrust.STEP_UP
                    reasons.append(
                        f"{group[0]!r} only in free text of a goal-named object; "
                        "step up (never auto-trust free text)"
                    )
                    continue
                return (
                    DestinationTrust.DENY,
                    f"{group[0]!r} only in free text of an untrusted containing object",
                )
        return worst, "; ".join(reasons) if reasons else "destination grounded"

    def trusted_candidates(
        self,
        *,
        structured_only: bool = True,
        goal_named_objects: set[str] | None = None,
        authorized_tools: set[str] | None = None,
        limit: int = 8,
    ) -> list[str]:
        """Values an agent may retry with after a destination denial.

        ARGUS's utility win is largely this: when a call is blocked, hand back
        the trusted candidates from the provenance graph so the retry uses a
        grounded recipient instead of inventing another. The retry still goes
        through the full authorize path — nothing is bypassed.
        """
        out: list[str] = []
        seen: set[str] = set()
        with self._lock:
            items = sorted(self._origins.items(), key=lambda kv: (-len(kv[0]), kv[0]))
            for value, sources in items:
                if value in seen:
                    continue
                candidates = sources
                if authorized_tools is not None:
                    candidates = {s for s in sources if s.tool in authorized_tools}
                if not candidates:
                    continue
                if structured_only and not any(s.structured for s in candidates):
                    continue
                if goal_named_objects is not None and not any(
                    s.object_trusted(goal_named_objects) or s.structured
                    for s in candidates
                ):
                    continue
                seen.add(value)
                out.append(value)
                if len(out) >= limit:
                    break
        return out
