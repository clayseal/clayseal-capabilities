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
from typing import Any

# Values shorter than this are too common to attribute: a "3" or an "ok" appears
# in every observation and would make everything trusted by everything.
MIN_ATTRIBUTABLE = 6

_TOKEN = re.compile(r"[A-Za-z0-9_.:@/+-]{%d,}" % MIN_ATTRIBUTABLE)

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


@dataclass(frozen=True)
class Source:
    """Where a value came from."""

    tool: str
    structured: bool          # from a named field, rather than from free text
    goal_named: bool          # the producing call referenced something the goal named

    def describe(self) -> str:
        where = "a structured field" if self.structured else "free text"
        named = " of a goal-named resource" if self.goal_named else ""
        return f"{where} of {self.tool}{named}"


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
                           goal_named: bool = False) -> None:
        """Note every attributable token this observation contained.

        Structured fields are recorded separately from the free-text body,
        because a value that appears only in prose carries much weaker evidence
        than one that appears in a named field.
        """
        with self._lock:
            for key, value in (structured_fields or {}).items():
                for token in self._tokens(value):
                    self._origins.setdefault(token, set()).add(
                        Source(tool, True, goal_named))
            for token in self._tokens(payload):
                self._origins.setdefault(token, set()).add(
                    Source(tool, False, goal_named))

    @staticmethod
    def _tokens(value: Any) -> list[str]:
        if value is None:
            return []
        if isinstance(value, (list, tuple, set)):
            return [t for v in value for t in ParameterProvenance._tokens(v)]
        if isinstance(value, Mapping):
            return [t for v in value.values() for t in ParameterProvenance._tokens(v)]
        out: list[str] = []
        seen: set[str] = set()
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
                if len(form) >= MIN_ATTRIBUTABLE and form not in seen:
                    seen.add(form)
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
                                                            not s.goal_named, s.tool))))
        return True, f"every part of the value is grounded, first in {best.describe()}"
