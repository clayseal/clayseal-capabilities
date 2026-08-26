"""W3C Trace Context, which is what replaces the session for audit.

WHY THIS EXISTS

`DecisionLog` produces a hash-chained record of every decision, which makes the
log internally verifiable and externally **unjoinable**. An enterprise holding
an incident has a trace of what its agent did and a receipt of what this gateway
decided, and nothing that lines the two up.

That was survivable while a session existed: the session id was the join key by
convention. MCP 2026-07-28 removes the session, and the migration guidance is
explicit that W3C Trace Context becomes "the correlation spine that replaces the
session for audit", with trace ids stamped onto durable records "so the
short-lived trace and the durable audit record can be matched during an
incident". It also says the quiet part: "correlation is manufactured now, budget
for it."

WHAT IS PARSED, AND WHY IT IS PARSED STRICTLY

A `traceparent` arrives in a request header, which means it arrives from outside
and may be anything. It is not a security boundary: nothing is authorized on the
strength of a trace id, and the worst a bad one does is put a wrong join key in
a log. But a log is evidence, and evidence with a field somebody else chose the
shape of is worse than a log with no field: a 4KB `traceparent` in every record
is a storage attack, and an unvalidated one lands whatever the sender wrote in
the middle of a signed receipt.

So the format is checked against the specification and a malformed one is
DROPPED rather than stored. A record with no trace is honest; a record with a
trace nobody can join to is not.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

#: `version-traceid-parentid-flags`, all lower-case hex, fixed widths.
#: An all-zero trace or parent id is invalid per the specification.
_TRACEPARENT = re.compile(
    r"^([0-9a-f]{2})-([0-9a-f]{32})-([0-9a-f]{16})-([0-9a-f]{2})$")

#: `tracestate` is a comma-separated vendor list and is carried opaquely. Capped
#: because it is the only unbounded field in the header set and it lands in
#: every record.
MAX_TRACESTATE = 512


@dataclass(frozen=True)
class TraceContext:
    """One parsed `traceparent`, plus the `tracestate` that came with it."""

    trace_id: str
    span_id: str
    flags: str = "01"
    version: str = "00"
    tracestate: str = ""

    @property
    def traceparent(self) -> str:
        return f"{self.version}-{self.trace_id}-{self.span_id}-{self.flags}"

    def to_dict(self) -> dict[str, str]:
        """What lands in a decision record. `trace_id` is the join key."""
        out = {"trace_id": self.trace_id, "span_id": self.span_id,
               "traceparent": self.traceparent}
        if self.tracestate:
            out["tracestate"] = self.tracestate
        return out

    @classmethod
    def parse(cls, traceparent: object,
              tracestate: object = None) -> TraceContext | None:
        """Read a header. Returns None for anything that is not one.

        Dropping beats storing: a record with no trace is honest, and one
        carrying a trace id nobody can join to is a field that looks like
        evidence and is not.
        """
        if not isinstance(traceparent, str):
            return None
        match = _TRACEPARENT.match(traceparent.strip())
        if match is None:
            return None
        version, trace_id, span_id, flags = match.groups()
        # The specification reserves an all-zero id and forbids version ff.
        if version == "ff" or set(trace_id) == {"0"} or set(span_id) == {"0"}:
            return None
        state = ""
        if isinstance(tracestate, str):
            candidate = tracestate.strip()
            if candidate and len(candidate) <= MAX_TRACESTATE and \
                    candidate.isprintable():
                state = candidate
        return cls(trace_id=trace_id, span_id=span_id, flags=flags,
                   version=version, tracestate=state)

    @classmethod
    def from_headers(cls, headers: object) -> TraceContext | None:
        """Pull a context out of anything dict-like, case-insensitively."""
        getter = getattr(headers, "get", None)
        if getter is None:
            return None

        def read(name: str) -> object:
            value = getter(name)
            if value is None:
                try:
                    lowered = {str(k).lower(): v
                               for k, v in dict(headers).items()}
                except Exception:  # noqa: BLE001 - not dict-like enough
                    return None
                value = lowered.get(name)
            return value

        return cls.parse(read("traceparent"), read("tracestate"))
