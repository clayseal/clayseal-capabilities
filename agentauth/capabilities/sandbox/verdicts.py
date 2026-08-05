"""Parser for iVisor's `IVISOR_TRACE=policy` verdict stream (iVisor ADR-0021).

Format:

    ivisor: policy <subsystem>.<action> verdict=<allow|deny|miss> <k>=<v> ...

Only the `ivisor: policy ` prefix and the `verdict=` key are contract; every
other key may be added or dropped by a future iVisor, so unknown keys are kept
rather than rejected. A value starting with `"` is a JSON string (unescaped
here); one starting with `[` is a JSON array (kept verbatim, callers re-parse).
Anything that does not conform is dropped rather than fatal — the stream is
shared with whatever else the sentry writes.

THE FORGERY BOUNDARY: `verified` is true only for lines that arrived on the
out-of-band trace fd. Guest fds are virtualized and only 0/1/2 exist, so a host
fd >= 3 is unreachable from inside the guest; a policy-shaped line on stdout or
stderr is a guest-authored claim and is never evidence.
"""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import Enum

POLICY_PREFIX = "ivisor: policy "

# Order matters: the first present key is the most identifying one.
_SUBJECT_KEYS = ("path", "name", "dst", "port")

_ESCAPES = {"n": "\n", "t": "\t", "r": "\r"}


class Verdict(str, Enum):
    """A policy outcome.

    MISS is not a refusal — the path simply is not in the guest's namespace.
    Counting it as a denial inflates every containment number.
    """

    ALLOW = "allow"
    DENY = "deny"
    MISS = "miss"


@dataclass(frozen=True)
class PolicyEvent:
    """One parsed verdict line."""

    event: str                      # "net.connect", "fs.open", "dns.query", ...
    verdict: Verdict
    fields: Mapping[str, str] = field(default_factory=dict)
    verified: bool = False          # trace-fd only; see module docstring
    at_ms: int | None = None        # host receipt time, not an iVisor field

    def get(self, key: str) -> str | None:
        return self.fields.get(key)

    @property
    def subsystem(self) -> str:
        """`net`, `fs`, `dns`, `proc` — the left half of the event name."""
        return self.event.split(".", 1)[0]

    def subject(self) -> str:
        """The most identifying field, for one-line rendering."""
        for key in _SUBJECT_KEYS:
            value = self.fields.get(key)
            if value is not None:
                return value
        return ""

    def summary(self) -> str:
        """A compact human summary: what happened, to what, and why."""
        out = f"{self.event} {self.verdict.value} {self.subject()}".rstrip()
        reason = self.get("reason") or self.get("errno")
        if reason:
            out += f" ({reason})"
        return out

    def matches_watch(self, patterns) -> bool:
        """True if this line names a subject the caller considers sensitive.

        Used to pull the interesting needles out of the `fsmiss` haystack.
        """
        subject = self.subject()
        return any(p in subject for p in patterns)


def parse_policy_line(line: str, *, verified: bool,
                      at_ms: int | None = None) -> PolicyEvent | None:
    """Parse one line. Returns None for anything that is not a policy line.

    A well-formed prefix with no usable `verdict=` is rejected too: a line we
    cannot classify must not become a silent allow.
    """
    text = line.rstrip("\r\n")
    if not text.startswith(POLICY_PREFIX):
        return None
    rest = text[len(POLICY_PREFIX):]
    event, _, tail = rest.partition(" ")
    event = event.strip()
    if not event:
        return None
    fields = _parse_fields(tail)
    raw_verdict = fields.get("verdict")
    if raw_verdict is None:
        return None
    try:
        verdict = Verdict(raw_verdict)
    except ValueError:
        return None
    return PolicyEvent(event=event, verdict=verdict, fields=fields,
                       verified=verified, at_ms=at_ms)


def _parse_fields(text: str) -> dict[str, str]:
    """Split `k=v k="quoted v" k=[json,array]` into a dict.

    Tolerates truncation: iVisor cuts values at 256 bytes to keep a line inside
    PIPE_BUF, and a torn pipe can cut anywhere.
    """
    out: dict[str, str] = {}
    i, n = 0, len(text)
    while i < n:
        while i < n and text[i] == " ":
            i += 1
        start = i
        while i < n and text[i] not in "= ":
            i += 1
        if i >= n or text[i] != "=":
            break  # a bare token; nothing useful left
        key = text[start:i]
        i += 1  # past '='
        head = text[i] if i < n else ""
        if head == '"':
            value, i = _scan_quoted(text, i)
        elif head == "[":
            value, i = _scan_bracketed(text, i)
        else:
            start = i
            while i < n and text[i] != " ":
                i += 1
            value = text[start:i]
        out[key] = value
    return out


def _scan_quoted(text: str, start: int) -> tuple[str, int]:
    """Read a JSON string at `start`, returning the unescaped text."""
    i, n = start + 1, len(text)
    chunks: list[str] = []
    while i < n:
        ch = text[i]
        if ch == "\\" and i + 1 < n:
            nxt = text[i + 1]
            chunks.append(_ESCAPES.get(nxt, nxt))
            i += 2
        elif ch == '"':
            return "".join(chunks), i + 1
        else:
            chunks.append(ch)
            i += 1
    return "".join(chunks), i


def _scan_bracketed(text: str, start: int) -> tuple[str, int]:
    """Read a bracketed JSON array verbatim — callers that want structure
    re-parse it with json.loads."""
    i, n = start, len(text)
    in_string = False
    while i < n:
        ch = text[i]
        if ch == "\\" and in_string:
            i += 1
        elif ch == '"':
            in_string = not in_string
        elif ch == "]" and not in_string:
            return text[start:i + 1], i + 1
        i += 1
    return text[start:], i
