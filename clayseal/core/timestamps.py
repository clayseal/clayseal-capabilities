"""One ISO 8601 parser, because `Z` is not optional in the wild.

`datetime.fromisoformat` did not accept a trailing `Z` until Python 3.11, and
this package supports 3.10. Every timestamp this library reads — a mandate
expiry, a delegation expiry, a step-up deadline, a policy document's
`expires_at` — is written by somebody else, and RFC 3339 spells UTC as `Z`. The
README's own example policy says `expires_at: 2027-12-31T00:00:00Z`.

What that cost, before this module existed: on Python 3.10 the parse raised, and
`TaskScope.is_expired` treats an unparseable expiry as EXPIRED — correctly, since
a grant whose validity cannot be established is not a valid grant. So every
policy with a `Z` expiry denied every call, on a version the distribution
advertises and CI tests. The failure was safe and total: the gateway refused
everything rather than allowing anything, which is why it survived so long
without being noticed as a security issue. It was a usability catastrophe
instead.

Nine call sites read timestamps. Exactly one of them knew about `Z` and carried
its own `.replace("Z", "+00:00")`. That is the shape this repository keeps
finding: one question, several implementations, and the ones that did not know
were the ones that broke. There is one implementation now.
"""
from __future__ import annotations

from datetime import datetime, timezone


def parse_iso8601(value: str | datetime) -> datetime:
    """Parse an ISO 8601 / RFC 3339 timestamp, including a trailing `Z`.

    Raises `ValueError` on anything unparseable, exactly as
    `datetime.fromisoformat` does, so a caller that already handles that keeps
    handling it.
    """
    if isinstance(value, datetime):
        return value
    text = str(value).strip()
    # `Z` is RFC 3339's UTC designator. `fromisoformat` learned it in 3.11;
    # rewriting it here means one behaviour on every supported version rather
    # than a parser that is stricter on the oldest one.
    if text.endswith(("Z", "z")):
        text = text[:-1] + "+00:00"
    return datetime.fromisoformat(text)


def parse_iso8601_utc(value: str | datetime) -> datetime:
    """`parse_iso8601`, with a naive result read as UTC.

    A timestamp with no offset is ambiguous, and the only safe reading for an
    expiry is the one that does not silently extend it by the local offset.
    Callers comparing against `datetime.now(timezone.utc)` need both sides aware.
    """
    parsed = parse_iso8601(value)
    return parsed.replace(tzinfo=timezone.utc) if parsed.tzinfo is None else parsed
