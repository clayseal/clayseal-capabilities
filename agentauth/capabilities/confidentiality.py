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
import unicodedata
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from agentauth.capabilities.parameter_provenance import ParameterProvenance

# Verbs whose RESULT moves data outward. Kept for callers that ask about the
# response rather than the request, and no longer the gate: see SOURCE_VERBS.
SINK_VERBS = frozenset({
    "write", "send", "post", "share", "create", "update", "pay",
    # These were absent while the gate was a CLOSED allowlist, so each of them
    # carried the verbatim secret out unchecked. `upload` and `publish` are not
    # exotic verbs; they are what a tool catalogue actually calls its sinks.
    "upload", "put", "email", "publish", "push", "export", "patch", "append",
    "commit", "copy", "move", "notify", "delete", "call", "invoke", "execute",
    "transfer", "sync", "deploy", "submit", "reply", "forward", "broadcast",
})

# Every call is a sink for its own ARGUMENTS, whatever its verb.
#
# This module used to check only SINK_VERBS, on the reasoning that "a read cannot
# leak". That is true of what a read returns and false of what it sends. A read's
# arguments travel to whoever serves the call: `search_web(q=<the customer's
# diagnosis>)` hands the diagnosis to the search provider, and no write ever
# happens.
#
# AgentLeak (El Yagoubi et al.) is built on exactly that premise, and it is the
# first outside corpus we have for this axis. As shipped we contained 6 of its 22
# recorded tool calls, 27.3%, and all sixteen misses were the same thing: the
# call was not a "sink verb". Treating the call's input as the sink takes it to
# 22 of 22 with no false blocks.
# Whether a call's arguments count as leaving is a PROPERTY OF THE DESTINATION,
# declared by the mandate, not a global switch.
#
# Turning it on globally takes AgentLeak from 27.3% to 100% and takes false
# positives on tau2 and BFCL from 2 of 8,040 to 99 of 17,921, a factor of
# twenty-two. The reason is not a bug: a read whose arguments carry the value the
# agent just legitimately read is ordinary work, `get_user(email=<the address
# from the record>)`, and refusing it is label creep in a new costume.
#
# So `argument_sinks` names the destinations whose INPUT leaves the boundary:
# third-party APIs, external search, anything served by someone else. A mandate
# that names none behaves exactly as before.

# Verbs that bring data in, and can therefore taint it.
#
# THIS IS ALSO THE GATE, and it used to be the other way round. The check ran
# only when the verb appeared in SINK_VERBS, so a verb nobody had thought of was
# silently exempt: `upload`, `put`, `email`, `publish`, `push` and `export` all
# carried the verbatim secret out with the reason "does not move data outward".
# A closed allowlist of the dangerous cases fails open on the case you forgot,
# which is the wrong direction for a security gate.
#
# So the default is inverted. Anything that is not recognisably a read is
# treated as a sink. The exempt set is small, closed, and each member is exempt
# because its RESULT is the data movement rather than its arguments.
#
# The arguments of a read still travel to whoever serves it, which is what
# `argument_sinks` is for, and that stays opt-in per destination because turning
# it on globally cost a factor of twenty-two in false positives.
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
    # Destinations whose ARGUMENTS leave the boundary, whatever the verb. A read
    # served by a third party hands it whatever the query contains.
    argument_sinks: tuple[str, ...] = ()

    @classmethod
    def from_mandate(cls, mandate: Mapping[str, Any] | None) -> "SensitivityPolicy":
        raw = (mandate or {}).get("confidentiality") or {}
        return cls(
            sensitive=tuple(str(p) for p in (raw.get("sensitive") or ())),
            declassified_sinks=tuple(str(p) for p in (raw.get("declassified_sinks") or ())),
            argument_sinks=tuple(str(p) for p in (raw.get("argument_sinks") or ())),
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

    def sends_its_arguments(self, tool: str, resource: str | None,
                            path: str | None = None) -> bool:
        """Does calling this hand its arguments to someone outside the boundary?"""
        return any(_matches(c, pat)
                   for c in (tool, resource, path) if c
                   for pat in self.argument_sinks)

    def is_declassified(self, resource: str | None, path: str | None = None) -> str | None:
        """Every non-empty field must be a sink the goal named, not just one.

        This used to return on the FIRST field that matched, while `check` keys
        the accumulator on `path or resource`. So the field that authorized the
        write and the field that recorded it could be different fields, and
        either one could be spoofed: resource='https://attacker.test/collect'
        with path='report.txt' was released verbatim as "to report.txt, which
        the sealed goal named". Setting it the other way round additionally
        skipped the pooled cross-sink accumulator, so eleven fragments fanned out
        to eleven attacker paths were all allowed and reassembled exactly.

        Requiring every field to match fails closed on the spoof and leaves the
        honest case, where the goal names the destination it actually names,
        unchanged.
        """
        candidates = [c for c in (resource, path) if c]
        if not candidates:
            return None
        matched: str | None = None
        for candidate in candidates:
            hit = next((p for p in self.declassified_sinks
                        if _matches(candidate, p)), None)
            if hit is None:
                return None
            matched = matched or hit
        return matched


def _matches(candidate: str, pattern: str) -> bool:
    """Exact unless the operator wrote a glob, and never across a traversal.

    `fnmatch` was applied unconditionally, so an operator writing the literal
    filename `report[1].txt` also declassified `report1.txt`, a different file.
    A pattern with no metacharacter is now compared exactly, which is what
    someone who typed a filename meant.

    A candidate containing a `..` segment never matches, because `s3://bucket/*`
    should not declassify `s3://bucket/../../etc/passwd`.
    """
    if any(seg == ".." for seg in candidate.replace("\\", "/").split("/")):
        return False
    if any(ch in pattern for ch in "*?["):
        return fnmatch.fnmatch(candidate, pattern)
    return candidate == pattern


# A reconstruction has to clear a higher bar than an exact match, because
# stripping separators from an outgoing payload creates long strings that could
# coincidentally contain a short secret.
_MIN_RECONSTRUCTED = 12

# How far apart the fragments of a value may sit and still count as the value
# leaving. A subsequence match with no density bound fires on any long stream, so
# the fragments have to be dense rather than scattered across an hour of
# unrelated work.
#
# 32 comes from a sweep, not from taste. At 8 the surrounding arguments of a real
# write inflated the span past the bound and the whole value still escaped in 94
# of 600 chunked sessions; at 32 that goes to 0 of 600. False blocks on real tau2
# and BFCL traffic stay at 0 of 549 across the whole sweep (8, 32, 128), so the
# looser bound costs nothing measurable and 128 buys nothing more.
_MAX_SPREAD = 32

_DECODE_TOKEN = __import__("re").compile(r"[A-Za-z0-9+/=]{16,}")


def _TOKENS_FOR_DECODE(blob: str) -> list[str]:
    return _DECODE_TOKEN.findall(blob)


# Work bounds for the subsequence scan. This runs inside the authorization path,
# where the rest of the stack costs 35us at the median, and the naive form is
# quadratic with a restart per occurrence of the first character: a 5,000
# character payload against a 64KB buffer did not finish in two minutes. Neither
# bound changes what is detected for realistic secrets; both stop a large payload
# from turning the check into a denial of service on itself.
_MAX_NEEDLE = 256          # longer values are matched on their first 256 chars
_MAX_STARTS = 32           # candidate start positions tried


def _subsequence_coverage(needle: str, haystack: str) -> tuple[int, int | None]:
    """How much of `needle` appears in order in `haystack`, and over what span.

    Returns (characters matched, span). Coverage rather than a yes/no match,
    because waiting for the whole value means the alarm fires on the write that
    completes it and the attacker already has all but the last fragment.

    Greedy from a bounded number of start positions, keeping the best coverage
    and the tightest span achieving it. Bounded rather than exhaustive: see the
    constants above.
    """
    if not needle or not haystack:
        return 0, None
    needle = needle[:_MAX_NEEDLE]
    best_cov = 0
    best_span: int | None = None
    first = needle[0]
    start = haystack.find(first)
    tried = 0
    while start != -1 and tried < _MAX_STARTS:
        tried += 1
        i, j = start, 0
        last = start
        while i < len(haystack) and j < len(needle):
            if haystack[i] == needle[j]:
                j += 1
                last = i
            i += 1
        span = last - start + 1
        if j > best_cov or (j == best_cov and best_span is not None and span < best_span):
            best_cov, best_span = j, span
        if best_cov == len(needle) and best_span == len(needle):
            break
        start = haystack.find(first, start + 1)
    return best_cov, best_span


# Key for the pooled, non-declassified sink history.
_POOL = "\x00pooled"


def _assemblable(target: str, blocks: Sequence[str]) -> bool:
    """Can `target` be assembled from these writes, each used at most once?

    Bounded depth-first search over which write covers which segment, and it
    replaces a greedy scan that committed to one write per segment and never
    reconsidered. Greedy is not a correct algorithm for this: a write consumed
    for a coincidental one-character match is gone when the segment that
    genuinely needed it comes up, and whether that happens depends on the order
    the writes arrived in.

    The module claimed order-independence and did not have it. Measured over 30
    shuffled arrival orders of the same fragments, greedy assembled a
    22-fragment value 3 times and an 11-fragment value 5 times. This search
    assembles both 30 times out of 30. In the live path that showed up as
    concurrency: the same fragments caught 12 times out of 12 when sent
    sequentially escaped 2 times out of 12 when sent in parallel, because
    parallel arrival is a shuffle for free.

    Two things make it cheap enough for the authorization path. The advance a
    write buys depends only on the POSITION reached, never on which writes are
    already spent, so it is computed once per position rather than once per
    search node. And the node budget is a hard ceiling, because the attacker
    chooses the block set.
    """
    advances_at: dict[int, list[tuple[int, int]]] = {}

    def advances(pos: int) -> list[tuple[int, int]]:
        got = advances_at.get(pos)
        if got is None:
            remaining = target[pos:]
            got = sorted(
                (a, i) for a, i in
                ((_longest_prefix_in(remaining, b), i) for i, b in enumerate(blocks))
                if a)
            advances_at[pos] = got
        return got

    stack: list[tuple[int, frozenset]] = [(0, frozenset())]
    seen: set[tuple[int, frozenset]] = set()
    nodes = 0
    while stack:
        pos, used = stack.pop()
        if pos >= len(target):
            return True
        state = (pos, used)
        if state in seen:
            continue
        seen.add(state)
        nodes += 1
        if nodes > _COVER_NODE_BUDGET:
            return False
        for advance, i in advances(pos):
            if i not in used:
                stack.append((pos + advance, used | {i}))
    return False


def _longest_prefix_in(needle: str, block: str) -> int:
    """Longest prefix of `needle` that appears contiguously inside `block`.

    Binary search rather than a walk down from the longest, because the property
    is monotone: if a prefix of length n is inside the block then so is every
    shorter prefix, being a substring of it. That turns 22 substring scans of a
    multi-kilobyte block into 5.
    """
    if not needle or needle[0] not in block:
        return 0
    lo, hi = 1, min(len(needle), len(block))
    while lo < hi:
        mid = (lo + hi + 1) // 2
        if needle[:mid] in block:
            lo = mid
        else:
            hi = mid - 1
    return lo


# Search nodes the cover may expand before it gives up. An attacker chooses the
# block set, so this has to be a hard bound rather than a hope. Measured: a
# genuine 22-fragment cover peaks at 915 nodes, and the worst case that finds
# nothing costs 14.8ms against 512 blocks of 5.4KB each.
_COVER_NODE_BUDGET = 2000


def _compact(text: str) -> str:
    """Alphanumerics only. Separators are how a split value hides."""
    return "".join(ch for ch in text if ch.isalnum())


# Latin lookalikes from Cyrillic, Greek and the Bengali digits, which is what a
# homoglyph substitution actually reaches for. NFKC does not fold these, because
# they are genuinely different characters; for THIS purpose they are the same
# character wearing a hat.
_CONFUSABLES = str.maketrans({
    "А": "A", "В": "B", "С": "C", "Е": "E", "Н": "H", "І": "I", "Ј": "J",
    "К": "K", "М": "M", "О": "O", "Р": "P", "Ѕ": "S", "Т": "T", "Х": "X",
    "а": "a", "с": "c", "е": "e", "і": "i", "ј": "j", "о": "o", "р": "p",
    "ѕ": "s", "х": "x", "у": "y", "Υ": "Y", "Ζ": "Z", "Ν": "N", "Ρ": "P",
    "Α": "A", "Β": "B", "Ε": "E", "Η": "H", "Ι": "I", "Κ": "K", "Μ": "M",
    "Ο": "O", "Τ": "T", "Χ": "X", "ο": "o", "ν": "v", "৪": "8", "০": "0",
})


def _fold(text: str) -> str:
    """One canonical spelling, so a cosmetic change is not a new string.

    Case-folding is here because a single `.lower()` defeated the whole
    single-write reconstruction pass. The compact form is already lossy, so
    folding costs nothing that was being relied on.
    """
    return unicodedata.normalize("NFKC", text).translate(_CONFUSABLES).casefold()


def _compact_fold(text: str) -> str:
    return "".join(ch for ch in _fold(text) if ch.isalnum())


def _rot13(text: str) -> str:
    out = []
    for ch in text:
        if "a" <= ch <= "z":
            out.append(chr((ord(ch) - 97 + 13) % 26 + 97))
        elif "A" <= ch <= "Z":
            out.append(chr((ord(ch) - 65 + 13) % 26 + 65))
        else:
            out.append(ch)
    return "".join(out)


_OPAQUE = __import__("re").compile(r"\S{16,}")
_DECIMAL_RUN = __import__("re").compile(r"(?:\b\d{1,3}\b[ ,]+){11,}\b\d{1,3}\b")
_MAX_DECODE_TOKENS = 8


def _decode_layer(blob: str) -> list[str]:
    """One round of every mechanical decoding, tried and discarded on failure.

    Decoded rather than pattern-matched, so a false positive would need the
    payload to actually decode to the sensitive value.
    """
    import base64
    import binascii
    import gzip
    import zlib

    out: list[str] = []
    if "\\" in blob:
        try:
            unescaped = blob.encode("utf-8", "ignore").decode("unicode_escape")
            if unescaped != blob:
                out.append(unescaped)
        except (UnicodeDecodeError, ValueError):
            pass
    if "%" in blob:
        from urllib.parse import unquote
        try:
            out.append(unquote(blob))
        except (UnicodeDecodeError, ValueError):
            pass
    for run in _DECIMAL_RUN.findall(blob)[:4]:
        try:
            out.append("".join(chr(int(n)) for n in run.replace(",", " ").split()
                               if 0 < int(n) < 0x110000))
        except ValueError:
            pass
    # Ordered strictest-first and stopped at the first success, because base85
    # accepts nearly any byte string and would otherwise turn every opaque token
    # into noise. This runs inside the authorization path, so the bound matters
    # as much as the coverage.
    for chunk in _OPAQUE.findall(blob)[:_MAX_DECODE_TOKENS]:
        for attempt in (
            lambda c: bytes.fromhex(c),
            lambda c: base64.b32decode(c + "=" * (-len(c) % 8), casefold=True),
            lambda c: base64.b64decode(c + "=" * (-len(c) % 4), validate=True),
            lambda c: base64.urlsafe_b64decode(c + "=" * (-len(c) % 4)),
            lambda c: base64.b85decode(c),
        ):
            try:
                raw = attempt(chunk)
            except (binascii.Error, ValueError, TypeError):
                continue
            if not raw:
                continue
            out.append(raw.decode("utf-8", "ignore"))
            # Magic bytes rather than try-everything: gzip is 1f 8b and a zlib
            # stream starts 78 01/9c/da. Guessing costs a decompress per token.
            if raw[:2] == b"\x1f\x8b":
                try:
                    out.append(gzip.decompress(raw).decode("utf-8", "ignore"))
                except (OSError, zlib.error, ValueError):
                    pass
            elif raw[:1] == b"\x78":
                try:
                    out.append(zlib.decompress(raw).decode("utf-8", "ignore"))
                except (OSError, zlib.error, ValueError):
                    pass
            break
    return [o for o in out if o]


# Renderings kept per write. Each one is searched by the block cover, so this is
# a direct multiplier on the cost of the authorization path.
_MAX_VARIANTS = 8


def _join(variants: Sequence[str]) -> str:
    """One write's spellings as one searchable string.

    The separator is non-alphanumeric and sensitive targets are compacted to
    alphanumerics, so no match can span two spellings.
    """
    return "\x00".join(variants)
# Total characters kept across a write's renderings.
_MAX_VARIANT_CHARS = 8192


def _variants(blob: str) -> tuple[str, ...]:
    """Every spelling of this payload we are willing to call the same payload.

    The FIRST element is the plain compacted form, which is what accumulates as
    the sink's stream. The rest are alternative renderings of the SAME write.

    This exists because normalisation used to happen only for a single write,
    against the raw blob, while the cross-write accumulators matched raw text.
    So encoding each FRAGMENT separately walked the whole value out at every
    chunk width and every fan-out width: the fragments never matched raw, and no
    single write held enough to normalise. Normalising per write BEFORE
    accumulating closes that, because the accumulator then compares fragments in
    the same space the single-write pass uses.

    What is still open, and named rather than implied: keyed transforms (a
    Caesar shift, digitwise arithmetic, anything with a secret), encryption, and
    paraphrase. Those need the key or the semantics, and no taint system has
    them. The set below is a lower bound on evasion, not a closed list.
    """
    if not blob:
        return ()
    seen: dict[str, None] = {}
    decoded = _decode_layer(blob)
    # One further round, which is what catches double base64 and base64-of-hex.
    decoded += [d for c in decoded[:4] for d in _decode_layer(c)]
    budget = _MAX_VARIANT_CHARS
    for form in [blob, blob[::-1], _rot13(blob), *decoded]:
        compact = _compact_fold(form)
        if compact and compact not in seen:
            seen[compact] = None
            budget -= len(compact)
        if len(seen) >= _MAX_VARIANTS or budget <= 0:
            break
    return tuple(seen)


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
    # sink -> the alphanumeric content ALLOWED out to it this session.
    #
    # Without this, splitting a secret across two writes defeated the whole
    # mechanism. Each fragment sits below the reconstruction floor and no single
    # write carries the value, so a per-write check sees nothing: measured, two
    # writes was enough, and one character per write also walked straight out.
    #
    # That is the seam between the volume axis and the sequence axis. Velocity
    # does not see it because a handful of writes is not a burst; flow control
    # did not see it because no write carried the value. Accumulating per sink
    # closes the seam, and only ALLOWED content accumulates, because a refused
    # write never happened.
    _emitted: dict[str, str] = field(default_factory=dict)
    # The same content kept as the individual write payloads rather than one
    # concatenation, because ORDER was doing the work and an attacker chooses it.
    #
    # Subsequence matching over a concatenated stream requires the fragments to
    # arrive in order. Sending them reversed escaped at every width, and shuffled
    # escaped from eleven fragments up. Each write is a contiguous piece of the
    # value, so the value is assemblable from the pieces in SOME order, and that
    # is the question to ask.
    _blocks: dict[str, list[str]] = field(default_factory=dict)
    max_blocks: int = 512
    # The same content again, pooled across EVERY non-declassified sink.
    #
    # A per-sink buffer is defeated by fanning out: one fragment to each of
    # twenty-two attacker addresses reassembles perfectly and each sink sees a
    # single character. Measured, and it walked the whole secret out at every
    # fan-out width. An attacker controls every sink they send to, so the pool of
    # sinks the goal did not name is one adversary and is accumulated as one.
    _emitted_pooled: str = ""
    # Bound on retained content per sink. A session that writes for hours must
    # not grow without limit inside the authorization path.
    max_emitted_chars: int = 65536
    # How much of a sensitive value has to reach a sink before the flow counts as
    # having happened. At 1.0 the alarm fires on the write that COMPLETES the
    # value, and the attacker already has everything but the last fragment: 21 of
    # 22 characters when the secret is dripped one character per write. That is
    # detection, not prevention.
    #
    # Below 1.0 the check trips early and the blast radius shrinks. It is set
    # from measurement rather than taste: subsequence matching flags 1 of 6,728
    # real benign writes across tau2 and BFCL even with deliberately awkward
    # secrets (common words, bare digits, short ids), so there is room to be
    # aggressive. See benchmarks/results/flow.md for the curve.
    leak_fraction: float = 0.5
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
        """May this action carry what it is carrying, to where it is going?

        The whole body runs under ONE acquisition of the tracker lock. It used
        to read the accumulated history under the lock, release it, do all the
        matching, then commit under the lock again using the values it had read.
        That is a lost update, and it is not a narrow race: concurrent writers
        each read the same empty history, each saw only its own fragment, each
        allowed it, and the commits clobbered one another. Eleven fragments of a
        22-character key issued in parallel reassembled in 9 of 12 trials, where
        the same fragments sent sequentially escaped in 0 of 12.

        `_lock` is an RLock and the helpers below take it re-entrantly, so
        holding it here costs an uncontended re-acquisition rather than a
        redesign.
        """
        if not policy.active:
            return FlowVerdict(True, "no confidentiality policy declared")
        if (verb in SOURCE_VERBS
                and not policy.sends_its_arguments(tool, resource, path)):
            return FlowVerdict(
                True,
                f"{verb!r} only brings data in, and {resource!r} is not "
                f"declared an argument sink")

        with self._lock:
            return self._check_locked(resource=resource, args=args,
                                      policy=policy, path=path)

    def _check_locked(self, *, resource: str, args: Any,
                      policy: SensitivityPolicy, path: str | None) -> FlowVerdict:
        # Judged against everything this sink has already received PLUS this
        # write, so a value assembled across several writes is caught on the one
        # that completes it.
        variants = _variants(_flatten(args))
        candidate = variants[0] if variants else ""
        sink_key = path or resource
        declassified = policy.is_declassified(resource, path)
        history = self._emitted.get(sink_key, "")
        pooled = self._emitted_pooled

        carried = self._carried(args)
        if not carried and candidate:
            carried = self._carried_across_writes(history + candidate)
        # Then against every sink the goal did not name, pooled. Skipped for a
        # declassified sink, whose traffic is authorized and must not make later
        # unrelated writes look like a leak.
        if not carried and candidate and declassified is None:
            carried = self._carried_across_writes(pooled + candidate)
        # Finally, order-independently: can the value be ASSEMBLED from the
        # pieces this sink received, in any order?
        #
        # For a non-declassified sink the pool is used ALONE. It is a superset
        # of that sink's own history, and adding both put every same-sink write
        # into the cover pool twice, which defeated the `pool.pop` that stops one
        # write from covering two segments of the value.
        if not carried and variants:
            blocks = list(self._blocks.get(_POOL if declassified is None
                                           else sink_key, ()))
            carried = self._carried_from_blocks(blocks + [_join(variants)])

        if not carried:
            self._emitted[sink_key] = (
                history + candidate)[-self.max_emitted_chars:]
            if variants:
                self._blocks.setdefault(sink_key, []).append(_join(variants))
                del self._blocks[sink_key][:-self.max_blocks]
            if declassified is None:
                self._emitted_pooled = (
                    pooled + candidate)[-self.max_emitted_chars:]
                if variants:
                    self._blocks.setdefault(_POOL, []).append(_join(variants))
                    del self._blocks[_POOL][:-self.max_blocks]
            return FlowVerdict(True, "carries no value from a sensitive read")

        # A sink the sealed goal named is authorized to receive this.
        if declassified is not None:
            return FlowVerdict(
                True, f"sensitive data to {declassified}, which the sealed goal named",
                tuple(sorted(carried)), declassified)

        # The destination is legitimate for this task and the DATA is not. The
        # write is refused, so its content does not join the sink's history.
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

    def _carried_from_blocks(self, blocks: list[str]) -> set[str]:
        """Can a sensitive value be assembled from these pieces, in ANY order?

        Each write contributes a contiguous piece of whatever it carried, so a
        value split across writes is assemblable from the pieces regardless of
        the order they were sent in. Greedy cover: repeatedly take the block that
        matches the longest prefix of what is still unassembled.

        This is what closes the order hole. Subsequence matching over the
        concatenated stream asked whether the value arrived in order, and an
        attacker picks the order: reversed escaped at every width, shuffled from
        eleven fragments up, both with zero refusals.
        """
        if not blocks:
            return set()
        with self._lock:
            tokens = list(self._sensitive_tokens.items())
        found: set[str] = set()
        for token, origins in tokens:
            target = _compact_fold(token)
            if len(target) < _MIN_RECONSTRUCTED:
                continue
            if _assemblable(target, blocks):
                found |= origins
        return found

    def _carried_across_writes(self, stream: str) -> set[str]:
        """Has this sink received the whole value, spread over several writes?

        Concatenating the stream and substring-matching does not work: an agent
        that puts a word of filler between fragments breaks contiguity, and the
        cheapest split (two writes) already defeats a per-write check.

        So the test is whether the value appears as a SUBSEQUENCE of everything
        this sink has received, which survives filler, reordering of surrounding
        text, and one character per write.

        A subsequence match on its own would fire constantly: any short string
        appears as a subsequence of enough text. Two bounds make it evidence.
        The value must be at least `_MIN_RECONSTRUCTED` characters, and the SPAN
        of stream it is found in must be at most `_MAX_SPREAD` times its length,
        so the fragments have to be dense rather than scattered across an hour of
        unrelated work. Both are measured against real tau2 and BFCL traffic in
        benchmarks/results/flow.md rather than assumed.
        """
        if not stream:
            return set()
        with self._lock:
            tokens = list(self._sensitive_tokens.items())
        found: set[str] = set()
        for token, origins in tokens:
            compact_token = _compact_fold(token)
            if len(compact_token) < _MIN_RECONSTRUCTED:
                continue
            target = min(len(compact_token), _MAX_NEEDLE)
            covered, span = _subsequence_coverage(compact_token, stream)
            if covered < _MIN_RECONSTRUCTED:
                continue
            if covered / target < self.leak_fraction:
                continue
            # The density bound guards PARTIAL matches, where a scattered
            # coincidence is plausible. A COMPLETE in-order match of a token of
            # twelve characters or more is not coincidence at any span, and
            # holding it to the bound is what let BFCL's larger write arguments
            # inflate the span until the whole value escaped in 45 of 91 chunked
            # sessions. Measured: exempting complete matches takes that to 0 of
            # 91 with false blocks on real traffic unchanged at 0.
            complete = covered >= target
            if complete or (span is not None and span <= _MAX_SPREAD * covered):
                found |= origins
        return found

    def _carried_after_normalisation(self, args: Any) -> set[str]:
        """Does any spelling of this payload contain a sensitive value?

        `_variants` does the work. What is here is the comparison, folded on both
        sides, because a single `.lower()` used to defeat this pass entirely.

        The dividing line the module claims is "mechanical transform with a
        mechanical inverse is handled, semantics is not", and the implementation
        used to violate it: rot13, base32, base85, gzip, and case are all
        mechanical and all walked straight out. They are handled now. What
        remains open is named in `_variants` and in flow.md rather than implied
        by a list of eight fixed cases.
        """
        blob = args if isinstance(args, str) else _flatten(args)
        variants = _variants(blob)
        if not variants:
            return set()
        with self._lock:
            found: set[str] = set()
            for token, origins in self._sensitive_tokens.items():
                if len(token) < _MIN_RECONSTRUCTED:
                    continue
                compact_token = _compact_fold(token)
                folded = _fold(token)
                if not compact_token:
                    continue
                for cand in variants:
                    if compact_token in cand or folded in cand:
                        found |= origins
                        break
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
