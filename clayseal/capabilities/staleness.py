"""Observation freshness: harm defined by the STATE the action was justified by.

## The gap this closes

Our measurement splits agent harm by what defines it, and four axes are already
characterised (`benchmarks/results/four_axes.md`).

**Target.** The action points somewhere it must not. Scope and binding contain
essentially all of it.

**Volume.** Each action is authorized and there are far too many. Velocity
contains bursts of ten or more with a blast radius of four.

**Sequence.** An authorized read followed by an authorized write of what it read.
`confidentiality.py` contains it per value.

**Content.** The action's *meaning* is the harm. Nobody contains this.

There is a fifth, and it is the one this module is for. **State.** The action was
authorized against what the agent read at step 3 and executes at step 20, after
the world moved. Approve invoice 41; invoice 41 is edited; the approval lands on
the new contents. Book the flight quoted at 200; the price is now 2,000. Transfer
to an account that was frozen after it was read.

Semantic time-of-check to time-of-use. Every field of the action is authorized
and correct. What is wrong is that the *justification* is stale, and the
justification is not part of the action, so no function of the action alone can
see it. That is not a hyperbole: in the benchmark's control pair the stale action
and the legitimate action are byte-identical, so scope, binding, budgets,
velocity and flow control necessarily return the same answer for both.

## Why this is decidable without a model

The justification for an action is an observation, and an observation has a
version. Staleness is then a comparison, not a judgement. Three definitions of
version, in decreasing order of strength, and none of them is a timer:

1. an explicit version, etag or generation counter the source supplied;
2. a re-read whose content digest differs;
3. an effect this session performed on the same object, which moves it by
   definition.

A timer would be the wrong shape. A five-second-old observation of a hot ledger
is stale and a five-day-old observation of an archived record is not; age is a
proxy for change and change is directly observable.

## The two rules, and what each costs

**Value staleness (free).** An argument carries a token that only a *superseded*
observation ever supplied. The agent re-read the object, or wrote to it, and then
acted on the copy it took before. This needs no extra traffic: every observation
it compares was already in the session.

**Object staleness (costs a re-read).** The agent's latest view of an object it
is about to act on no longer matches the world. Nothing in the session can reveal
this, because by construction nobody looked. The only way to know is to look, so
the layer re-reads the justifying observation before the action and compares.

The second rule is the one that catches the classic TOCTOU, and it is not free.
`benchmarks/state.py` measures exactly how many extra reads it costs on real
tau2 and BFCL traffic, because "double your tool calls" and "one extra read on
2% of actions" are different products.

## What it will not do

**An observation the mandate did not declare volatile is not tracked.** Which
objects can move under the agent comes from the mandate, exactly as the sensitive
set does for flow control. Absent policy means no staleness checking, so a
mandate written before this module behaves exactly as it did.

**A value the agent paraphrases is gone.** Attribution is by token, inherited
from `parameter_provenance`, so an agent that describes the old contents instead
of quoting them is not attributable. Same standing limit as every taint system,
and it is measured rather than assumed.

**Revalidation is only as good as the re-read.** If the re-read is served from
the same cache the first read was, the version will not move and the check will
pass. That is a property of the tool, not of this module.
"""
from __future__ import annotations

import fnmatch
import hashlib
import threading
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Any

from clayseal.capabilities.parameter_provenance import ParameterProvenance
from clayseal.capabilities.velocity import EFFECT_VERBS

# Verbs that act on the world, and are therefore the ones whose justification has
# to still be true. Deliberately the same set velocity uses: a rung that disagreed
# with velocity about what counts as an effect would leave a hole between them.
CONSEQUENTIAL_VERBS = EFFECT_VERBS

# Verbs that acquire an observation.
OBSERVING_VERBS = frozenset({"read", "search", "list", "get", "query"})


def _matches(candidate: str, pattern: str) -> bool:
    return fnmatch.fnmatch(candidate, pattern) or candidate == pattern


@dataclass(frozen=True)
class StalenessPolicy:
    """Which objects can move under the agent, and whether to go and look.

    Both come from the mandate. Nothing is inferred at runtime, because a policy
    an attacker can influence is not a policy: an injected instruction that could
    declare an object non-volatile would turn the check off.
    """

    # Glob patterns over resource identifiers or paths. An object matching none
    # of these is assumed stable, and this module says nothing about it.
    volatile: tuple[str, ...] = ()
    # Re-read a justifying observation before acting on it. This is the operating
    # point that costs tool calls, and it is the one that catches a change nobody
    # in the session observed. Off by default: the free rule still applies.
    revalidate: bool = False
    # Treat the session's own effects on an object as superseding earlier views
    # of it. Free, and it is the third definition of staleness: an object this
    # agent just wrote to is not the object it read. Separable from the rest
    # because it is the one rule with a plausible cost on ordinary traffic, an
    # agent that edits a record and then uses a field it read beforehand is
    # doing something a strict reading calls stale, and `benchmarks/state.py`
    # measures what that reading costs instead of assuming it is free.
    effects_supersede: bool = True
    # Compare values with separators, case and surrounding prose stripped.
    # Exact matching is exact, and the evasion sweep in `benchmarks/state.py`
    # showed every mechanical restatement of a stale value walking straight past
    # it. Separable so the sweep can report the profile with and without.
    normalise: bool = True

    @classmethod
    def from_mandate(cls, mandate: Mapping[str, Any] | None) -> StalenessPolicy:
        raw = (mandate or {}).get("freshness") or {}
        return cls(
            volatile=tuple(str(p) for p in (raw.get("volatile") or ())),
            revalidate=bool(raw.get("revalidate", False)),
            effects_supersede=bool(raw.get("effects_supersede", True)),
            normalise=bool(raw.get("normalise", True)),
        )

    @property
    def active(self) -> bool:
        """Absent policy means no staleness checking, so adding this module
        changes nothing for a mandate written before it existed."""
        return bool(self.volatile)

    def is_volatile(self, resource: str | None, path: str | None = None) -> bool:
        return any(_matches(c, pat)
                   for c in (resource, path) if c
                   for pat in self.volatile)


@dataclass(frozen=True)
class StaleVerdict:
    allowed: bool
    reason: str
    # Objects whose observed version no longer matches what the agent acted on.
    stale: tuple[str, ...] = ()
    # Objects whose observations supplied this action's arguments.
    justified_by: tuple[str, ...] = ()
    # Re-reads this decision required. The cost, per decision, so a deployment
    # can add it up rather than take a claim about it.
    revalidations: int = 0


@dataclass(frozen=True)
class _Observation:
    key: str
    version: str
    # Whether the version came from the source (etag, generation counter) or was
    # derived from the payload. Derived versions are weaker: a source that
    # returns fields in a different order every call would look like it moved.
    explicit: bool
    seq: int


# Bounded traversal, for the same reason `parameter_provenance` bounds its
# tokenizer: attacker-shaped tool output reaches `observe`, and a deeply nested
# or self-referential payload raised RecursionError INSIDE the authorization
# path, which is a denial of service on the thing that decides whether actions
# are allowed. Found by a test written against this module, not in production.
#
# A payload we cannot fully walk yields a shorter flattening, which produces a
# version that is stable for identical content and differs when the walkable part
# differs. It cannot make a moved object look unmoved unless the change is
# entirely below the depth bound, and 24 levels of nesting is far past any real
# record.
_MAX_FLATTEN_DEPTH = 24


def _flatten(value: Any, *, _depth: int = 0, _seen: frozenset[int] = frozenset()) -> str:
    if value is None or _depth > _MAX_FLATTEN_DEPTH:
        return ""
    if isinstance(value, (Mapping, list, tuple, set, frozenset)):
        marker = id(value)
        if marker in _seen:
            return ""
        seen = _seen | {marker}
        nest = {"_depth": _depth + 1, "_seen": seen}
        if isinstance(value, Mapping):
            return "|".join(f"{k}={_flatten(v, **nest)}" for k, v in sorted(
                value.items(), key=lambda kv: str(kv[0])))
        if isinstance(value, (set, frozenset)):
            return "|".join(sorted(_flatten(v, **nest) for v in value))
        return "|".join(_flatten(v, **nest) for v in value)
    return str(value)


def _digest(*parts: Any) -> str:
    h = hashlib.sha256()
    for part in parts:
        h.update(_flatten(part).encode("utf-8", "replace"))
        h.update(b"\x1f")
    return h.hexdigest()[:16]


# A named field only carries evidence when its value is specific enough to be
# worth comparing. An empty string, a bare flag or a single digit appears in
# every record; treating those as attributable would let one object's version
# govern every action that happens to say `status=1`.
_MIN_FIELD_VALUE = 3


def _field_slots(name: Any, value: Any) -> list[tuple[str, str]]:
    """The (field, value) slots a named field occupies.

    Scalars only, and deliberately not recursive: a nested structure's fields
    belong to the nested object, and flattening them would attribute a value to
    the wrong thing.
    """
    if not isinstance(value, (str, int, float)) or isinstance(value, bool):
        return []
    text = str(value).strip()
    if len(text) < _MIN_FIELD_VALUE:
        return []
    return [(str(name), text)]


# Floor for a NORMALISED match, which is looser than an exact one: stripping
# separators out of ordinary text makes long strings, and a short value could
# appear inside one by coincidence. Same reasoning and the same direction as the
# reconstruction floor in `confidentiality.py`, which the flow benchmark set by
# measurement.
_MIN_NORMALISED = 8

# Work bound. This runs inside the authorization path, and the substring scan is
# linear in the index; a session that reads for an hour must not turn the check
# into a denial of service on itself.
_MAX_SCAN = 4096


def _normalise(text: Any) -> str:
    return "".join(ch for ch in str(text).lower() if ch.isalnum())


def content_version(payload: Any,
                    structured_fields: Mapping[str, Any] | None = None) -> str:
    """The version a re-read of this content would produce.

    Exported because a revalidation hook has to compute the same thing the
    ledger computed, and a hook that hashed differently would report every
    object as moved. This is definition (2): no etag, so the content is the
    version.
    """
    return _digest(payload, structured_fields)


@dataclass
class ObservationLedger:
    """What this session observed, at which version, and what it is still true of.

    Built on `ParameterProvenance` rather than beside it: the tokenizer, the
    edge-trimming and the observation record are the ones already wired into the
    live path, and every observation recorded here is also recorded there, so the
    egress and envelope layers see exactly what they saw before. What this adds
    is the version dimension that provenance does not carry, provenance answers
    *which tool supplied this value*, and staleness needs *which version of which
    object supplied it, and is that version still current*.
    """

    provenance: ParameterProvenance = field(default_factory=ParameterProvenance)
    # object key -> the agent's most recent observation of it.
    _current: dict[str, _Observation] = field(default_factory=dict)
    # token -> the (key, version) pairs that supplied it. A value that appeared
    # in v1 and again in v2 has two suppliers, and only one of them is stale.
    _suppliers: dict[str, set[tuple[str, str]]] = field(default_factory=dict)
    # (field name, value) -> the same, for values with no attributable token.
    #
    # Found by measurement, not by review. Token attribution missed 5 of 56
    # value-staleness cases on tau2 and every one of them was a short-worded
    # field: `city='New York'`, `address2='Suite 394'`, `address1='445 Maple
    # Drive'`. No run of six characters, so `parameter_provenance` has nothing to
    # index and a stale delivery address is invisible. Lowering the attribution
    # floor is not the fix: it is 6 precisely because shorter strings appear
    # everywhere, but a value that arrives in a NAMED field carries the name as
    # extra evidence, and `city` plus `New York` is specific where `New York`
    # alone is not.
    #
    # It requires the observation and the action to agree on the field name,
    # which they do when the action re-submits a record's own fields, which is
    # the shape this axis is about. A rename between the two schemas defeats it,
    # and that limit is published rather than papered over.
    _field_suppliers: dict[tuple[str, str], set[tuple[str, str]]] = field(
        default_factory=dict)
    # The same two indexes over normalised values: lowercase alphanumerics only.
    _norm_suppliers: dict[str, set[tuple[str, str]]] = field(default_factory=dict)
    _norm_field_suppliers: dict[tuple[str, str], set[tuple[str, str]]] = field(
        default_factory=dict)
    _seq: int = 0
    _revalidations: int = 0
    _lock: Any = field(default_factory=threading.RLock, repr=False, compare=False)

    # ----------------------------------------------------------------- #
    # Observing
    # ----------------------------------------------------------------- #
    def observe(self, tool: str, resource: str, payload: Any, *,
                policy: StalenessPolicy, path: str | None = None,
                structured_fields: Mapping[str, Any] | None = None,
                version: str | None = None) -> None:
        """Record what this observation returned, and at what version.

        A re-read that returns the same version does NOT supersede anything.
        That is the difference between "the object was looked at again" and "the
        object changed", and getting it wrong would refuse an agent that
        double-checks its work.
        """
        self.provenance.record_observation(
            tool, payload, structured_fields=structured_fields)
        key = path or resource
        if not policy.is_volatile(resource, path):
            return
        explicit = version is not None
        stamp = version if explicit else _digest(payload, structured_fields)
        with self._lock:
            self._seq += 1
            previous = self._current.get(key)
            if previous is not None and previous.version == stamp:
                # Nothing moved. Keep the earlier sequence number so the object's
                # history reflects changes rather than glances.
                self._index(key, stamp, payload, structured_fields)
                return
            self._current[key] = _Observation(key, stamp, explicit, self._seq)
            self._index(key, stamp, payload, structured_fields)

    def record_effect(self, tool: str, resource: str, args: Any, *,
                      policy: StalenessPolicy, path: str | None = None) -> None:
        """The session changed this object, so every earlier view of it is old.

        An agent's own write is knowledge of the new state, not ignorance of it,
        so this installs a fresh observation carrying what the write supplied
        rather than only invalidating. Without that, an agent that writes a file
        and then copies it would be refused for acting on its own work, which is
        ordinary and correct.

        It is an approximation and worth naming: the agent knows what it put
        there and nothing else about the object's new state.

        An effect on an object this session never observed is ignored. There is
        no justification to be stale, because the agent never looked, and
        installing one would invent a version nobody compared against. Measured
        cost of getting this wrong: on tau2 an earlier revision let a blind write
        create an object out of whatever token sorted first in its arguments, so
        `modify_user_address(address1='101 Highway', ...)` created an object
        called `Highway`, and the customer's second address change was then
        refused for carrying a user id whose only supplier was that phantom. Two
        of three false blocks on the whole corpus came from it.
        """
        key = path or resource
        if not policy.is_volatile(resource, path) or not policy.effects_supersede:
            return
        with self._lock:
            if key not in self._current:
                return
            self._seq += 1
            previous = self._current.get(key)
            stamp = _digest("effect", tool, args, previous.version if previous else "",
                            self._seq)
            self._current[key] = _Observation(key, stamp, False, self._seq)
            # The write's arguments are named fields, and they are the agent's
            # knowledge of the object's new state, so they index as both. Without
            # the field half here, an agent that edits a record and then submits a
            # field it wrote is refused for carrying a value whose only supplier
            # was superseded by its own write.
            self._index(key, stamp, args, args if isinstance(args, Mapping) else None)

    def _index(self, key: str, version: str, payload: Any,
               structured_fields: Mapping[str, Any] | None) -> None:
        for source in (payload, structured_fields):
            for token in ParameterProvenance._tokens(source):
                self._suppliers.setdefault(token, set()).add((key, version))
                normal = _normalise(token)
                if len(normal) >= _MIN_NORMALISED:
                    self._norm_suppliers.setdefault(normal, set()).add((key, version))
        for name, value in (structured_fields or {}).items():
            for slot in _field_slots(name, value):
                self._field_suppliers.setdefault(slot, set()).add((key, version))
                normal = _normalise(slot[1])
                if len(normal) >= _MIN_FIELD_VALUE:
                    self._norm_field_suppliers.setdefault(
                        (slot[0], normal), set()).add((key, version))

    def _all_superseded(self, suppliers: set[tuple[str, str]] | None) -> str | None:
        """The object to blame when EVERY tracked view that supplied a value is old.

        "Every", not "any": a value that also appears in the current view is
        current, which is what lets an agent re-read an object and then resubmit
        the fields that did not change. Caller holds the lock.
        """
        if not suppliers:
            return None
        tracked = [(k, v) for k, v in suppliers if k in self._current]
        if not tracked:
            return None
        if any(self._current[k].version == v for k, v in tracked):
            return None
        return min(k for k, _ in tracked)

    # ----------------------------------------------------------------- #
    # Deciding
    # ----------------------------------------------------------------- #
    def check(self, *, tool: str, verb: str, resource: str, args: Any,
              policy: StalenessPolicy, path: str | None = None,
              revalidate: Callable[[str], str | None] | None = None
              ) -> StaleVerdict:
        """Is the justification for this action still true?"""
        if not policy.active:
            return StaleVerdict(True, "no freshness policy declared")
        if verb not in CONSEQUENTIAL_VERBS:
            return StaleVerdict(True, f"{verb!r} does not act on the world")

        tokens = ParameterProvenance._tokens(args)
        slots = [slot for name, value in (args or {}).items()
                 for slot in _field_slots(name, value)] \
            if isinstance(args, Mapping) else []
        with self._lock:
            justified: set[str] = set()
            for token in tokens:
                for key, _version in self._suppliers.get(token, ()):
                    justified.add(key)
            for slot in slots:
                for key, _version in self._field_suppliers.get(slot, ()):
                    justified.add(key)
            # The object the action targets, when the session has a view of it.
            # This is the `approve(invoice_id=41)` shape, where the arguments name
            # the object and the justification is its contents.
            target = path or resource
            if target in self._current:
                justified.add(target)

            if not justified:
                # Nothing this session observed supplied any part of the action.
                # A session-level "the world moved" tracker refuses here, which
                # is the label-creep failure that keeps such trackers out of
                # production. See the unrelated-mutation arm of benchmarks/state.py.
                return StaleVerdict(
                    True, "no tracked observation justified this action")

            # ---- Rule 1: value staleness. Free, and needs no re-read. ----
            #
            # A part of the action is stale when EVERY tracked observation that
            # ever supplied it has since been superseded. "Every", not "any": a
            # value that also appears in the current view is current, which is
            # what lets an agent re-read and then resubmit the fields that did
            # not change.
            probes: list[tuple[Any, dict]] = [(tokens, self._suppliers),
                                              (slots, self._field_suppliers)]
            if policy.normalise:
                probes.append((
                    [_normalise(t) for t in tokens], self._norm_suppliers))
                probes.append((
                    [(n, _normalise(v)) for n, v in slots],
                    self._norm_field_suppliers))
            for probe, index in probes:
                for item in probe:
                    stale_key = self._all_superseded(index.get(item))
                    if stale_key is None:
                        continue
                    shown = item if isinstance(item, str) else f"{item[0]}={item[1]!r}"
                    return StaleVerdict(
                        False,
                        f"{shown} came from a view of {stale_key!r} this session "
                        f"has already superseded; the action carries a value the "
                        f"agent knows is out of date",
                        stale=(stale_key,), justified_by=tuple(sorted(justified)))

            # The same test one level looser: the stale value restated inside a
            # longer argument. Exact matching cannot see `"as previously
            # recorded, credit_card_2408938, unchanged"`, and the evasion sweep
            # found that every mechanical restatement escaped without this.
            if policy.normalise:
                blob = _normalise(_flatten(args))[:_MAX_SCAN]
                if blob:
                    for value, suppliers in self._norm_suppliers.items():
                        if len(value) < _MIN_NORMALISED or value not in blob:
                            continue
                        stale_key = self._all_superseded(suppliers)
                        if stale_key is None:
                            continue
                        return StaleVerdict(
                            False,
                            f"a value from a superseded view of {stale_key!r} is "
                            f"restated inside this action's arguments; it carries "
                            f"data the agent knows is out of date",
                            stale=(stale_key,), justified_by=tuple(sorted(justified)))

            current = {k: self._current[k] for k in justified if k in self._current}

        # ---- Rule 2: object staleness. One re-read per justifying object. ----
        used = 0
        if revalidate is not None and policy.revalidate:
            for key in sorted(current):
                used += 1
                now = revalidate(key)
                if now is None:
                    continue
                if now != current[key].version:
                    with self._lock:
                        self._revalidations += used
                    return StaleVerdict(
                        False,
                        f"the observation of {key!r} that justifies this action is "
                        f"at version {current[key].version}, and {key!r} is now at "
                        f"{now}; the world moved between the read and the write",
                        stale=(key,), justified_by=tuple(sorted(justified)),
                        revalidations=used)
            with self._lock:
                self._revalidations += used

        return StaleVerdict(
            True, "every justifying observation is still current",
            justified_by=tuple(sorted(justified)), revalidations=used)

    # ----------------------------------------------------------------- #
    # Introspection
    # ----------------------------------------------------------------- #
    def would_revalidate(self, *, verb: str, resource: str, args: Any,
                         policy: StalenessPolicy, path: str | None = None) -> int:
        """How many re-reads this action would cost, without performing them.

        The cost measurement calls this rather than counting refusals, because a
        deployment pays for every check, not only for the ones that fire.
        """
        if not policy.active or verb not in CONSEQUENTIAL_VERBS:
            return 0
        with self._lock:
            justified: set[str] = set()
            for token in ParameterProvenance._tokens(args):
                for key, _version in self._suppliers.get(token, ()):
                    justified.add(key)
            if isinstance(args, Mapping):
                for name, value in args.items():
                    for slot in _field_slots(name, value):
                        for key, _v in self._field_suppliers.get(slot, ()):
                            justified.add(key)
            target = path or resource
            if target in self._current:
                justified.add(target)
            return len(justified & set(self._current))

    @property
    def revalidations(self) -> int:
        with self._lock:
            return self._revalidations

    @property
    def tracked_objects(self) -> set[str]:
        with self._lock:
            return set(self._current)


def volatile_from_mandate(mandate: Mapping[str, Any] | None) -> StalenessPolicy:
    """Convenience shim mirroring the other rungs' `*_from_mandate` factories."""
    return StalenessPolicy.from_mandate(mandate)
