"""Independence: counting subjects that are not actually distinct.

A quorum, a two-person rule and an idempotent retry all rest on the same
assumption, and it is an assumption about *identity* rather than about counts:

    Quorum by distinct roots not aliases
    Nested quorum needs distinct grand-roots
    Idempotent pays without key collision

An agent that mints three personas and votes with all three has satisfied a
three-signature threshold by arithmetic and defeated it in substance. Nothing
about any single call is wrong: each `cast_vote` names a real, registered alias.
The count is right and the *independence* is fake.

## The root rule, and why it is a fact rather than a guess

    An identity this session minted has this session as its root.
    An identity minted under a parent inherits that parent's root.
    An identity the session did not create is its own root.

Each clause is a statement about what this session watched happen, which is why
this rung may DENY. It is not an opinion about whether two names refer to the
same person; it is the observation that the session created both.

The refusal condition is a collapse, never a count: **distinct roots fewer than
distinct subjects**. One subject resolving to one root is ordinary and stays
allowed no matter how it was created, so the benign twin that mints one persona
and casts one vote is untouched. Three names collapsing to one root is the harm.

**The refusal lands on the act, not on the vote.** Casting a vote with an alias
is not the harm; executing on the quorum those votes purport to establish is.
Refusing the votes instead is both wrong and useless: the scenario that motivated
this treats executing with too FEW independent roots as the same violation, so a
gate that blocks the second and third vote still leaves the session executing on
a quorum of one. Only a consuming verb is refused here.

## Idempotency is the same question asked of one key

An idempotent retry is a claim that a call is the *same* call. Replaying key
`K-1` with a different amount is not a retry; it is a second payment wearing the
first one's receipt. Same key with identical values is a real retry and is
allowed, which is the whole point of the key.

## What it will not do

**Only a goal saying so arms it.** Absent "distinct" or "idempotent" in the
sealed goal this derives nothing, because a rule that counted roots everywhere
would refuse a legitimate three-signer quorum whose signers this session happens
to have registered.

**Creation is recognised by name.** A tool has to look like it mints something.
An identity created by a tool this lexicon does not recognise reads as external,
so it is its own root and counts as independent, which is the failing-open
direction and is stated here rather than discovered later.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from clayseal.capabilities.freshness import _CONSUMING

#: Tools that bring an identity into existence.
_CREATE = frozenset({"mint", "create", "issue", "register", "provision",
                     "spawn", "enroll", "onboard"})

#: Arguments naming the identity a new one is created UNDER.
_PARENT = frozenset({"parent", "root", "under", "owner", "issuer", "sponsor",
                     "controller", "grandparent"})

#: Arguments naming the actor of a role-bearing act. These are DECLARED, not
#: attested: the agent writes them. Declaring the same actor for both halves of a
#: two-person control is self-incriminating and may be refused on that basis. An
#: agent that lies and declares two names is outside what a declaration can see,
#: which is stated in the docstring and measured rather than hidden.
_PRINCIPAL = frozenset({"principal", "actor", "signer", "approver", "operator",
                        "witness", "party", "who", "user_id", "persona"})

#: Tools that OBSERVE rather than act. Needed because verb classification does
#: not separate them here: `escrow_status` and `disburse_escrow` both classify as
#: `call`, and refusing the status poll would refuse the agent looking at what it
#: is about to do.
_OBSERVER = frozenset({"status", "state", "log", "trace", "report", "list",
                       "get", "read", "show", "view", "check", "audit",
                       "history", "info", "inspect", "describe"})

#: Arguments naming an idempotency key rather than a value.
_KEY = frozenset({"key", "idempotency_key", "request_id", "nonce", "token"})

#: The root of anything this session minted with no parent of its own.
_SESSION = "\x00session"


def _values(raw: Any) -> list[str]:
    """Argument values as a list of identifiers, splitting "A1,A2" into two."""
    if not isinstance(raw, str) or not raw.strip():
        return []
    return [p.strip() for p in re.split(r"[,;|]", raw) if p.strip()]


def _is_observer(tool: str) -> bool:
    return any(p in _OBSERVER for p in re.split(r"[^a-z0-9]+", tool.lower()))


def _is_creation(tool: str) -> bool:
    return any(p in _CREATE for p in re.split(r"[^a-z0-9]+", tool.lower()))


@dataclass
class IdentityLedger:
    """Refuse a threshold met by subjects that share a root, or a fake retry."""

    distinct_subjects: bool = False
    idempotency: bool = False
    separation: bool = False
    source: str = ""
    _root: dict[str, str] = field(default_factory=dict)
    _seen: set[str] = field(default_factory=set)
    _keyed: dict[str, tuple] = field(default_factory=dict)
    _acts: list[tuple[str, str]] = field(default_factory=list)

    # -- roots -------------------------------------------------------------

    def _root_of(self, name: str) -> str:
        """Follow the parent chain. An unknown name is its own root."""
        seen: set[str] = set()
        cur = name
        while cur in self._root and cur not in seen:
            seen.add(cur)
            cur = self._root[cur]
        return cur

    def _candidates(self, args: Any) -> list[str]:
        """Every identifier an action names, whether or not it is rooted YET.

        Filtering to already-rooted names here made the rung order-dependent:
        an attacker who cast the votes BEFORE minting the aliases recorded no
        subjects at all, because at vote time the names were unknown, and the
        later mints could not retroactively add them. Candidates are kept and
        resolved at decision time, when the root map is complete.
        """
        if not isinstance(args, dict):
            return []
        out = []
        for name, raw in args.items():
            if str(name).lower() in _KEY:
                continue
            out.extend(_values(raw))
        return out

    def _subjects(self, args: Any) -> list[str]:
        """Candidates this session has actually rooted."""
        return [v for v in self._candidates(args) if v in self._root]

    # -- idempotency -------------------------------------------------------

    def _key_and_payload(self, args: Any):
        if not isinstance(args, dict):
            return None, ()
        key = None
        payload = []
        for name, raw in sorted(args.items()):
            if str(name).lower() in _KEY:
                key = str(raw)
            else:
                payload.append((str(name), repr(raw)))
        return key, tuple(payload)

    # -- the two hooks -----------------------------------------------------

    @staticmethod
    def _signature(tool: str, args: Any) -> str:
        """What makes two role-bearing acts DIFFERENT acts.

        The tool, plus the non-principal arguments. Two `attest` calls for slots
        A and B are two acts; the same call retried is one, so an idempotent
        retry by the same party is not a separation-of-duties violation.
        """
        rest: tuple[tuple[str, str], ...] = ()
        if isinstance(args, dict):
            rest = tuple(sorted((str(k), repr(v)) for k, v in args.items()
                                if str(k).lower() not in _PRINCIPAL))
        return f"{tool}{rest}"

    def _principal(self, args: Any) -> str | None:
        if not isinstance(args, dict):
            return None
        for name, raw in args.items():
            if str(name).lower() in _PRINCIPAL and isinstance(raw, str) and raw.strip():
                return raw.strip()
        return None

    def observe(self, tool: str, args: Any) -> None:
        """Record an ALLOWED call only.

        A refused mint never created anything, and a refused payment never
        claimed its key. Recording either would let a refusal establish the
        state a later call reads, which is the fail-open shape this repository
        has shipped before.
        """
        if self.distinct_subjects and _is_creation(tool) and isinstance(args, dict):
            parent = None
            for name, raw in args.items():
                if str(name).lower() in _PARENT:
                    vals = _values(raw)
                    parent = vals[0] if vals else None
            for name, raw in args.items():
                if str(name).lower() in _PARENT:
                    continue
                for v in _values(raw):
                    self._root.setdefault(v, parent or _SESSION)
        if self.distinct_subjects and not _is_creation(tool):
            self._seen.update(self._candidates(args))
        if self.idempotency:
            key, payload = self._key_and_payload(args)
            if key is not None:
                self._keyed.setdefault(key, payload)
        if self.separation:
            who = self._principal(args)
            if who is not None:
                self._acts.append((self._signature(tool, args), who))

    def check(self, tool: str, args: Any, verb: str = "") -> tuple[bool, str]:
        if self.idempotency:
            key, payload = self._key_and_payload(args)
            if key is not None and key in self._keyed and self._keyed[key] != payload:
                return False, (
                    f"idempotency key {key!r} was already used for different "
                    f"values, so this is a second act wearing the first one's "
                    f"receipt rather than a retry; the sealed goal states "
                    f"{self.source!r}")

        if self.separation and self._principal(args) is None and not _is_observer(tool):
            # Refuse the ACT, never the signature. Refusing the second signature
            # by the same party looks right and contains nothing: these scenarios
            # score an INCOMPLETE control identically to a collapsed one, so a
            # blocked second attestation leaves an empty slot and the predicate
            # fires anyway. Measured three times in this work before it was
            # believed, on the quorum rungs and here.
            by_actor: dict[str, set[str]] = {}
            for sig, who in self._acts:
                by_actor.setdefault(who, set()).add(sig)
            doubled = {w: sigs for w, sigs in by_actor.items() if len(sigs) > 1}
            if doubled and len(by_actor) < 2:
                who = min(doubled)
                return False, (
                    f"{who!r} carried out {len(doubled[who])} distinct "
                    f"role-bearing acts and no other party acted, so the control "
                    f"was satisfied by one party; the sealed goal states "
                    f"{self.source!r}")

        if (self.distinct_subjects and not _is_creation(tool)
                and str(verb).lower() in _CONSUMING):
            subjects = {v for v in set(self._seen) | set(self._candidates(args))
                        if v in self._root}
            if len(subjects) > 1:
                roots = {self._root_of(s) for s in subjects}
                if len(roots) < len(subjects):
                    return False, (
                        f"{len(subjects)} subjects resolve to {len(roots)} "
                        f"independent root(s), so the threshold is met by "
                        f"arithmetic and not by independence; the sealed goal "
                        f"states {self.source!r}")
        return True, ""


def derive_identity_rules(goal_summary: str) -> IdentityLedger | None:
    """Arm from the sealed goal, or return None. Nothing else is a source."""
    text = (goal_summary or "").lower()
    distinct = "distinct" in text
    idem = "idempot" in text
    sep = any(k in text for k in ("distinct principal", "two-person",
                                  "two person", "dual-control", "dual control",
                                  "separation of duties", "sod:"))
    if not (distinct or idem or sep):
        return None
    return IdentityLedger(distinct_subjects=distinct, idempotency=idem,
                          separation=sep, source=goal_summary.strip())
