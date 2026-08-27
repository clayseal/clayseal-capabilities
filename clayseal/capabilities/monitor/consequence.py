"""Consequence classification, the "danger signal" for the two-signal gate.

Borrowed from the immune system: a T-cell needs two signals to act, an antigen
(something foreign) AND co-stimulation (a danger signal from tissue damage).
Novelty alone is not enough. The behavioral layer applies the same rule: an
action that departs from the goal envelope is escalated for review, but it is
only hard-blocked when it is also *consequential*, when it mutates external
state or exfiltrates. A departing read is reconnaissance to log, not damage to
stop.

Consequence is a pure function of action metadata (verb, resource, argument
keys), so it is injection-resistant like the rest of the behavioral layer.
"""
from __future__ import annotations

import re
from enum import IntEnum

from clayseal.capabilities.monitor.action import Action, path_hint

# Security-relevant surfaces (kept in sync with aml.py's delegated-trust check).
#: As a set, for word-membership tests.
_SECURITY_SURFACE_WORDS = frozenset()   # filled below
_SECURITY_SURFACE = ("auth", "permission", "role", "acl", "iam", "credential",
                     "security", "policy", "token", "secret", "grant", "privilege",
                     "sudo", "admin", "firewall", "access", "key")
_SECURITY_SURFACE_WORDS = frozenset(_SECURITY_SURFACE)
_DESTRUCTIVE = {"delete", "remove", "drop", "wipe", "revoke", "cancel", "destroy",
                "terminate", "purge"}
_EGRESS = {"send", "post", "transfer", "share", "publish", "email", "upload", "pay"}
_WRITE = {"write", "create", "update", "set", "add", "modify", "deploy", "merge",
          "commit", "install", "execute", "run"}


class ConsequenceLevel(IntEnum):
    NONE = 0        # names no target: nothing was observed or moved
    DISCLOSURE = 1  # read content into a context that cannot be un-read
    WRITE = 2       # mutates state within scope
    EGRESS = 3      # moves data or value outward
    DESTRUCTIVE = 4 # irreversible loss
    SECURITY = 5    # touches the authorization surface itself


#: Split on anything that is not a letter or digit, so `access_key`, `iam-role`
#: and `api.token` all yield the words they are made of.
_WORDS = re.compile(r"[^a-z0-9]+")


def _touches_security_surface(action: Action) -> bool:
    """Does this action name part of the authorization surface?

    Matched on WORDS, not substrings. Substring matching read `acl` out of
    "oracle", `iam` out of "William Diamond", `key` out of "monkey wrench" and
    `access` out of "accessory", so ordinary business arguments classified as
    SECURITY, the highest consequence level there is. For a read that is not a
    cosmetic mislabel: SECURITY is at or above WRITE, so it turns a step-up into
    an action a rung is allowed to refuse outright.

    Splitting on non-alphanumerics keeps every intended hit, because the names
    that matter are compounds: `access_key`, `iam-role`, `rotate.secret`.
    """
    hay = " ".join([
        action.tool, action.resource, path_hint(action),
        " ".join(str(v) for v in action.args.values()),
    ]).lower()
    return not _SECURITY_SURFACE_WORDS.isdisjoint(_WORDS.split(hay))


def classify(action: Action) -> tuple[ConsequenceLevel, str]:
    verb = action.verb.lower()
    if _touches_security_surface(action) and verb not in {"read", "get", "list", "search"}:
        return ConsequenceLevel.SECURITY, "touches the authorization surface"
    if verb in _DESTRUCTIVE:
        return ConsequenceLevel.DESTRUCTIVE, f"destructive verb {verb!r}"
    if verb in _EGRESS:
        return ConsequenceLevel.EGRESS, f"egress verb {verb!r}"
    if verb in _WRITE:
        return ConsequenceLevel.WRITE, f"state-mutating verb {verb!r}"
    if _names_a_target(action):
        return (ConsequenceLevel.DISCLOSURE,
                f"read {verb!r} discloses content into the session")
    # Nothing named, nothing disclosed. An action with no target to read is the
    # only genuinely inconsequential one left.
    return ConsequenceLevel.NONE, "names nothing to read"


def _names_a_target(action: Action) -> bool:
    """Did this action actually read something, or merely occur?

    A read with no resource and no path disclosed nothing, and calling it a
    disclosure would make the danger signal fire on an action that touched no
    content at all.
    """
    return bool(str(action.resource or "").strip() or path_hint(action))


def is_consequential(action: Action) -> bool:
    """The danger signal: did this action have an effect the session cannot undo?

    Reading counts. A read puts content into a context that later actions can
    act on and no later action can remove, so a departing read is a disclosure
    rather than a lookup. Including it is worth +8.8 points of AgentHarm
    containment (45.0% -> 53.8% per session) at zero benign cost: 0 refusals
    in 20,619 benign events and 5,851 benign sessions across eight corpora. The
    reason it costs nothing is that a benign read is an ON-plan read, so the
    reclassification only ever fires on a read the sealed goal did not ask for.
    """
    return classify(action)[0] > ConsequenceLevel.NONE


def is_effectful(action: Action) -> bool:
    """The stronger signal: does this action mutate external state or exfiltrate?

    This is `is_consequential` as it read before DISCLOSURE existed, and it is
    what every rung that ends in an unrecoverable DENY asks for. The two are
    deliberately different questions. A disclosure is worth escalating, because
    an envelope with imperfect recall will miss legitimate reads and a human can
    wave those through. It is not worth refusing outright, because a refusal the
    supervisor cannot lift turns every recall miss into lost work.
    """
    return classify(action)[0] >= ConsequenceLevel.WRITE
