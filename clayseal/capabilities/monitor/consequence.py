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

# THE security-surface vocabulary. `aml.py` imports this rather than keeping a
# second copy: its copy carried a comment saying it was kept in sync with this
# one and was not, it lacked "key", so an untrusted-context action naming an
# `access_key` was a security touch on this ladder and not a delegated-trust
# laundering hit over there. Two lists that must agree are one list.
SECURITY_SURFACE_WORDS = frozenset({
    "auth", "permission", "role", "acl", "iam", "credential",
    "security", "policy", "token", "secret", "grant", "privilege",
    "sudo", "admin", "firewall", "access", "key",
})
_DESTRUCTIVE = {"delete", "remove", "drop", "wipe", "revoke", "cancel", "destroy",
                "terminate", "purge"}
_EGRESS = {"send", "post", "transfer", "share", "publish", "email", "upload", "pay"}
_WRITE = {"write", "create", "update", "set", "add", "modify", "deploy", "merge",
          "commit", "install", "execute", "run"}

# Acquisition verbs: the only way to be classified BELOW WRITE.
#
# WHY A READ LIST AND NOT A LONGER EFFECT LIST. DISCLOSURE used to be the
# fallthrough, so a verb in none of the three effect sets above was called a
# read. That put a closed vocabulary in front of the PERMISSIVE answer, and
# every word it lacked was a way past the gate rather than a way into it.
# Measured through SessionBroker, not asserted: an off-plan action moving
# 50,000 to an unknown address is DENY when its verb is `send` or `write`, and
# STEP_UP with the reason "off-plan disclosure: read content the sealed goal did
# not ask for" when its verb is `disburse`, `remit`, `provision`, `settle` or
# `void`. `exec`, which `sandbox/monitor_feed.py` emits for every `proc.exec`
# the sandbox reports, landed there too, because the write list holds `execute`
# and `run` and not `exec`.
#
# The shipped path reaches it without any exotic vocabulary at all.
# `tool_verbs.classify_verb` returns `call` for a name it does not recognise,
# and its own comment says `call` means "nothing downstream treats it as
# reversible". This ladder treated it as exactly that.
#
# Adding disburse/remit/exec to _WRITE is the same defect with a later failure
# point. What changes the failure MODE is which answer the closed list guards.
# A read this list is missing is now a WRITE: it costs friction and cannot be
# used to walk past a rung. A deployment with real verbs declares them under
# `tools.effects`, which is already where `Policy.verb_for` and the MCP proxy
# take a verb from, and a declared `read` lands in this set.
#
# NOT shared with `tool_verbs._READ` even though the words coincide today: that
# list matches the PREFIX OF A TOOL NAME and this one matches a whole verb.
# They answer different questions and are free to diverge.
_READ = {"read", "get", "list", "search", "find", "view", "show", "check",
         "fetch", "lookup", "query", "describe", "calculate", "cd", "ls",
         "cat", "grep", "sort", "diff", "pwd", "du", "wc", "tail", "head"}

# Reads exempt from the security-surface rung. Deliberately NOT `_READ`: this
# set decides when naming the authorization surface is harmless, and widening it
# would DEMOTE actions that currently classify as SECURITY. This change makes
# nothing more permissive, so the four words it had are the four words it keeps.
_SECURITY_READ_EXEMPT = {"read", "get", "list", "search"}


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


def touches_security_surface(action: Action) -> bool:
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
    return not SECURITY_SURFACE_WORDS.isdisjoint(_WORDS.split(hay))


def classify(action: Action) -> tuple[ConsequenceLevel, str]:
    verb = action.verb.lower()
    if touches_security_surface(action) and verb not in _SECURITY_READ_EXEMPT:
        return ConsequenceLevel.SECURITY, "touches the authorization surface"
    if verb in _DESTRUCTIVE:
        return ConsequenceLevel.DESTRUCTIVE, f"destructive verb {verb!r}"
    if verb in _EGRESS:
        return ConsequenceLevel.EGRESS, f"egress verb {verb!r}"
    if verb in _WRITE:
        return ConsequenceLevel.WRITE, f"state-mutating verb {verb!r}"
    if verb not in _READ:
        # Fail closed at the LOWEST effectful rung. Not EGRESS or DESTRUCTIVE:
        # an unknown verb is unknown, and inventing an egress would bind
        # destination rules to an action that may carry no destination.
        #
        # No target check here, unlike the read below. A read that named
        # nothing disclosed nothing, which is a fact about reads. An effect
        # that names nothing still had its effect: `terraform_destroy` takes no
        # path, and `velocity.py` measured that 641 of 833 missed attacks carry
        # no target at all.
        return (ConsequenceLevel.WRITE,
                f"unrecognised verb {verb!r}: not known to be a read")
    if _names_a_target(action):
        return (ConsequenceLevel.DISCLOSURE,
                f"read {verb!r} discloses content into the session")
    # Nothing named, nothing disclosed. A recognised read with no target to read
    # is the only genuinely inconsequential action left.
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
