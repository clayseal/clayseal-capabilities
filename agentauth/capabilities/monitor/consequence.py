"""Consequence classification — the "danger signal" for the two-signal gate.

Borrowed from the immune system: a T-cell needs two signals to act, an antigen
(something foreign) AND co-stimulation (a danger signal from tissue damage).
Novelty alone is not enough. The behavioral layer applies the same rule: an
action that departs from the goal envelope is escalated for review, but it is
only hard-blocked when it is also *consequential* — when it mutates external
state or exfiltrates. A departing read is reconnaissance to log, not damage to
stop.

Consequence is a pure function of action metadata (verb, resource, argument
keys), so it is injection-resistant like the rest of the behavioral layer.
"""
from __future__ import annotations

from enum import IntEnum

from agentauth.capabilities.monitor.action import Action

# Security-relevant surfaces (kept in sync with aml.py's delegated-trust check).
_SECURITY_SURFACE = ("auth", "permission", "role", "acl", "iam", "credential",
                     "security", "policy", "token", "secret", "grant", "privilege",
                     "sudo", "admin", "firewall", "access", "key")
_DESTRUCTIVE = {"delete", "remove", "drop", "wipe", "revoke", "cancel", "destroy",
                "terminate", "purge"}
_EGRESS = {"send", "post", "transfer", "share", "publish", "email", "upload", "pay"}
_WRITE = {"write", "create", "update", "set", "add", "modify", "deploy", "merge",
          "commit", "install", "execute", "run"}


class ConsequenceLevel(IntEnum):
    NONE = 0        # read-only / observation
    WRITE = 1       # mutates state within scope
    EGRESS = 2      # moves data or value outward
    DESTRUCTIVE = 3 # irreversible loss
    SECURITY = 4    # touches the authorization surface itself


def _touches_security_surface(action: Action) -> bool:
    hay = " ".join([action.tool, action.resource,
                    " ".join(str(v) for v in action.args.values())]).lower()
    return any(term in hay for term in _SECURITY_SURFACE)


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
    return ConsequenceLevel.NONE, "read-only"


def is_consequential(action: Action) -> bool:
    """The danger signal: does this action mutate external state or exfiltrate?"""
    return classify(action)[0] > ConsequenceLevel.NONE
