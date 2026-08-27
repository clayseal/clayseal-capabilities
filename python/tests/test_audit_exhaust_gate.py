"""`on_audit_exhausted="allow"` is a fail-open and must be opted into.

It turns "the human ran out of attention" into ALLOW. That is the same shape as
the planner's old allow-all: an undefended decision pooling into the ordinary
allow count, invisible downstream. It stays available because the attention axis
needs both ends of the policy, but it is gated and stamped.
"""
from __future__ import annotations

from clayseal.capabilities.broker import SessionBroker


def _fields():
    names = {f for f in SessionBroker.__dataclass_fields__}
    return names


def test_the_acknowledgement_flag_exists_and_defaults_off():
    assert "allow_on_exhaust_acknowledged" in _fields()
    assert SessionBroker.__dataclass_fields__[
        "allow_on_exhaust_acknowledged"].default is False


def test_the_default_policy_is_still_deny():
    assert SessionBroker.__dataclass_fields__["on_audit_exhausted"].default == "deny"


def test_an_unacknowledged_allow_policy_denies():
    """The load-bearing property: setting the policy string alone is not enough.
    A config that inherits `allow` from a template gets the safe branch."""
    import inspect

    src = inspect.getsource(SessionBroker._finalize)
    assert "allow_on_exhaust_acknowledged" in src
    assert "denied: allow-on-exhaust not acknowledged" in src


def test_an_acknowledged_allow_is_stamped_as_its_own_layer():
    """`layer="audit-exhausted"` so no analysis can count it as a clean pass."""
    import inspect

    src = inspect.getsource(SessionBroker._finalize)
    assert 'Outcome.ALLOW, "audit-exhausted"' in src
