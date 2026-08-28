

# --------------------------------------------------------------------------- #
# Absence is a violation
# --------------------------------------------------------------------------- #
def test_an_absent_token_is_a_violation_by_default():
    """Presenting nothing used to be the attacker's best move.

    `verify_delegation_chain(None)` returned no violations, so any caller using
    this as an authorization gate failed open on a sub-agent that simply omitted
    its credential. A delegation benchmark scored the shipped primitive at 0.0%
    containment for exactly this reason: containment is measured at the
    attacker's best presentation, and the best presentation was silence.
    """
    from clayseal.core.delegation import verify_delegation_chain

    assert verify_delegation_chain(None) == ["no delegation token presented"]


def test_a_caller_may_opt_into_treating_absence_as_undelegated():
    """Some callers legitimately mean "this action is not delegated". That has
    to be an explicit choice rather than the default."""
    from clayseal.core.delegation import verify_delegation_chain

    assert verify_delegation_chain(None, require_token=False) == []
