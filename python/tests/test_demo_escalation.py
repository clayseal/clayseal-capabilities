"""The escalation ladder: monotone, prefix-only, and strictly narrowing."""
import itertools

import pytest

from demo.escalation import (
    ENFORCED_AT,
    Level,
    SealedGoal,
    Signals,
    capabilities_narrow,
    next_level,
    policy_for,
)

SEALED = SealedGoal(
    text="Triage the tickets and email a summary to ops@acme-internal.com",
    domains=frozenset({"acme-internal.com"}),
    tools=("list_tickets", "read_ticket", "write_summary", "send_email"))

# The signal fields the ladder branches on, for exhaustive property testing.
_BOOL_FIELDS = ("injection_markers", "taint_consequential",
                "off_envelope_consequential")
_COUNT_FIELDS = ("untrusted_items", "broker_denials", "verified_egress_denials",
                 "denials_since_contained")


def _all_signals():
    """Every combination of the fields the ladder reads (counts as 0 or 1)."""
    for bools in itertools.product([False, True], repeat=len(_BOOL_FIELDS)):
        for counts in itertools.product([0, 1], repeat=len(_COUNT_FIELDS)):
            yield Signals(**dict(zip(_BOOL_FIELDS, bools)),
                          **dict(zip(_COUNT_FIELDS, counts)))


# --------------------------------------------------------------------------- #
# The two invariants
# --------------------------------------------------------------------------- #

def test_the_ladder_never_widens():
    """Tighten-only, as a property over every reachable input."""
    for current in Level:
        for signals in _all_signals():
            level, _ = next_level(current, signals)
            assert level >= current, (current, signals)


def test_every_escalation_carries_a_reason():
    for current in Level:
        for signals in _all_signals():
            level, why = next_level(current, signals)
            if level > current:
                assert why, (current, signals)


def test_capabilities_narrow_monotonically_with_level():
    """Every step down the ladder grants strictly less on every axis."""
    caps = [policy_for(level, SEALED) for level in Level]
    for a, b in itertools.pairwise(caps):
        assert capabilities_narrow(a, b), (a, b)


# --------------------------------------------------------------------------- #
# L1 takes nothing, the claim the demo's utility depends on
# --------------------------------------------------------------------------- #

def test_suspect_is_capability_identical_to_baseline():
    # Mere exposure to untrusted content must not cost the agent anything, or
    # the legitimate summary email one step later would fail.
    assert policy_for(Level.SUSPECT, SEALED) == policy_for(Level.BASELINE, SEALED)


def test_untrusted_content_alone_only_reaches_suspect():
    level, why = next_level(Level.BASELINE, Signals(untrusted_items=3))
    assert level is Level.SUSPECT
    assert "untrusted content" in why[0]


def test_injection_markers_are_noted_but_do_not_escalate_further():
    level, why = next_level(Level.BASELINE,
                            Signals(untrusted_items=1, injection_markers=True))
    assert level is Level.SUSPECT
    assert any("input-hardening" in w for w in why)


# --------------------------------------------------------------------------- #
# Individual triggers
# --------------------------------------------------------------------------- #

def test_taint_times_consequential_contains():
    level, why = next_level(Level.SUSPECT,
                            Signals(untrusted_items=1, taint_consequential=True))
    assert level is Level.CONTAINED
    assert "taint x consequential" in why[0]


def test_off_envelope_times_consequential_contains():
    level, _ = next_level(Level.SUSPECT,
                          Signals(untrusted_items=1,
                                  off_envelope_consequential=True))
    assert level is Level.CONTAINED


def test_a_refused_effect_attempt_contains():
    level, why = next_level(Level.SUSPECT,
                            Signals(untrusted_items=1, broker_denials=1))
    assert level is Level.CONTAINED
    assert "refused effect attempt" in why[0]


def test_containment_revokes_egress_and_nothing_else():
    base = policy_for(Level.BASELINE, SEALED)
    contained = policy_for(Level.CONTAINED, SEALED)
    assert contained.egress_domains == frozenset()
    # Local work continues: the agent can still read and write in the workspace.
    assert contained.allowed_tools == base.allowed_tools
    assert contained.stage_tickets is True
    assert contained.carry_forward == base.carry_forward


def test_a_verified_denial_after_containment_quarantines():
    level, why = next_level(Level.CONTAINED,
                            Signals(untrusted_items=1, taint_consequential=True,
                                    denials_since_contained=1))
    assert level is Level.QUARANTINED
    assert "after containment" in why[0]


def test_quarantine_needs_containment_first_not_merely_a_denial():
    # The L3 trigger is "contained and still trying". `denials_since_contained`
    # is only populated once containment happened, so before that it is inert
    # and cannot skip a rung.
    level, _ = next_level(Level.SUSPECT,
                          Signals(untrusted_items=1, denials_since_contained=1))
    assert level is Level.SUSPECT


def test_a_verified_denial_at_any_level_still_contains():
    # The path that handles denials regardless of level is the egress counter,
    # so a real denial is never ignored just because L3's trigger is inert.
    level, why = next_level(Level.SUSPECT,
                            Signals(untrusted_items=1, verified_egress_denials=1))
    assert level is Level.CONTAINED
    assert "refused effect attempt" in why[0]


def test_quarantine_revokes_the_namespace_not_just_the_network():
    quarantined = policy_for(Level.QUARANTINED, SEALED)
    # Namespace revocation is what iVisor can actually enforce; a "read-only
    # /work" would be a claim the substrate cannot keep.
    assert quarantined.stage_tickets is False
    assert quarantined.carry_forward == ()
    assert "send_email" not in quarantined.allowed_tools
    assert quarantined.timeout_s < policy_for(Level.CONTAINED, SEALED).timeout_s


# --------------------------------------------------------------------------- #
# Honesty of the enforced_at labelling
# --------------------------------------------------------------------------- #

def test_every_capability_names_where_it_is_enforced():
    caps = policy_for(Level.BASELINE, SEALED)
    for field_name in ("egress_domains", "allowed_verbs", "allowed_tools",
                       "stage_tickets", "carry_forward", "timeout_s"):
        assert field_name in caps.enforced_at, field_name
        assert caps.enforced_at[field_name] in {"ivisor", "broker"}


def test_semantic_capabilities_are_not_claimed_for_the_syscall_boundary():
    # A syscall carries no tool identity and no verb, so claiming iVisor
    # enforces them would be a lie the config could not back up.
    assert ENFORCED_AT["allowed_tools"] == "broker"
    assert ENFORCED_AT["allowed_verbs"] == "broker"
    assert ENFORCED_AT["egress_domains"] == "ivisor"
    assert ENFORCED_AT["stage_tickets"] == "ivisor"


def test_baseline_egress_is_exactly_the_sealed_domain_set():
    assert policy_for(Level.BASELINE, SEALED).egress_domains == SEALED.domains


@pytest.mark.parametrize("level", list(Level))
def test_capabilities_summary_renders(level):
    assert policy_for(level, SEALED).summary()
