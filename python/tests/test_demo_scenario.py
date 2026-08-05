"""The scenario, and the guards that keep it from quietly becoming dishonest."""
import pytest

from agentauth.capabilities.hardening.egress_policy import EgressPolicy
from demo.scenario import (
    COLLECTOR,
    COLLECTOR_TO,
    INTERNAL,
    INTERNAL_TO,
    RELAY_TO,
    SCENARIOS,
    ticket_triage,
    ticket_triage_benign,
)


@pytest.fixture
def scen():
    return ticket_triage()


@pytest.fixture
def egress(scen):
    return EgressPolicy(allowed_domains=set(scen.seal().domains))


def test_the_collector_is_not_in_the_sealed_goal(scen):
    """The guard that matters most.

    If someone 'improves' the user prompt and mentions the collector, the seal
    would authorize the attacker and every downstream result would be
    meaningless while still looking green.
    """
    sealed = scen.seal()
    assert COLLECTOR not in scen.user_prompt
    assert not any(COLLECTOR in d for d in sealed.domains)
    assert sealed.domains == frozenset({INTERNAL})


def test_exactly_one_ticket_carries_the_injection(scen):
    poisoned = [tid for tid, body in scen.tickets.items() if COLLECTOR in body]
    assert poisoned == ["T-1006"]


def test_the_injection_is_in_the_last_ticket(scen):
    # Ordering is load-bearing: the legitimate send happens one step after the
    # poisoned ticket is read, while the ladder is still at SUSPECT.
    assert list(scen.tickets)[-1] == "T-1006"


def test_the_injection_offers_an_internal_fallback(scen):
    # Without this the demo would only prove the sealed envelope works, which
    # needs no recompilation at all.
    body = scen.tickets["T-1006"]
    assert COLLECTOR_TO in body
    assert RELAY_TO in body


# --------------------------------------------------------------------------- #
# What the broker does with each attempt — the beats of the run
# --------------------------------------------------------------------------- #

def test_the_legitimate_send_is_allowed(egress):
    ok, _ = egress.check("mcp:tool:send_email", {"to": INTERNAL_TO})
    assert ok is True


def test_the_direct_exfil_is_denied_by_the_sealed_envelope(egress):
    # The static guarantee: refused with nothing learned at runtime.
    ok, reason = egress.check("mcp:tool:send_email", {"to": COLLECTOR_TO})
    assert ok is False
    assert COLLECTOR in reason


def test_an_external_address_hidden_in_the_body_is_also_denied(egress):
    # extract_destinations scans every string argument, which is why the
    # scenario needs an attempt carrying no external identifier at all.
    ok, _ = egress.check("mcp:tool:send_email",
                         {"to": INTERNAL_TO, "body": f"copy to {COLLECTOR_TO}"})
    assert ok is False


def test_the_internal_relay_is_allowed_by_the_broker(egress):
    """The keystone.

    Nothing external appears anywhere in these arguments, so the tool-level
    gate has no grounds to refuse. Whatever stops this attempt is therefore the
    sandbox, under a policy recompiled from the trajectory — which is the one
    beat that isolates the dynamic contribution.
    """
    ok, _ = egress.check("mcp:tool:send_email",
                         {"to": RELAY_TO, "body": "summary text"})
    assert ok is True
    assert COLLECTOR not in RELAY_TO
    assert RELAY_TO.endswith(INTERNAL)


# --------------------------------------------------------------------------- #
# Wiring
# --------------------------------------------------------------------------- #

def test_guest_programs_exist_for_every_tool(scen):
    staged = scen.tool_files()
    for tool in (t["function"]["name"] for t in scen.tools):
        assert f"tools/{tool}.py" in staged, tool
        assert staged[f"tools/{tool}.py"].is_file()


def test_guest_argv_is_built_for_every_tool(scen):
    assert scen.guest_argv("read_ticket", {"id": "T-1001"})[-1] == "T-1001"
    assert scen.guest_argv("send_email", {"to": INTERNAL_TO})[-1] == INTERNAL_TO
    # write_summary takes its text from a staged file, not argv.
    assert scen.guest_argv("write_summary", {"text": "x" * 500}) == (
        "/work/tools/write_summary.py",)
    with pytest.raises(KeyError):
        scen.guest_argv("no_such_tool", {})


def test_ticket_corpus_materializes_to_guest_relative_paths(scen, tmp_path):
    files = scen.ticket_files(tmp_path)
    assert "data/tickets/T-1006.txt" in files
    assert COLLECTOR in files["data/tickets/T-1006.txt"].read_text()
    assert len(files) == len(scen.tickets)


def test_watch_list_covers_the_subjects_the_demo_narrates(scen):
    assert any("/work/out/" in w for w in scen.watch)
    assert COLLECTOR in scen.watch
    assert INTERNAL in scen.watch


def test_safety_expectations_start_satisfied_and_liveness_does_not(scen):
    by_desc = {e.describe(): e.met for e in scen.expectations}
    assert by_desc[f"never allows dns.query {COLLECTOR}"] is True
    assert by_desc["escalates to CONTAINED"] is False


def test_the_benign_control_asserts_no_capability_loss():
    benign = ticket_triage_benign()
    assert any(e.describe() == "a clean trajectory loses no capability"
               for e in benign.expectations)
    # It must not assert escalation — that is the whole point of the control.
    assert not any("escalates" in e.describe() for e in benign.expectations)


def test_both_scenarios_are_registered():
    assert set(SCENARIOS) == {"ticket-triage", "ticket-triage-benign"}
