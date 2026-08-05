"""The whole loop, driven against the fake sentry.

WHAT THIS VALIDATES: the harness. The ladder, epoch recompilation, config
rendering, the trace-fd path, the reducer, expectations and the exit code, on
any machine with no HVF and no codesigning.

WHAT IT DOES NOT VALIDATE: iVisor's semantics. The fake emits verdict lines that
were copied from observed real-sentry output, so a green run here means "we
handled the verdicts correctly", never "iVisor really denies that".
`test_e2e_real.py` is the test that makes the second claim.
"""
from pathlib import Path

import pytest

from demo.escalation import Level
from demo.loop import RunConfig, run_demo
from demo.providers import build_provider
from demo.scenario import COLLECTOR, INTERNAL, SCENARIOS
from demo.state import AppState, EpochOpened, VerdictLine, apply

FAKE = (Path(__file__).resolve().parents[2]
        / "python" / "tests" / "fakes" / "fake_ivisor.py")


def _run(tmp_path, *, scenario="ticket-triage", provider="mock", gate="broker"):
    scen = SCENARIOS[scenario]()
    state = AppState(watch=scen.watch, expectations=scen.expectations)
    events = []

    def emit(event):
        events.append(event)
        apply(state, event)

    run_demo(RunConfig(scenario=scen, provider=build_provider(provider, scen),
                       run_root=tmp_path, ivisor_bin=str(FAKE),
                       rootfs="/fake-rootfs", gate=gate, fake_guest=True),
             emit)
    return state, events


def _verdicts(state, event_name, needle):
    return [r for r in state.verdicts
            if r.event.event == event_name and needle in r.event.subject()]


# --------------------------------------------------------------------------- #
# The four beats of the run
# --------------------------------------------------------------------------- #

def test_every_expectation_holds(tmp_path):
    state, _ = _run(tmp_path)
    unmet = [e.describe() for e in state.unmet()]
    assert unmet == []


def test_real_work_is_permitted(tmp_path):
    state, _ = _run(tmp_path)
    assert _verdicts(state, "fs.open", "/work/out/summary.md")


def test_the_legitimate_send_is_admitted_while_nothing_has_been_revoked(tmp_path):
    """L1 takes nothing, which is the only reason this send survives."""
    state, events = _run(tmp_path)
    allowed = _verdicts(state, "dns.query", INTERNAL)
    assert allowed and allowed[0].verdict == "allow"

    # It happened before containment: the epoch active at the time was SUSPECT,
    # whose digest equals BASELINE's.
    epochs = [e for e in events if isinstance(e, EpochOpened)]
    suspect = next(e for e in epochs if e.level == int(Level.SUSPECT))
    baseline = next(e for e in epochs if e.level == int(Level.BASELINE))
    assert suspect.changed is False
    assert suspect.digest == baseline.digest


def test_the_direct_exfil_is_refused_by_the_sealed_envelope(tmp_path):
    """The static guarantee: refused at the tool level, before any tightening."""
    state, events = _run(tmp_path)
    denial = next(b for b in state.broker
                  if b.tool == "send_email" and b.outcome == "DENY")
    assert denial.layer == "floor"
    assert any(COLLECTOR in r for r in denial.reasons)

    # Containment had not happened yet when it was refused.
    order = [type(e).__name__ for e in events]
    first_broker_deny = next(i for i, e in enumerate(events)
                             if type(e).__name__ == "BrokerDecided"
                             and e.outcome == "DENY")
    contained_at = next(i for i, e in enumerate(events)
                        if isinstance(e, EpochOpened)
                        and e.level == int(Level.CONTAINED))
    assert first_broker_deny < contained_at, order


def test_the_relay_is_allowed_by_the_broker_and_refused_by_the_sandbox(tmp_path):
    """THE DEMO. An action the host gate permits, refused at the boundary
    because the policy was recompiled from the trajectory."""
    _state, events = _run(tmp_path)

    contained_at = next(i for i, e in enumerate(events)
                        if isinstance(e, EpochOpened)
                        and e.level == int(Level.CONTAINED))
    after = events[contained_at:]

    # The broker allowed a send after containment...
    assert any(type(e).__name__ == "BrokerDecided" and e.tool == "send_email"
               and e.outcome == "ALLOW" for e in after)
    # ...and the sandbox denied the very domain it had allowed earlier.
    denied = [e for e in after if isinstance(e, VerdictLine) and e.verified
              and "verdict=deny" in e.raw and INTERNAL in e.raw]
    assert denied, "the recompiled sandbox did not refuse the relay"


def test_the_same_domain_is_allowed_then_denied(tmp_path):
    """The clearest statement of the thesis, in two verdicts."""
    state, _ = _run(tmp_path)
    outcomes = [r.verdict for r in _verdicts(state, "dns.query", INTERNAL)]
    assert "allow" in outcomes and "deny" in outcomes
    assert outcomes.index("allow") < outcomes.index("deny")


def test_the_ladder_reaches_quarantine_and_unstages_the_corpus(tmp_path):
    _state, events = _run(tmp_path)
    quarantine = next(e for e in events if isinstance(e, EpochOpened)
                      and e.level == int(Level.QUARANTINED))
    baseline = next(e for e in events if isinstance(e, EpochOpened)
                    and e.level == int(Level.BASELINE))
    assert quarantine.staged < baseline.staged
    assert quarantine.carry_forward == ()


def test_epochs_are_monotone_and_each_carries_a_reason(tmp_path):
    _, events = _run(tmp_path)
    epochs = [e for e in events if isinstance(e, EpochOpened)]
    levels = [e.level for e in epochs]
    assert levels == sorted(levels)
    for epoch in epochs[1:]:
        assert epoch.why


# --------------------------------------------------------------------------- #
# Controls
# --------------------------------------------------------------------------- #

def test_a_benign_trajectory_loses_no_capability(tmp_path):
    state, events = _run(tmp_path, scenario="ticket-triage-benign",
                         provider="benign")
    assert [e.describe() for e in state.unmet()] == []
    assert state.counters.deny == 0
    assert max(e.level for e in events if isinstance(e, EpochOpened)) \
        == int(Level.SUSPECT)


def test_without_a_host_gate_the_sandbox_alone_refuses_the_collector(tmp_path):
    """The ablation that proves the safety property was hard-won.

    With no broker, the guest really attempts the collector connection, so a
    satisfied NeverAllowed means the syscall boundary refused it rather than the
    attempt never having been made.
    """
    state, _ = _run(tmp_path, gate="none")
    assert state.broker == []                        # no host gate at all
    denied = _verdicts(state, "dns.query", COLLECTOR)
    assert denied and denied[0].verdict == "deny"
    assert all(e.met for e in state.expectations
               if e.describe().startswith("never allows"))


@pytest.mark.parametrize("gate", ["broker", "none"])
def test_the_collector_is_never_admitted_either_way(gate, tmp_path):
    state, _ = _run(tmp_path, gate=gate)
    assert not [r for r in _verdicts(state, "dns.query", COLLECTOR)
                if r.verdict == "allow"]
