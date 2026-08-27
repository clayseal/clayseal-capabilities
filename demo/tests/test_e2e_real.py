"""The demo against the real sentry, the only test that validates iVisor's
semantics rather than our handling of them.

    cp <iVisor>/target/release/ivisor /tmp/ivisor-signed
    codesign --force --sign - --entitlements <iVisor>/entitlements.plist \\
        /tmp/ivisor-signed
    IVISOR_E2E=1 IVISOR_BIN=/tmp/ivisor-signed \\
    IVISOR_ROOTFS=<iVisor>/guests/rootfs pytest demo/tests/test_e2e_real.py -q
"""
import os
from pathlib import Path

import pytest

from demo.escalation import Level
from demo.loop import RunConfig, run_demo
from demo.providers import build_provider
from demo.scenario import COLLECTOR, INTERNAL, SCENARIOS
from demo.state import AppState, EpochOpened, apply

pytestmark = pytest.mark.skipif(
    not os.environ.get("IVISOR_E2E"),
    reason="set IVISOR_E2E=1 with IVISOR_BIN and IVISOR_ROOTFS to run")

IVISOR_BIN = os.environ.get("IVISOR_BIN", "ivisor")
IVISOR_ROOTFS = os.environ.get("IVISOR_ROOTFS", "")


@pytest.fixture(scope="module", autouse=True)
def require_rootfs():
    if not IVISOR_ROOTFS or not Path(IVISOR_ROOTFS).is_dir():
        pytest.skip(f"IVISOR_ROOTFS={IVISOR_ROOTFS!r} is not a directory")


def _run(tmp_path, *, scenario="ticket-triage", provider="mock", gate="broker"):
    scen = SCENARIOS[scenario]()
    state = AppState(watch=scen.watch, expectations=scen.expectations)
    events = []

    def emit(event):
        events.append(event)
        apply(state, event)

    run_demo(RunConfig(scenario=scen, provider=build_provider(provider, scen),
                       run_root=tmp_path, ivisor_bin=IVISOR_BIN,
                       rootfs=IVISOR_ROOTFS, gate=gate), emit)
    return state, events


def _dns(state, needle):
    return [r for r in state.verdicts
            if r.event.event == "dns.query" and needle in r.event.subject()]


def test_every_expectation_holds_against_the_real_sentry(tmp_path):
    state, _ = _run(tmp_path)
    assert [e.describe() for e in state.unmet()] == []


def test_the_same_domain_is_admitted_then_refused(tmp_path):
    """The thesis, in two verdicts from the real kernel."""
    state, _ = _run(tmp_path)
    outcomes = [r.verdict for r in _dns(state, INTERNAL)]
    assert "allow" in outcomes, "the legitimate send was never admitted"
    assert "deny" in outcomes, "the recompiled policy never refused the relay"
    assert outcomes.index("allow") < outcomes.index("deny")


def test_the_collector_is_never_admitted(tmp_path):
    state, _ = _run(tmp_path)
    assert not [r for r in _dns(state, COLLECTOR) if r.verdict == "allow"]


def test_the_suspect_epoch_is_byte_identical(tmp_path):
    """`digest unchanged` against the real config renderer, not a fixture."""
    _, events = _run(tmp_path)
    epochs = [e for e in events if isinstance(e, EpochOpened)]
    baseline = next(e for e in epochs if e.level == int(Level.BASELINE))
    suspect = next(e for e in epochs if e.level == int(Level.SUSPECT))
    assert suspect.digest == baseline.digest
    assert suspect.changed is False


def test_quarantine_removes_the_corpus_from_the_namespace(tmp_path):
    _state, events = _run(tmp_path)
    quarantine = next((e for e in events if isinstance(e, EpochOpened)
                       and e.level == int(Level.QUARANTINED)), None)
    assert quarantine is not None
    baseline = next(e for e in events if isinstance(e, EpochOpened)
                    and e.level == int(Level.BASELINE))
    assert quarantine.staged < baseline.staged


def test_a_benign_trajectory_loses_nothing(tmp_path):
    state, events = _run(tmp_path, scenario="ticket-triage-benign",
                         provider="benign")
    assert [e.describe() for e in state.unmet()] == []
    assert state.counters.deny == 0
    assert max(e.level for e in events if isinstance(e, EpochOpened)) \
        == int(Level.SUSPECT)


def test_without_a_host_gate_ivisor_alone_refuses_the_collector(tmp_path):
    state, _ = _run(tmp_path, gate="none")
    assert state.broker == []
    denied = _dns(state, COLLECTOR)
    assert denied and denied[0].verdict == "deny"
    assert denied[0].event.get("reason") == "not-allowlisted"
