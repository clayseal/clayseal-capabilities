"""Computing the ladder's inputs from the trajectory prefix.

Deliberately independent of the broker: `compute_signals` reads only the demo's
own record of what has happened. That is what lets `--gate none` run the ladder
with no host gate at all, which is the ablation that proves the sandbox is
enforcing on its own rather than shadowing the broker's decisions.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from agentauth.capabilities.hardening.input_hardening import scan
from agentauth.capabilities.monitor.action import Action, ContextItem, Trajectory
from agentauth.capabilities.monitor.aml import AmlAnalytics
from agentauth.capabilities.monitor.provenance import TaintTracker
from agentauth.capabilities.sandbox.verdicts import PolicyEvent, Verdict
from demo.escalation import Level, Signals

_EGRESS_EVENTS = ("dns.query", "net.connect", "net.udp")


@dataclass
class DemoTrajectory:
    """What the demo itself observed. Distinct from the broker's trajectory.

    The broker's `_trajectory` holds tool-level actions and drives conformance.
    Lifting syscall verdicts into it would be a category error: they carry
    `tool="ivisor.fs"`, which is outside any sealed envelope, so `last_deviation`
    would report OFF_TOOL on every step and the broker would start refusing for
    reasons that have nothing to do with the injection. `monitor_feed`'s own
    docstring warns about exactly this. Hence two records, never merged.
    """

    attempted: list[Action] = field(default_factory=list)
    returns: list[tuple[ContextItem, str]] = field(default_factory=list)
    verified_events: list[PolicyEvent] = field(default_factory=list)
    broker_denials: int = 0
    # Set by the loop when the broker refuses at the envelope tier. Recorded
    # rather than recomputed: the broker already owns the envelope and its own
    # running trajectory, and a second conformance check here could disagree
    # with the one that actually made the decision.
    off_envelope_consequential: bool = False
    contained_at_step: int | None = None

    def context(self) -> list[ContextItem]:
        return [item for item, _ in self.returns]


def compute_signals(traj: DemoTrajectory, evidence: Trajectory,
                    *, level: Level) -> Signals:
    """Signals from the prefix only. The pending action is not an input."""
    tracker = TaintTracker(traj.context())
    taint_consequential = any(tracker.assess(a).escalate for a in traj.attempted)

    injection_markers = any(_has_markers(text) for _, text in traj.returns)

    egress_denials = sum(1 for e in traj.verified_events
                         if e.verified and e.verdict is Verdict.DENY
                         and e.event in _EGRESS_EVENTS)

    since = 0
    if traj.contained_at_step is not None:
        since = sum(1 for e in traj.verified_events[traj.contained_at_step:]
                    if e.verified and e.verdict is Verdict.DENY)

    aml = AmlAnalytics().assess(evidence) if evidence.actions else None

    return Signals(
        untrusted_items=len(traj.returns),
        injection_markers=injection_markers,
        taint_consequential=taint_consequential,
        off_envelope_consequential=traj.off_envelope_consequential,
        broker_denials=traj.broker_denials,
        verified_egress_denials=egress_denials,
        denials_since_contained=since,
        aml_typologies=frozenset(aml.typologies) if aml else frozenset(),
    )



def _has_markers(text: str) -> bool:
    """Injection-DELIVERY markers (zero-width, bidi, homoglyphs).

    Advisory only: it upgrades the epoch's stated reason, never the level. A
    clean-ASCII instruction carries no markers at all, which is exactly why the
    ladder does not depend on this signal.
    """
    return bool(scan(text))
