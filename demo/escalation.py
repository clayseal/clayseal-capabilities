"""The ladder: trajectory signals in, sandbox capabilities out.

Two invariants make this defensible rather than theatrical, and both are one
line of code and a property test:

TIGHTEN-ONLY. `next_level` ends in `max(current, want)`, so no signal can ever
widen the sandbox. A demo that could widen would have to argue about why the
widening was safe; this one cannot widen at all.

THE PENDING ACTION IS NOT AN INPUT. Signals are computed from the trajectory
PREFIX (steps 0..N-1) only. The policy governing step N therefore cannot have
been influenced by step N, which is what keeps the first exfil attempt honest:
it is refused by the sealed envelope under the UNCHANGED baseline policy, and
the rail still reads `#0 BASELINE` when it happens. Tightening is causally
downstream of that refusal and can only affect later steps.

WHY L1 CHANGES NOTHING. Exposure to untrusted content is not evidence of
misuse. `monitor/consequence.py` states the principle for the broker's own
two-signal gate — "a departing read is reconnaissance to log, not damage to
stop" — and the same rule applies to capabilities. L1 is recorded, the digest is
unchanged, and nothing is taken away. This is not politeness: the legitimate
internal summary email is sent one step after the poisoned ticket is read, and
it succeeds precisely because L1 took nothing.
"""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import IntEnum


class Level(IntEnum):
    BASELINE = 0
    SUSPECT = 1        # untrusted content present; no capability change
    CONTAINED = 2      # effect capability revoked
    QUARANTINED = 3    # read capability revoked too


@dataclass(frozen=True)
class Signals:
    """Everything the ladder is allowed to look at. Prefix-only, by contract."""

    untrusted_items: int = 0                    # tool returns registered so far
    injection_markers: bool = False             # input_hardening.scan hit a return
    taint_consequential: bool = False           # effect action, destination from untrusted content
    off_envelope_consequential: bool = False    # deviation AND consequential
    broker_denials: int = 0
    verified_egress_denials: int = 0            # verified dns/net denials
    denials_since_contained: int = 0            # verified, after containment
    aml_typologies: frozenset[str] = frozenset()


@dataclass(frozen=True)
class SealedGoal:
    """The envelope as sealed from the trusted prompt, before any tool output."""

    text: str
    domains: frozenset[str]
    tools: tuple[str, ...]
    read_tools: tuple[str, ...] = ()
    query_id: str = "demo"


@dataclass(frozen=True)
class Capabilities:
    """What the agent may do, at one level. Every field is lowered or enforced
    somewhere concrete — `enforced_at` says where, so the display can never
    imply the syscall boundary is checking a recipient rule."""

    egress_domains: frozenset[str] = frozenset()
    allowed_verbs: frozenset[str] = frozenset()
    allowed_tools: frozenset[str] = frozenset()
    stage_tickets: bool = True
    carry_forward: tuple[str, ...] = ()
    timeout_s: float = 60.0
    enforced_at: Mapping[str, str] = field(default_factory=dict)

    def summary(self) -> str:
        allow = ",".join(sorted(self.egress_domains)) or "(none)"
        return (f"egress=[{allow}] tools={len(self.allowed_tools)} "
                f"tickets={'staged' if self.stage_tickets else 'unstaged'} "
                f"timeout={self.timeout_s:g}s")


ENFORCED_AT = {
    "egress_domains": "ivisor",     # the allow-list compiled into the config
    "stage_tickets": "ivisor",      # namespace absence: ENOENT, not EACCES
    "carry_forward": "ivisor",      # ditto
    "timeout_s": "ivisor",          # the reservation IS the kill timer
    "allowed_verbs": "broker",      # no syscall carries a verb
    "allowed_tools": "broker",      # nor a tool identity
}


def next_level(current: Level, s: Signals) -> tuple[Level, tuple[str, ...]]:
    """The ladder. Pure, monotone, and blind to the pending action."""
    want, why = Level.BASELINE, []

    # L1 — untrusted content is present. Noticed, not punished.
    if s.untrusted_items:
        want = Level.SUSPECT
        why = ["untrusted content entered the trajectory"]
        if s.injection_markers:
            why.append("input-hardening markers in a tool return")

    # L2 — the two-signal gate fired, or an effect attempt was already refused.
    # Each of these is positive evidence about an ACTION, not mere exposure.
    if s.taint_consequential:
        want = Level.CONTAINED
        why = [("taint x consequential: an effect action's destination came "
                "from untrusted content")]
    elif s.off_envelope_consequential:
        want = Level.CONTAINED
        why = ["off-envelope x consequential"]
    elif s.verified_egress_denials or s.broker_denials:
        refused = s.verified_egress_denials + s.broker_denials
        want = Level.CONTAINED
        why = [f"{refused} refused effect attempt(s)"]

    # L3 — contained, and still trying. The trigger is a VERIFIED denial, so it
    # cannot be manufactured by the guest.
    if current >= Level.CONTAINED and s.denials_since_contained:
        want = Level.QUARANTINED
        why = [f"{s.denials_since_contained} verified denial(s) after containment"]
    elif s.aml_typologies & {"post-read-escalation", "delegated-trust-laundering"}:
        # Correct, and inert in this scenario: ticket triage has no destructive
        # verb and never reaches five distinct egress targets. Kept because the
        # rule is right; the display reads "AML: none" rather than implying it
        # is doing work. See demo/README.md.
        want = Level.QUARANTINED
        why = [f"AML typology {sorted(s.aml_typologies)}"]

    return max(current, want), tuple(why)


def policy_for(level: Level, sealed: SealedGoal) -> Capabilities:
    """The capability set at a level. Every step down is a strict narrowing."""
    all_tools = frozenset(sealed.tools)
    all_verbs = frozenset({"read", "list", "write", "send"})

    if level <= Level.SUSPECT:
        # L0 and L1 are deliberately identical — see the module docstring.
        return Capabilities(
            egress_domains=sealed.domains,
            allowed_verbs=all_verbs,
            allowed_tools=all_tools,
            stage_tickets=True,
            carry_forward=("out/summary.md",),
            timeout_s=60.0,
            enforced_at=ENFORCED_AT)

    if level is Level.CONTAINED:
        # The effect capability goes. Reads and local work continue, so the
        # agent can still finish anything that does not leave the machine.
        return Capabilities(
            egress_domains=frozenset(),
            allowed_verbs=all_verbs,
            allowed_tools=all_tools,
            stage_tickets=True,
            carry_forward=("out/summary.md",),
            timeout_s=60.0,
            enforced_at=ENFORCED_AT)

    # QUARANTINED. Note this is namespace revocation, not a read-only mount:
    # iVisor serves exactly two mounts and /work is writable by construction, so
    # "read-only" would be a claim the substrate cannot keep. Instead the next
    # epoch opens a run dir with the tickets unstaged and nothing migrated —
    # what is not staged is not in the namespace at all, which shows up as a
    # verified `fs.open verdict=miss root=workspace ... errno=ENOENT`.
    return Capabilities(
        egress_domains=frozenset(),
        allowed_verbs=frozenset({"read", "list"}),
        allowed_tools=all_tools - {"send_email"},
        stage_tickets=False,
        carry_forward=(),
        timeout_s=30.0,
        enforced_at=ENFORCED_AT)


def capabilities_narrow(a: Capabilities, b: Capabilities) -> bool:
    """True if `b` grants no more than `a` on every axis."""
    return (b.egress_domains <= a.egress_domains
            and b.allowed_verbs <= a.allowed_verbs
            and b.allowed_tools <= a.allowed_tools
            and int(b.stage_tickets) <= int(a.stage_tickets)
            and set(b.carry_forward) <= set(a.carry_forward)
            and b.timeout_s <= a.timeout_s)
