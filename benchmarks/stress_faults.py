"""What the gateway decides when one of its own components is broken.

    python -m benchmarks.stress_faults

`stress_gates` throws hostile INPUTS at every gate and checks none of them
crashes or yields an allow out of confusion. This is the other half, and it is
the half a production incident is actually made of: the input is ordinary and a
COMPONENT is broken. A Redis-backed ledger times out. An identity provider is
unreachable. A tier hits a shape its author did not anticipate and raises.

The question a security control has to answer is not whether that happens but
what it decides while it is happening. A gate that allows because its budget
ledger threw is a gate that an attacker turns off by making the ledger throw.

## The rule this measures

Every seam is classified before the run, not after it:

``enforcement``  a tier whose whole job is to refuse. A fault here MUST NOT
                 produce an allow. Failing closed is the only acceptable answer
                 and a raise reaching the caller is second best to that.
``advisory``     a tier that informs a decision it does not own. A fault here
                 MAY allow, and the allow has to be deliberate and stated,
                 because an advisory tier that fails closed turns every outage
                 into a denial of service.
``bookkeeping``  logging, metrics, receipts. A fault here must change no
                 decision at all, in either direction.

Classifying first is what makes the run falsifiable. Reading the outcomes and
then deciding which were meant to fail open would measure nothing.
"""
from __future__ import annotations

import argparse
import sys
from collections import Counter

from clayseal.capabilities.monitor.action import Action
from clayseal.capabilities.policy import load_policy_text

POLICY = """
version: 1
goal: {id: fault-probe, summary: Pay approved invoices under /finance/ap}
profile: supervised
tools:
  allow: [pay_vendor, read_file]
  effects: {pay_vendor: transfer, read_file: read}
paths:
  allow: ["/finance/ap/**"]
  arg_names: {read_file: path}
  pathless: [pay_vendor]
egress: {domains: [acme-internal.com], bind_recipients: true}
budgets:
  value:
    ceilings: {payments: "50000"}
    tracked: {pay_vendor: {arg: amount, budget: payments, identity: [invoice]}}
"""

ENFORCEMENT = "enforcement"
ADVISORY = "advisory"
BOOKKEEPING = "bookkeeping"

#: (label, kind, how to break it). Classified BEFORE the run.
SEAMS: list[tuple[str, str, str, str]] = [
    ("value_budget.reserve", ENFORCEMENT, "value_budget", "reserve"),
    ("value_budget.commit", ENFORCEMENT, "value_budget", "commit"),
    ("value_budget.would_allow", ENFORCEMENT, "value_budget", "would_allow"),
    ("value_budget.remaining", ENFORCEMENT, "value_budget", "remaining"),
    ("scope.is_expired", ENFORCEMENT, "scope", "is_expired"),
    ("egress.check", ENFORCEMENT, "egress", "check"),
    ("egress.check_with_provenance", ENFORCEMENT, "egress",
     "check_with_provenance"),
    ("egress.binds", ENFORCEMENT, "egress", "binds"),
    ("provenance.check_destination", ENFORCEMENT, "provenance",
     "check_destination"),
    ("provenance.is_grounded", ENFORCEMENT, "provenance", "is_grounded"),
    ("sensitivity.is_sensitive", ENFORCEMENT, "sensitivity", "is_sensitive"),
    ("sensitivity.sends_its_arguments", ENFORCEMENT, "sensitivity",
     "sends_its_arguments"),
    ("grants.allows_resource", ENFORCEMENT, "grants", "allows_resource"),
    ("grants.allows_destination", ENFORCEMENT, "grants", "allows_destination"),
    ("grants.allows_shape", ENFORCEMENT, "grants", "allows_shape"),
    ("flow.check", ENFORCEMENT, "flow", "check"),
    ("flow.observe", ADVISORY, "flow", "observe"),
    ("provenance.record_observation", ADVISORY, "provenance",
     "record_observation"),
    ("provenance.trusted_candidates", ADVISORY, "provenance",
     "trusted_candidates"),
    ("session.adopt", ADVISORY, "session", "adopt"),
    ("grants.consume", ADVISORY, "grants", "consume"),
    ("decision_log.append", BOOKKEEPING, "decision_log", "append"),
    ("decision_log.durability", BOOKKEEPING, "decision_log", "durability"),
    ("metrics.record_action", BOOKKEEPING, "metrics", "record_action"),
    ("metrics.record_prevented", BOOKKEEPING, "metrics", "record_prevented"),
    ("metrics.record_monitor_trigger", BOOKKEEPING, "metrics",
     "record_monitor_trigger"),
]


class Boom(RuntimeError):
    """A component failing the way a component fails: unexpectedly."""


def _benign() -> Action:
    return Action(step=0, tool="pay_vendor", resource="mcp:tool:pay_vendor",
                  verb="transfer",
                  args={"amount": "100.00", "invoice": "INV-1"}, meta={})


def _hostile() -> Action:
    """An action the healthy gateway refuses: outside the path scope."""
    return Action(step=0, tool="read_file", resource="/etc/shadow", verb="read",
                  args={"path": "/etc/shadow"}, meta={"path": "/etc/shadow"})


def outcome_with_fault(holder: str, attribute: str, action: Action) -> str:
    """Decide one action with one component broken. Never raises to the caller."""
    stack = load_policy_text(POLICY).build()
    target = getattr(stack.broker, holder, None)
    if target is None or not hasattr(target, attribute):
        return "absent"

    def explode(*_args, **_kwargs):
        raise Boom(f"{holder}.{attribute} is down")

    try:
        setattr(target, attribute, explode)
    except (AttributeError, TypeError):
        # A frozen dataclass refuses attribute assignment. Reporting it as
        # "unpatchable" left two enforcement seams untested, and an untested
        # seam in a table of green ones reads as covered.
        try:
            object.__setattr__(target, attribute, explode)
        except (AttributeError, TypeError):
            return "unpatchable"
    try:
        return stack.authorize(action).outcome
    except Boom:
        return "raised"
    except Exception as exc:
        return f"raised:{type(exc).__name__}"


def verdict(kind: str, benign: str, hostile: str, healthy_benign: str) -> str:
    """Did this seam behave as its classification requires?"""
    if benign in ("absent", "unpatchable"):
        return "skipped"
    if kind == ENFORCEMENT:
        # A fault must never turn a refusal into an allow.
        return "ok" if hostile != "allow" else "FAIL-OPEN"
    if kind == BOOKKEEPING:
        # A fault must change no decision, in either direction, and must not
        # reach the caller as an exception. The first version of this rule only
        # checked that the hostile action was not ALLOWED, which let a raise
        # pass as "ok" because a crash is not an allow. A probe whose verdict is
        # weaker than its claim measures nothing, which is the same lesson the
        # path differential learned by excluding the population its bug was in.
        if str(benign).startswith("raised") or str(hostile).startswith("raised"):
            return "CRASHED-THE-GATEWAY"
        return "ok" if (benign == healthy_benign and hostile != "allow") \
            else "CHANGED-A-DECISION"
    # Advisory: allowed to allow, and not allowed to crash the caller on either
    # path. A tier that only informs a decision must not be able to prevent one.
    if str(benign).startswith("raised") or str(hostile).startswith("raised"):
        return "CRASHED-THE-GATEWAY"
    return "ok"


def main(argv: list[str] | None = None) -> int:
    argparse.ArgumentParser(description=__doc__).parse_args(
        argv if argv is not None else sys.argv[1:])

    healthy = load_policy_text(POLICY).build()
    healthy_benign = healthy.authorize(_benign()).outcome
    healthy2 = load_policy_text(POLICY).build()
    healthy_hostile = healthy2.authorize(_hostile()).outcome

    print("# What the gateway decides while one of its components is broken\n")
    print("STATUS: current\n")
    print("```bash\npython -m benchmarks.stress_faults\n```\n")
    print(f"Healthy baseline: a benign payment is `{healthy_benign}`, an "
          f"out-of-scope read is `{healthy_hostile}`.\n")
    print("| seam | class | benign action | out-of-scope action | verdict |")
    print("| --- | --- | --- | --- | --- |")

    tally: Counter[str] = Counter()
    for label, kind, holder, attribute in SEAMS:
        benign = outcome_with_fault(holder, attribute, _benign())
        hostile = outcome_with_fault(holder, attribute, _hostile())
        result = verdict(kind, benign, hostile, healthy_benign)
        tally[result] += 1
        print(f"| `{label}` | {kind} | {benign} | {hostile} | "
              f"{'ok' if result == 'ok' else '**' + result + '**'} |")

    bad = sum(v for k, v in tally.items() if k not in ("ok", "skipped"))
    print(f"\n{tally['ok']} seam(s) behaved as classified, "
          f"{tally.get('skipped', 0)} skipped, **{bad} did not**.\n")
    if not bad:
        print("No broken component turned a refusal into an allow, and no "
              "bookkeeping\nfailure changed a decision. An attacker who can "
              "make a component fail gains\nnothing by doing it.")
    return 1 if bad else 0


if __name__ == "__main__":
    raise SystemExit(main())
