"""Named profiles: one object that says what a deployment turned on, and why.

`DeployableStack.from_goal` takes fourteen switches that change the security
posture materially, and one of them, `defer_allows_bound`, is a MEASURED
NEGATIVE RESULT kept in the tree so the finding reproduces. A constructor with
fourteen knobs and no named settings has three problems:

- A deployment picks a configuration by accident rather than by decision.
- A published number is a property of a configuration, and nothing recorded
  which one produced it.
- The one switch you must never enable looks exactly like the thirteen you may.

A profile is a frozen set of those switches with a name, a stated intent, and
where one exists, the measurement that justifies each departure from the
default. `stack.profile` already existed as a bare string; this gives it
something to be the name OF.

    from clayseal.capabilities.profiles import AUTONOMOUS, SUPERVISED
    stack = SUPERVISED.build(goal, scope=scope, egress=egress)

THE THREE PROFILES
------------------
They differ on ONE axis: what happens to an action the floor cleared but the
plan did not predict. That is the axis the whole security/utility tradeoff lives
on, and naming three points on it is more useful than naming fourteen switches.

``AUTONOMOUS``  refuse it. No human is watching, so an unexplained consequential
                action does not execute. Highest containment, lowest utility.
``SUPERVISED``  ask about it. A human is on the escalation path, and the audit
                budget bounds how often they are interrupted, because step-up
                policies are attackable by exhaustion.
``BENCHMARK``   what every published number was measured under. Present so a
                result can be reproduced exactly, NOT as a deployment
                recommendation, and it says so.

WHAT A PROFILE DOES NOT DO
--------------------------
It does not choose the mandate, the scope, the egress allow-list or the budgets.
Those are authority and come from the grant. A profile only decides how the
gateway behaves when the grant is silent or the plan is incomplete.
"""
from __future__ import annotations

from dataclasses import dataclass, field, replace
from typing import Any

#: Switches that must never be enabled without a stated reason, and the reason
#: they are dangerous. Checked by `build()`, so a profile cannot quietly turn one
#: on: turning it on requires acknowledging it.
HAZARDS: dict[str, str] = {
    "defer_allows_bound": (
        "MEASURED NEGATIVE RESULT. On AgentDojo travel this took ASR from 5.6% "
        "to 27.8% and dropped blocks from 17 to 3. The motivating argument, an "
        "injected step's destination never clears the binding floor, so this "
        "gate catches nothing the floor missed, holds on banking (0.0% either "
        "way) and is FALSE on travel. The flag exists so the result reproduces, "
        "not so it can be enabled. See benchmarks/results/denial_diagnosis.md."
    ),
    "allow_on_exhaust_acknowledged": (
        "Fail-open on the authorization path. Turns 'the human ran out of "
        "attention' into ALLOW, which pools into the ordinary allow count and "
        "is invisible downstream. Only meaningful with "
        "on_audit_exhausted='allow', and both together are a research "
        "configuration for the attention axis, not a deployment."
    ),
}


@dataclass(frozen=True)
class Profile:
    """A named, frozen set of `DeployableStack.from_goal` switches."""

    name: str
    #: One sentence a reader can check the switches against.
    intent: str
    switches: dict[str, Any] = field(default_factory=dict)
    #: switch -> why it departs from the library default. A profile is reviewable
    #: only if every departure carries its reason, so `build()` refuses a switch
    #: that has none.
    rationale: dict[str, str] = field(default_factory=dict)
    #: Hazards this profile deliberately accepts, mapped to the caller's reason.
    #: Empty for every shipped profile.
    accepted_hazards: dict[str, str] = field(default_factory=dict)

    def with_switches(self, **overrides: Any) -> Profile:
        """A variant of this profile. Reasons are required for what you change.

        Pass ``rationale={"switch": "why"}`` alongside the overrides. Forcing the
        reason at the point of change is what keeps a profile from decaying back
        into fourteen anonymous booleans.
        """
        supplied = dict(overrides.pop("rationale", {}) or {})
        rationale = dict(self.rationale)
        rationale.update(supplied)
        switches = dict(self.switches)
        switches.update(overrides)
        # Every CHANGED switch needs a fresh reason, including one this profile
        # already set. Inheriting the parent's rationale for a value you just
        # changed is worse than having none: the profile then explains a setting
        # it no longer has, which reads as reviewed and is not.
        missing = [
            k for k, v in overrides.items()
            if k not in supplied and self.switches.get(k, object()) != v
        ]
        if missing:
            raise ValueError(
                f"profile {self.name!r}: no rationale given for "
                f"{sorted(missing)}. Pass rationale={{'switch': 'why'}}, a "
                f"switch without a stated reason is how a posture drifts."
            )
        return replace(
            self,
            name=f"{self.name}+custom",
            switches=switches,
            rationale=rationale,
        )

    def build(self, goal: Any, **kwargs: Any) -> Any:
        """Build a `DeployableStack` under this profile.

        ``kwargs`` carry the AUTHORITY, scope, egress, budgets, envelope, and
        the profile carries the POSTURE. A caller that passes a posture switch
        here is overriding the profile silently, so that is refused: change the
        profile with `with_switches`, where the change needs a reason.
        """
        from clayseal.capabilities.deployable_stack import DeployableStack

        collisions = sorted(set(kwargs) & set(self.switches))
        if collisions:
            raise ValueError(
                f"profile {self.name!r} already sets {collisions}; overriding a "
                f"profile switch at the call site hides the posture. Use "
                f"profile.with_switches({collisions[0]}=..., rationale=...)."
            )
        for hazard, why in HAZARDS.items():
            if self.switches.get(hazard) and hazard not in self.accepted_hazards:
                raise ValueError(
                    f"profile {self.name!r} enables {hazard!r} without "
                    f"acknowledging it.\n\n{why}"
                )
        stack = DeployableStack.from_goal(goal, **self.switches, **kwargs)
        object.__setattr__(stack, "profile", self.name)
        return stack

    def describe(self) -> str:
        """The posture as text, for a startup log or a deployment review."""
        lines = [f"profile: {self.name}", f"intent:  {self.intent}", "switches:"]
        for key in sorted(self.switches):
            why = self.rationale.get(key, "")
            lines.append(f"  {key} = {self.switches[key]!r}" + (f"  # {why}" if why else ""))
        return "\n".join(lines)


AUTONOMOUS = Profile(
    name="autonomous",
    intent=(
        "No human on the escalation path. A consequential action the sealed "
        "plan did not predict does not execute."
    ),
    switches={
        "graduated": False,
        "defer_to_binding": False,
        "defer_allows_bound": False,
        "scope_is_advisory": False,
        "enable_replan": True,
        "enable_flow": True,
        "session_rules": False,
        "content_rules": False,
        "strict_mandate": True,
        "audit_budget": 0,
    },
    rationale={
        "graduated": (
            "An unknown egress destination hard-denies. With nobody to confirm "
            "it, STEP_UP and DENY are the same outcome for the agent and DENY "
            "is the one that is legible in the record."
        ),
        "defer_to_binding": (
            "Off. Deferring an off-plan consequential action to the binding "
            "floor is only safe when the resulting STEP_UP reaches somebody."
        ),
        "defer_allows_bound": "Hazard. Never enabled, see profiles.HAZARDS.",
        "scope_is_advisory": (
            "The resource list is treated as an operator grant, not a planner "
            "guess, so replanning may not widen it."
        ),
        "enable_replan": (
            "On. Shape-level replanning is gated on the destination-binding "
            "interlock, and without it an open-ended task posts zero clean "
            "utility (benchmarks/results/agentdyn.md)."
        ),
        "enable_flow": (
            "On. STEP_UP-only, so on this profile it becomes a denial, which "
            "is the correct reading of an unattended secret-derived write."
        ),
        "session_rules": (
            "Off. Corpus-derived patterns should not decide an unattended "
            "deployment's behaviour on traffic unlike those corpora."
        ),
        "content_rules": (
            "Off. Sixty patterns keyed to two benchmark corpora, priced at "
            "19.7 points on SLEIGHT and 11.9 on AgentHarm with the two halves "
            "disjoint and neither transferring, and 0 on BPL "
            "(content_rule_contribution.md). A rule matching `brainfuck` or a "
            "two-package typosquat list decides nothing about this deployment, "
            "and the harm cues fire on `drugs` and `bomb`, which are ordinary "
            "words in a pharmacy or a demolition firm."
        ),
        "strict_mandate": (
            "A mandate that fails to cover a money-moving tool is a startup "
            "failure rather than a silent gap."
        ),
        "audit_budget": (
            "Zero: there is no attention to spend, so a step-up is a denial "
            "rather than an unanswerable question left open."
        ),
    },
)

SUPERVISED = Profile(
    name="supervised",
    intent=(
        "A human answers step-ups. Uncertainty becomes a question, and the "
        "audit budget bounds how many questions the session may ask."
    ),
    switches={
        "graduated": True,
        "defer_to_binding": True,
        "defer_allows_bound": False,
        "scope_is_advisory": False,
        "enable_replan": True,
        "enable_flow": True,
        "session_rules": False,
        "content_rules": False,
        "strict_mandate": True,
        "audit_budget": 8,
    },
    rationale={
        "graduated": (
            "An unknown destination is genuinely ambiguous between an injected "
            "address and one the agent legitimately read, and the two are "
            "indistinguishable when they share a source. STEP_UP halts the "
            "attacker autonomously and lets a human confirm a novel payee."
        ),
        "defer_to_binding": (
            "On. `off-plan and consequential` accounts for 100% of hard false "
            "blocks on the shippable path, and 10 of its 11 denials turned a "
            "task that would have succeeded into one that failed. With a human "
            "on the path those become questions."
        ),
        "defer_allows_bound": "Hazard. Never enabled, see profiles.HAZARDS.",
        "scope_is_advisory": (
            "Default off: only set this when the resource list came from a "
            "planner guess rather than a signed mandate."
        ),
        "enable_replan": "On, same reason as the autonomous profile.",
        "enable_flow": (
            "On. Sound where it fires and incomplete in what it catches, which "
            "is exactly the profile that should ask rather than refuse."
        ),
        "session_rules": (
            "Off. Measured at zero contribution on the benchmark corpora "
            "(benchmarks/results/corpus_rule_contribution.md), which says "
            "nothing about a deployment's own traffic. Measure there before "
            "adopting them."
        ),
        "content_rules": (
            "Off. Sixty patterns keyed to two benchmark corpora, priced at "
            "19.7 points on SLEIGHT and 11.9 on AgentHarm with the two halves "
            "disjoint and neither transferring, and 0 on BPL "
            "(content_rule_contribution.md). A rule matching `brainfuck` or a "
            "two-package typosquat list decides nothing about this deployment, "
            "and the harm cues fire on `drugs` and `bomb`, which are ordinary "
            "words in a pharmacy or a demolition firm."
        ),
        "strict_mandate": "Same as autonomous: uncovered money tools fail at startup.",
        "audit_budget": (
            "Eight. Human attention is the scarce resource the protocol spends, "
            "and an unbounded step-up count is an unbounded exhaustion surface. "
            "Tune it to the deployment; do not remove it."
        ),
    },
)

BENCHMARK = Profile(
    name="benchmark",
    intent=(
        "Reproduces the published numbers exactly. NOT a deployment "
        "recommendation, it exists so a result can be checked."
    ),
    switches={
        "graduated": False,
        "defer_to_binding": False,
        "defer_allows_bound": False,
        "scope_is_advisory": False,
        "enable_replan": True,
        "enable_flow": True,
        "session_rules": True,
        "content_rules": True,
        "strict_mandate": False,
        "audit_budget": None,
    },
    rationale={
        "session_rules": (
            "ON because every published number was produced with the pack on, "
            "and this profile exists to be that configuration. It is NOT "
            "load-bearing: with it off, sleight stays 28/122, agentharm "
            "196/507, BPL joint 52/132 at 2 false blocks, and benign cost stays "
            "0 of 20,619 events "
            "(benchmarks/results/corpus_rule_contribution.md). The corpus "
            "project name one rule carried has been removed. A deployment "
            "profile that leaves this off gives up no measured containment."
        ),
        "content_rules": (
            "ON. Unlike `session_rules`, this pack is worth real containment on "
            "SLEIGHT and AgentHarm, so reproducing those published numbers "
            "requires it. That it is worth them ONLY on the corpora it was "
            "written against is the reason it is off everywhere else."
        ),
        "strict_mandate": (
            "Off: the harnesses build intentionally incomplete mandates in "
            "order to measure the escape."
        ),
        "audit_budget": (
            "Unbounded, which is why supervised-utility figures measured under "
            "this profile must be read with the endorsements-per-task column "
            "beside them. Nobody was charged for the interruptions."
        ),
        "defer_allows_bound": "Hazard. Off even here, see profiles.HAZARDS.",
        "graduated": "Off: the published hard-deny numbers were measured this way.",
        "defer_to_binding": "Off: as measured.",
        "scope_is_advisory": "Off for deterministic corpora; live AgentDojo sets it True.",
        "enable_replan": "On: as measured.",
        "enable_flow": "On: as measured.",
    },
)

PROFILES: dict[str, Profile] = {
    p.name: p for p in (AUTONOMOUS, SUPERVISED, BENCHMARK)
}


def get_profile(name: str) -> Profile:
    if name not in PROFILES:
        raise KeyError(
            f"unknown profile {name!r}; known: {', '.join(sorted(PROFILES))}"
        )
    return PROFILES[name]
