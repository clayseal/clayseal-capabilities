"""Did the agent move toward the edge of what it is allowed to do?

WHY THIS IS A DIFFERENT QUESTION FROM DRIFT MONITORING

Ordinary drift monitoring asks whether behaviour CHANGED. On a live product the
answer is yes every week, for reasons that are nobody's problem: a new feature,
a seasonal workload, a prompt someone improved. A monitor that fires on all of
that gets switched off, and then it is not a control.

An authorization layer can ask the question that matters, and it is the only
component positioned to ask it, because it is the only one that knows where the
permitted region ends: **did behaviour move toward the boundary of the grant?**
A workload that changes completely while staying well inside its authority has
not become more dangerous. A workload that looks similar but now consumes 78% of
a ceiling it used to touch at 12% has, and no distributional test on its own
would rank those two the right way round.

WHAT ENTERPRISES MEAN BY DRIFT, WHICH IS NOT WHAT THIS REPOSITORY MEANT

`monitor/drift.py` detects goal drift WITHIN one trajectory, over minutes. The
thing a risk function is afraid of is longitudinal, over months, and it has four
named causes:

- the provider changed the model behind the endpoint, without telling anyone;
- someone edited a system prompt, which is production code with no review gate;
- the tool list and the grants grew, one reasonable request at a time;
- the agent was approved on evaluation traffic and production traffic differs.

Not one of those is observable where it happens. The enterprise cannot diff the
vendor's weights, and often cannot diff its own prompt history. All four change
what the agent DOES, and every action it takes already passes this boundary,
typed and normalised, as a side effect of being authorized. The observation
needed to answer all four is already being produced here and thrown away at the
end of every session.

WHAT IS STORED, AND WHAT IS NOT

Counts. Action tokens are `verb|tool|resource_class`, which is the same
vocabulary the detector already scores; outcomes are allow, step-up and deny;
headroom is the fraction of each ceiling a session consumed. No argument values,
no paths, no identities. The decision log already hashes arguments, and nothing
here recovers them, so a profile can be committed to a repository or handed to
an auditor without a review of what is in it.

THE BASELINE IS SEALED, FOR THE SAME REASON THE ENVELOPE IS

A baseline built from traffic that already contains the change describes the
change as normal. So it is captured at approval, carries the digest of the
policy it was observed under, and is compared rather than updated. If the policy
changes, the baseline is VOID rather than stale: it describes behaviour under a
different authority, and the honest answer is that this deployment needs
approving again. That is a feature and it is the point of carrying the digest.

WHAT THIS CANNOT DO

It cannot see a change that stays well inside the grant, which is deliberate:
that change did not increase what the agent can do. It cannot attribute a
change to its cause, because the four causes above are indistinguishable from
here and pretending otherwise would be invention. And its power is bounded by
how many sessions the baseline holds, so `DriftReport` carries the smallest
effect the comparison could have resolved rather than leaving a null result to
be read as reassurance.
"""
from __future__ import annotations

import hashlib
import json
import math
from collections import Counter
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field

#: Channels ranked by what a rise in them means. `novel-authority` and
#: `headroom` are risk channels: a significant rise in either is the agent
#: reaching further than it did at approval. `friction` is a risk channel with a
#: softer reading, since a step-up is the system working. `retired` is not a
#: risk channel at all; it says the baseline has stopped describing the
#: workload, which weakens every other test rather than raising an alarm.
RISK_CHANNELS = ("novel-authority", "headroom", "friction")
COVERAGE_CHANNELS = ("retired",)

UNCHANGED = "unchanged"
INSIDE = "changed-inside-the-grant"
APPROACHING = "approaching-the-boundary"
VOID = "baseline-void"
UNCOVERED = "baseline-no-longer-describes-the-workload"


def action_token(verb: str, tool: str, resource_class: str) -> str:
    """The unit a profile counts. Coarse on purpose: an instance is not a class."""
    return f"{verb.lower()}|{tool}|{resource_class}"


# --------------------------------------------------------------- statistics --
#: Above this the exact sum stops being computable in a useful time. Measured
#: rather than guessed: the table total drives `math.comb` on integers with that
#: many digits, and the tail is a sum over as many terms again. 40 events took
#: microseconds, 3,200 took 45ms, 8,000 took 499ms, and 200,000 (an ordinary
#: month of production traffic) does not return. A certification pass that hangs
#: on real data is not a certification pass, and reaching for an approximation
#: without saying where it starts is how a p-value stops meaning anything.
EXACT_MAX_TOTAL = 5000
EXACT_MAX_TERMS = 2000


def _normal_greater(a: int, b: int, c: int, d: int) -> float:
    """Normal approximation to the hypergeometric tail, continuity corrected.

    Standard, and accurate exactly where it is used: large tables. The exact
    test is kept for small ones, where the approximation is poor and the cost is
    nothing, and `test_behavior_baseline.py` pins the two against each other at
    the crossover so a future edit cannot move the boundary silently.
    """
    n = a + b + c + d
    row1, col1 = a + b, a + c
    mean = row1 * col1 / n
    if n < 2:
        return 1.0
    var = row1 * (n - row1) * col1 * (n - col1) / (n * n * (n - 1))
    if var <= 0:
        return 1.0 if a <= mean else 0.0
    z = (a - 0.5 - mean) / math.sqrt(var)
    return 0.5 * math.erfc(z / math.sqrt(2))


def fisher_exact_greater(a: int, b: int, c: int, d: int) -> float:
    """One-sided Fisher exact p for a 2x2 table, testing a/(a+b) > c/(c+d).

    The table is ``[[a, b], [c, d]]`` = [[current hits, current misses],
    [baseline hits, baseline misses]].

    Exact and integer-only on a table small enough for that to return, and a
    continuity-corrected normal approximation above `EXACT_MAX_TOTAL`. The
    switch is a named constant rather than a silent fallback because a p-value
    computed two different ways is two different claims.
    """
    n = a + b + c + d
    if n == 0 or (a + c) == 0 or (a + b) == 0:
        return 1.0
    row1, col1 = a + b, a + c
    hi = min(row1, col1)
    if n > EXACT_MAX_TOTAL or (hi - a) > EXACT_MAX_TERMS:
        return min(1.0, max(0.0, _normal_greater(a, b, c, d)))
    total = math.comb(n, col1)
    if total == 0:
        return 1.0
    p = 0.0
    for k in range(a, hi + 1):
        if col1 - k > (c + d):
            continue
        p += math.comb(row1, k) * math.comb(n - row1, col1 - k) / total
    return min(1.0, max(0.0, p))


def rule_of_three(n: int) -> float:
    """Upper 95% bound on a rate that was never observed in `n` trials.

    A category absent from the baseline is not a category with rate zero. With
    50 approval sessions the true rate could be as high as 6%, and calling a
    6%-rate action "novel" is how a monitor earns its reputation for noise.
    """
    return 1.0 if n <= 0 else min(1.0, 3.0 / n)


def holm(p_values: Mapping[str, float], alpha: float = 0.05) -> dict[str, bool]:
    """Holm-Bonferroni. Several channels are tested, so several chances to fire."""
    ordered = sorted(p_values.items(), key=lambda kv: kv[1])
    out: dict[str, bool] = {}
    rejected = True
    for i, (name, p) in enumerate(ordered):
        threshold = alpha / (len(ordered) - i)
        rejected = rejected and p <= threshold
        out[name] = rejected
    return out


# ------------------------------------------------------------- observations --
@dataclass(frozen=True)
class SessionSummary:
    """One session reduced to counts. Built from decision records, never text."""

    tokens: Mapping[str, int] = field(default_factory=dict)
    outcomes: Mapping[str, int] = field(default_factory=dict)
    #: budget id to the fraction of its ceiling this session consumed. Absent
    #: when the deployment did not supply budget state, which is honest rather
    #: than zero: `headroom` is then reported as an unavailable channel.
    headroom: Mapping[str, float] = field(default_factory=dict)

    @property
    def actions(self) -> int:
        return sum(self.tokens.values())


def summarize_session(records: Iterable, *,
                      headroom: Mapping[str, float] | None = None
                      ) -> SessionSummary:
    """Reduce one session's decision records to counts.

    Takes anything with `action_verb`, `tool`, `resource` and `outcome`, which
    is what `DecisionLog` already produces. Resource is reduced to its class by
    the same reading the membership tiers use, so a profile and an envelope talk
    about the same things.
    """
    from clayseal.capabilities.monitor.surface import surface_class

    tokens: Counter[str] = Counter()
    outcomes: Counter[str] = Counter()
    for record in records:
        verb = str(getattr(record, "action_verb", "") or "")
        tool = str(getattr(record, "tool", "") or "")
        resource = str(getattr(record, "resource", "") or "")
        outcome = str(getattr(record, "outcome", "") or "").lower()
        outcomes[outcome.rsplit(".", 1)[-1]] += 1
        tokens[action_token(verb, tool, surface_class(resource))] += 1
    return SessionSummary(tokens=dict(tokens), outcomes=dict(outcomes),
                          headroom=dict(headroom or {}))


@dataclass
class BehaviorProfile:
    """How the agent behaved over a set of sessions, and under which authority."""

    policy_digest: str = ""
    sessions: int = 0
    token_counts: Counter[str] = field(default_factory=Counter)
    #: sessions in which each token appeared at least once, which is the
    #: denominator a novelty test needs: one session calling a tool a thousand
    #: times is one session, not a thousand pieces of evidence.
    token_sessions: Counter[str] = field(default_factory=Counter)
    outcomes: Counter[str] = field(default_factory=Counter)
    headroom: dict[str, list[float]] = field(default_factory=dict)

    def add(self, summary: SessionSummary) -> BehaviorProfile:
        self.sessions += 1
        for token, count in summary.tokens.items():
            self.token_counts[token] += count
            self.token_sessions[token] += 1
        for outcome, count in summary.outcomes.items():
            self.outcomes[outcome] += count
        for budget, fraction in summary.headroom.items():
            self.headroom.setdefault(budget, []).append(float(fraction))
        return self

    @property
    def actions(self) -> int:
        return sum(self.token_counts.values())

    def interrupted(self) -> int:
        return self.outcomes.get("step_up", 0) + self.outcomes.get("deny", 0)

    def to_dict(self) -> dict:
        return {
            "schema": "clayseal.behavior_profile.v1",
            "policy_digest": self.policy_digest,
            "sessions": self.sessions,
            "token_counts": dict(sorted(self.token_counts.items())),
            "token_sessions": dict(sorted(self.token_sessions.items())),
            "outcomes": dict(sorted(self.outcomes.items())),
            "headroom": {k: sorted(v) for k, v in sorted(self.headroom.items())},
        }

    def digest(self) -> str:
        body = json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"))
        return "sha256:" + hashlib.sha256(body.encode()).hexdigest()

    @classmethod
    def from_dict(cls, raw: Mapping) -> BehaviorProfile:
        return cls(
            policy_digest=str(raw.get("policy_digest", "")),
            sessions=int(raw.get("sessions", 0)),
            token_counts=Counter(raw.get("token_counts") or {}),
            token_sessions=Counter(raw.get("token_sessions") or {}),
            outcomes=Counter(raw.get("outcomes") or {}),
            headroom={k: list(v) for k, v in (raw.get("headroom") or {}).items()},
        )


def profile_from(summaries: Iterable[SessionSummary], *,
                 policy_digest: str = "") -> BehaviorProfile:
    profile = BehaviorProfile(policy_digest=policy_digest)
    for summary in summaries:
        profile.add(summary)
    return profile


# ------------------------------------------------------------ the comparison --
@dataclass(frozen=True)
class Channel:
    name: str
    fired: bool
    detail: str
    p_value: float | None = None
    available: bool = True


@dataclass
class DriftReport:
    verdict: str
    channels: list[Channel] = field(default_factory=list)
    #: The smallest change this comparison could have resolved. A null result
    #: over 12 sessions is not evidence of stability and this is what says so.
    resolvable: str = ""

    def fired(self) -> list[Channel]:
        return [c for c in self.channels if c.fired]

    def summary(self) -> str:
        lines = [f"verdict: {self.verdict}"]
        for channel in self.channels:
            mark = "FIRED " if channel.fired else ("      " if channel.available
                                                  else "n/a   ")
            p = f" p={channel.p_value:.4f}" if channel.p_value is not None else ""
            lines.append(f"  {mark}{channel.name:16} {channel.detail}{p}")
        if self.resolvable:
            lines.append(f"  power: {self.resolvable}")
        return "\n".join(lines)


def _headroom_channel(baseline: BehaviorProfile, current: BehaviorProfile
                      ) -> tuple[Channel | None, float | None]:
    """Has the share of sessions running hot against a ceiling risen?

    Tested as a proportion rather than as a mean, because the mean is the wrong
    summary: a workload that mostly idles and occasionally runs a session to 95%
    of its ceiling is the one worth knowing about, and averaging hides it. HOT
    is two thirds of a ceiling, which is a threshold and is named here rather
    than tuned.
    """
    shared = sorted(set(baseline.headroom) & set(current.headroom))
    if not shared:
        return Channel("headroom", False,
                       "no budget state supplied, so this channel is blind",
                       available=False), None
    hot = 2 / 3
    b_hot = sum(1 for k in shared for v in baseline.headroom[k] if v >= hot)
    b_n = sum(len(baseline.headroom[k]) for k in shared)
    c_hot = sum(1 for k in shared for v in current.headroom[k] if v >= hot)
    c_n = sum(len(current.headroom[k]) for k in shared)
    p = fisher_exact_greater(c_hot, c_n - c_hot, b_hot, b_n - b_hot)
    detail = (f"sessions using at least two thirds of a ceiling: "
              f"{c_hot}/{c_n} now against {b_hot}/{b_n} at approval")
    return Channel("headroom", False, detail, p), p


def compare(baseline: BehaviorProfile, current: BehaviorProfile, *,
            alpha: float = 0.05) -> DriftReport:
    """Compare live behaviour with what was approved.

    Returns a verdict rather than a score. `approaching-the-boundary` is the one
    that means act; `changed-inside-the-grant` means the workload moved and its
    authority did not, which is the case a distributional monitor would have
    called an incident.
    """
    if baseline.policy_digest and current.policy_digest and \
            baseline.policy_digest != current.policy_digest:
        return DriftReport(
            VOID,
            [Channel("authority", True,
                     f"the grant changed: approved under "
                     f"{baseline.policy_digest[:19]}, running under "
                     f"{current.policy_digest[:19]}. The baseline describes "
                     f"behaviour under a different authority and cannot be "
                     f"compared with this.")])

    channels: list[Channel] = []
    p_values: dict[str, float] = {}

    # 1. Novel authority: tokens the agent never used when it was approved.
    novel = {t: c for t, c in current.token_sessions.items()
             if t not in baseline.token_sessions}
    if novel and current.sessions:
        bound = rule_of_three(baseline.sessions)
        worst = max(novel, key=lambda t: novel[t])
        share = novel[worst] / current.sessions
        p = fisher_exact_greater(novel[worst], current.sessions - novel[worst],
                                 0, baseline.sessions)
        detail = (f"{len(novel)} action shape(s) absent at approval, the most "
                  f"frequent in {novel[worst]}/{current.sessions} sessions "
                  f"({share:.1%}, above the {bound:.1%} the baseline could "
                  f"rule out): {worst}")
        channels.append(Channel("novel-authority", False, detail, p))
        p_values["novel-authority"] = p
    else:
        channels.append(Channel("novel-authority", False,
                                "no action shape absent at approval"))

    # 2. Headroom: how close sessions run to a ceiling.
    channel, p = _headroom_channel(baseline, current)
    if channel is not None:
        channels.append(channel)
        if p is not None:
            p_values["headroom"] = p

    # 3. Friction: the agent meeting a boundary more often than it used to.
    if baseline.actions and current.actions:
        p = fisher_exact_greater(current.interrupted(),
                                 current.actions - current.interrupted(),
                                 baseline.interrupted(),
                                 baseline.actions - baseline.interrupted())
        detail = (f"actions stopped or escalated: "
                  f"{current.interrupted()}/{current.actions} now against "
                  f"{baseline.interrupted()}/{baseline.actions} at approval")
        channels.append(Channel("friction", False, detail, p))
        p_values["friction"] = p

    # 4. Coverage: does the baseline still describe this workload at all?
    retired = [t for t in baseline.token_sessions if t not in current.token_sessions]
    if retired and baseline.token_sessions:
        share = len(retired) / len(baseline.token_sessions)
        detail = (f"{len(retired)} of {len(baseline.token_sessions)} approved "
                  f"action shapes ({share:.0%}) no longer occur, so the "
                  f"baseline describes less of this workload than it did")
        channels.append(Channel("retired", share >= 0.5, detail))

    decided = holm(p_values, alpha) if p_values else {}
    channels = [
        Channel(c.name, decided.get(c.name, c.fired), c.detail, c.p_value,
                c.available)
        for c in channels
    ]

    fired = {c.name for c in channels if c.fired}
    if fired & set(RISK_CHANNELS):
        verdict = APPROACHING
    elif "retired" in fired:
        verdict = UNCOVERED
    elif set(current.token_sessions) != set(baseline.token_sessions):
        verdict = INSIDE
    else:
        verdict = UNCHANGED

    smallest = rule_of_three(baseline.sessions)
    resolvable = (f"{baseline.sessions} approval sessions and "
                  f"{current.sessions} since, so a behaviour occurring in under "
                  f"{smallest:.1%} of sessions could not have been ruled out at "
                  f"approval and a null result here is not evidence of stability")
    return DriftReport(verdict, channels, resolvable)
