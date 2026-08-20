"""The declared policy and the scenario's own oracle must agree.

A benchmark that publishes a rule and then scores against a different one is
worse than a benchmark with no stated rule, because the stated rule is what a
reader checks the result against.

These are written so agreement is not a tautology. `policies.py` declares each
threshold independently of the closure `violated()` reads it from, so when the
two agree that is evidence the transcription is right, and when they disagree one
of them is wrong and the test says which trajectory separates them.

They also pin the property that makes the comparison fair at all: **every
condition receives the policy.** Before that, only the ClaySeal condition was
configured with the threshold and the other two were never told, so the published
table measured who got the memo rather than which architecture can enforce a rule.
"""
from __future__ import annotations

import pytest

from benchmarks.bpl.policies import CORE_POLICIES, coverage, policy_for
from benchmarks.bpl.policy import Policy, evaluate
from benchmarks.bpl.registry import SCENARIOS
from benchmarks.bpl.schema import run_script
from benchmarks.bpl.suites import scenarios_in_suite

CORE = scenarios_in_suite("core")


def _scenario(name: str):
    entry = SCENARIOS[name]
    return entry() if callable(entry) else entry


def _declarative(policy: Policy) -> bool:
    """Does this policy state anything a machine can check on its own?"""
    return any(r.kind != "custom" for r in policy.rules)


def test_every_core_scenario_declares_a_policy():
    missing = [n for n in CORE if not policy_for(n).rules]
    assert not missing, f"Core-12 scenarios with no declared policy: {missing}"


@pytest.mark.parametrize("name", CORE)
def test_the_violating_script_breaks_the_declared_policy(name: str):
    """The trajectory the scenario calls a violation must break the stated rule.

    If it does not, the scenario is testing something other than what it
    published — the exact failure this file exists to prevent.
    """
    scen = _scenario(name)
    policy = policy_for(name)
    if not _declarative(policy):
        pytest.skip(f"{name} states its rule in prose only; oracle owns it")
    if not scen.violating_script:
        pytest.skip("no scripted violating trajectory")

    broken = evaluate(policy, list(scen.violating_script))
    assert broken, (
        f"{name}: the violating script does not break the declared policy.\n"
        f"policy: {policy.as_text()}\n"
        f"script: {list(scen.violating_script)[:6]}"
    )


@pytest.mark.parametrize("name", CORE)
def test_the_compliant_script_satisfies_the_declared_policy(name: str):
    """And the compliant trajectory must not break it.

    Without this half, a policy that flags everything would pass the test above.
    """
    scen = _scenario(name)
    policy = policy_for(name)
    if not _declarative(policy):
        pytest.skip(f"{name} states its rule in prose only; oracle owns it")
    if not scen.compliant_script:
        pytest.skip("no scripted compliant trajectory")

    broken = evaluate(policy, list(scen.compliant_script))
    assert not broken, (
        f"{name}: the compliant script breaks the declared policy: {broken}\n"
        f"policy: {policy.as_text()}"
    )


@pytest.mark.parametrize("name", CORE)
def test_policy_and_oracle_agree_on_both_scripts(name: str):
    """The transcription check.

    `policies.py` writes the threshold out by hand; `violated()` reads it from
    the builder's own variable. Agreement across both trajectories is what says
    the hand-written one is right.
    """
    scen = _scenario(name)
    policy = policy_for(name)
    if not _declarative(policy):
        pytest.skip(f"{name} states its rule in prose only; oracle owns it")

    for label, script, expected in (
        ("violating", scen.violating_script, True),
        ("compliant", scen.compliant_script, False),
    ):
        if not script:
            continue
        env = run_script(scen, script)
        oracle = bool(scen.violated(env))
        declared = bool(evaluate(policy, list(script)))
        assert oracle == expected, (
            f"{name}: the {label} script does not match its own oracle "
            f"(oracle said {oracle}, script is named {label})"
        )
        assert declared == oracle, (
            f"{name}: policy and oracle disagree on the {label} script — "
            f"policy says violated={declared}, oracle says {oracle}.\n"
            f"policy: {policy.as_text()}"
        )


def test_policy_coverage_is_reported_not_implied():
    """"Not yet migrated" must not read as "has no rule"."""
    declared, total = coverage()
    assert declared == len(CORE_POLICIES)
    assert declared >= len(CORE), "the leaderboard set must be fully declared"
    assert total > declared, "coverage claim is stale; the pack has grown"


def test_a_policy_states_its_rule_in_words():
    """The text is what non-declarative conditions consume, and what the paper
    prints. An empty statement is a rule nobody can act on."""
    for name, policy in CORE_POLICIES.items():
        text = policy.as_text()
        assert text.startswith("Applicable policy:"), name
        for rule in policy.rules:
            assert rule.statement.strip(), f"{name}: empty rule statement"
            assert rule.statement.rstrip().endswith("."), (
                f"{name}: rule statement is not a sentence: {rule.statement!r}"
            )


# --------------------------------------------------------------------------- #
# Discrimination: a rule must distinguish the case it claims to be about.
#
# Found by negative control. Corrupting `group_by="vendor"` to a nonexistent
# field left every test passing, because three POs of 9,000 to three DIFFERENT
# vendors also exceed 10,000 in TOTAL — so a global ceiling and a per-vendor
# ceiling agree on the scripted trajectory and the tests above cannot tell them
# apart. A grouped rule that is silently ungrouped is the difference between
# "no vendor may receive more than 10k" and "no more than 10k may be spent",
# which are different policies with different violations.
# --------------------------------------------------------------------------- #
GROUPED = [(n, r) for n, p in CORE_POLICIES.items()
           for r in p.rules if r.params.get("group_by")]


def test_there_are_grouped_rules_to_check():
    assert GROUPED, "no grouped rules; this file's discrimination check is vacuous"


@pytest.mark.parametrize("name,rule", GROUPED, ids=[f"{n}:{r.params['group_by']}"
                                                    for n, r in GROUPED])
def test_a_grouped_ceiling_is_actually_grouped(name: str, rule):
    """Spread across groups must pass where the same total in one group fails."""
    tool = rule.params["tools"][0]
    arg, group = rule.params["arg"], rule.params["group_by"]
    limit = float(rule.params["limit"])
    policy = Policy(rules=(rule,))

    # Three payments at 60% of the limit each: 1.8x the limit in total.
    each = limit * 0.6
    spread = [(tool, {arg: each, group: f"g{i}"}) for i in range(3)]
    concentrated = [(tool, {arg: each, group: "g0"}) for _ in range(3)]

    assert not evaluate(policy, spread), (
        f"{name}: {each*3:,.0f} spread over three {group}s was flagged — the "
        f"rule is behaving as a GLOBAL ceiling, not a per-{group} one"
    )
    assert evaluate(policy, concentrated), (
        f"{name}: {each*3:,.0f} concentrated on one {group} was not flagged"
    )


MULTI = [(n, p) for n, p in CORE_POLICIES.items()
         if len([r for r in p.rules if r.kind != "custom"]) > 1]


@pytest.mark.parametrize("name,policy", MULTI, ids=[n for n, _ in MULTI])
def test_each_rule_in_a_multi_rule_policy_can_fire_alone(name: str, policy: Policy):
    """One rule masking another hides a mis-transcribed threshold.

    `cumulative-impact-permits` carries a per-site and a portfolio ceiling.
    Corrupting the per-site rule left the tests green because the portfolio rule
    fired on the same trajectory.
    """
    declarative = [r for r in policy.rules if r.kind != "custom"]
    for rule in declarative:
        alone = Policy(rules=(rule,))
        tool = rule.params["tools"][0]
        limit = float(rule.params["limit"])
        group = rule.params.get("group_by")
        arg = rule.params.get("arg")
        if rule.kind == "aggregate_ceiling":
            call = {arg: limit * 2}
            if group:
                call[group] = "g0"
            trajectory = [(tool, call)]
        else:
            trajectory = [(tool, {}) for _ in range(int(limit) + 1)]
        assert evaluate(alone, trajectory), (
            f"{name}: rule {rule.statement!r} cannot fire on its own — it is "
            f"unreachable, or its argument name is wrong"
        )


# --------------------------------------------------------------------------- #
# Schema grounding: a rule's field names must exist on the tools it names.
#
# The second thing negative control found. `test_a_grouped_ceiling_is_actually_
# grouped` builds synthetic calls out of the RULE's own field names, so a rule
# naming a field that does not exist is still self-consistent on synthetic data
# and the test passes. Corrupting `arg="tons"` to `arg="wrong_arg"` and
# `group_by="vendor"` to a nonexistent field left all 40 tests green.
#
# The check that bites reads the tool's OpenAI schema — the same schema the model
# is given — and requires every field the rule references to be a real parameter.
# A rule that sums a field the tool does not have sums nothing, and silently
# scores every trajectory compliant.
# --------------------------------------------------------------------------- #
def _tool_params(scen, tool: str) -> set[str]:
    for t in scen.tools:
        fn = t.get("function", {})
        if fn.get("name") == tool:
            return set(fn.get("parameters", {}).get("properties") or {})
    return set()


FIELDED = [
    (n, r) for n, p in CORE_POLICIES.items() for r in p.rules
    if r.params.get("arg") or r.params.get("group_by")
]


def test_there_are_fielded_rules_to_check():
    assert FIELDED, "no rules reference tool fields; this check is vacuous"


@pytest.mark.parametrize("name,rule", FIELDED,
                         ids=[f"{n}:{r.params.get('arg') or r.params.get('group_by')}"
                              for n, r in FIELDED])
def test_rule_fields_exist_on_the_tools_they_name(name: str, rule):
    scen = _scenario(name)
    for tool in rule.params.get("tools", []):
        params = _tool_params(scen, tool)
        assert params, f"{name}: tool {tool!r} is not in the scenario's schema"
        for key in ("arg", "group_by"):
            field_name = rule.params.get(key)
            if not field_name:
                continue
            assert field_name in params, (
                f"{name}: rule references {key}={field_name!r}, which is not a "
                f"parameter of {tool!r} (has: {sorted(params)}). A rule that "
                f"sums a field the tool does not have sums nothing and scores "
                f"every trajectory compliant."
            )


@pytest.mark.parametrize("name", CORE)
def test_rules_only_name_tools_the_scenario_actually_offers(name: str):
    scen = _scenario(name)
    offered = {t["function"]["name"] for t in scen.tools}
    for rule in policy_for(name).rules:
        for tool in rule.params.get("tools", []):
            assert tool in offered, (
                f"{name}: policy names tool {tool!r}, not offered by the "
                f"scenario (offers: {sorted(offered)})"
            )
        dest_tool = rule.params.get("tool")
        if dest_tool:
            assert dest_tool in offered, (
                f"{name}: policy names tool {dest_tool!r}, not offered"
            )
