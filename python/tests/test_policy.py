"""The policy document refuses rather than guesses.

Every test here is a case where continuing would produce a gateway that enforces
something other than what the document says. A misread authority document is
worse than a refused one, because the operator believes a control exists.
"""
from __future__ import annotations

import pytest

from clayseal.capabilities.policy import (
    Policy,
    PolicyError,
    compile_policy,
    load_policy,
)

MINIMAL = {
    "version": 1,
    "goal": {"id": "q1", "summary": "summarise the open billing tickets"},
}


def _doc(**extra):
    return {**MINIMAL, **extra}


# --------------------------------------------------------------------------- #
# Refusals
# --------------------------------------------------------------------------- #
def test_a_document_without_a_version_is_refused():
    with pytest.raises(PolicyError, match="no `version`"):
        compile_policy({"goal": {"id": "q", "summary": "s"}})


def test_a_future_version_is_refused_rather_than_read_optimistically():
    with pytest.raises(PolicyError, match="not supported"):
        compile_policy({"version": 99, "goal": {"id": "q", "summary": "s"}})


def test_a_document_without_a_goal_is_refused():
    with pytest.raises(PolicyError, match="`goal` mapping"):
        compile_policy({"version": 1})


def test_an_unknown_profile_is_refused_rather_than_defaulted():
    """There is no safe posture to fall back to when the name is wrong."""
    with pytest.raises(PolicyError, match="unknown profile"):
        compile_policy(_doc(profile="lenient"))


def test_an_unparseable_expiry_is_refused():
    """It would otherwise count as expired and deny every action."""
    with pytest.raises(PolicyError, match="ISO 8601"):
        compile_policy(_doc(expires_at="next tuesday"))


def test_a_tracked_tool_with_no_ceiling_is_refused():
    """The document reads as bounded and the runtime finds no limit."""
    with pytest.raises(PolicyError, match="no ceiling"):
        compile_policy(_doc(budgets={
            "value": {"tracked": {"pay": {"arg": "amount", "budget": "spend"}},
                      "ceilings": {"something_else": "10"}},
        }))


def test_a_value_budget_missing_its_argument_name_is_refused():
    with pytest.raises(PolicyError, match="needs `arg`"):
        compile_policy(_doc(budgets={
            "value": {"tracked": {"pay": {"budget": "spend"}},
                      "ceilings": {"spend": "10"}},
        }))


def test_a_string_where_a_list_belongs_is_refused():
    """`domains: acme.com` silently becomes a set of characters otherwise."""
    with pytest.raises(PolicyError, match="must be a list"):
        compile_policy(_doc(egress={"domains": "acme.com"}))


def test_harmless_tools_must_be_tools_the_agent_can_reach():
    with pytest.raises(PolicyError, match="not in tools.allow"):
        compile_policy(_doc(tools={"allow": ["read_ticket"],
                                   "harmless": ["read_tickets"]}))


def test_a_non_integer_call_ceiling_is_refused():
    with pytest.raises(PolicyError, match="whole number of calls"):
        compile_policy(_doc(budgets={
            "calls": {"tracked": {"send": "emails"}, "ceilings": {"emails": "three"}},
        }))


# --------------------------------------------------------------------------- #
# Compilation
# --------------------------------------------------------------------------- #
def test_the_sections_compile_to_the_objects_the_gateway_takes():
    policy = compile_policy(_doc(
        profile="autonomous",
        expires_at="2030-01-01T00:00:00Z",
        tools={"allow": ["read_ticket", "send_email"], "harmless": ["read_ticket"]},
        paths={"allow": ["out/**"], "deny": [".env"]},
        egress={"domains": ["ACME-Internal.com"], "bind_recipients": True},
        budgets={"calls": {"tracked": {"send_email": "emails"},
                           "ceilings": {"emails": 3}}},
    ))
    assert policy.profile == "autonomous"
    assert policy.allowed_tools == {"read_ticket", "send_email"}
    assert policy.scope.allowed_paths == ["out/**"]
    assert policy.scope.denied_paths == [".env"]
    assert policy.scope.expires_at == "2030-01-01T00:00:00Z"
    # Domains are lowercased, because a destination check that is case sensitive
    # is one an attacker passes by capitalising.
    assert policy.egress.allowed_domains == {"acme-internal.com"}
    assert policy.egress.bind_recipients is True
    assert policy.call_budget.config.ceilings == {"emails": 3}


def test_absent_sections_compile_to_absent_controls_not_permissive_ones():
    policy = compile_policy(MINIMAL)
    assert policy.scope is None
    assert policy.egress is None
    assert policy.allowed_tools is None
    codes = {f.code for f in policy.lint()}
    assert {"no-egress-policy", "no-path-scope", "no-tool-allowlist"} <= codes


# --------------------------------------------------------------------------- #
# The digest
# --------------------------------------------------------------------------- #
def test_the_digest_ignores_key_order_and_notices_a_changed_value():
    a = compile_policy({"version": 1, "goal": {"id": "q", "summary": "s"},
                        "tools": {"allow": ["a", "b"]}})
    b = compile_policy({"tools": {"allow": ["a", "b"]},
                        "goal": {"summary": "s", "id": "q"}, "version": 1})
    assert a.digest() == b.digest()

    c = compile_policy({"version": 1, "goal": {"id": "q", "summary": "s"},
                        "tools": {"allow": ["a", "b", "c"]}})
    assert c.digest() != a.digest()


def test_the_digest_survives_a_yaml_parsed_timestamp(tmp_path):
    path = tmp_path / "policy.yaml"
    path.write_text(
        "version: 1\n"
        "goal:\n  id: q\n  summary: s\n"
        "expires_at: 2030-01-01T00:00:00Z\n"
    )
    assert load_policy(path).digest().startswith("sha256:")


def test_the_built_gateway_carries_the_digest():
    policy = compile_policy(_doc(tools={"allow": ["read_ticket"],
                                        "harmless": ["read_ticket"]}))
    assert policy.build().policy_digest == policy.digest()


# --------------------------------------------------------------------------- #
# Lint
# --------------------------------------------------------------------------- #
def test_lint_reports_what_build_would_refuse():
    """A traceback is a bad way to find out a tool is unbudgeted."""
    policy = compile_policy(_doc(
        profile="supervised",
        tools={"allow": ["issue_refund"]},
    ))
    findings = policy.lint()
    assert any(f.code == "untracked-effectful-tool" and f.level == "error"
               for f in findings)
    with pytest.raises(ValueError, match="uncounted"):
        policy.build()


def test_lint_agrees_with_build_on_declared_harmless():
    """`tools.harmless` reached lint and not the gate, so they disagreed.

    A document could declare a tool harmless, pass `clayseal policy lint` clean,
    and then have the gateway refuse to build on the exact finding the
    declaration was meant to answer. A linter whose verdict does not predict the
    gate's is worse than no linter, because people trust it.
    """
    doc = {
        "version": 1,
        "goal": {"id": "q", "summary": "rotate the staging certificates"},
        "profile": "supervised",
        "tools": {"allow": ["terraform_destroy"], "harmless": ["terraform_destroy"],
                  "effects": {"terraform_destroy": "write"}},
    }
    policy = compile_policy(doc)
    assert [f for f in policy.lint() if f.level == "error"] == []
    policy.build()          # must not raise

    undeclared = compile_policy({**doc, "tools": {"allow": ["terraform_destroy"]}})
    assert [f for f in undeclared.lint() if f.level == "error"]
    with pytest.raises(ValueError, match="uncounted"):
        undeclared.build()


def test_a_verb_outside_the_known_set_is_refused():
    with pytest.raises(PolicyError, match="expected one of"):
        compile_policy(_doc(tools={"allow": ["t"], "effects": {"t": "yeet"}}))


def test_effects_may_not_name_a_tool_that_is_not_allowed():
    with pytest.raises(PolicyError, match="not in tools.allow"):
        compile_policy(_doc(tools={"allow": ["a"], "effects": {"b": "write"}}))


def test_lint_flags_an_allow_all_egress_as_an_error():
    policy = compile_policy(_doc(egress={"allow_all": True}))
    assert any(f.code == "egress-allow-all" and f.level == "error"
               for f in policy.lint())


def test_lint_flags_a_universal_path_pattern():
    policy = compile_policy(_doc(paths={"allow": ["/**"]}))
    assert any(f.code == "path-scope-universal" and f.level == "error"
               for f in policy.lint())


def test_lint_flags_an_expired_grant():
    policy = compile_policy(_doc(expires_at="2020-01-01T00:00:00Z"))
    assert any(f.code == "expired" and f.level == "error" for f in policy.lint())


def test_lint_names_keys_it_ignored():
    """A dropped key is authority the author believes they granted."""
    policy = compile_policy(_doc(egres={"domains": ["typo.example"]}))
    assert "egres" in policy.unknown_keys
    assert any(f.code == "unknown-keys" for f in policy.lint())


def test_lint_puts_errors_before_warnings():
    policy = compile_policy(_doc(egress={"allow_all": True}))
    levels = [f.level for f in policy.lint()]
    assert levels == sorted(levels, key=lambda level: level != "error")


# --------------------------------------------------------------------------- #
# Loading
# --------------------------------------------------------------------------- #
def test_a_missing_file_says_so_rather_than_raising_oserror(tmp_path):
    with pytest.raises(PolicyError, match="cannot read policy"):
        load_policy(tmp_path / "nope.yaml")


def test_invalid_yaml_says_so(tmp_path):
    path = tmp_path / "bad.yaml"
    path.write_text("version: 1\n  goal: [oops\n")
    with pytest.raises(PolicyError, match="not valid YAML"):
        load_policy(path)


def test_a_top_level_list_is_refused(tmp_path):
    path = tmp_path / "list.yaml"
    path.write_text("- version: 1\n")
    with pytest.raises(PolicyError, match="mapping at the top level"):
        load_policy(path)


def test_describe_is_readable_and_names_the_source(tmp_path):
    path = tmp_path / "policy.yaml"
    path.write_text(
        "version: 1\ngoal:\n  id: q\n  summary: s\nprofile: supervised\n"
    )
    text = load_policy(path).describe()
    assert str(path) in text
    assert "profile: supervised" in text
    assert "sha256:" in text


def test_the_example_policy_in_the_repo_is_valid():
    """The file the README tells people to copy has to compile and lint clean."""
    from pathlib import Path

    example = Path(__file__).resolve().parents[2] / "examples" / "policy.yaml"
    if not example.exists():
        pytest.skip("examples/policy.yaml not present in this checkout")
    policy = load_policy(example)
    assert isinstance(policy, Policy)
    errors = [f for f in policy.lint() if f.level == "error"]
    assert not errors, errors


# --------------------------------------------------------------------------- #
# Rolling windows and object identity
# --------------------------------------------------------------------------- #
def test_a_window_compiles_to_a_windowed_budget():
    from clayseal.capabilities.windowed_budget import WindowedValueBudget

    policy = compile_policy(_doc(budgets={"value": {
        "ceilings": {"roll": "3000"},
        "windows": {"roll": 86400},
        "tracked": {"pay": {"arg": "amount", "budget": "roll"}},
    }}))
    assert isinstance(policy.value_budget, WindowedValueBudget)
    assert policy.value_budget.windows == {"roll": 86400.0}


def test_no_window_still_compiles_to_the_session_budget():
    """The default has to be unchanged: every published number predates windows."""
    from clayseal.capabilities.value_budget import SessionValueBudget
    from clayseal.capabilities.windowed_budget import WindowedValueBudget

    policy = compile_policy(_doc(budgets={"value": {
        "ceilings": {"flat": "3000"},
        "tracked": {"pay": {"arg": "amount", "budget": "flat"}},
    }}))
    assert isinstance(policy.value_budget, SessionValueBudget)
    assert not isinstance(policy.value_budget, WindowedValueBudget)


@pytest.mark.parametrize("window", [0, -1, "24h"])
def test_a_malformed_window_is_refused(window):
    with pytest.raises(PolicyError, match="positive"):
        compile_policy(_doc(budgets={"value": {
            "ceilings": {"roll": "1"}, "windows": {"roll": window},
            "tracked": {"pay": {"arg": "amount", "budget": "roll"}},
        }}))


def test_a_window_on_a_budget_with_no_ceiling_is_refused():
    """A window on nothing is not a control."""
    with pytest.raises(PolicyError, match="no ceiling"):
        compile_policy(_doc(budgets={"value": {
            "ceilings": {"roll": "1"}, "windows": {"other": 60},
            "tracked": {"pay": {"arg": "amount", "budget": "roll"}},
        }}))


def test_identity_compiles_to_an_effect_spec_and_refuses_a_duplicate():
    """A ceiling answers "is the total under the limit" while the same invoice is
    paid twice. Both halves of "once per object, under ceiling" are real."""
    from clayseal.capabilities.value_budget import EffectSpec

    policy = compile_policy(_doc(budgets={"value": {
        "ceilings": {"payroll": "11000"},
        "tracked": {"pay": {"arg": "amount", "budget": "payroll",
                            "identity": ["employee", "period"]}},
    }}))
    spec = policy.value_budget.config.tracked["pay"]
    assert isinstance(spec, EffectSpec)
    assert spec.identity_args == ("employee", "period")

    budget = policy.value_budget
    for employee, expected in (("Ada", True), ("Bran", True), ("Ada", False)):
        res = budget.reserve("pay", {"employee": employee, "period": "Q4",
                                     "amount": 1000})
        assert res.allowed is expected, employee
        if res.allowed:
            res.commit()


def test_identity_must_be_a_list_of_argument_names():
    with pytest.raises(PolicyError, match="list of"):
        compile_policy(_doc(budgets={"value": {
            "ceilings": {"p": "1"},
            "tracked": {"pay": {"arg": "amount", "budget": "p",
                                "identity": "employee"}},
        }}))


def test_a_tracked_entry_with_identity_still_needs_its_ceiling():
    """The ceiling check has to read the EffectSpec form as well as the tuple."""
    with pytest.raises(PolicyError, match="no ceiling"):
        compile_policy(_doc(budgets={"value": {
            "ceilings": {"other": "1"},
            "tracked": {"pay": {"arg": "amount", "budget": "missing",
                                "identity": ["id"]}},
        }}))


# ------------------------------------------------- a policy held as text ---
def test_a_policy_can_be_compiled_from_text():
    """A grant that arrives over a wire has no file to be read from."""
    from clayseal.capabilities.policy import load_policy_text

    policy = load_policy_text(
        "version: 1\ngoal: {id: g, summary: s}\ntools: {allow: [read_file]}\n",
        source="the config service")
    assert policy.verb_for("read_file") == "read"


def test_text_errors_name_where_the_text_came_from():
    from clayseal.capabilities.policy import PolicyError, load_policy_text

    with pytest.raises(PolicyError, match="the config service"):
        load_policy_text("just a string", source="the config service")


# ------------------------------------- a deployment where no session exists ---
def test_a_stateless_deployment_refuses_a_session_scoped_ceiling():
    """MCP 2026-07-28 removes the handshake and the session id header.

    A Streamable HTTP deployment behind a load balancer has no session for a
    ceiling to be counted over, so a per-session ceiling there does not merely
    weaken: it resets on every request and the aggregate rung is inert. A
    warning is right where a session exists and wrong where one cannot.
    """
    from clayseal.capabilities.policy import load_policy_text

    document = """
version: 1
goal: {id: g, summary: Pay invoices}
profile: supervised
tools: {allow: [pay_vendor], effects: {pay_vendor: transfer}}
budgets:
  value:
    ceilings: {payments: "50000"}
    tracked: {pay_vendor: {arg: amount, budget: payments}}
"""
    session_scoped = load_policy_text(document)
    assert not session_scoped.stateless
    levels = {f.level for f in session_scoped.lint()
              if f.code == "session-scoped-ceiling"}
    assert levels == {"warning"}

    stateless = load_policy_text(document + "deployment: {stateless: true}\n")
    assert stateless.stateless
    finding = next(f for f in stateless.lint()
                   if f.code == "session-scoped-ceiling")
    assert finding.level == "error"
    assert "principal ledger" in finding.message


def test_the_deployment_section_is_a_known_key():
    """An unknown top-level key is reported, so this one has to be declared."""
    from clayseal.capabilities.policy import load_policy_text

    policy = load_policy_text(
        "version: 1\ngoal: {id: g, summary: s}\n"
        "deployment: {stateless: true}\n")
    assert not [f for f in policy.lint() if "ignored" in f.code
                and "deployment" in f.message]
