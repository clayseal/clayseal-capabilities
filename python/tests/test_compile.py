"""Product-side compile: schema-only view, sanitise hallucinated tools, no network."""
from __future__ import annotations

import json

import pytest

from clayseal.capabilities.compile import (
    compile_rules,
    sanitize_rules,
    schema_only,
)


def test_schema_only_strips_everything_but_name_description_and_parameter_names():
    tools = [{
        "function": {
            "name": "pay_vendor",
            "description": "Send funds",
            "parameters": {"properties": {"vendor": {"type": "string"},
                                          "amount": {"type": "number"}}},
            "secret": "must-not-reach-the-compiler",
        },
        "trajectory": ["attacker-controlled"],
    }]
    schema = schema_only(tools)
    assert schema == [{
        "name": "pay_vendor",
        "description": "Send funds",
        "parameters": ["amount", "vendor"],
    }]


def test_sanitize_drops_a_tool_the_catalogue_was_not_shown():
    names = {"checklist_item", "commit_irreversible"}
    out = sanitize_rules({
        "precedence": [
            {"before": "checklist_item", "after": "commit_irreversible"},
            {"before": "invented_tool", "after": "commit_irreversible"},
        ],
        "invalidations": [{"establishes": "ghost", "invalidators": ["checklist_item"]}],
        "entities": [{"key": "vendor", "allowed": ["Acme"]}],
        "distinct_subjects": 1,
        "idempotency": "yes",
    }, names)
    assert out["precedence"] == [
        {"before": "checklist_item", "after": "commit_irreversible"},
    ]
    assert out["invalidations"] == []
    assert out["entities"] == [{"key": "vendor", "allowed": ["Acme"]}]
    assert out["distinct_subjects"] is True
    assert out["idempotency"] is True


def test_sanitize_expands_list_valued_prerequisites():
    """'dual notify before wire' names two notifiers."""
    names = {"notify_ops", "notify_risk", "wire"}
    out = sanitize_rules({
        "precedence": [{"before": ["notify_ops", "notify_risk"], "after": "wire"}],
        "invalidations": [],
        "entities": [],
    }, names)
    got = {(r["before"], r["after"]) for r in out["precedence"]}
    assert got == {("notify_ops", "wire"), ("notify_risk", "wire")}


def test_compile_rules_without_ask_derives_nothing():
    assert compile_rules(
        [{"function": {"name": "pay", "parameters": {"properties": {}}}}],
        "Pay Acme only",
        ask=None,
    ) is None


def test_compile_rules_uses_injected_ask_and_never_invents_a_tool():
    def ask(system, payload):
        assert "Pay Acme only" in payload
        return json.dumps({
            "precedence": [],
            "invalidations": [],
            "entities": [{"key": "vendor", "allowed": ["Acme"]}],
            "distinct_subjects": False,
            "idempotency": False,
        })

    tools = [{"function": {"name": "pay_vendor",
                           "description": "Send funds",
                           "parameters": {"properties": {"vendor": {}}}}}]
    out = compile_rules(tools, "Pay Acme only", ask=ask)
    assert out["entities"] == [{"key": "vendor", "allowed": ["Acme"]}]


def test_sanitize_rules_drops_an_entity_list_that_is_not_a_list():
    from clayseal.capabilities.compile import sanitize_rules

    out = sanitize_rules({
        "entities": [{"key": "vendor", "allowed": True}],
        "precedence": [],
        "invalidations": [],
    }, {"create_po"})
    assert out["entities"] == []


def test_a_raising_ask_derives_nothing_rather_than_refusing_work():
    def ask(_system, _payload):
        raise RuntimeError("backend down")

    assert compile_rules(
        [{"function": {"name": "pay", "parameters": {"properties": {}}}}],
        "Pay Acme only",
        ask=ask,
    ) is None


def test_compile_budgets_drops_other_catalogues_and_bad_limits():
    from clayseal.capabilities.compile import sanitize_budgets

    out = sanitize_budgets({
        "value": [
            {"id": "bonus", "limit": "15,000", "tools": ["pay_bonus"], "arg": "amount"},
            {"id": "airline", "limit": 100, "tools": ["cancel_reservation"], "arg": "amount"},
            {"id": "nan", "limit": "NaN", "tools": ["pay_bonus"], "arg": "amount"},
        ],
        "calls": [
            {"id": "grants", "limit": 3, "tools": ["grant_repo_access"]},
            {"id": "ghost", "limit": 3, "tools": ["not_a_tool"]},
        ],
        "recipients": [
            {"tool": "send_email", "arg": "to", "allowed": ["acme-internal.com"]},
            {"tool": "book_flight", "arg": "to", "allowed": ["x.com"]},
        ],
        "scope": ["pay_bonus", "grant_repo_access", "not_a_tool",
                  "cancel_reservation"],
    }, {"pay_bonus", "grant_repo_access", "send_email"})
    assert out["value"] == [
        {"id": "bonus", "limit": 15000.0, "tools": ["pay_bonus"], "arg": "amount"},
    ]
    assert out["calls"] == [
        {"id": "grants", "limit": 3, "tools": ["grant_repo_access"]},
    ]
    assert out["recipients"] == [
        {"tool": "send_email", "arg": "to", "allowed": ["acme-internal.com"]},
    ]
    assert out["scope"] == ["pay_bonus", "grant_repo_access"]


def test_sanitize_budgets_drops_a_bool_allow_set_instead_of_raising():
    from clayseal.capabilities.compile import sanitize_budgets

    out = sanitize_budgets({
        "value": [{"id": "x", "limit": 1, "tools": True, "arg": "amount"}],
        "calls": [{"id": "y", "limit": 1, "tools": False}],
        "recipients": [
            {"tool": "send_email", "arg": "to", "allowed": True},
            {"tool": "send_email", "arg": "to", "allowed": ["acme.com"]},
        ],
        "scope": True,
    }, {"send_email", "pay_vendor"})
    assert out["value"] == []
    assert out["calls"] == []
    assert out["recipients"] == [
        {"tool": "send_email", "arg": "to", "allowed": ["acme.com"]},
    ]
    assert out["scope"] == []
    from clayseal.capabilities.compile import compile_budgets

    assert compile_budgets(
        [{"function": {"name": "pay_bonus", "parameters": {"properties": {
            "amount": {"type": "number"}}}}}],
        "Total bonus usd across all pay_bonus calls must not exceed 15,000 per day.",
        ask=None,
    ) is None


def test_compile_budgets_drops_a_scope_that_names_the_whole_catalogue():
    from clayseal.capabilities.compile import sanitize_budgets

    names = {"pay_bonus", "grant_repo_access"}
    out = sanitize_budgets(
        {"scope": ["pay_bonus", "grant_repo_access", "ghost"]}, names)
    assert out["scope"] == []


def test_compile_session_without_ask_derives_nothing():
    from clayseal.capabilities.compile import compile_session

    assert compile_session(
        [{"function": {"name": "pay_bonus", "parameters": {"properties": {
            "amount": {"type": "number"}}}}}],
        "must not exceed 15,000",
        ask=None,
    ) is None


def _pay_tools():
    return [
        {"function": {"name": "checklist_item",
                      "description": "Tick a box",
                      "parameters": {"properties": {}}}},
        {"function": {"name": "pay_vendor",
                      "description": "Send funds",
                      "parameters": {"properties": {"vendor": {}, "amount": {}}}}},
        {"function": {"name": "wire_funds",
                      "description": "Wire to ops",
                      "parameters": {"properties": {"amount": {}}}}},
    ]


def _rules(wire: bool) -> str:
    prec = [{"before": "checklist_item", "after": "pay_vendor"}]
    if wire:
        prec.append({"before": "checklist_item", "after": "wire_funds"})
    return json.dumps({
        "precedence": prec,
        "invalidations": [],
        "entities": [{"key": "vendor", "allowed": ["Acme"]}],
        "distinct_subjects": False,
        "idempotency": False,
    })


def test_k_drops_a_tool_that_only_appeared_in_one_draw():
    from clayseal.capabilities.compile import compile_rules, select_tools_under_k, tools_named

    answers = [_rules(wire=False)] * 4 + [_rules(wire=True)]
    n = {"i": 0}

    def ask(_system, _payload):
        raw = answers[n["i"]]
        n["i"] += 1
        return raw

    tight = compile_rules(_pay_tools(), "Pay Acme after the checklist.",
                          ask=ask, draws=5, k=0.5)
    assert tight is not None
    after = {p["after"] for p in tight["precedence"]}
    assert after == {"pay_vendor"}
    assert "wire_funds" not in tight["tool_freq"]
    assert tight["named_any"] is True

    n["i"] = 0
    loose = compile_rules(_pay_tools(), "Pay Acme after the checklist.",
                          ask=ask, draws=5, k=1e-4)
    assert "wire_funds" in loose["tool_freq"]
    named = [tools_named(json.loads(a)) for a in answers]
    freq = select_tools_under_k(
        named, {"checklist_item", "pay_vendor", "wire_funds"}, 1e-4)
    assert freq["wire_funds"] == 0.2


def test_k_for_raises_the_floor_on_one_tool():
    from clayseal.capabilities.compile import compile_rules

    answers = [_rules(wire=False)] * 4 + [_rules(wire=True)]
    n = {"i": 0}

    def ask(_system, _payload):
        raw = answers[n["i"]]
        n["i"] += 1
        return raw

    out = compile_rules(
        _pay_tools(), "Pay Acme after the checklist.",
        ask=ask, draws=5, k=1e-4, k_for={"wire_funds": 0.5},
    )
    assert out is not None
    assert "wire_funds" not in out["tool_freq"]
    assert any(p["after"] == "pay_vendor" for p in out["precedence"])


def test_a_failed_draw_votes_for_nothing_rather_than_granting():
    from clayseal.capabilities.compile import compile_rules

    def ask(_system, _payload):
        raise RuntimeError("backend down")

    assert compile_rules(_pay_tools(), "Pay Acme", ask=ask, draws=3, k=0.5) is None


def test_a_single_success_among_failures_is_not_unanimous():
    """Four failures plus one grant used to look like frequency 1.0."""
    from clayseal.capabilities.compile import compile_rules

    n = {"i": 0}

    def ask(_system, _payload):
        n["i"] += 1
        if n["i"] < 5:
            raise RuntimeError("down")
        return _rules(wire=True)

    out = compile_rules(_pay_tools(), "Pay Acme", ask=ask, draws=5, k=0.5)
    assert out is not None
    assert "wire_funds" not in (out.get("tool_freq") or {})
    assert out["named_any"] is True


def test_select_tools_under_k_rejects_a_k_outside_the_unit_interval():
    from clayseal.capabilities.compile import select_tools_under_k

    with pytest.raises(ValueError, match=r"\[0, 1\]"):
        select_tools_under_k([{"pay"}], {"pay"}, 1.5)
