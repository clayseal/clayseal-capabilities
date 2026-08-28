"""Every bare refusal CODE has to carry a sentence someone can act on.

Refusal reasons come in two shapes. Most are built from the thing that failed
and already read as English:

    tool 'wire_funds' not granted
    egress to 'evil.test' not on allow-list

The rest are bare enums, and those are the ones a reader cannot act on:

    value_budget_exceeded
    call_budget_exceeded

Harvesting the reasons the gateway emits across the full 132-scenario BPL suite
gave 27 distinct strings, of which the bare-enum ones accounted for 75 of the
refusals by volume, `value_budget_exceeded` alone for 49. That is the most
common refusal in the system, and on its own it says nothing about what to do
instead. The README tells you to hand the reason back to the agent.

The rule this file enforces: a reason with no spaces in it is a code, and a code
must be explained. A reason with spaces was built from data and explains itself.

`.reasons` keeps the codes untouched. Only `str(exc)` changes.
"""
from __future__ import annotations

import pytest

from clayseal.capabilities import Guardrail, Refused, StepUpRequired
from clayseal.capabilities.reasons import explain, explained, known_codes

POLICY = "examples/refund.yaml"


def _looks_like_a_code(reason: str) -> bool:
    """A bare enum, rather than a sentence built from the thing that failed."""
    return " " not in reason.strip()


def _drive(policy: str, tool_impls: dict, calls: list[tuple[str, dict]]):
    """Run calls until one is refused; return its reasons, or ()."""
    guard = Guardrail.from_policy_file(policy)
    tools = guard.wrap_all(tool_impls)
    for name, kwargs in calls:
        try:
            tools[name](**kwargs)
        except (Refused, StepUpRequired) as exc:
            return exc.reasons, exc
    return (), None


def _refund_tools():
    return {"issue_refund": lambda invoice, amount: "ok",
            "list_open_refunds": lambda: [],
            "wire_funds": lambda **k: "ok"}


REFUSAL_PATHS = [
    ("session spend ceiling",
     [("issue_refund", {"invoice": f"INV-{i}", "amount": 900.0}) for i in range(4)]),
    ("tool not granted",
     [("wire_funds", {"to": "ops-float", "amount": 1.0})]),
    ("negative amount",
     [("issue_refund", {"invoice": "INV-9", "amount": -50.0})]),
    ("unparseable amount",
     [("issue_refund", {"invoice": "INV-9", "amount": "1e999"})]),
]


@pytest.mark.parametrize("name,calls", REFUSAL_PATHS, ids=[c[0] for c in REFUSAL_PATHS])
def test_every_bare_code_the_gateway_emits_is_explained(name, calls):
    reasons, exc = _drive(POLICY, _refund_tools(), calls)
    assert reasons, f"{name}: nothing was refused, so this path proves nothing"
    for reason in reasons:
        if _looks_like_a_code(reason):
            assert explain(reason) != reason, (
                f"{name}: refusal code {reason!r} has no explanation. "
                "Add one to clayseal/capabilities/reasons.py."
            )


@pytest.mark.parametrize("name,calls", REFUSAL_PATHS, ids=[c[0] for c in REFUSAL_PATHS])
def test_the_message_carries_the_explanation_and_reasons_keeps_the_code(name, calls):
    reasons, exc = _drive(POLICY, _refund_tools(), calls)
    assert reasons and exc is not None
    message = str(exc)
    for reason in reasons:
        # The stable surface is untouched: integrations match on this.
        assert reason in exc.reasons
        if _looks_like_a_code(reason):
            # ...and the human surface is not the raw code.
            assert reason not in message, (
                f"{name}: the raw code {reason!r} leaked into the message")
            assert explain(reason) in message


def test_explanations_are_actually_explanations():
    """Guard the guard.

    An entry that merely restates its own code would satisfy every assertion
    above while helping nobody, so require each one to be a real sentence.
    """
    for code in known_codes():
        text = explain(code)
        assert text != code
        assert len(text) > 60, f"{code}: {text!r} is too short to be an explanation"
        assert " " in text
        assert text[0].islower() or text[0].isupper()


def test_an_unknown_code_falls_through_rather_than_raising():
    """A refusal must never be replaced by a crash while formatting it."""
    assert explain("some_code_added_later") == "some_code_added_later"
    assert explained(("value_budget_exceeded", "unknown_code")) == (
        explain("value_budget_exceeded"), "unknown_code")


def test_the_most_common_refusal_in_the_suite_is_covered():
    """The control.

    `value_budget_exceeded` is 49 of the refusals across the BPL suite and
    `call_budget_exceeded` 23. If the parametrized paths above ever stop
    reaching a refusal, they pass vacuously; this does not.
    """
    for code in ("value_budget_exceeded", "call_budget_exceeded"):
        assert code in known_codes()
        assert explain(code) != code
