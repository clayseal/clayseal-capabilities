"""No attacker-controlled input may make a decision take unbounded time.

Python's `re` backtracks, so `(?:group)+suffix` explores exponentially many
splits when the suffix never matches. Measured on this codebase before the
rewrites: one 16 KB tool argument took 3.5 s inside the egress host pattern,
2.7 s in the secret-path pattern and 2.3 s in the sed-path one. Every one of
them reads arguments an agent controls, so that was a hang anybody could
trigger with a single call.

This is a budget, not a benchmark: it fails if a decision path becomes
super-linear again, whoever adds the pattern.
"""
from __future__ import annotations

import time

import pytest

#: Shapes that make a backtracking engine explore splits.
PAYLOADS = {
    "dotted labels": "a." * 8000,
    "traversal": "../" * 5000,
    "url encoded": "%2e" * 5000,
    "at signs": "x" * 8000 + "@" + "y." * 4000,
    "hyphenated": "a-" * 8000,
    "scheme": "https://" + "a." * 8000,
    "mixed": "a.b-c_d." * 2000,
}
#: Generous: the same work on ordinary input is well under a millisecond.
BUDGET_MS = 250.0


def _elapsed_ms(fn, *args) -> float:
    start = time.process_time()
    fn(*args)
    return (time.process_time() - start) * 1000


@pytest.mark.parametrize("name", sorted(PAYLOADS))
def test_the_egress_check_is_bounded(name):
    from agentauth.capabilities.hardening.egress_policy import EgressPolicy

    payload = PAYLOADS[name]
    policy = EgressPolicy(allowed_domains={"acme-internal.com"})
    took = _elapsed_ms(policy.check, "mcp:tool:send_email",
                       {"to": payload, "body": payload})
    assert took < BUDGET_MS, f"{name}: {took:.0f} ms"


@pytest.mark.parametrize("name", sorted(PAYLOADS))
def test_the_secret_path_check_is_bounded(name):
    from agentauth.capabilities.monitor.sealed_plan import is_secret_path

    took = _elapsed_ms(is_secret_path, PAYLOADS[name])
    assert took < BUDGET_MS, f"{name}: {took:.0f} ms"


@pytest.mark.parametrize("name", sorted(PAYLOADS))
def test_reading_a_policy_document_is_bounded(name):
    from agentauth.capabilities.policy_draft import extract

    took = _elapsed_ms(extract, PAYLOADS[name], ["issue_refund"])
    assert took < BUDGET_MS, f"{name}: {took:.0f} ms"


def test_a_whole_authorization_is_bounded_on_an_adversarial_argument():
    """The end the attacker actually reaches."""
    from agentauth.capabilities.guardrail import Guardrail

    guard = Guardrail.from_policy_file("examples/refund.yaml")
    tools = guard.wrap_all({"issue_refund": lambda **k: "ok"})
    worst = 0.0
    for payload in PAYLOADS.values():
        start = time.process_time()
        try:
            tools["issue_refund"](invoice=payload, amount=1.0, note=payload)
        except Exception:  # noqa: BLE001 - a refusal is a fine outcome here
            pass
        worst = max(worst, (time.process_time() - start) * 1000)
    assert worst < BUDGET_MS, f"{worst:.0f} ms"
