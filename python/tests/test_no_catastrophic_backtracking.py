"""No attacker-controlled input may make a decision take unbounded time.

Python's `re` backtracks, so `(?:group)+suffix` explores exponentially many
splits when the suffix never matches. Measured on this codebase before the
rewrites: one 16 KB tool argument took 3.5 s inside the egress host pattern,
2.7 s in the secret-path pattern and 2.3 s in the sed-path one. Every one of
them reads arguments an agent controls, so that was a hang anybody could
trigger with a single call.

Every pattern in the library was then measured against a doubling input. Three
were quadratic, growing fourfold per doubling; all three were "find path-shaped
tokens in a string" and all three are now a single pass over the tokens. No
pattern in the library exceeds 10 ms on 8 KB of any adversarial shape.

Bounding the input first was the other option and it is second best. A cap can
hide a match past it, so it is only sound where the input has a natural size,
and it leaves the hazard in place for the next call site. Where the input has a
grammar, scanning it linearly costs nothing and removes the hazard instead.

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
    from clayseal.capabilities.hardening.egress_policy import EgressPolicy

    payload = PAYLOADS[name]
    policy = EgressPolicy(allowed_domains={"acme-internal.com"})
    took = _elapsed_ms(policy.check, "mcp:tool:send_email",
                       {"to": payload, "body": payload})
    assert took < BUDGET_MS, f"{name}: {took:.0f} ms"


@pytest.mark.parametrize("name", sorted(PAYLOADS))
def test_the_secret_path_check_is_bounded(name):
    from clayseal.capabilities.monitor.sealed_plan import is_secret_path

    took = _elapsed_ms(is_secret_path, PAYLOADS[name])
    assert took < BUDGET_MS, f"{name}: {took:.0f} ms"


@pytest.mark.parametrize("name", sorted(PAYLOADS))
def test_reading_a_policy_document_is_bounded(name):
    from clayseal.capabilities.policy_draft import extract

    took = _elapsed_ms(extract, PAYLOADS[name], ["issue_refund"])
    assert took < BUDGET_MS, f"{name}: {took:.0f} ms"


def test_a_whole_authorization_is_bounded_on_an_adversarial_argument():
    """The end the attacker actually reaches."""
    from clayseal.capabilities.guardrail import Guardrail

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


@pytest.mark.parametrize("name", sorted(PAYLOADS))
def test_reading_a_command_is_bounded(name):
    """`session_rules` scans commands for paths and archive artefacts."""
    from clayseal.capabilities.session_rules import (
        _names_a_zip,
        _paths_in_command,
    )

    payload = PAYLOADS[name]
    assert _elapsed_ms(_paths_in_command, payload) < BUDGET_MS
    assert _elapsed_ms(_names_a_zip, payload) < BUDGET_MS


def test_no_pattern_in_the_library_is_super_linear():
    """The sweep itself, so a new pattern cannot reintroduce the class."""
    import importlib
    import pkgutil
    import re

    import clayseal.capabilities
    import clayseal.core

    patterns = {}
    for pkg in (clayseal.capabilities, clayseal.core):
        for mod in pkgutil.walk_packages(pkg.__path__, pkg.__name__ + "."):
            try:
                loaded = importlib.import_module(mod.name)
            except Exception:  # noqa: BLE001 - optional extras may be absent
                continue
            for attr, value in vars(loaded).items():
                if isinstance(value, re.Pattern):
                    patterns[f"{mod.name}.{attr}"] = value

    assert patterns, "no patterns found; the sweep is not running"
    units = ["a", "a.", "a-", "../", "%2e", "a@", "/a", "a:", "a/"]
    slow = []
    for label, pattern in patterns.items():
        for unit in units:
            probe = unit * (8000 // len(unit)) + "!"
            if _elapsed_ms(pattern.search, probe) > 50.0:
                slow.append(f"{label} on {unit!r}")
                break
    assert not slow, f"super-linear on 8 KB: {slow}"


# --------------------------------------------------------------------------- #
# The confidentiality flow tracker, which is the other unbounded-work hazard and
# is not a regex at all.
#
# `benchmarks/results/flow.md` measures its tail and says the quiet part out
# loud: "The tail also has an attacker on it... one write can hold the tracker
# lock for seconds." The cost is driven by how many sensitive tokens the session
# has seen, which an agent that reads a lot of secrets controls, times the length
# of the payload, which it also controls.
#
# The check is enabled by default and its expensive path switches on once a
# session has read something sensitive, which is exactly the sessions it protects.
# --------------------------------------------------------------------------- #

#: Sensitive values in one session. A long-running agent that reads many records
#: reaches this without trying, and this is the multiplier on every later write.
FLOW_TOKEN_COUNTS = [1, 50, 400]

#: Per `check`, on the shapes below. Generous against BUDGET_MS above, because
#: this path does real work rather than pattern matching, but far below the
#: 2.1 ms p99 and 219 ms peak flow.md records.
FLOW_BUDGET_MS = 100.0


def _tracker(token_count: int):
    """A session that has read `token_count` distinct secrets."""
    import random
    import string

    from clayseal.capabilities.confidentiality import FlowTracker, SensitivityPolicy

    rng = random.Random(20260827)  # noqa: S311 - a fixture, not a credential
    policy = SensitivityPolicy(sensitive=("secrets/**",), argument_sinks=("net:**",))
    tracker = FlowTracker()
    for _ in range(token_count):
        value = "".join(rng.choice(string.ascii_letters + string.digits) for _ in range(22))
        tracker.observe("read_file", "secrets/k", value, policy=policy, path="secrets/k")
    return tracker, policy


FLOW_PAYLOADS = {
    "ordinary prose": "the quick brown fox jumps over the lazy dog " * 30,
    "one repeated character": "a" * 8000,
    "alternating": "ab" * 4000,
    "alphanumeric soup": ("abc123XYZ" * 900),
    "all separators": "-" * 8000,
}


@pytest.mark.parametrize("tokens", FLOW_TOKEN_COUNTS)
@pytest.mark.parametrize("shape", sorted(FLOW_PAYLOADS))
def test_a_flow_check_is_bounded_however_many_secrets_the_session_holds(tokens, shape):
    tracker, policy = _tracker(tokens)
    payload = FLOW_PAYLOADS[shape]

    tracker.check(tool="send", verb="send", resource="net:x",
                  args={"body": payload}, policy=policy)          # warm the folds

    elapsed = _elapsed_ms(
        lambda: tracker.check(tool="send", verb="send", resource="net:x",
                              args={"body": payload}, policy=policy))
    assert elapsed < FLOW_BUDGET_MS, (
        f"{shape} against {tokens} sensitive tokens took {elapsed:.1f} ms; "
        "a single write can stall the gateway")


def test_flow_cost_does_not_explode_with_the_number_of_secrets():
    """Bounded per call is not enough if it is quadratic in the session.

    400 secrets is 400x the tokens of 1. The check is inherently linear in that,
    so this asserts the CONSTANT stays sane rather than that the growth is flat:
    before the fold caching, 400 tokens cost 10.5 ms against 0.70 ms for one, and
    the per-token work was being recomputed on every decision though the tokens
    never change.
    """
    payload = FLOW_PAYLOADS["ordinary prose"]

    def cost(tokens: int) -> float:
        tracker, policy = _tracker(tokens)
        for _ in range(2):
            tracker.check(tool="send", verb="send", resource="net:x",
                          args={"body": payload}, policy=policy)
        return min(_elapsed_ms(
            lambda: tracker.check(tool="send", verb="send", resource="net:x",
                                  args={"body": payload}, policy=policy))
            for _ in range(3))

    one, many = cost(1), cost(400)
    assert many < 40.0, f"400 secrets cost {many:.1f} ms per write"
    assert many < one * 400, (
        f"cost grew {many / max(one, 1e-9):.0f}x for 400x the secrets; "
        "something is worse than linear in the token count")


def test_the_flow_budget_can_actually_fail():
    """The control.

    Every assertion above passes if `check` returns without doing anything. Give
    the tracker a payload that genuinely carries a secret and require it to be
    refused, so the budget is measured over a check that ran.
    """
    from clayseal.capabilities.confidentiality import FlowTracker, SensitivityPolicy

    policy = SensitivityPolicy(sensitive=("secrets/**",), argument_sinks=("net:**",))
    tracker = FlowTracker()
    tracker.observe("read_file", "secrets/k", "SUPERSECRETVALUE12345",
                    policy=policy, path="secrets/k")
    verdict = tracker.check(tool="send", verb="send", resource="net:x",
                            args={"body": "here it is: SUPERSECRETVALUE12345"},
                            policy=policy)
    assert not verdict.allowed, "the tracker allowed a verbatim secret; it is inert"
