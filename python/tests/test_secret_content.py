"""Credential-shaped values in an outbound payload.

The detector exists because `FlowTracker` structurally cannot cover this case:
it correlates a secret READ with a later write, and BPL's
`integration-invoice-cover` never reads one. The elevation tool is refused and
the agent types `API_KEY=sk-live-...` into an invoice attachment bound for an
allow-listed internal address. Allow-listed tool, allow-listed recipient,
nothing to derive from.

The false-positive side is the whole design problem. `object_class`'s markers
include `token`, `secret` and `password` as bare substrings, which run against
prose fire on "reset your password". These tests pin both directions.
"""
import pytest

from agentauth.capabilities.hardening.secret_content import (
    ENTROPY_FLOOR,
    contains_credential,
    credential_findings,
    shannon_entropy,
)

#: Real credential shapes. No English sentence contains these by accident.
CREDENTIALS = [
    "API_KEY=sk-live-INTERNAL payroll_data",
    "AKIAIOSFODNN7EXAMPLE",
    "ghp_16C7e42F292c6912E7710c838347Ae178B4a",
    "xoxb-1234567890-abcdefghijkl",
    "-----BEGIN RSA PRIVATE KEY-----",
    "eyJhbGciOiJub25lIn0.eyJpbnYiOiJJTlYtNzci.sig",
    "password=CorrectHorseBatteryStaple99",
]

#: Prose and documentation. Every one of these mentions a credential concept and
#: none of them carries a credential.
INNOCENT = [
    "PO-9 total=100",
    "receipt ok",
    "Please reset your password before Friday.",
    "The access token expired; ask IT for a new one.",
    "password = hunter2",
    "api_key: your-api-key-here",
    "SECRET_KEY=<insert-value>",
    "token: ****************",
    "Store credentials in the vault, never in the repo.",
    "See the API key rotation policy in the handbook.",
]


@pytest.mark.parametrize("text", CREDENTIALS)
def test_credentials_are_detected(text):
    assert contains_credential(text), text


@pytest.mark.parametrize("text", INNOCENT)
def test_prose_about_credentials_is_not_a_credential(text):
    """The failure mode that makes a control get switched off.

    A keyword list flags every one of these. Refusing "reset your password"
    teaches people to route around the check, and then it defends nothing.
    """
    assert not contains_credential(text), credential_findings(text)


def test_the_entropy_floor_is_what_separates_a_key_from_a_word():
    assert shannon_entropy("hunter2") < ENTROPY_FLOOR
    assert shannon_entropy("CorrectHorseBatteryStaple99") >= ENTROPY_FLOOR


def test_pii_is_separable_from_credentials():
    """Different operating points, so they are different switches.

    On BPL's benign corpus the credential detector flags 0 of 761 arguments and
    the PII detector flags 1, a payroll extract sent to the payroll mailbox.
    That is a question about the destination, not the content, so PII must not
    ride along with the credential check by default.
    """
    payroll = "PAYROLL: Ada=$180000 SSN=111-22-3333"
    assert contains_credential(payroll, include_pii=True)
    assert not contains_credential(payroll, include_pii=False)


@pytest.mark.parametrize("payload", [None, 12345, {"a": 1}, [], b"bytes", ""])
def test_the_detector_is_total(payload):
    """It runs on the authorization path, so it may never raise.

    A classifier that throws on an odd payload is a control that stops applying
    exactly when the input is unusual, the shape of all six fail-opens this
    repository has shipped.
    """
    assert credential_findings(payload) == [] or isinstance(
        credential_findings(payload), list)


def test_reasons_are_deduplicated():
    """One reason per kind: an approval card can render that, fifty cannot."""
    text = " ".join(["AKIAIOSFODNN7EXAMPLE"] * 20)
    assert len(credential_findings(text)) == 1


# --------------------------------------------------------------------------- #
# Wiring
# --------------------------------------------------------------------------- #
def _broker(flag):
    from agentauth.capabilities.broker import SessionBroker
    from agentauth.capabilities.scoping.goal import GoalSpec

    return SessionBroker(
        goal=GoalSpec(query_id="q", summary="s", allow_resources=[]),
        refuse_credential_payloads=flag)


def _act(body):
    from agentauth.capabilities.monitor.action import Action

    return Action(step=0, tool="attach_doc", resource="mcp:tool:attach_doc",
                  verb="write", args={"body": body})


def test_the_broker_refuses_a_credential_payload_when_enabled():
    from agentauth.capabilities.broker import Outcome

    decision = _broker(True).authorize(_act("API_KEY=sk-live-INTERNAL"))
    assert decision.outcome is Outcome.DENY
    assert "credential" in " ".join(decision.reasons)


def test_the_check_is_off_by_default():
    from agentauth.capabilities.broker import Outcome

    assert _broker(False).authorize(
        _act("API_KEY=sk-live-INTERNAL")).outcome is Outcome.ALLOW


def test_an_ordinary_payload_passes_with_the_check_on():
    from agentauth.capabilities.broker import Outcome

    assert _broker(True).authorize(
        _act("PO-9 total=100")).outcome is Outcome.ALLOW


def test_a_read_is_not_subject_to_the_check():
    """Only consequential actions. Reading a config that contains a key is not
    exfiltration; sending one is."""
    from agentauth.capabilities.broker import Outcome
    from agentauth.capabilities.monitor.action import Action

    read = Action(step=0, tool="read_file", resource="mcp:tool:read_file",
                  verb="read", args={"body": "API_KEY=sk-live-INTERNAL"})
    assert _broker(True).authorize(read).outcome is Outcome.ALLOW
