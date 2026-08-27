"""The no-secret-observed fast path must not create an ordering hole.

`_check_locked` skips its four detection passes when nothing sensitive has been
read, because each of them matches the payload against `_sensitive_tokens` and
returns empty when that is empty. The skip is only sound if the write is still
RECORDED: a read can make a value sensitive after a write already carried part
of it, and the assembly check needs that piece to still be in the history.
"""
from __future__ import annotations

import pytest

from agentauth.capabilities.confidentiality import FlowTracker, SensitivityPolicy

SECRET = "AKIA9F3C1D77B02E4419QZ"


def _policy():
    return SensitivityPolicy(sensitive=("*vault*",), argument_sinks=("*sink*",))


def _send(tracker, policy, body):
    return tracker.check(tool="post", verb="send", resource="sink",
                         args={"body": body}, policy=policy)


@pytest.mark.parametrize("read_first", [True, False])
def test_a_fragment_sent_before_the_read_is_still_assembled(read_first):
    """Half the key leaves, THEN the key is read, then the other half leaves.

    The first write takes the fast path. If it were skipped rather than
    recorded, the second write would assemble against half a history and pass.
    """
    policy, tracker = _policy(), FlowTracker()
    half = len(SECRET) // 2
    first, second = SECRET[:half], SECRET[half:]

    if read_first:
        tracker.observe("read_vault", "vault/creds", {"key": SECRET},
                        policy=policy)
        assert _send(tracker, policy, first).allowed
    else:
        assert _send(tracker, policy, first).allowed      # the fast path
        tracker.observe("read_vault", "vault/creds", {"key": SECRET},
                        policy=policy)

    verdict = _send(tracker, policy, second)
    assert not verdict.allowed, "the completing fragment escaped"
    assert "vault/creds" in verdict.reason


def test_the_fast_path_records_into_the_pool_as_well():
    """The pooled history is what catches a value split across DIFFERENT sinks."""
    policy = SensitivityPolicy(sensitive=("*vault*",), argument_sinks=("*sink*",))
    tracker = FlowTracker()
    half = len(SECRET) // 2

    tracker.check(tool="post", verb="send", resource="sink-a",
                  args={"body": SECRET[:half]}, policy=policy)
    tracker.observe("read_vault", "vault/creds", {"key": SECRET}, policy=policy)
    verdict = tracker.check(tool="post", verb="send", resource="sink-b",
                            args={"body": SECRET[half:]}, policy=policy)
    assert not verdict.allowed, "split across two sinks escaped the pool"


def test_nothing_sensitive_read_means_every_write_is_allowed():
    policy, tracker = _policy(), FlowTracker()
    for body in ("hello", SECRET, "", {"nested": ["a", "b"]}):
        assert _send(tracker, policy, body).allowed


# --- Attestation freshness ---------------------------------------------------

def test_a_replaced_binary_does_not_attest_under_the_old_hash(tmp_path):
    """The cache is a module-level one in a process that serves many sessions.

    Keyed on the path alone it kept reporting the previous build's hash, and
    the previous build's SIZE, after the file was replaced.
    """
    import time

    from agentauth.capabilities.sandbox.attest import ivisor_binary_identity

    binary = tmp_path / "ivisor"
    binary.write_bytes(b"BUILD-ONE")
    first = ivisor_binary_identity(str(binary))

    time.sleep(0.01)                       # move the mtime
    binary.write_bytes(b"BUILD-TWO-IS-LONGER")
    second = ivisor_binary_identity(str(binary))

    assert second["sha256"] != first["sha256"]
    assert second["size"] == len(b"BUILD-TWO-IS-LONGER")
    # Unchanged file still hits the cache rather than re-hashing every call.
    assert ivisor_binary_identity(str(binary)) == second


def test_an_unreadable_binary_reports_rather_than_raises(tmp_path):
    from agentauth.capabilities.sandbox.attest import ivisor_binary_identity

    identity = ivisor_binary_identity(str(tmp_path / "not-there"))
    assert identity["sha256"] is None and identity["error"] == "unreadable"


# --- Security-surface matching -----------------------------------------------

@pytest.mark.parametrize("value", [
    "William Diamond",      # iam
    "oracle-prod",          # acl
    "monkey wrench",        # key
    "accessory-11",         # access
    "Miami office",         # iam
    "enrolled user",        # role
])
def test_ordinary_business_data_is_not_the_authorization_surface(value):
    """Substring matching read a security term out of each of these.

    SECURITY is the highest consequence level. For a read it sits at or above
    WRITE, so a false hit turns a step-up into something a rung may refuse
    outright.
    """
    from agentauth.capabilities.monitor.action import Action
    from agentauth.capabilities.monitor.consequence import (
        ConsequenceLevel,
        classify,
    )

    action = Action(0, "issue_refund", "mcp:tool:issue_refund", "write",
                    args={"field": value})
    assert classify(action)[0] is not ConsequenceLevel.SECURITY


@pytest.mark.parametrize("value", [
    "access_key", "iam-role", "rotate.secret", "api token", "sudo rm",
    "admin panel", "firewall rule", "grant privilege", "credential file",
    "acl entry",
])
def test_the_real_authorization_surface_is_still_caught(value):
    from agentauth.capabilities.monitor.action import Action
    from agentauth.capabilities.monitor.consequence import (
        ConsequenceLevel,
        classify,
    )

    action = Action(0, "issue_refund", "mcp:tool:issue_refund", "write",
                    args={"field": value})
    assert classify(action)[0] is ConsequenceLevel.SECURITY


def test_a_compound_tool_name_still_matches():
    from agentauth.capabilities.monitor.action import Action
    from agentauth.capabilities.monitor.consequence import (
        ConsequenceLevel,
        classify,
    )

    action = Action(0, "update_iam_policy", "mcp:tool:update_iam_policy",
                    "write", args={})
    assert classify(action)[0] is ConsequenceLevel.SECURITY
