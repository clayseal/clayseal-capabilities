"""Biscuit path-pattern dynamic scope tests (SM-7)."""

from __future__ import annotations

import pytest

pytest.importorskip("biscuit_auth")
# `agentauth.biscuit_scope` and `agentauth.identity` both come from the OPTIONAL
# identity layer (`pip install clayseal[biscuit-service]`). Without
# the skip this module raised ModuleNotFoundError at COLLECTION, which is not a
# skipped test, it aborts the whole run before any other test executes. That is
# how the suite could be described as green locally only by passing
# `--ignore=python/tests/test_biscuit_scope.py`, and it would have failed CI on
# the first run that reached the test step.
pytest.importorskip(
    "agentauth.biscuit_scope",
    reason="needs the optional identity layer: pip install "
           "'clayseal[biscuit-service]'",
)
pytest.importorskip("agentauth.identity")

from agentauth.biscuit_scope import FILE_RESOURCE, evaluate_path_scope
from agentauth.identity import _capabilities as sdk_caps
from biscuit_auth import BiscuitBuilder, Check, Fact, KeyPair


def _mint_token() -> tuple[str, str]:
    kp = KeyPair()
    root_public = kp.public_key.to_bytes().hex()
    builder = BiscuitBuilder("")
    builder.add_fact(Fact("capability({r}, {a})", {"r": FILE_RESOURCE, "a": "read"}))
    builder.add_fact(Fact("bound_key({k})", {"k": "test-keyhash"}))
    builder.add_check(Check("check if valid_pop(true)"))
    token = builder.build(kp.private_key).to_base64()
    return token, root_public


def test_path_scope_denies_out_of_scope():
    allowed, reason = evaluate_path_scope(
        "swe_triage/auth.py",
        allowed_paths=["swe_triage/parser.py"],
        denied_paths=[],
    )
    assert not allowed
    assert "outside" in reason


def test_attenuation_embeds_allowed_path_facts():
    token, root_public = _mint_token()
    narrowed = sdk_caps.attenuate_biscuit(
        token_b64=token,
        root_public_hex=root_public,
        path_patterns=["swe_triage/parser.py", "tests/**"],
        denied_paths=["**/.ssh/**"],
    )
    allowed_paths, denied_paths = sdk_caps.read_path_scope(narrowed, root_public)
    assert "swe_triage/parser.py" in allowed_paths
    assert any(".ssh" in item for item in denied_paths)


def test_authorize_denies_out_of_path_before_capability():
    token, root_public = _mint_token()
    narrowed = sdk_caps.attenuate_biscuit(
        token_b64=token,
        root_public_hex=root_public,
        path_patterns=["swe_triage/parser.py"],
    )
    denied = sdk_caps.authorize_biscuit(
        token_b64=narrowed,
        root_public_hex=root_public,
        operation=(FILE_RESOURCE, "read"),
        file_path="swe_triage/auth.py",
    )
    assert not denied["allowed"]
    assert "outside" in denied["reason"]
