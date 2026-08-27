"""Shared pytest fixtures for agent-receipts."""

from __future__ import annotations

import pytest


def requires_corpus(*names: str) -> pytest.MarkDecorator:
    """Skip unless the named external corpora have been fetched.

    `python/tests` is the FAST gate, it runs on every push and must not need the
    1.1 GB of external corpora that `benchmarks/fetch_corpora.sh` pulls. A test in
    here that loads one is not wrong, it is in the wrong tier, and it should say
    so by skipping rather than failing the build for everyone who has not cloned
    RedCode.

    The nightly `invariants` job fetches the corpora and runs `python/tests` as
    well, so these are still exercised, a skip here is a deferral, not a hole.
    """
    from pathlib import Path

    root = Path(__file__).resolve().parents[2] / ".benchmark-corpus"
    missing = [n for n in names if not (root / n).exists()]
    return pytest.mark.skipif(
        bool(missing),
        reason=f"external corpora not fetched: {missing}. "
               f"Run benchmarks/fetch_corpora.sh",
    )


@pytest.fixture
def allow_stub_proofs(monkeypatch: pytest.MonkeyPatch) -> None:
    """Enable stub inference/composed proofs for prove-mode integration tests."""
    monkeypatch.setenv("AGENT_RECEIPTS_ALLOW_STUB", "1")
    monkeypatch.setenv("AGENT_RECEIPTS_ALLOW_UNSIGNED_CERTIFICATE", "1")
    monkeypatch.setenv("AGENT_RECEIPTS_REQUIRE_BUNDLE_SIGNATURES", "0")


@pytest.fixture
def trusted_signer(monkeypatch: pytest.MonkeyPatch):
    """Pin a generated Ed25519 key as a trusted envelope signer."""
    from agentauth.core.signing import generate_keypair

    key = generate_keypair()
    monkeypatch.setenv("AGENT_RECEIPTS_TRUSTED_SIGNER_PUBLIC_KEYS", key.public_key_hex)
    return key
