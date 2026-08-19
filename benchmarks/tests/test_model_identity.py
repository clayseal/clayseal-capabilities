"""The mismatch check must fire on a substitution and stay silent on a version pin.

Both polarities are pinned because both have already gone wrong here. The
substitution is real: `<azure-openai-resource>` has a deployment named
`gpt-4o-mini-2024-07-18` that serves `gpt-5-mini`, and every results file written
against it before `ModelIdentity` existed carried a weak-model label on a
frontier-model cell. The false alarm is equally real: every Azure deployment
answers with a dated version suffix, so an exact-equality check warns on every
run, and a warning printed on every run is one nobody reads by the time the
substitution appears.
"""
from benchmarks.core.reporting import ModelIdentity


def test_a_version_pin_is_not_a_mismatch():
    ident = ModelIdentity(requested="gpt-4.1-mini",
                          reported="gpt-4.1-mini-2025-04-14")
    assert not ident.mismatched
    assert ident.label() == "gpt-4.1-mini-2025-04-14"


def test_the_real_substitution_is_a_mismatch():
    ident = ModelIdentity(requested="gpt-4o-mini-2024-07-18",
                          reported="gpt-5-mini-2025-08-07")
    assert ident.mismatched
    assert "gpt-5-mini-2025-08-07" in ident.label()


def test_a_prefix_that_is_not_a_version_suffix_is_a_mismatch():
    # The size class is part of the identity: `gpt-4.1` answered by
    # `gpt-4.1-mini-...` is a different model, not a pinned version.
    assert ModelIdentity(requested="gpt-4.1",
                         reported="gpt-4.1-mini-2025-04-14").mismatched
    assert ModelIdentity(requested="gpt-4", reported="gpt-4o").mismatched


def test_an_unverified_identity_does_not_claim_a_mismatch():
    ident = ModelIdentity(requested="gpt-4.1-mini", reported="")
    assert not ident.mismatched
    assert "unverified" in ident.label()
