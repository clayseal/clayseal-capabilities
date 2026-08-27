"""The identity a session acts as, and why it is read narrowly.

`session_identity` feeds `EgressPolicy.self_identifiers`, which decides what is
NOT egress. Everything it returns is a string the destination scanner will stop
seeing in content fields, so over-collection here is a hole, not noise.

The environments these benchmarks ship hold directories of other people, and the
attacker is one of the rows. A walk over every nested dict returns the acting
user together with the attacker.
"""
import pytest

# broker_defense imports AgentDojo's executor at module level, so this file runs
# in the benchmark environment and skips in the library one.
pytest.importorskip("agentdojo")

from benchmarks.live.broker_defense import session_identity


def _env():
    """A mailbox component owned by one account, holding a directory of many."""
    return {
        "calendar": {"account_email": "emma.johnson@bluesparrowtech.com",
                     "events": []},
        "email_database": {
            "inbox_list": [
                {"account_email": "emma.johnson@bluesparrowtech.com"},
                {"account_email": "alice.miller@gmail.com"},
                {"account_email": "trustme@gmail.com"},
                {"account_email": "security_maintenance@gmail.com"},
            ]},
        "github_platform": {
            "account_list": [{"email": "a.chen@bluesparrowtech.com"}]},
    }


def test_identity_is_the_signed_in_account_only():
    assert session_identity(_env()) == {"emma.johnson@bluesparrowtech.com"}


def test_a_directory_of_other_accounts_is_not_this_session_s_identity():
    got = session_identity(_env())
    for other in ("trustme@gmail.com", "security_maintenance@gmail.com",
                  "alice.miller@gmail.com", "a.chen@bluesparrowtech.com"):
        assert other not in got


def test_a_non_address_identity_field_is_ignored():
    # 'sender' and other placeholder tokens would be stripped out of content
    # fields and mangle the text the destination scanner reads.
    assert session_identity({"m": {"account_id": "sender"}}) == set()


def test_an_environment_with_no_signed_in_account_yields_nothing():
    assert session_identity({"bank": {"balance": 10}}) == set()
    assert session_identity(None) == set()
