"""Session content must not reach a third party on ambient credentials alone.

The entailment judge's prompt carries the user's request text and the declared
write payloads. That is the content this gateway exists to keep inside the
deployment, and `make_chat_client` will build a client from `OPENAI_API_KEY`,
`AZURE_OPENAI_*`, or a key file in the home directory. A deployment holding an
OpenAI key for an unrelated reason must not start calling out because of it.
"""
from __future__ import annotations

import pytest

from agentauth.capabilities import deployable_stack as ds
from agentauth.capabilities.scoping.goal import GoalSpec

CREDENTIALS = ["OPENAI_API_KEY", "AZURE_OPENAI_ENDPOINT", "AZURE_OPENAI_KEY",
               "AZURE_OPENAI_API_KEY"]


def _goal():
    return GoalSpec(query_id="q", summary="s", allow_resources=[],
                    allow_agent_memory_writes=False)


@pytest.fixture
def sentinel_judge(monkeypatch):
    """Stand in for a real client so no test can make a network call."""
    monkeypatch.setattr(ds, "default_entailment_judge",
                        lambda **_: "JUDGE-BUILT")
    for var in [*CREDENTIALS, "CLAYSEAL_ENTAILMENT"]:
        monkeypatch.delenv(var, raising=False)


@pytest.mark.parametrize("var", CREDENTIALS)
def test_a_credential_in_the_environment_does_not_enable_the_judge(
        sentinel_judge, monkeypatch, var):
    monkeypatch.setenv(var, "sk-not-a-real-key-000000000000")
    assert ds.DeployableStack.from_goal(_goal()).broker.entailment_judge is None


def test_the_default_build_makes_no_outbound_client(sentinel_judge):
    assert ds.DeployableStack.from_goal(_goal()).broker.entailment_judge is None


@pytest.mark.parametrize("value", ["1", "true", "TRUE", "yes", "on"])
def test_an_explicit_opt_in_enables_it(sentinel_judge, monkeypatch, value):
    monkeypatch.setenv("CLAYSEAL_ENTAILMENT", value)
    stack = ds.DeployableStack.from_goal(_goal())
    # The broker wraps whatever it is given in its own wall-clock bound, so the
    # test is that one exists, not that it is the object handed over.
    assert stack.broker.entailment_judge is not None


@pytest.mark.parametrize("value", ["0", "false", "no", "off", "", "maybe"])
def test_anything_else_leaves_it_off(sentinel_judge, monkeypatch, value):
    monkeypatch.setenv("CLAYSEAL_ENTAILMENT", value)
    assert ds.DeployableStack.from_goal(_goal()).broker.entailment_judge is None


def test_a_judge_passed_explicitly_is_still_honoured(sentinel_judge):
    """Opting in by argument stays available; only the ambient path is closed."""
    stack = ds.DeployableStack.from_goal(_goal(), entailment_judge=lambda *a: [])
    assert stack.broker.entailment_judge is not None


def test_passing_none_explicitly_disables_it_even_when_opted_in(
        sentinel_judge, monkeypatch):
    monkeypatch.setenv("CLAYSEAL_ENTAILMENT", "1")
    stack = ds.DeployableStack.from_goal(_goal(), entailment_judge=None)
    assert stack.broker.entailment_judge is None
