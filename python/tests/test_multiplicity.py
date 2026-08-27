"""How many times the sealed goal accounts for an effect.

The aggregate rung enforces a ceiling somebody declared, and measured on eleven
independently-authored corpora **0 of 520 tasks declare one**. The rung is
therefore inert for exactly the deployments that will never write a budget.

The envelope is derived rather than declared, and it could say which tools and
whether a phase repeats at all, never how many times: a goal reading "email a
summary" admitted one send and fifty identically. This derives the count from the
goal so the bound exists without anyone writing it.

Everything here is about staying conservative. A bound nobody asked for that
refuses legitimate work teaches an operator to switch the rung off, and then the
deployment has neither.
"""
from __future__ import annotations

import pytest

from clayseal.capabilities.broker import SessionBroker
from clayseal.capabilities.hardening.egress_policy import EgressPolicy
from clayseal.capabilities.monitor.action import Action
from clayseal.capabilities.monitor.generation import compile_envelope
from clayseal.capabilities.monitor.intent_envelope import Deviation, Phase
from clayseal.capabilities.monitor.multiplicity import (
    apply_multiplicity,
    multiplicity_for,
)
from clayseal.capabilities.scoping.goal import GoalSpec


# --------------------------------------------------------------------------- #
# What the goal says
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("text,verb,expected", [
    # An explicit numeral, directly bound to the effect noun.
    ("Send 3 emails to the vendor list", "send", 3),
    ("Refund up to 5 charges", "transfer", 5),
    # A number word.
    ("Pay the two invoices that cleared", "transfer", 2),
    ("Refund both charges", "transfer", 2),
    # A singular determiner.
    ("Triage the tickets and email a summary to ops", "send", 1),
    ("Issue a refund for the duplicate charge", "transfer", 1),
    ("Write a summary to out/summary.md", "write", 1),
    ("Email a summary to ops@acme.com", "send", 1),
])
def test_a_goal_that_says_how_many_yields_that_many(text, verb, expected):
    assert multiplicity_for(text, verb) == expected


@pytest.mark.parametrize("text,verb", [
    # Iteration markers: the goal has said it does not know the count either.
    ("Email each customer a summary", "send"),
    ("Email all affected customers", "send"),
    ("Process every refund in the queue", "transfer"),
    ("Post the report to every channel", "send"),
    # A plural effect noun.
    ("Write summaries for the open tickets", "write"),
    ("Email the summaries to the leads", "send"),
    # No effect noun at all.
    ("Reconcile the ledger", "transfer"),
    ("Summarise the tickets", "send"),
])
def test_a_goal_that_does_not_say_yields_no_bound(text, verb):
    """Unbounded is the safe default and most goals get it."""
    assert multiplicity_for(text, verb) == 0


def test_a_numeral_must_be_adjacent_to_the_effect_noun():
    """The first version read any numeral in the clause.

    On `sleight` that turned a path fragment into a bound of 43. A bound derived
    from a coincidence is a rung nobody can reason about.
    """
    assert multiplicity_for("Clean up ~/run-43 and email the log", "send") == 0


def test_an_ambiguous_clause_yields_no_bound():
    """"Delete 900 stale files then write a report" supports 900 and 1.

    There is no principled way to pick: the larger is a bound nobody meant, the
    smaller refuses work the goal asks for. So neither.
    """
    assert multiplicity_for("Delete 900 stale files then write a report", "write") == 0
    assert multiplicity_for("Send a report to Alice and Bob", "send") == 0


def test_plurality_is_read_off_the_noun_that_matched():
    """Checking the whole clause let an unrelated plural suppress a correct read.

    "delete 900 stale files then write a report" had its singular read of "a
    report" cancelled by "files", leaving only the spurious 900.
    """
    assert multiplicity_for("Archive the old files and write a report", "write") == 1


def test_an_unknown_verb_class_is_never_bounded():
    assert multiplicity_for("Send 3 emails", "read") == 0
    assert multiplicity_for("", "send") == 0


# --------------------------------------------------------------------------- #
# What it does to an envelope
# --------------------------------------------------------------------------- #
def test_a_bare_goal_gains_a_bounded_phase():
    """The common case. A goal with no structured intent compiles to an envelope
    with no phases at all, so without this the capability would exist only for
    deployments that already wrote a plan."""
    goal = GoalSpec(query_id="q", summary="Triage the tickets and email a summary")
    envelope = compile_envelope(goal, derive_counts=True).envelope
    phases = list(getattr(envelope, "phases", ()) or ())
    # Two phases, and both are right: "a summary" is one thing to write and one
    # thing to send, and `summary` is an effect noun for each verb class.
    assert [(sorted(p.verbs), p.max) for p in phases] == [(["send"], 1),
                                                          (["write"], 1)]


def test_a_goal_that_says_nothing_gains_no_phase():
    goal = GoalSpec(query_id="q", summary="Email each customer their statement")
    assert not (getattr(compile_envelope(goal, derive_counts=True).envelope, "phases", ()) or ())


def test_a_declared_bound_is_never_overruled():
    """A phase that already carries `max` was configured by somebody, and a
    derived guess does not get to overrule a declaration in either direction."""
    class Env:
        phases = (Phase(verbs=frozenset({"send"}), max=7),)

    from dataclasses import dataclass, field

    @dataclass
    class Simple:
        phases: tuple = field(default_factory=tuple)

    envelope = Simple(phases=(Phase(verbs=frozenset({"send"}), max=7),))
    out = apply_multiplicity(envelope, "email a summary")
    assert out.phases[0].max == 7


def test_derivation_can_be_switched_off():
    goal = GoalSpec(query_id="q", summary="Triage the tickets and email a summary")
    envelope = compile_envelope(goal, derive_counts=False).envelope
    assert not (getattr(envelope, "phases", ()) or ())


# --------------------------------------------------------------------------- #
# What the gateway does with it
# --------------------------------------------------------------------------- #
def _broker(summary):
    goal = GoalSpec(query_id="q", summary=summary)
    return SessionBroker(goal=goal, intent_envelope=compile_envelope(goal, derive_counts=True).envelope,
                         egress=EgressPolicy(allowed_domains={"acme-internal.com"}))


def _send(step):
    return Action(step=step, tool="send_email", verb="send",
                  resource="mcp:tool:send_email",
                  args={"to": "ops@acme-internal.com", "body": "the summary"})


def test_the_bound_is_enforced_with_no_budget_declared_anywhere():
    """The whole point: an aggregate constraint on a deployment that declares
    nothing, which is 0 of 520 external corpus tasks."""
    broker = _broker("Triage the tickets and email a summary to ops@acme-internal.com")
    assert broker.authorize(_send(0)).allowed is True
    second = broker.authorize(_send(1))
    assert second.allowed is False


def test_exceeding_a_derived_bound_steps_up_rather_than_denying():
    """A derived bound is evidence, not proof.

    A retry after a failed send looks exactly like a second send, and nothing in
    the sentence distinguishes them. A halt a person can clear costs one
    interruption; a denial costs the task.
    """
    broker = _broker("Triage the tickets and email a summary to ops@acme-internal.com")
    broker.authorize(_send(0))
    second = broker.authorize(_send(1))
    assert second.outcome.value == "step_up"
    assert any("sealed goal accounts for" in r for r in second.reasons)
    assert any("derived from the goal, not declared" in r for r in second.reasons)


def test_a_goal_with_no_derivable_count_bounds_nothing():
    broker = _broker("Email each customer their statement")
    for step in range(5):
        assert broker.authorize(_send(step)).allowed is True


def test_the_count_is_read_before_any_untrusted_content_exists():
    """Seal time, from the goal text only.

    The bound cannot be influenced by what the agent later reads, which is what
    separates it from a limit inferred at runtime.
    """
    import ast
    import inspect

    from clayseal.capabilities.monitor import multiplicity

    # The AST, not the source text. The docstrings legitimately NAME the things
    # this module must not touch while explaining why it does not touch them, and
    # a substring search cannot tell an explanation from a usage. The same fix
    # `test_bpl_suite_reporting` needed for the same reason.
    tree = ast.parse(inspect.getsource(multiplicity))
    forbidden = {"observe_output", "structured_fields", "trajectory",
                 "tool_result", "observe_fact", "record_observation"}
    used = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Name):
            used.add(node.id)
        elif isinstance(node, ast.Attribute):
            used.add(node.attr)
        elif isinstance(node, ast.arg):
            used.add(node.arg)
    assert not (used & forbidden), sorted(used & forbidden)


def test_the_deviation_is_its_own_kind():
    """So a reader of a decision record can tell a derived count miss from an
    off-plan tool, which are different evidence."""
    assert Deviation.OVER_COUNT.value == "over-count"


# --------------------------------------------------------------------------- #
# The optional inferrer
# --------------------------------------------------------------------------- #
from clayseal.capabilities.monitor.multiplicity import (
    bounded_multiplicity,
    default_multiplicity_inferrer,
    llm_multiplicity_inferrer,
)


def _says(value):
    return lambda goal_text, verb_class: value


def test_without_an_inferrer_nothing_changes():
    assert bounded_multiplicity("email a summary", "send") == (1, "derived")
    assert bounded_multiplicity("handle the queue", "send") == (0, "")


def test_fill_gaps_infers_only_where_the_text_says_nothing():
    """Where the sentence carries evidence, that evidence wins.

    A reviewer can check a derived bound against the goal. They cannot check a
    model's opinion, so the model does not get to overrule what they can.
    """
    assert bounded_multiplicity(
        "email a summary", "send", inferrer=_says(2)) == (1, "derived")
    assert bounded_multiplicity(
        "handle the queue", "send", inferrer=_says(2)) == (2, "inferred")


def test_an_inferrer_may_never_raise_a_derived_bound():
    """The monotone rule, same as `conditional_ceiling`.

    A proposal that only shrinks authority is safe whoever wrote it. One that can
    widen is a lever for whoever influenced the model.
    """
    for mode in ("fill_gaps", "tighten"):
        value, source = bounded_multiplicity(
            "email a summary", "send", inferrer=_says(9), mode=mode)
        assert (value, source) == (1, "derived"), mode


def test_tighten_mode_lets_an_inferrer_lower_a_derived_bound():
    assert bounded_multiplicity(
        "send 3 emails", "send", inferrer=_says(1), mode="tighten") == (1, "inferred")


@pytest.mark.parametrize("proposal", [0, -1, 5000, None, True, False, "2", 1.5])
def test_a_nonsense_proposal_is_ignored(proposal):
    """Including booleans, which are ints in Python and must not pass as counts."""
    assert bounded_multiplicity(
        "handle the queue", "send", inferrer=_says(proposal)) == (0, "")


def test_an_inferrer_that_raises_falls_back_to_the_derived_reading():
    """It can only ever create a step-up, so losing it forfeits an advisory."""
    def explodes(goal_text, verb_class):
        raise RuntimeError("no")

    assert bounded_multiplicity("email a summary", "send",
                                inferrer=explodes) == (1, "derived")
    assert bounded_multiplicity("handle the queue", "send",
                                inferrer=explodes) == (0, "")


def test_an_unknown_mode_disables_the_inferrer():
    assert bounded_multiplicity(
        "handle the queue", "send", inferrer=_says(2), mode="anything") == (0, "")


def test_the_inferrer_sees_the_goal_and_nothing_else():
    """Seal time, trusted text. That is what makes a model acceptable here: the
    planner privilege split allows an LLM in the control plane and never in the
    decision path."""
    seen = []

    def record(goal_text, verb_class):
        seen.append((goal_text, verb_class))
        return None

    bounded_multiplicity("handle the queue", "send", inferrer=record)
    assert seen == [("handle the queue", "send")]


def test_the_bound_carries_its_provenance_into_the_step_up():
    """A step-up whose origin is unknown is not reviewable."""
    goal = GoalSpec(query_id="q",
                    summary="Work through the escalation queue and notify the owner")
    envelope = compile_envelope(
        goal, inferrer=lambda g, v: 1 if v == "send" else None, derive_counts=True).envelope
    phase = next(p for p in envelope.phases if "send" in p.verbs)
    assert (phase.max, phase.max_source) == (1, "inferred")

    from clayseal.capabilities.hardening.egress_policy import EgressPolicy

    broker = SessionBroker(goal=goal, intent_envelope=envelope,
                           egress=EgressPolicy(allowed_domains={"acme-internal.com"}))
    broker.authorize(_send(0))
    second = broker.authorize(_send(1))
    assert second.outcome.value == "step_up"
    assert any("[inferred]" in r for r in second.reasons)


def test_a_derived_bound_is_labelled_derived():
    goal = GoalSpec(query_id="q", summary="Email a summary to ops@acme-internal.com")
    phase = next(p for p in compile_envelope(goal, derive_counts=True).envelope.phases if "send" in p.verbs)
    assert (phase.max, phase.max_source) == (1, "derived")


def test_the_model_backed_inferrer_returns_none_on_every_failure():
    class Broken:
        class chat:
            class completions:
                @staticmethod
                def create(**kwargs):
                    raise RuntimeError("rate limited")

    infer = llm_multiplicity_inferrer(Broken(), "m", budget_seconds=2)
    assert infer("email a summary", "send") is None


@pytest.mark.parametrize("content", ['{"count": null}', "{}", "not json",
                                     '{"count": "two"}', '{"count": 0}',
                                     '{"count": 99999}'])
def test_the_model_backed_inferrer_rejects_a_bad_completion(content):
    class Client:
        class chat:
            class completions:
                @staticmethod
                def create(**kwargs):
                    message = type("M", (), {"content": content})()
                    choice = type("C", (), {"message": message})()
                    return type("R", (), {"choices": [choice]})()

    infer = llm_multiplicity_inferrer(Client(), "m", budget_seconds=2)
    assert infer("handle the queue", "send") is None


def test_the_model_backed_inferrer_is_bounded():
    """It runs inside envelope compilation, and a control plane that hangs is a
    control plane that is down."""
    import time

    class Slow:
        class chat:
            class completions:
                @staticmethod
                def create(**kwargs):
                    time.sleep(30)

    infer = llm_multiplicity_inferrer(Slow(), "m", budget_seconds=0.25)
    started = time.monotonic()
    assert infer("handle the queue", "send") is None
    assert time.monotonic() - started < 5.0


def test_without_credentials_there_is_no_default_inferrer(monkeypatch, tmp_path):
    """Absent configuration is not an error: the deterministic reading stands."""
    for name in ("OPENAI_API_KEY", "AZURE_OPENAI_ENDPOINT", "AZURE_OPENAI_KEY",
                 "AZURE_OPENAI_API_KEY"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("HOME", str(tmp_path))
    assert default_multiplicity_inferrer() is None
