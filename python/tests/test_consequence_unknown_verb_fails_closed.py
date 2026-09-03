"""An unrecognised verb must not be graded as a read.

The three effect sets in `consequence.py` are closed, and DISCLOSURE used to be
what a verb fell through to when it was in none of them. DISCLOSURE sits below
WRITE, so `is_effectful` was False and every rung whose refusal path asks for an
effect declined to fire. Reproduced through `SessionBroker` before the fix: an
off-plan action moving 50,000 to an unknown address was DENY when its verb was
`send` and STEP_UP, reasoned "read content the sealed goal did not ask for",
when its verb was `disburse`.

The shipped path reached it with no exotic vocabulary at all.
`tool_verbs.classify_verb` answers `call` for any name it does not recognise,
and `sandbox/monitor_feed.py` emits `exec` for every process the sandbox reports.

Measured cost of failing closed instead, on the benign side: zero. Forcing this
rung to DESTRUCTIVE on EVERY action, which is the most aggressive thing the
ladder can express, changes no benign outcome on 19,085 held-out-mandate benign
events (tau2, BFCL, ATIF, AgentHarm) or on the 132 BPL benign twins, while the
same forcing does move AgentHarm attack containment. Benign traffic that reaches
this rung is on-plan; off-plan benign traffic is refused by the floor before the
rung is consulted.
"""
from __future__ import annotations

import pytest

from clayseal.capabilities.monitor.action import Action
from clayseal.capabilities.monitor.consequence import (
    ConsequenceLevel,
    classify,
    is_effectful,
)
from clayseal.capabilities.tool_verbs import classify_verb

#: Words nobody put in a list, plus the two the shipped code actually emits.
UNFAMILIAR = ["disburse", "provision", "settle", "void", "archive", "escalate",
              "remit", "release", "wire", "call", "exec"]


def _act(verb: str) -> Action:
    # A neutral tool name on purpose: `disburse_grant` would carry the word
    # `grant` into the security-surface check and pass this test for the wrong
    # reason, which is how the first version of this probe fooled its author.
    return Action(0, "disburse_funds", "mcp:tool:disburse_funds", verb,
                  args={"amount": 50000, "to": "somebody@example.test"})


@pytest.mark.parametrize("verb", UNFAMILIAR)
def test_an_unrecognised_verb_is_at_least_a_write(verb):
    level, why = classify(_act(verb))
    assert level >= ConsequenceLevel.WRITE, why
    assert is_effectful(_act(verb)), why


@pytest.mark.parametrize("verb", UNFAMILIAR)
def test_an_unrecognised_verb_that_names_nothing_still_had_its_effect(verb):
    # `terraform_destroy` takes no path. The no-target exemption is a fact about
    # reads and must not be extended to verbs nobody recognised.
    assert is_effectful(Action(0, "t", "", verb))


def test_the_verb_the_shipped_classifier_emits_for_an_unknown_name():
    # This is the path a deployment is on when it declares nothing.
    assert classify_verb("wire_funds") == "call"
    assert is_effectful(_act(classify_verb("wire_funds")))


@pytest.mark.parametrize("verb", ["read", "get", "list", "search", "view",
                                  "fetch", "describe", "lookup", "cat", "grep"])
def test_a_recognised_read_is_still_a_disclosure(verb):
    # The other half of the trade. A read must keep landing below WRITE, or the
    # two-signal gate refuses reconnaissance it is supposed to escalate.
    level, why = classify(_act(verb))
    assert level is ConsequenceLevel.DISCLOSURE, why
    assert not is_effectful(_act(verb))


def test_a_recognised_read_naming_nothing_is_still_inconsequential():
    assert classify(Action(0, "noop", "", "read"))[0] is ConsequenceLevel.NONE


def test_aml_and_consequence_read_one_security_vocabulary():
    # They had two copies under a comment claiming they were in sync, and the
    # copy in aml.py was missing "key".
    from clayseal.capabilities.monitor import aml, consequence

    assert aml.touches_security_surface is consequence.touches_security_surface
    assert "key" in consequence.SECURITY_SURFACE_WORDS
    assert not hasattr(aml, "_SECURITY_SURFACE")
