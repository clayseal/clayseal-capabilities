"""An undeclared dangerous tool must be caught before it ever runs.

`classify_verb` returns `call` for a name it does not recognise, and `call` is
DISCLOSURE, below WRITE, so an undeclared `wire_funds` is not `is_effectful`:
the floor's write and egress rules do not engage and no rung may refuse it.

Widening the inference to recognise `wire`, `destroy`, `purge` and the rest was
tried and measured. It raised containment on the BPL suite from 54 to 58 of 132
and raised FALSE BLOCKS from 2 to 8, leaving the joint metric unchanged at 52.
`granted_read` inferred to a write. Guessing harder is the wrong lever, because
a read misread as an effect is refused, and this is the utility leak the
classifier's own comment warns about.

The lever that costs nothing is the policy lint, which runs before deployment.
These tests hold that line: inference stays conservative, and the lint refuses
to let an undeclared effectful tool ship.
"""
from __future__ import annotations

import pytest

from clayseal.capabilities.policy import load_policy_text

DANGEROUS = ["wire_funds", "terraform_destroy", "purge_bucket"]

POLICY = """
version: 1
goal: {{id: q, summary: Manage infrastructure and payments.}}
expires_at: 2027-12-31T00:00:00Z
tools:
  allow: [{tools}]
paths:
  pathless: [{tools}]
"""


def _lint(tools):
    return load_policy_text(POLICY.format(tools=", ".join(tools))).lint()


def test_an_undeclared_effectful_tool_is_an_error_not_a_warning():
    codes = {f.code for f in _lint([*DANGEROUS, "get_status"])
             if f.level == "error"}
    assert "untracked-effectful-tool" in codes


@pytest.mark.parametrize("tool", DANGEROUS)
def test_the_lint_names_the_tool_whose_verb_it_had_to_guess(tool):
    findings = [f for f in _lint([*DANGEROUS, "get_status"])
                if f.code == "verb-not-declared"]
    assert findings, "nothing reported the guessed verb"
    assert tool in " ".join(f.message for f in findings)


def test_declaring_the_effect_clears_both_findings():
    doc = POLICY.format(tools=", ".join([*DANGEROUS, "get_status"])).replace(
        "tools:\n  allow:",
        "tools:\n  harmless: [get_status]\n  effects: {wire_funds: transfer, "
        "terraform_destroy: write, purge_bucket: write, get_status: read}\n"
        "  allow:")
    policy = load_policy_text(doc)
    assert policy.unclassified_tools() == []
    assert not [f for f in policy.lint() if f.code == "verb-not-declared"]


@pytest.mark.parametrize("tool", [
    "get_user", "list_orders", "search_flights", "read_ticket", "find_invoice",
    "view_report", "check_status", "describe_instance", "lookup_customer",
    "get_scheduled_transactions", "list_deleted_items", "search_payments",
])
def test_a_read_is_still_a_read(tool):
    """Inference stays conservative in the direction that costs utility."""
    from clayseal.capabilities.tool_verbs import classify_verb

    assert classify_verb(tool) == "read"
