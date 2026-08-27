"""The policy in the README has to be a policy the tool accepts.

The first version of that block used a `value_budget:` key with `ceiling` and
`amount_arg`. No such schema exists. A reader copying it would have got a parse
error from the first thing they tried.
"""
from __future__ import annotations

import re
import tempfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]


def _first_yaml_block() -> str:
    readme = ROOT / "README.md"
    if not readme.exists():
        pytest.skip("README.md not present")
    blocks = re.findall(r"```yaml\n(.*?)```", readme.read_text(), re.DOTALL)
    if not blocks:
        pytest.skip("no yaml block in README.md")
    return blocks[0]


def test_the_readme_policy_loads():
    from clayseal.capabilities.policy import load_policy_text

    policy = load_policy_text(_first_yaml_block())
    assert policy.allowed_tools == {"list_open_refunds", "issue_refund"}


def test_the_readme_policy_lints_without_errors():
    from clayseal.capabilities.policy import load_policy_text

    findings = load_policy_text(_first_yaml_block()).lint()
    errors = [f for f in findings if f.level == "error"]
    assert not errors, [f"{f.code}: {f.message}" for f in errors]


def test_the_readme_policy_builds_a_working_gateway():
    """A policy that parses but cannot enforce is still a broken example."""
    from clayseal.capabilities.guardrail import Guardrail, Refused

    with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as fh:
        fh.write(_first_yaml_block())
        path = fh.name

    guard = Guardrail.from_policy_file(path)
    tools = guard.wrap_all({
        "list_open_refunds": lambda: [{"invoice": "INV-001", "amount": 900.0}],
        "issue_refund": lambda invoice, amount: f"refunded {invoice}",
    })
    assert tools["issue_refund"](invoice="INV-001", amount=900.0)
    # The $1,000 session ceiling is now spent, so a second $900 refund cannot run.
    with pytest.raises(Refused):
        tools["issue_refund"](invoice="INV-002", amount=900.0)
