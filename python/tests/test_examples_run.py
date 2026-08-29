"""Every script in `examples/` runs.

`test_documented_quickstart.py` covers the code blocks inside the docs. This
covers the files the docs tell people to run, which is the other half of the same
promise. Both exist because the first thing a new user executes is the worst
place to discover an API changed.

Each runs in a subprocess with the repository root as the working directory, so a
script that quietly depends on being imported rather than executed fails here.
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
EXAMPLES = sorted((REPO / "examples").glob("*.py"))


def test_there_are_examples_to_run():
    """Guard the guard: an empty glob would pass every test below."""
    assert EXAMPLES, "examples/ has no scripts"


@pytest.mark.parametrize("script", EXAMPLES, ids=[p.name for p in EXAMPLES])
def test_example_runs(script: Path):
    result = subprocess.run(
        [sys.executable, str(script)],
        cwd=REPO, capture_output=True, text=True, timeout=120, check=False,
    )
    assert result.returncode == 0, (
        f"{script.name} exited {result.returncode}\n"
        f"--- stdout ---\n{result.stdout}\n--- stderr ---\n{result.stderr}"
    )


def test_the_gateway_example_actually_refuses_something():
    """A quickstart that never denies is a quickstart that demonstrates nothing.

    `01_gateway.py` plants an injected destination in a ticket the agent is
    allowed to read. If every call is allowed, either the example stopped
    exercising the gateway or the gateway stopped working, and both are worth
    failing over.
    """
    result = subprocess.run(
        [sys.executable, str(REPO / "examples" / "01_gateway.py")],
        cwd=REPO, capture_output=True, text=True, timeout=120, check=False,
    )
    assert result.returncode == 0, result.stderr
    # `HOLD` is a step-up and `DENY` is a refusal. The example prints them
    # differently on purpose, and either one proves the gateway answered, so
    # accept both rather than pinning the example to one verdict.
    assert ("DENY" in result.stdout or "HOLD" in result.stdout), result.stdout
    assert "collector-metrics.example" in result.stdout


def test_the_proxy_example_holds_the_ceiling_and_the_tool_never_runs():
    """The README's opening claim, asserted rather than narrated.

    `02_the_proxy.py` issues eleven $900 refunds against a $1,000 ceiling. Two
    things have to be true and they are different claims: the agent was refused
    (the JSON-RPC errors) and the money did not move (the server's own ledger,
    which the example prints back). A demo that asserted only the first would
    pass with a proxy that denied the client and forwarded the call anyway.
    """
    result = subprocess.run(
        [sys.executable, str(REPO / "examples" / "02_the_proxy.py")],
        cwd=REPO, capture_output=True, text=True, timeout=120, check=False,
    )
    assert result.returncode == 0, result.stderr
    out = result.stdout

    # Refused, ten times, at the ceiling rather than for some other reason.
    assert out.count("value_budget_exceeded") == 10, out

    # A tool outside the grant is never advertised, and is still refused if the
    # client calls it without being told.
    assert "withheld from the catalog: wire_funds" in out, out
    assert "tool 'wire_funds' is not in this session's policy" in out, out

    # The claim that matters: exactly one refund reached the server.
    assert "the server executed 2 call(s)" in out, out
    assert out.count("issue_refund {") == 1, out


def test_the_example_policy_is_the_one_the_docs_name():
    """README and DEV_GUIDE both point at `examples/policy.yaml`."""
    from clayseal.capabilities.policy import load_policy

    policy = load_policy(REPO / "examples" / "policy.yaml")
    assert [f for f in policy.lint() if f.level == "error"] == []
    assert policy.allowed_tools
