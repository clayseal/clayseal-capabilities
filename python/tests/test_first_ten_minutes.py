"""The path `docs/START.md` sends a new reader down, walked end to end.

A getting-started page is the highest-traffic document in a repository and the
one nobody re-runs. This walks the sequence it prescribes in a temporary
directory, so a change that breaks the newcomer's path fails here instead of on
somebody's first evening with the library.
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
START = ROOT / "docs" / "START.md"
CLI = [sys.executable, "-m", "clayseal.capabilities.cli"]


@pytest.fixture()
def workspace(tmp_path: Path) -> Path:
    """A directory that is not the checkout, which is where the reader is."""
    return tmp_path


def _run(args, cwd, **kw):
    return subprocess.run([*CLI, *args], cwd=cwd, capture_output=True,
                          text=True, timeout=120, check=False, **kw)


def test_step_one_the_demo_runs(workspace: Path) -> None:
    result = _run(["try", "--fast"], workspace)
    assert result.returncode == 0, result.stdout + result.stderr


def test_step_two_the_starter_policy_refuses_to_lint_until_it_is_edited(
        workspace: Path) -> None:
    """The template must not be usable as-is.

    `policy new` writes a file that names placeholder tools and a TODO goal. If
    that linted clean, the guide would be teaching people to ship it.
    """
    policy = workspace / "policy.yaml"
    written = _run(["policy", "new"], workspace)
    assert written.returncode == 0, written.stderr
    policy.write_text(written.stdout)

    lint = _run(["policy", "lint", str(policy)], workspace)
    assert lint.returncode != 0, "an unedited starter policy linted clean"
    assert "unedited-template" in lint.stdout


def test_step_two_it_lints_clean_once_the_todos_are_answered(
        workspace: Path) -> None:
    policy = workspace / "policy.yaml"
    policy.write_text(_run(["policy", "new"], workspace).stdout
                      .replace("summary: TODO describe the job in one sentence",
                               "summary: Triage billing tickets and email ops")
                      .replace("your_read_tool", "read_ticket")
                      .replace("your_send_tool", "send_email")
                      .replace("your_refund_tool", "issue_refund")
                      .replace("id: TODO-name-this-run", "id: billing-triage"))
    lint = _run(["policy", "lint", str(policy)], workspace)
    assert lint.returncode == 0, lint.stdout + lint.stderr


def test_step_three_the_wrapped_tools_enforce_that_policy(
        workspace: Path) -> None:
    """The whole point: the file from step two governs real functions.

    Both documented exception types have to be reachable, since step four tells
    the reader to catch them and explains that they mean different things.
    """
    policy = workspace / "policy.yaml"
    policy.write_text(_run(["policy", "new"], workspace).stdout
                      .replace("summary: TODO describe the job in one sentence",
                               "summary: Triage billing tickets and email ops@acme.example")
                      .replace("your_read_tool", "read_ticket")
                      .replace("your_send_tool", "send_email")
                      .replace("your_refund_tool", "issue_refund")
                      .replace("id: TODO-name-this-run", "id: billing-triage")
                      .replace("your-company.example", "acme.example"))

    script = workspace / "step3.py"
    script.write_text(
        "from clayseal.capabilities import Guardrail, Refused, StepUpRequired\n"
        "guard = Guardrail.from_policy_file('policy.yaml')\n"
        "tools = guard.wrap_all({'send_email': lambda to, body: 'sent',\n"
        "                        'read_ticket': lambda id: {'id': id}})\n"
        "def act(**kw):\n"
        "    try:\n"
        "        return 'ok ' + tools['send_email'](**kw)\n"
        "    except Refused as exc:\n"
        "        return 'refused ' + exc.reasons[0]\n"
        "    except StepUpRequired as exc:\n"
        "        return 'held ' + exc.reasons[0]\n"
        "print(act(to='ops@acme.example', body='x'))\n"
        "print(act(to='collector@evil.test', body='x'))\n")
    result = subprocess.run([sys.executable, str(script)], cwd=workspace,
                            capture_output=True, text=True, timeout=120,
                            check=False)
    assert result.returncode == 0, result.stdout + result.stderr
    allowed, stopped = result.stdout.strip().splitlines()
    assert allowed.startswith("ok "), allowed
    assert stopped.startswith(("refused ", "held ")), stopped
    assert "evil.test" in stopped


def test_step_three_named_recipients_and_a_refund_ceiling_both_bind(
        workspace: Path) -> None:
    """The path a rename-only first deploy actually takes.

    Filling `egress.recipients` used to look broken: a sibling mailbox on the
    granted domain was held with a provenance sentence, so the agent thought
    the allow-list had not applied. The refund ceiling is the other half of
    `clayseal try`, and wrapping it has to refuse the second spend.
    """
    policy = workspace / "policy.yaml"
    policy.write_text(_run(["policy", "new"], workspace).stdout
                      .replace("summary: TODO describe the job in one sentence",
                               "summary: Triage billing tickets and email ops@acme.example")
                      .replace("your_read_tool", "read_ticket")
                      .replace("your_send_tool", "send_email")
                      .replace("your_refund_tool", "issue_refund")
                      .replace("id: TODO-name-this-run", "id: billing-triage")
                      .replace("your-company.example", "acme.example")
                      .replace("recipients: []", "recipients: [ops@acme.example]"))
    lint = _run(["policy", "lint", str(policy)], workspace)
    assert lint.returncode == 0, lint.stdout + lint.stderr

    script = workspace / "billing.py"
    script.write_text(
        "from clayseal.capabilities import Guardrail, Refused, StepUpRequired\n"
        "guard = Guardrail.from_policy_file('policy.yaml')\n"
        "tools = guard.wrap_all({\n"
        "    'read_ticket': lambda id: {'id': id},\n"
        "    'send_email': lambda to, body: 'sent',\n"
        "    'issue_refund': lambda invoice, amount: 'ok',\n"
        "})\n"
        "def act(fn, **kw):\n"
        "    try:\n"
        "        return 'ok ' + str(fn(**kw))\n"
        "    except Refused as exc:\n"
        "        return 'refused ' + exc.reasons[0]\n"
        "    except StepUpRequired as exc:\n"
        "        return 'held ' + exc.reasons[0]\n"
        "print(act(tools['issue_refund'], invoice='INV-1', amount=900.0))\n"
        "print(act(tools['issue_refund'], invoice='INV-2', amount=200.0))\n"
        "print(act(tools['send_email'], to='ops@acme.example', body='x'))\n"
        "print(act(tools['send_email'], to='finance@acme.example', body='x'))\n"
        "print(act(tools['send_email'], to='evil@evil.test', body='x'))\n")
    result = subprocess.run([sys.executable, str(script)], cwd=workspace,
                            capture_output=True, text=True, timeout=120,
                            check=False)
    assert result.returncode == 0, result.stdout + result.stderr
    first, second, ops, sibling, off_domain = result.stdout.strip().splitlines()
    assert first.startswith("ok "), first
    assert second.startswith("refused "), second
    assert "value_budget" in second
    assert ops.startswith("ok "), ops
    assert sibling.startswith("held "), sibling
    assert "egress.recipients" in sibling
    assert "appears in no observation" not in sibling
    assert off_domain.startswith(("refused ", "held ")), off_domain
    assert "evil.test" in off_domain


def test_the_starter_names_verbs_the_compiler_will_accept() -> None:
    """A first-user who copies the comment into `tools.effects` has to succeed."""
    from clayseal.capabilities.policy import KNOWN_VERBS
    from clayseal.capabilities.starter import starter_policy

    text = starter_policy()
    assert "delete, execute" not in text
    line = next(ln for ln in text.splitlines() if ln.startswith("  # One of:"))
    named = {part.strip() for part in line.split(":", 1)[1].split(",")}
    assert named == set(KNOWN_VERBS), named


def test_the_guide_only_promises_commands_that_exist() -> None:
    """Every `clayseal ...` line in START.md has to be a real command.

    Cheap, and it catches the way a getting-started page usually goes wrong,
    which is naming a command that was renamed somewhere else.
    """
    import re

    text = START.read_text()
    subcommands = {
        m.group(1) for m in re.finditer(r"^\s*clayseal (\w+(?: \w+)?)", text, re.MULTILINE)
    }
    assert subcommands, "no clayseal commands found in the guide"
    help_text = _run(["--help"], ROOT).stdout
    for command in sorted(subcommands):
        top = command.split()[0]
        assert top in help_text, f"START.md names `clayseal {command}`, which does not exist"


def test_the_getting_started_page_does_not_quote_paper_rates() -> None:
    """Rates live in EVIDENCE.md. START is the first ten minutes."""
    text = START.read_text()
    assert "83.3" not in text
    assert "18.9" not in text
