"""Agent-facing surfaces have to ship in the wheel and stay in lockstep.

`AGENTS.md`, `llms.txt` and the Cursor/Claude skill files are what GitHub and
editors find. `clayseal howto` and `clayseal skill` are what a `pip install`
user has. They are the same strings, from `agent_guide.py`, because a README
an agent cannot reach after install is how the last onboarding path broke.
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from clayseal.capabilities.agent_guide import (
    agents_markdown,
    howto_text,
    llms_txt,
    skill_markdown,
    worked_policy_text,
)

ROOT = Path(__file__).resolve().parents[2]
CLI = [sys.executable, "-m", "clayseal.capabilities.cli"]
REPO_ONLY = ("docs/", "examples/", "benchmarks/", "python/", "scripts/")


def _run(args, cwd=ROOT, **kw):
    return subprocess.run(
        [*CLI, *args], cwd=cwd, capture_output=True, text=True,
        timeout=30, check=False, **kw,
    )


def _checkout_paths(text: str) -> list[str]:
    offenders = []
    for line in text.splitlines():
        for token in line.split():
            bare = token.strip("'\"(),")
            if bare.startswith(("https://", "http://")):
                continue
            if bare.startswith(REPO_ONLY):
                offenders.append(bare)
    return offenders


def test_howto_is_the_deploy_path() -> None:
    result = _run(["howto"])
    assert result.returncode == 0, result.stderr
    text = result.stdout
    assert text == howto_text()
    for needle in (
        "clayseal try",
        "clayseal policy new",
        "clayseal policy lint",
        "clayseal proxy",
        "wrap_all",
        "Refused",
        "StepUpRequired",
        "mcpServers",
        "clayseal skill --write",
        "read, write, send, transfer, call",
        "paths.pathless",
        "no path argument was found",
        "clayseal serve",
        "not in egress.recipients",
        "ceilings start over",
    ):
        assert needle in text, needle
    assert not _checkout_paths(text), _checkout_paths(text)


def test_skill_prints_the_same_markdown_as_the_committed_files() -> None:
    result = _run(["skill"])
    assert result.returncode == 0, result.stderr
    assert result.stdout == skill_markdown()
    for path in (
        ROOT / ".cursor/skills/clayseal/SKILL.md",
        ROOT / ".claude/skills/clayseal/SKILL.md",
    ):
        assert path.read_text() == skill_markdown(), path
    assert "disable-model-invocation" not in skill_markdown()
    assert "name: clayseal" in skill_markdown()
    assert "paths.pathless" in skill_markdown()
    assert "clayseal serve" in skill_markdown()
    assert "not in egress.recipients" in skill_markdown()
    assert "ceilings start over" in skill_markdown()
    assert not _checkout_paths(skill_markdown())


def test_repo_agent_files_match_the_package() -> None:
    assert (ROOT / "AGENTS.md").read_text() == agents_markdown()
    assert (ROOT / "llms.txt").read_text() == llms_txt()
    assert "clayseal howto" in agents_markdown()
    assert "pip install clayseal" in llms_txt()


def test_skill_write_lands_where_editors_look(tmp_path: Path) -> None:
    result = _run(["skill", "--write"], cwd=tmp_path)
    assert result.returncode == 0, result.stderr
    cursor = tmp_path / ".cursor/skills/clayseal/SKILL.md"
    claude = tmp_path / ".claude/skills/clayseal/SKILL.md"
    agents = tmp_path / "AGENTS.md"
    assert cursor.read_text() == skill_markdown()
    assert claude.read_text() == skill_markdown()
    assert "clayseal howto" in agents.read_text()
    assert "wrote" in result.stderr
    assert "clayseal policy new" in result.stderr


def test_skill_write_points_at_lint_when_a_policy_already_exists(
        tmp_path: Path) -> None:
    (tmp_path / "policy.yaml").write_text("version: 1\n")
    result = _run(["skill", "--write"], cwd=tmp_path)
    assert result.returncode == 0, result.stderr
    assert "clayseal policy lint" in result.stderr
    assert "clayseal policy new" not in result.stderr


def test_skill_write_refuses_to_clobber(tmp_path: Path) -> None:
    _run(["skill", "--write"], cwd=tmp_path)
    again = _run(["skill", "--write"], cwd=tmp_path)
    assert again.returncode == 1
    assert "exists" in again.stderr
    forced = _run(["skill", "--write", "--force"], cwd=tmp_path)
    assert forced.returncode == 0, forced.stderr


def test_readme_tells_an_agent_the_command() -> None:
    """PyPI renders the README. An agent that never clones still has to see this."""
    readme = (ROOT / "README.md").read_text()
    assert "clayseal howto" in readme
    assert "clayseal skill --write" in readme
    assert "mcpServers" in readme
    assert "paths.pathless" in readme
    assert "clayseal serve" in readme
    assert "clayseal try --fast" in readme
    assert "Keys must match" in readme or "keys must match" in readme.lower()


def test_policy_with_no_subcommand_points_at_new() -> None:
    result = _run(["policy"])
    assert result.returncode == 2
    assert "clayseal policy new" in result.stderr
    assert "new" in result.stdout


def test_policy_new_prints_edit_hints_on_stderr_even_when_yaml_goes_to_stdout(
        tmp_path,
) -> None:
    """`> policy.yaml` swallows stdout. The next edit has to survive that."""
    result = _run(["policy", "new"], cwd=tmp_path)
    assert result.returncode == 0, result.stderr
    assert "your_read_tool" in result.stdout
    assert result.stdout.lstrip().startswith("#")
    assert "now edit the TODOs" not in result.stdout
    assert "now edit the TODOs" in result.stderr
    assert "clayseal policy lint policy.yaml" in result.stderr
    assert "egress.recipients" in result.stderr


def test_howto_worked_policy_lints_without_an_unaccounted_send() -> None:
    """A paste of the worked YAML must not then warn that send_email is untracked."""
    from clayseal.capabilities.policy import load_policy_text

    findings = load_policy_text(worked_policy_text()).lint()
    errors = [f for f in findings if f.level == "error"]
    assert not errors, errors
    assert not any(f.code == "unaccounted-tool" for f in findings)
    assert "send_email: sends" in howto_text()


def test_skill_write_says_so_when_it_cannot_create_the_directory(
        tmp_path: Path,
) -> None:
    (tmp_path / "AGENTS.md").write_text("already here\n")
    (tmp_path / ".cursor").write_text("not a directory\n")
    (tmp_path / ".claude").write_text("not a directory\n")
    result = _run(["skill", "--write"], cwd=tmp_path)
    assert result.returncode == 1
    assert "Traceback" not in result.stderr
    assert "cannot write" in result.stderr


def test_proxy_warns_when_the_command_is_a_python_file(tmp_path: Path) -> None:
    """A tools.py is not an MCP server. Do not fail silently with 0 allowed."""
    result = _run(
        ["proxy", "--policy", "missing.yaml", "--",
         sys.executable, str(tmp_path / "tools.py")],
        cwd=tmp_path,
    )
    assert "Guardrail" in result.stderr
    assert "howto" in result.stderr
    assert result.returncode != 0
