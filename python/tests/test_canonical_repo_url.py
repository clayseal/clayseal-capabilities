"""One canonical home, named the same way everywhere.

The repository URL is not decoration. It is in the packaging metadata PyPI
publishes, in the security-advisory link a reporter follows, in the trusted
publishing coordinates that decide whether a release can upload at all, and in
every absolute link the README needs so the PyPI page is not full of dead ends.

It was `pberlizov/clayseal`, a personal repository, in 45 tracked places before
anyone noticed, and making the README work on PyPI propagated it to 76. A name
that lives in that many files drifts back one file at a time, so this pins it.

If the project genuinely moves, change `CANONICAL` here and let the failures
list what else needs changing. That is the point.
"""
from __future__ import annotations

import re
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
CANONICAL = "clayseal/clayseal-capabilities"

#: Homes this project has had. A reference to any of them is a stale link, and
#: for the advisory URL it is a link that sends a vulnerability report to a
#: repository the maintainers may not be watching.
FORMER = ("pberlizov/clayseal", "pberlizov/clay-seal-core",
          "pberlizov/agentauth-capabilities")


def _tracked_text_files() -> list[Path]:
    out = subprocess.run(["git", "ls-files"], cwd=ROOT,
                         capture_output=True, text=True).stdout.split()
    keep = (".md", ".py", ".toml", ".yml", ".yaml", ".cfg", ".txt", ".svg")
    return [ROOT / name for name in out if name.endswith(keep)]


@pytest.mark.parametrize("stale", FORMER)
def test_no_file_still_points_at_a_former_home(stale: str) -> None:
    offenders = [
        str(p.relative_to(ROOT)) for p in _tracked_text_files()
        if stale in p.read_text(errors="ignore")
    ]
    assert not offenders, f"{stale} still appears in {offenders}"


def test_the_packaging_metadata_names_it() -> None:
    """What PyPI shows, and what `pip show` prints."""
    pyproject = (ROOT / "pyproject.toml").read_text()
    urls = re.search(r"\[project\.urls\](.*?)(?:\n\[|\Z)", pyproject, re.DOTALL)
    assert urls, "pyproject has no [project.urls]"
    for line in urls.group(1).strip().splitlines():
        if "github.com" in line:
            assert CANONICAL in line, f"stale project URL: {line.strip()}"


def test_the_security_advisory_link_goes_to_the_right_repository() -> None:
    """A misdirected report is a vulnerability nobody reads."""
    security = (ROOT / "SECURITY.md").read_text()
    assert f"{CANONICAL}/security/advisories/new" in security


def test_the_trusted_publishing_coordinates_match() -> None:
    """These decide whether a release can upload at all.

    PyPI checks the workflow's OIDC claim against the owner and repository
    registered on the project. Wrong values do not fail at lint time, they fail
    at the upload step of a tagged release, which is the worst moment to find
    out.
    """
    owner, repository = CANONICAL.split("/")
    workflow = (ROOT / ".github" / "workflows" / "release.yml").read_text()
    assert f"owner:       {owner}" in workflow
    assert f"repository:  {repository}" in workflow

    releasing = (ROOT / "docs" / "RELEASING.md").read_text()
    assert f"| Owner | `{owner}` |" in releasing
    assert f"| Repository | `{repository}` |" in releasing


def test_the_readme_absolute_links_use_it() -> None:
    """Every link in the README had to become absolute for the PyPI page.

    That made the repository name load-bearing in 31 more places, so it is
    checked rather than trusted.
    """
    readme = (ROOT / "README.md").read_text()
    # Anchored to URL characters. A looser pattern ran past the end of the
    # clone URL and swallowed the shell lines under it, which reported the
    # `cd` command as a repository name.
    url_char = r"[A-Za-z0-9._-]"
    github = re.findall(rf"https://raw\.githubusercontent\.com/({url_char}+/{url_char}+)/",
                        readme)
    github += re.findall(rf"https://github\.com/({url_char}+/{url_char}+?)(?:\.git)?[/)\s]",
                         readme)
    wrong = sorted({repo for repo in github if repo != CANONICAL})
    assert not wrong, f"README links point at {wrong}"


def test_every_clone_instruction_cds_into_the_directory_it_creates() -> None:
    """`git clone .../clayseal-capabilities.git` makes `clayseal-capabilities/`.

    The rename broke this in three files at once, because the directory name is
    the repository name and the instruction underneath still said `cd clayseal`.
    Checked across every document rather than only the README, which is the
    mistake the first version of this test made.
    """
    import re

    for doc in _tracked_text_files():
        if doc.suffix != ".md":
            continue
        text = doc.read_text(errors="ignore")
        for match in re.finditer(r"git clone \S*?/([A-Za-z0-9._-]+?)(?:\.git)?\n(cd \S+)",
                                 text):
            cloned, cd_line = match.group(1), match.group(2)
            assert cd_line == f"cd {cloned}", (
                f"{doc.relative_to(ROOT)}: clones {cloned!r} then runs "
                f"{cd_line!r}, which enters a directory that does not exist")
