"""Nothing a user sees may name a path that only exists in a git checkout.

This has now been three separate bugs of one shape:

  1. The README quickstart loaded `examples/refund.yaml`, directly under
     `pip install clayseal`, so the second thing on the page raised for
     everyone who followed the first thing.
  2. `clayseal try` closed by pointing at `docs/EVIDENCE.md`.
  3. The README's images and links were relative, which GitHub resolves and
     the PyPI project page, rendered from the same file, does not.

They share a cause. Everything here is developed and tested from the repository
root, where every one of those paths exists, so the checkout is the one
environment that cannot detect the mistake.

These tests take the outside view: what does a person who ran `pip install`
actually have.
"""
from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
README = ROOT / "README.md"

#: Directories that live in the repository and never in a wheel.
REPO_ONLY = ("docs/", "examples/", "benchmarks/", "python/", "scripts/")


def test_the_cli_prints_no_path_that_needs_a_checkout() -> None:
    """These commands are run by people who have installed, not cloned."""
    for argv in (["try", "--fast"], ["howto"], ["skill"], ["policy", "new"]):
        result = subprocess.run(
            [sys.executable, "-m", "clayseal.capabilities.cli", *argv],
            cwd=ROOT, capture_output=True, text=True, timeout=120, check=False,
        )
        assert result.returncode == 0, result.stderr
        offenders = []
        for stream in (result.stdout, result.stderr):
            for line in stream.splitlines():
                for token in line.split():
                    bare = token.strip("'\"(),")
                    if bare.startswith("https://") or bare.startswith("http://"):
                        continue          # a URL is reachable from anywhere
                    if bare.startswith(REPO_ONLY):
                        offenders.append(bare)
        assert not offenders, (
            f"`clayseal {' '.join(argv)}` names {offenders}, which a pip "
            f"install does not have. Print a URL or a command instead.")


def test_the_readme_images_are_absolute() -> None:
    """PyPI renders this file and cannot resolve a relative src.

    A broken hero image on the project page is worse than a broken link,
    because it is the first thing a visitor does not see.
    """
    relative = re.findall(r'src="(?!https?:)([^"]+)"', README.read_text())
    assert not relative, (
        f"relative image sources {relative} render on GitHub and break on PyPI")


def test_the_readme_links_are_absolute() -> None:
    """Same file, two renderers, and only one of them resolves relative paths."""
    relative = [
        target for _, target in re.findall(r"\[([^\]]+)\]\(([^)\s]+)\)",
                                           README.read_text())
        if not target.startswith(("http://", "https://", "#", "mailto:"))
    ]
    assert not relative, (
        f"relative links {relative[:5]} break on the PyPI project page")


def test_in_page_anchors_stay_relative() -> None:
    """The other direction, so the fix above cannot be over-applied.

    An in-page anchor rewritten to an absolute URL still works and stops being
    in-page navigation, which is a quiet downgrade nobody notices. The anchors
    live in EVIDENCE.md, which is the long document with a contents list; the
    README is short enough now to have none, and that is why this checks the
    file that has them instead of the one that used to.
    """
    evidence = (ROOT / "docs" / "EVIDENCE.md").read_text()
    anchors = re.findall(r"\[[^\]]+\]\((#[^)\s]+)\)", evidence)
    assert anchors, "EVIDENCE.md lost its contents list"


def test_the_shipped_package_ships_what_it_promises() -> None:
    """Anything importable at runtime has to be inside the package.

    `clayseal.capabilities.starter` holds the policy template that
    `clayseal policy new` writes. If it were data in the repository instead of
    a module, the command would work in the checkout and fail from the wheel.
    """
    from clayseal.capabilities.starter import starter_policy

    text = starter_policy()
    assert "version: 1" in text
    assert "TODO" in text, "the template must mark the decisions it cannot make"


def test_the_readme_does_not_load_a_checkout_only_policy() -> None:
    """PyPI readers hitting load_policy('examples/...') was the original trap."""
    body = README.read_text()
    assert 'load_policy("examples/' not in body
    assert 'from_policy_file("examples/' not in body
