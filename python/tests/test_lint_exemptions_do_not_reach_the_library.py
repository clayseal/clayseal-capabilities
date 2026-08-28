"""A lint exemption written for the harness must not reach the shipped package.

CI runs `ruff check .` over the whole repository. Making that pass meant granting
per-directory exemptions to `benchmarks/`, `python/tests/` and `demo/`, where a
rule is right in general and wrong for that code: seeded RNG is the point of a
reproducible benchmark, and a harness that must survive one malformed corpus of
nine catches broadly on purpose.

The hazard that creates is a glob. `benchmarks/**` is narrow; a later `**` or
`*/tests/**` would be silently broader, and the file it quietly exempted could be
`clayseal/capabilities/broker.py`. Nothing would fail — the lint would simply
stop asking.

So the config states an invariant and this asserts it: no per-file-ignore may
match a path under `clayseal/` or `agentauth/` except the small set that was
written FOR those files, each of which is justified in `pyproject.toml`.
"""
from __future__ import annotations

import fnmatch
from pathlib import Path

import pytest

# `tomllib` is 3.11+. The CI matrix includes 3.10, where this file would fail to
# COLLECT and take the whole suite with it, so it degrades to a skip there. The
# guard still runs on 3.13 and 3.14, which is where the matrix keeps it honest.
tomllib = pytest.importorskip(
    "tomllib", reason="tomllib is 3.11+; this guard runs on the newer matrix legs")

ROOT = Path(__file__).resolve().parents[2]

#: Exemptions deliberately written for the shipped package. Each carries its
#: reason in pyproject.toml; this list exists so an ACCIDENTAL one is not
#: mistaken for a deliberate one.
DELIBERATE = {
    "clayseal/capabilities/commit.py",
    "clayseal/capabilities/used_token_store.py",
    "clayseal/capabilities/hardening/object_class.py",
    "clayseal/core/budget.py",
    "clayseal/core/signing.py",
    "clayseal/core/task_scope.py",
    "clayseal/capabilities/hardening/input_hardening.py",
}

#: Rules that must never be exempted for shipped code, whatever the file.
#: Undefined names, bugbear correctness, syntax errors, pylint errors.
NEVER_EXEMPT_PREFIXES = ("F8", "E7", "E9", "PLE")


def _per_file_ignores() -> dict[str, list[str]]:
    with (ROOT / "pyproject.toml").open("rb") as handle:
        config = tomllib.load(handle)
    return config["tool"]["ruff"]["lint"].get("per-file-ignores", {})


def _shipped_files() -> list[str]:
    out = []
    for package in ("clayseal", "agentauth"):
        for path in (ROOT / package).rglob("*.py"):
            out.append(str(path.relative_to(ROOT)))
    return out


def test_no_exemption_reaches_the_library_by_accident():
    shipped = _shipped_files()
    assert shipped, "no shipped sources found; this test is not checking anything"

    leaked: dict[str, list[str]] = {}
    for pattern, rules in _per_file_ignores().items():
        if pattern in DELIBERATE:
            continue
        matched = [f for f in shipped if fnmatch.fnmatch(f, pattern)]
        if matched:
            leaked[pattern] = sorted(matched)[:5] + [f"({len(matched)} files)"]

    assert not leaked, (
        "these per-file-ignores reach the shipped package without being written "
        f"for it: {leaked}. Narrow the glob, or add the file to DELIBERATE here "
        "with its reason in pyproject.toml.")


def test_the_deliberate_list_has_not_gone_stale():
    """An entry naming a file that no longer exists hides a real exemption behind
    a dead one."""
    patterns = set(_per_file_ignores())
    for entry in DELIBERATE:
        assert entry in patterns, f"{entry} is listed here but not in pyproject.toml"
        assert (ROOT / entry).exists(), f"{entry} no longer exists"


@pytest.mark.parametrize("prefix", NEVER_EXEMPT_PREFIXES)
def test_the_correctness_families_are_exempted_nowhere_in_the_library(prefix):
    """Style is negotiable per directory. Undefined names are not."""
    offenders = []
    for pattern, rules in _per_file_ignores().items():
        if not any(fnmatch.fnmatch(f, pattern) for f in _shipped_files()):
            continue
        for rule in rules:
            # PLE2502/PLE2515 on the Trojan-Source detector and its fixtures are
            # the documented exception: that module holds the characters it
            # detects, so flagging it is the antivirus quarantining its own
            # signature file.
            if rule in {"PLE2502", "PLE2515"}:
                continue
            if rule.startswith(prefix):
                offenders.append(f"{pattern}: {rule}")
    assert not offenders, offenders


def test_the_matcher_would_notice_a_broad_glob():
    """The control.

    Every assertion above passes if `_shipped_files` returns nothing or the
    matcher never matches. Feed it a glob that obviously reaches the library and
    require it to be seen.
    """
    shipped = _shipped_files()
    assert any(fnmatch.fnmatch(f, "clayseal/**") for f in shipped) or any(
        fnmatch.fnmatch(f, "clayseal/*.py") or "/" in f for f in shipped)
    assert [f for f in shipped if fnmatch.fnmatch(f, "*.py")], (
        "the matcher matches nothing; this file is inert")
