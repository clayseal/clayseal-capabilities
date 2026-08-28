"""The API reference has to name every symbol the package exports.

`clayseal.capabilities` exports 57 names and there was no reference for any of
them. A reference that covers some of them is worse than none in one specific
way: a reader who finds 50 documented concludes the other 7 do not exist, rather
than that nobody wrote them up.

So this asserts coverage in both directions. Missing means a symbol is exported
and undocumented. Extra means the page names something that is no longer
exported, which sends a reader to an ImportError.

It checks presence, not prose. A rule cannot tell whether a description is any
good; it can stop the page silently falling behind the code.
"""
from __future__ import annotations

import pathlib
import re

import pytest

import clayseal.capabilities as caps

ROOT = pathlib.Path(__file__).resolve().parents[2]
API = ROOT / "docs" / "API.md"


def _text() -> str:
    return API.read_text()


def _mentioned() -> set[str]:
    """Names the page refers to, taken from inline code spans only.

    Prose is not a mention: `Guardrail` in a sentence could be a coincidence of
    English, and requiring the backticks means the page names symbols as symbols.
    """
    return set(re.findall(r"`([A-Za-z_][A-Za-z0-9_]*)`", _text()))


def test_the_reference_exists_and_is_not_a_stub():
    assert API.exists(), "docs/API.md is gone"
    assert len(_text()) > 2000, "docs/API.md has been emptied"


@pytest.mark.parametrize("name", sorted(caps.__all__))
def test_every_export_is_named_in_the_reference(name):
    assert name in _mentioned(), (
        f"{name} is exported from clayseal.capabilities and appears nowhere in "
        "docs/API.md")


def test_the_reference_does_not_name_symbols_that_no_longer_exist():
    """The mirror failure: a page sending readers to an ImportError."""
    exported = set(caps.__all__)
    # Only check CamelCase and snake_case identifiers that look like exports;
    # the page also mentions modules, parameters and CLI words in backticks.
    candidates = {n for n in _mentioned()
                  if n[0].isupper() or "_" in n}
    stale = {n for n in candidates
             if n not in exported
             and not hasattr(caps, n)
             and n not in _KNOWN_NON_EXPORTS}
    assert not stale, f"docs/API.md names symbols that are not importable: {sorted(stale)}"


#: Words in backticks on that page that are deliberately not exports: modules,
#: parameters, CLI fragments and types from `clayseal.core`.
_KNOWN_NON_EXPORTS = {
    "house_rules", "session_rules", "enable_flow", "entailment_judge",
    "from_goal", "from_policy_file", "wrap_all", "would_allow", "reserve",
    "clayseal_core", "outcome", "layer", "reasons", "except",
    "InMemoryUsedTokenStore", "DEPLOYMENT_SHAPE", "API",
    # A method on the `UsedTokenStore` Protocol, not a top-level export. The
    # check flagged it correctly: it is not importable from the package, and the
    # right answer is to say so here rather than to stop checking method names.
    "mark_used",
}


def test_the_matcher_is_not_vacuous():
    """The control.

    Every assertion above passes if `_mentioned()` returned every possible
    string. Require it to be a bounded set that excludes something obvious.
    """
    mentioned = _mentioned()
    assert mentioned, "no code spans found; the page format changed"
    assert "ThisSymbolDoesNotExist" not in mentioned
    assert "Guardrail" in mentioned
