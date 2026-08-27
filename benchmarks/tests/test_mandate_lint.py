"""The linter must fire on exactly the configs that escaped, and on nothing else.

Both halves are load-bearing. `stress_aggregation.py` found three escapes that
are not defects in the ledger, the ledger debited exactly what it was told to,
correctly, on every one, so the only place they can be caught is the mandate.
And a coverage linter that reports a finding on an ordinary read-only catalog is
one an operator mutes in week one, at which point the three real escapes are
undetected again *and* the repository has a muted linter instead of a known gap.

Each test names the `stress_aggregation` axis it corresponds to, so a future
change to either file has to reckon with the other.
"""
import pytest

from agentauth.capabilities.mandate_lint import (
    Finding,
    lint_mandate,
    require_clean,
)
from agentauth.capabilities.value_budget import EffectSpec

CLEAN_CATALOG = ["payments.transfer", "reports.get_balance",
                 "search.query", "files.read", "calendar.list_events"]


def _codes(findings: list[Finding]) -> set[str]:
    return {f.code for f in findings}


def test_a_fully_accounted_mandate_produces_no_findings():
    """The false-alarm half, under the current contract.

    `get_balance`, `query`, `read` and `list_events` all touch money-adjacent
    surfaces and none is an effect, but the linter cannot know that from a
    name, and `benchmarks/mandate_search.py` measures what trusting names costs:
    over 4,000 sampled mandates, 211 escaped while the linter called them clean,
    every one through an opaquely-named tool. So a reachable tool must either
    debit a budget or be declared harmless.
    """
    findings = lint_mandate(
        catalog=CLEAN_CATALOG,
        declared_harmless=[t for t in CLEAN_CATALOG if t != "payments.transfer"],
        value_tracked={"payments.transfer":
                       EffectSpec(budget_id="p", amount_arg="amount")},
        ceilings={"p": 100}, principal_scoped=True)
    assert findings == [], f"false findings: {[str(f) for f in findings]}"


def test_an_undeclared_read_tool_is_a_warning_not_an_error():
    """The cost of the rule above, and why it is a warning.

    Firing an ERROR on every unenumerated read tool would make `strict_mandate`
    unsatisfiable without a full catalog declaration, and a mode nobody can
    satisfy is a mode nobody turns on. So it is visible by default and blocking
    only under `require_clean(strict=True)`.
    """
    findings = lint_mandate(
        catalog=CLEAN_CATALOG,
        value_tracked={"payments.transfer": ("amount", "p")},
        ceilings={"p": 100}, principal_scoped=True)
    unaccounted = [f for f in findings if f.code == "unaccounted-tool"]
    assert unaccounted and all(f.severity == "warning" for f in unaccounted)
    require_clean(findings)                       # must not raise by default
    with pytest.raises(ValueError, match="unaccounted-tool"):
        require_clean(findings, strict=True)


def test_an_opaquely_named_effectful_tool_is_still_caught():
    """The 211. `process_item_47` moves money and no name rule can tell."""
    findings = lint_mandate(
        catalog=["payments.transfer", "process_item_47"],
        value_tracked={"payments.transfer": ("amount", "p")},
        ceilings={"p": 100}, principal_scoped=True)
    assert any(f.subject == "process_item_47" for f in findings)


def test_untracked_sibling_tool_is_an_error():
    # stress_aggregation axis: "untracked sibling tool", which landed 20,000
    # against a ceiling of 100 because `payments.wire` was outside `tracked`.
    findings = lint_mandate(
        catalog=CLEAN_CATALOG + ["payments.wire"],
        value_tracked={"payments.transfer": ("amount", "p")},
        ceilings={"p": 100}, principal_scoped=True)
    assert "untracked-effectful-tool" in _codes(findings)
    assert any(f.subject == "payments.wire" for f in findings)


def test_key_splitting_is_an_error():
    # stress_aggregation axis: "key splitting (2 budget ids)", which landed 200
    # against a ceiling of 100 by using two names for one effect.
    findings = lint_mandate(
        value_tracked={"payments.transfer": ("amount", "a"),
                       "payments.payout": ("amount", "b")},
        ceilings={"a": 100, "b": 100}, principal_scoped=True)
    split = [f for f in findings if f.code == "split-aggregation-key"]
    assert split and split[0].severity == "error"
    assert split[0].escape == "key splitting"


def test_session_scoping_is_reported_as_a_warning_not_an_error():
    # stress_aggregation axis: "session restart". A warning rather than an error
    # because a per-session ceiling is a coherent thing to want; the point is
    # that choosing it should be visible. `principal_ledger.py` is the fix.
    findings = lint_mandate(value_tracked={"payments.transfer": ("amount", "p")},
                            ceilings={"p": 100})
    scoped = [f for f in findings if f.code == "session-scoped-ceiling"]
    assert scoped and scoped[0].severity == "warning"
    require_clean(findings)      # must not raise on a warning alone


def test_a_principal_scoped_ledger_silences_the_session_warning():
    findings = lint_mandate(value_tracked={"payments.transfer": ("amount", "p")},
                            ceilings={"p": 100}, principal_scoped=True)
    assert "session-scoped-ceiling" not in _codes(findings)


def test_undeclared_batch_multiplicity_is_an_error():
    # stress_aggregation axis: "batch amortization". `EffectSpec.count_arg`
    # closes it in the ledger; this catches a mandate that did not use it.
    findings = lint_mandate(
        value_tracked={"payments.batch_transfer": ("amount", "p")},
        ceilings={"p": 100}, principal_scoped=True)
    assert "undeclared-multiplicity" in _codes(findings)


def test_a_declared_count_argument_silences_the_multiplicity_finding():
    findings = lint_mandate(
        value_tracked={"payments.batch_transfer": EffectSpec(
            budget_id="p", amount_arg="amount", count_arg="items")},
        ceilings={"p": 100}, principal_scoped=True)
    assert "undeclared-multiplicity" not in _codes(findings)


def test_a_minor_unit_without_a_scale_is_an_error():
    # stress_aggregation axis: "unit confusion". The ledger has no unit; it
    # debits the number in the field.
    findings = lint_mandate(
        value_tracked={"payments.transfer_cents": ("amount", "p")},
        ceilings={"p": 100}, principal_scoped=True)
    assert "undeclared-unit" in _codes(findings)


def test_a_tracked_tool_with_no_ceiling_is_an_error():
    findings = lint_mandate(
        value_tracked={"payments.transfer": ("amount", "p")},
        ceilings={}, principal_scoped=True)
    assert "uncapped-budget" in _codes(findings)


def test_require_clean_raises_on_an_error_and_names_the_tool():
    findings = lint_mandate(
        catalog=["payments.wire"],
        value_tracked={"payments.transfer": ("amount", "p")},
        ceilings={"p": 100}, principal_scoped=True)
    with pytest.raises(ValueError, match="payments.wire"):
        require_clean(findings)


def test_the_linter_needs_a_catalog_to_find_a_missing_tool():
    """Stated as a limit rather than left implicit.

    You cannot tell that a money tool is absent from a ledger by reading the
    ledger. With no catalog the untracked-sibling check is silent, and a caller
    who omits the catalog should not read that silence as coverage.
    """
    findings = lint_mandate(
        value_tracked={"payments.transfer": ("amount", "p")},
        ceilings={"p": 100}, principal_scoped=True)
    assert "untracked-effectful-tool" not in _codes(findings)


# --------------------------------------------------------------------------- #
# The closure property
# --------------------------------------------------------------------------- #
def test_no_aggregation_escape_is_silent():
    """Every axis that still escapes the ceiling must be caught at configure time.

    This is the claim `aggregation_residual.md` makes, expressed as a test rather
    than as prose. Five of eleven aggregation-key axes still escape, and the
    defence of that number is that each one is a mandate the linter refuses
    before the session starts. If someone adds an escaping axis without a
    corresponding rule, "the ledger is sound and the mandate is checkable" stops
    being true and this fails.
    """
    from benchmarks.stress_aggregation import AXES, _lint_coverage

    escaping = {a()["axis"] for a in AXES if a()["escaped"]}
    coverage = _lint_coverage()

    unprobed = escaping - set(coverage)
    assert not unprobed, f"escaping axes with no lint probe: {sorted(unprobed)}"

    silent = sorted(a for a in escaping if not coverage[a])
    assert not silent, f"escapes neither contained nor detectable: {silent}"


def test_the_closure_property_holds_over_sampled_mandate_space():
    """The claim, tested as a universal instead of on four hand-written axes.

    `aggregation_residual.md` says the ledger is sound and every way past it is
    a mandate-completeness problem the linter detects. Four examples is weak
    evidence for that, and the adaptive-evaluation literature's central
    criticism is precisely that hand-crafted attacks under-count.

    Sampling mandate space found **211 of 4,000 escaping while the linter called
    them clean**, all through opaquely-named tools. The `unaccounted-tool` rule
    closed it: 0 of 40,000 across two seeds. This test is the small, fast
    version, if someone reintroduces name-trust, it fails here first.
    """
    from benchmarks.mandate_search import run

    rows = run(600, seed=7)
    escaping_but_clean = [r for r in rows if r["escaped"] and not r["lint"]]
    assert escaping_but_clean == [], escaping_but_clean[:3]
    # And the sample must actually contain escapes, or it proves nothing.
    assert sum(1 for r in rows if r["escaped"]) > 50
