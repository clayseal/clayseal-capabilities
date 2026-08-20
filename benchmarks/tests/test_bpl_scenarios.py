"""Scripted unit tests for the BPL-v1 scenario pack (no live LLM)."""
from __future__ import annotations

import pytest

from benchmarks.bpl.registry import SCENARIOS, get_scenario, list_scenarios, scenarios_by_family
from benchmarks.bpl.schema import run_script, tool_names


# Live arm needs iVisor; skip in default unit tests.
SIMULATED = [n for n in SCENARIOS if n != "bulk-exfil-live"]


def test_registry_loads_unique_names_and_families():
    names = list_scenarios(include_live=False)
    assert len(names) == len(set(names))
    assert len(names) >= 48  # + deep tier
    by = scenarios_by_family()
    assert set(by) == {"aggregate", "escape", "confidentiality"}
    for fam, members in by.items():
        assert members, f"family {fam} empty"
        for n in members:
            s = get_scenario(n)
            assert s.family == fam
            assert s.name == n
    frontier = [n for n in names if "frontier" in get_scenario(n).tags]
    assert len(frontier) >= 14
    ultra = [n for n in names if "ultra" in get_scenario(n).tags]
    assert len(ultra) >= 6
    lit = [n for n in names if "literature" in get_scenario(n).tags]
    assert len(lit) >= 9
    deep = [n for n in names if "deep" in get_scenario(n).tags]
    assert len(deep) >= 8
    aml = [n for n in names if "aml" in get_scenario(n).tags]
    assert len(aml) >= 8
    unorth = [n for n in names if "unorthodox" in get_scenario(n).tags]
    assert len(unorth) >= 8
    cross = [n for n in names if "crossdomain" in get_scenario(n).tags]
    assert len(cross) >= 10
    specialty = [n for n in names if "specialty" in get_scenario(n).tags]
    assert len(specialty) >= 6
    institutional = [n for n in names if "institutional" in get_scenario(n).tags]
    assert len(institutional) >= 8
    apex = [n for n in names if "apex" in get_scenario(n).tags]
    assert len(apex) >= 30
    nightmare = [n for n in names if "nightmare" in get_scenario(n).tags]
    assert len(nightmare) >= 10
    paradox = [n for n in names if "paradox" in get_scenario(n).tags]
    assert len(paradox) >= 12
    edge = [n for n in names if "edge" in get_scenario(n).tags]
    assert len(edge) >= 12
    assert len(names) >= 132


@pytest.mark.parametrize("name", [
    n for n in SIMULATED if "edge" in get_scenario(n).tags
])
def test_edgecase_tier(name: str):
    scen = get_scenario(name)
    assert "edge" in scen.tags
    assert len(scen.violating_script) >= scen.min_steps
    assert any(t in scen.tags for t in (
        "long-horizon", "short-fuse", "plain-sight", "stacked", "marathon",
        "micro-drip", "scope-creep", "slow-boil", "delayed-blast", "chronicle",
        "ceiling", "minimal", "omission", "label-launder", "audit", "exfil",
        "status", "secret", "runbook", "creds", "launder", "quorum",
        "heisenberg", "cover", "summary", "naf"))
    if "long-horizon" in scen.tags:
        assert scen.min_steps >= 30
        assert scen.max_iters >= 80
    if "short-fuse" in scen.tags:
        assert scen.min_steps <= 5
        assert len(scen.violating_script) <= 12


@pytest.mark.parametrize("name", [
    n for n in SIMULATED if "paradox" in get_scenario(n).tags
])
def test_paradox_tier(name: str):
    scen = get_scenario(name)
    assert scen.difficulty >= 10
    assert scen.min_steps >= 25
    assert len(scen.violating_script) >= scen.min_steps
    assert scen.max_iters >= 60
    assert scen.clayseal_expected == "open"
    assert any(t in scen.tags for t in (
        "heisenberg", "measurement", "lacuna", "alias", "enumeration",
        "commit-reveal", "crypto-bind", "ltl", "eventually", "sar",
        "meta-policy", "interpretation", "homomorphic", "field-split",
        "quorum", "nested", "identity", "cover", "counterfactual", "token",
        "retroactive", "predicate", "reidentification", "adaptive",
        "composition", "naf", "closed-world", "risk", "two-clock",
        "settlement", "race"))


@pytest.mark.parametrize("name", [
    n for n in SIMULATED if "apex" in get_scenario(n).tags
])
def test_apex_tier(name: str):
    scen = get_scenario(name)
    assert scen.difficulty >= 7
    assert scen.min_steps >= 20
    assert len(scen.violating_script) >= scen.min_steps
    assert scen.max_iters >= 50
    assert scen.clayseal_expected in ("open", "partial", "contain")
    assert any(t in scen.tags for t in (
        "launder", "mandate", "quorum", "sanctions", "gross", "exception",
        "obligation", "tenant", "attestation", "delegation", "amendment",
        "intersection", "identity", "beneficial-owner", "semantic", "exposure",
        "recursion", "authority", "deferred", "shared-ref", "exfil", "integrity",
        "scope-decay", "policy-version", "skew", "fx", "stale-quote", "arb",
        "omission", "dual-notify", "idempotency", "collision", "shadow",
        "promote", "batch", "path-dependent", "ceiling", "lossy-summary",
        "policy", "refund-cycle", "budget-wash", "witness", "equivocation",
        "cache", "authz", "poison", "heisenberg", "measurement", "lacuna",
        "alias", "enumeration", "commit-reveal", "crypto-bind", "ltl",
        "eventually", "sar", "meta-policy", "interpretation", "homomorphic",
        "field-split", "nested", "cover", "counterfactual", "token",
        "retroactive", "predicate", "reidentification", "adaptive",
        "composition", "naf", "closed-world", "risk", "two-clock",
        "settlement", "race"))


@pytest.mark.parametrize("name", [
    n for n in SIMULATED if "institutional" in get_scenario(n).tags
])
def test_institutional_tier(name: str):
    scen = get_scenario(name)
    assert scen.difficulty >= 5
    assert len(scen.violating_script) >= scen.min_steps >= 15
    assert any(t in scen.tags for t in (
        "kyc", "cip", "banking", "bankruptcy", "automatic-stay", "procurement",
        "threshold", "gdpr", "rtbf", "iam", "jit", "qms", "capa", "privilege",
        "legal", "aviation", "mel"))

@pytest.mark.parametrize("name", [
    n for n in SIMULATED if "specialty" in get_scenario(n).tags
])
def test_specialty_tier(name: str):
    scen = get_scenario(name)
    assert scen.difficulty >= 5
    assert len(scen.violating_script) >= scen.min_steps >= 15
    assert any(t in scen.tags for t in (
        "clinical", "gcp", "protocol", "insurance", "siu", "maritime", "colreg",
        "export-control", "durc", "auction", "cartel", "sports", "advantage"))

@pytest.mark.parametrize("name", [
    n for n in SIMULATED if "crossdomain" in get_scenario(n).tags
])
def test_crossdomain_tier(name: str):
    scen = get_scenario(name)
    assert scen.difficulty >= 5
    assert len(scen.violating_script) >= scen.min_steps >= 15
    assert any(t in scen.tags for t in (
        "tax", "market-abuse", "hro", "itil", "casino", "haccp", "coc",
        "escrow", "fiduciary", "sanctions", "economic-substance", "wash",
        "checklist", "change", "structuring", "food-safety", "election",
        "notary", "related-party", "export-control"))

@pytest.mark.parametrize("name", [
    n for n in SIMULATED
    if "unorthodox" in get_scenario(n).tags
    and "crossdomain" not in get_scenario(n).tags
    and "specialty" not in get_scenario(n).tags
])
def test_unorthodox_tier(name: str):
    scen = get_scenario(name)
    assert scen.difficulty >= 5
    assert len(scen.violating_script) >= scen.min_steps >= 15
    assert any(t in scen.tags for t in (
        "tax", "market-abuse", "aviation", "healthcare", "sox", "hro",
        "environmental", "spoofing", "sterile-cockpit", "swiss-cheese",
        "sod", "two-person", "cumulative", "alert-fatigue"))

@pytest.mark.parametrize("name", [
    n for n in SIMULATED if "aml" in get_scenario(n).tags
])
def test_aml_tier(name: str):
    scen = get_scenario(name)
    assert len(scen.violating_script) >= scen.min_steps >= 15
    assert any(t in scen.tags for t in (
        "structuring", "smurfing", "layering", "fan-out", "round-trip",
        "tbml", "mule", "integration", "velocity"))


@pytest.mark.parametrize("name", [
    n for n in SIMULATED
    if "literature" in get_scenario(n).tags and "deep" not in get_scenario(n).tags
])
def test_literature_tier(name: str):
    scen = get_scenario(name)
    assert scen.difficulty >= 5
    assert len(scen.violating_script) >= scen.min_steps >= 15
    assert any(t in scen.tags for t in (
        "mast", "hammond", "agentlab", "phantompolicy", "incident"))


@pytest.mark.parametrize("name", [
    n for n in SIMULATED if "deep" in get_scenario(n).tags
])
def test_deep_tier(name: str):
    scen = get_scenario(name)
    assert scen.difficulty >= 5
    assert len(scen.violating_script) >= scen.min_steps >= 15
    assert any(t in scen.tags for t in (
        "stego", "calvano", "laban", "lost-middle", "scopegate",
        "confused-deputy", "toctou", "smsr", "msmp", "token"))


@pytest.mark.parametrize("name", [
    n for n in SIMULATED if "ultra" in get_scenario(n).tags
])
def test_ultra_min_steps(name: str):
    scen = get_scenario(name)
    assert scen.difficulty >= 5
    assert len(scen.violating_script) >= scen.min_steps >= 15


@pytest.mark.parametrize("name", [
    n for n in SIMULATED if "frontier" in get_scenario(n).tags
])
def test_frontier_min_steps_and_difficulty(name: str):
    scen = get_scenario(name)
    assert scen.difficulty >= 4
    assert scen.min_steps >= 15
    assert len(scen.violating_script) >= scen.min_steps
    assert "implicit-policy" in scen.tags or "frontier" in scen.tags


@pytest.mark.parametrize("name", SIMULATED)
def test_scripts_exist_and_per_call_blind(name: str):
    scen = get_scenario(name)
    assert scen.violating_script, f"{name}: missing violating_script"
    assert scen.compliant_script, f"{name}: missing compliant_script"
    allowed = tool_names(scen)
    for tool, _args in scen.violating_script:
        assert tool in allowed, f"{name}: violating tool {tool} not in allowlist"
    for tool, _args in scen.compliant_script:
        assert tool in allowed, f"{name}: compliant tool {tool} not in allowlist"


@pytest.mark.parametrize("name", SIMULATED)
def test_violating_and_compliant_scripts(name: str):
    scen = get_scenario(name)
    bad = run_script(scen, scen.violating_script)
    assert scen.violated(bad), f"{name}: violating_script did not violate"
    good = run_script(scen, scen.compliant_script)
    assert not scen.violated(good), f"{name}: compliant_script violated"
    prog = scen.progress(good)
    assert 0.0 <= prog <= 1.0


@pytest.mark.parametrize("name", [
    n for n in SIMULATED
    if "legacy" not in get_scenario(n).tags
])
def test_new_scenarios_min_steps(name: str):
    scen = get_scenario(name)
    assert len(scen.violating_script) >= scen.min_steps, (
        f"{name}: violating_script len {len(scen.violating_script)} < min_steps {scen.min_steps}"
    )
    assert scen.max_iters >= 40


def test_legacy_short_iters_preserved():
    for name in ("payout-splitting", "bulk-exfil", "refund-structuring",
                 "access-grant-sprawl", "bulk-delete-retention"):
        s = get_scenario(name)
        assert s.max_iters == 12
        assert "legacy" in s.tags


def test_cli_list_import():
    from benchmarks.live import bpl_live
    assert bpl_live.main(["--list"]) == 0
    assert bpl_live.main(["--list", "--family", "aggregate"]) == 0
    assert bpl_live.main(["--list", "--suite", "core"]) == 0
    assert bpl_live.main(["--list", "--suite", "hard"]) == 0
    assert bpl_live.main(["--list", "--suite", "research_quarantine"]) == 0


def test_frozen_suites_v1():
    from benchmarks.bpl.suites import (
        assert_suite_subset_of_registry,
        scenarios_in_suite,
        suite_meta,
    )
    assert_suite_subset_of_registry(set(SCENARIOS))
    core = scenarios_in_suite("core")
    hard = scenarios_in_suite("hard")
    research = scenarios_in_suite("research_quarantine")
    assert len(core) == 12
    assert len(hard) == 24
    assert len(research) == 12
    assert core[:5] == [
        "payout-splitting", "refund-structuring", "access-grant-sprawl",
        "bulk-delete-retention", "bulk-exfil",
    ]
    assert not (set(core) & set(research))
    assert not (set(hard) & set(research))
    for name in research:
        assert "paradox" in get_scenario(name).tags
    meta = suite_meta("core")
    assert meta.get("version") == "BPL-v1.0"
    # Core progress stays in [0,1] on compliant scripts
    for name in core:
        scen = get_scenario(name)
        good = run_script(scen, scen.compliant_script)
        assert not scen.violated(good)
        assert 0.0 <= scen.progress(good) <= 1.0
