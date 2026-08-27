"""BPL-v1 scenario registry."""
from __future__ import annotations

from collections.abc import Callable

from benchmarks.bpl.scenarios.aggregate import AGGREGATE_BUILDERS
from benchmarks.bpl.scenarios.aml import AML_BUILDERS
from benchmarks.bpl.scenarios.apex import APEX_BUILDERS
from benchmarks.bpl.scenarios.confidentiality import CONFIDENTIALITY_BUILDERS
from benchmarks.bpl.scenarios.crossdomain import CROSSDOMAIN_BUILDERS
from benchmarks.bpl.scenarios.deep import DEEP_BUILDERS
from benchmarks.bpl.scenarios.edgecases import EDGECASE_BUILDERS
from benchmarks.bpl.scenarios.escape import ESCAPE_BUILDERS
from benchmarks.bpl.scenarios.frontier import FRONTIER_BUILDERS
from benchmarks.bpl.scenarios.institutional import INSTITUTIONAL_BUILDERS
from benchmarks.bpl.scenarios.legacy import LEGACY_BUILDERS
from benchmarks.bpl.scenarios.literature import LITERATURE_BUILDERS
from benchmarks.bpl.scenarios.live_exfil import bulk_exfil_live
from benchmarks.bpl.scenarios.nightmare import NIGHTMARE_BUILDERS
from benchmarks.bpl.scenarios.paradox import PARADOX_BUILDERS
from benchmarks.bpl.scenarios.specialty import SPECIALTY_BUILDERS
from benchmarks.bpl.scenarios.ultra import ULTRA_BUILDERS
from benchmarks.bpl.scenarios.unorthodox import UNORTHODOX_BUILDERS
from benchmarks.bpl.schema import Family, Scenario

# Builder callables, instantiate via SCENARIOS[name]().
SCENARIO_BUILDERS: dict[str, Callable[[], Scenario]] = {
    **LEGACY_BUILDERS,
    **AGGREGATE_BUILDERS,
    **ESCAPE_BUILDERS,
    **CONFIDENTIALITY_BUILDERS,
    **FRONTIER_BUILDERS,
    **ULTRA_BUILDERS,
    **LITERATURE_BUILDERS,
    **DEEP_BUILDERS,
    **AML_BUILDERS,
    **UNORTHODOX_BUILDERS,
    **CROSSDOMAIN_BUILDERS,
    **SPECIALTY_BUILDERS,
    **INSTITUTIONAL_BUILDERS,
    **APEX_BUILDERS,
    **NIGHTMARE_BUILDERS,
    **PARADOX_BUILDERS,
    **EDGECASE_BUILDERS,
    "bulk-exfil-live": bulk_exfil_live,
}

# Alias kept for callers that expect SCENARIOS like the old bpl_live module.
SCENARIOS = SCENARIO_BUILDERS


def list_scenarios(*, family: Family | str | None = None,
                   include_live: bool = True) -> list[str]:
    names = []
    for name, builder in SCENARIO_BUILDERS.items():
        if not include_live and name == "bulk-exfil-live":
            continue
        scen = builder()
        if family and family != "all" and scen.family != family:
            continue
        names.append(name)
    return names


def get_scenario(name: str) -> Scenario:
    """Build the scenario AND attach the policy declared for it.

    `policies.py` exists so every condition is handed the rule, and it said so
    in its docstring while nothing read it. `Scenario.policy` defaults to an
    empty `Policy()`, no builder assigned it, and `apply_call` reads
    `scen.policy`, so the declared Core-12 rules reached the coverage report
    and the agreement test and never reached the enforcement path.

    What that cost is specific. With no `scope` rule the per-call condition
    falls back to "every tool in the scenario's own catalog", and the scripts
    only ever call tools from that catalog, so per-call could not refuse
    anything whatever the scenario was. Its 0-of-132 was arithmetic rather than
    a measurement, and the table called that row "given the policy".

    Attaching it here rather than in each builder keeps the declaration in one
    auditable table, which is the reason `policies.py` was written that way.
    Scenarios with no declared policy still get an empty one; that is the
    migration state, not a claim, and `--policy-coverage` prints it.
    """
    if name not in SCENARIO_BUILDERS:
        raise KeyError(f"unknown BPL scenario: {name}")
    from benchmarks.bpl.policies import policy_for

    scen = SCENARIO_BUILDERS[name]()
    scen.policy = policy_for(name)
    return scen


def scenarios_by_family() -> dict[str, list[str]]:
    out: dict[str, list[str]] = {
        "aggregate": [], "escape": [], "confidentiality": []}
    for name, builder in SCENARIO_BUILDERS.items():
        if name == "bulk-exfil-live":
            continue
        scen = builder()
        out[scen.family].append(name)
    return out
