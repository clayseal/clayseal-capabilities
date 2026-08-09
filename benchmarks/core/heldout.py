"""Held-out mandates: making the false-block number a measurement again.

Thirteen loaders build a task's grant from the resources and tools its own benign
events use. On six corpora the grant IS the benign side, exactly:

    tau2, BFCL, ATIF, InjecAgent, ToolEmu, ASB    100% of tasks
    AgentHarm                                      50% (the benign variants)

So no benign event can fall outside its own grant, and 0.00% false-block at the
scope rung follows by arithmetic. Our strongest published claim, zero false blocks
across 18,356 benign events, is largely a tautology at that rung.

That does not make the whole number empty. Protected zones are global constants,
egress binding comes from the goal, and the velocity cap is already calibrated on
held-out traffic, so those rungs can and do refuse benign events (ATIF 1.94%, tau2
0.03%). It is the SCOPE rung specifically that cannot fail.

The fix is the same shape as the velocity calibration split. Build the grant from
HALF a task's benign events and score the other half. A benign event the grant was
not built from can genuinely fall outside it, so the number becomes evidence:
it measures whether a mandate written from observed traffic generalises to the
traffic it did not observe, which is exactly the question an operator faces on the
day after they write it.

This is deliberately a separate module rather than a change to the loaders. The
loaders should keep producing the corpus faithfully; whether a mandate is held out
is a property of the MEASUREMENT, and mixing the two is how the circularity got in.
"""
from __future__ import annotations

import random
from dataclasses import replace
from typing import Any

from benchmarks.core.events import BenchmarkTask, EventLabel


def _grant_is_benign_side(task: BenchmarkTask) -> bool:
    """Is this task's grant simply the set of things its benign events touch?"""
    resources = set(task.mandate.get("allowed_resources") or ())
    tools = set(task.allowed_tools or ())
    benign_resources = {e.resource for e in task.events
                        if e.label is EventLabel.BENIGN}
    benign_tools = {e.tool_name for e in task.events
                    if e.label is EventLabel.BENIGN}
    if resources and benign_resources and resources == benign_resources:
        return True
    return bool(tools and benign_tools and tools == benign_tools)


def hold_out_mandate(task: BenchmarkTask, seed: int = 0,
                     fraction: float = 0.5, *,
                     tool_level: int = 0, path_level: int = 0,
                     verb_level: int = 0,
                     namespaces: Any | None = None) -> BenchmarkTask | None:
    """Rebuild a task's grant from a fraction of its benign events.

    Returns None when the task has too few benign events to split, or when its
    grant was not benign-derived in the first place and therefore needs no
    correction.

    The attack events are untouched and all still scored, so containment is
    unaffected. Only the benign side changes, and only by making its grant
    narrower than the traffic it is judged against.
    """
    if not _grant_is_benign_side(task):
        return None
    benign = [e for e in task.events if e.label is EventLabel.BENIGN]
    if len(benign) < 2:
        return None

    shuffled = list(benign)
    random.Random(f"{seed}:{task.task_id}").shuffle(shuffled)
    cut = max(1, int(len(shuffled) * fraction))
    observed = shuffled[:cut]

    granted_resources = sorted({e.resource for e in observed})
    granted_tools = {e.tool_name for e in observed}

    mandate: dict[str, Any] = dict(task.mandate)
    if mandate.get("allowed_resources"):
        mandate["allowed_resources"] = granted_resources
    capabilities = [c for c in task.capabilities
                    if c.get("resource") in set(granted_resources)] or task.capabilities

    held = replace(
        task,
        mandate=mandate,
        capabilities=capabilities,
        allowed_tools=granted_tools if task.allowed_tools else task.allowed_tools,
        meta={**task.meta, "mandate_held_out": True,
              "observed_benign": len(observed), "total_benign": len(benign)},
    )
    if tool_level <= 0 and path_level <= 0 and verb_level <= 0:
        return held
    # The operator saw the same half of the traffic, but wrote a PATTERN over it
    # instead of an enumeration. The observed instances are the only input; the
    # unobserved half is never consulted, so the grant is still built from data
    # it is not scored on.
    from benchmarks.core.patterns import generalize_task

    observed_paths = [e.path for e in observed if e.path] or None
    return generalize_task(
        held,
        tool_level=tool_level,
        path_level=path_level,
        verb_level=verb_level,
        namespaces=namespaces,
        observed_tools=granted_tools,
        observed_resources=granted_resources,
        observed_paths=observed_paths,
    )


def hold_out_corpus(tasks: list[BenchmarkTask], seed: int = 0,
                    fraction: float = 0.5, *,
                    tool_level: int = 0,
                    path_level: int = 0,
                    verb_level: int = 0) -> tuple[list[BenchmarkTask], int]:
    """Apply `hold_out_mandate` where it applies. Returns (tasks, n_corrected).

    ``tool_level`` / ``path_level`` restate the rebuilt grant as patterns (see
    ``benchmarks.core.patterns``). At level 0 this function is byte-for-byte the
    behaviour it had before patterns existed.

    The namespace level needs a surface to generalise TO, and it is learned from
    the calibration half of the clean tasks using the runner's own split, so a
    task that contributed to a namespace is never scored against it.
    """
    namespaces = None
    if max(tool_level, path_level, verb_level) >= 3:
        from benchmarks.core.patterns import calibration_indices, namespace_from

        calib, _ = calibration_indices(tasks, seed)
        namespaces = namespace_from(tasks, calib)
    out: list[BenchmarkTask] = []
    corrected = 0
    for task in tasks:
        held = hold_out_mandate(task, seed=seed, fraction=fraction,
                                tool_level=tool_level, path_level=path_level,
                                verb_level=verb_level, namespaces=namespaces)
        if held is None:
            out.append(task)
        else:
            out.append(held)
            corrected += 1
    return out, corrected


def circular_unsplittable(tasks: list[BenchmarkTask]) -> int:
    """Tasks whose grant is benign-derived and which cannot be held out.

    A task with a single benign event has nothing to split: half of one event is
    no event. InjecAgent is entirely this shape, 2,108 tasks with one benign
    event each, so its grant is circular and no held-out number can be produced
    for it. That is not a reason to report the circular 0.00% as though it were a
    measurement; it is a reason to report nothing and say why.
    """
    return sum(1 for t in tasks
               if _grant_is_benign_side(t)
               and len([e for e in t.events if e.label is EventLabel.BENIGN]) < 2)
