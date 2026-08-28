"""Pattern generalisation of a grant: mandates as PATTERNS, not instances.

Every loader in this repo builds a task's grant by enumerating the instances its
benign events touch: this exact tool name, this exact resource ref, this exact
file. A human operator does not write a mandate that way. They write ``/app/**``,
or "the reservation tools", or "the airline agent's tool surface". The instance
list is what a logger produces; the pattern is what a mandate is.

That gap is measurable and it is the largest number in the project. Rebuild a
tau2 grant from half a session's benign events and it refuses 47.91% of the other
half, and 100% of those refusals are ``tool 'x' not granted``, a tool the same
session used, in the same domain, drawn from the same catalog, that simply did
not happen to fall in the observed half.

This module derives a covering PATTERN SET from observed instances, at a declared
generalisation LEVEL, on three dimensions:

    tool       get_reservation_details
    resource   mcp:tool:get_reservation_details
    path       app/summary.txt

    level 0  exact        the instance itself
    level 1  up1          one segment up          get_reservation_*   app/*
    level 2  up2          two segments up         get_*               app-parent/**
    level 3  namespace    the goal bucket's own   <domain catalog>    app/**
                          surface, learned from
                          OTHER clean sessions
    level 4  everything   no constraint on this   *                   **
                          dimension

Levels are CUMULATIVE: the level-2 pattern set contains the level-1 set, which
contains the exact set. So the grant is monotone in the level by construction and
containment can only fall as the level rises, which is what makes the curve
readable.

## The one thing that could make this dishonest

Level 3 is learned rather than written, so it is a calibrated policy and the
invariants apply to it in full:

* it is derived from CLEAN tasks only, so it cannot move when attack traffic
  changes (invariant 1);
* it is derived from the calibration HALF of the clean tasks, using the same
  index permutation ``benchmarks.core.runner._calibration_split`` uses, so every
  task the namespace was learned from is a task the runner does not score
  (invariant 4);
* it never reads an event's label, a task's ``risk_kind``, or any field that
  distinguishes an attack.

``namespace_from`` asserts the first of those; ``calibration_indices`` implements
the second and is checked against the runner's own split in the tests.
"""
from __future__ import annotations

import fnmatch
import random
from collections.abc import Iterable
from dataclasses import replace
from typing import Any

from benchmarks.core.events import BenchmarkTask, EventLabel

LEVELS = ["exact", "up1", "up2", "namespace", "everything"]
EXACT, UP1, UP2, NAMESPACE, EVERYTHING = range(5)


def level_index(name: str | int) -> int:
    if isinstance(name, int):
        return name
    return LEVELS.index(name)


# --------------------------------------------------------------------------- #
# Instance -> pattern, per dimension
# --------------------------------------------------------------------------- #
def _seg_up(text: str, sep: str, n: int, *, keep_min: int = 1) -> str | None:
    """Drop ``n`` trailing ``sep``-separated segments and wildcard the tail.

    ``keep_min`` is a floor, not a nicety: without it ``book_reservation`` two
    segments up is the empty prefix, i.e. every tool in the world, and level 2
    would silently mean level 4 for any two-segment name.
    """
    segs = [s for s in text.split(sep) if s != ""]
    if len(segs) - n < keep_min:
        return None
    keep = segs[: len(segs) - n]
    if not keep:
        return None
    lead = sep if sep == "/" and text.startswith("/") else ""
    return lead + sep.join(keep) + sep + "*"


def tool_patterns(tool: str, level: int) -> set[str]:
    """Covering pattern set for one observed tool name at ``level``."""
    out = {tool}
    if level >= UP1:
        p = _seg_up(tool, "_", 1)
        if p:
            out.add(p)
    if level >= UP2:
        p = _seg_up(tool, "_", 2)
        if p:
            out.add(p)
    if level >= EVERYTHING:
        out.add("*")
    return out


def _split_ref(ref: str) -> tuple[str, str]:
    """``mcp:tool:get_user`` -> (``mcp:tool:``, ``get_user``); bare -> (``""``, ref)."""
    if ":" not in ref:
        return "", ref
    head, _, leaf = ref.rpartition(":")
    return head + ":", leaf


def resource_patterns(resource: str, level: int) -> set[str]:
    """Covering pattern set for one observed resource ref at ``level``.

    A namespaced ref (``mcp:tool:x``, ``file:/a/b``) generalises inside its
    namespace, never across it, so ``mcp:tool:*`` can never become ``net:*``.
    Connector substitution is a documented attack in this codebase and it lives
    exactly on that boundary.

    Level 3 deliberately does NOT emit ``<scheme>:*``. It did in the first
    version and the ladder-monotonicity test caught it on ASB: a wildcard scheme
    makes ``capability-token`` a pass-through, so that rung began allowing attack
    events the naive ``tool-allowlist`` rung below it still blocked. The
    resource namespace is the bucket's OBSERVED resource surface (supplied by the
    caller from ``Namespaces``), which mirrors the tool dimension instead of
    dissolving it.
    """
    out = {resource}
    head, leaf = _split_ref(resource)
    sep = "/" if "/" in leaf else "_"
    if level >= UP1:
        p = _seg_up(leaf, sep, 1)
        if p:
            out.add(head + p)
    if level >= UP2:
        p = _seg_up(leaf, sep, 2)
        if p:
            out.add(head + p)
    if level >= EVERYTHING:
        out.add("*")
    return out


def path_patterns(path: str, level: int) -> set[str]:
    """Covering pattern set for one observed path at ``level``.

    ``net:...`` / ``http://...`` refs are destinations, not filesystem paths;
    ``normalize_scope_path`` passes them through untouched, so they are
    generalised on the resource ladder rather than sliced into path segments.
    """
    out = {path}
    if ":" in path.split("/", 1)[0]:
        out |= resource_patterns(path, level)
        if level >= EVERYTHING:
            out.update({"**", "/**"})
        return out
    lead = "/" if path.startswith("/") else ""
    segs = [s for s in path.split("/") if s]
    if level >= UP1 and len(segs) >= 2:
        out.add(lead + "/".join(segs[:-1]) + "/*")
    if level >= UP2 and len(segs) >= 3:
        out.add(lead + "/".join(segs[:-2]) + "/**")
    if level >= NAMESPACE and segs:
        out.add(lead + segs[0] + "/**")
    if level >= EVERYTHING:
        out.update({"**", "/**"})
    return out


def generalize_declared_path(pattern: str, level: int) -> set[str]:
    """Generalise a path pattern an operator already wrote (``app/**``).

    RedCode's grant is not instance-derived: it is a declared workspace boundary,
    a constant. Its literal prefix is treated as the instance directory, so
    ``app/**`` one level up is the parent of ``app``, which is the filesystem
    root. That is a one-step collapse rather than a curve, and reporting it as
    such is the point: a mandate already written at its namespace has nowhere
    left to generalise to except everything.
    """
    if level >= EVERYTHING:
        return {pattern, "**", "/**"}
    literal = pattern.split("*", 1)[0].rstrip("/")
    if not literal or level <= EXACT:
        return {pattern}
    lead = "/" if literal.startswith("/") else ""
    segs = [s for s in literal.split("/") if s]
    out = {pattern}
    if level >= NAMESPACE and segs:
        out.add(lead + segs[0] + "/**")
    if level >= UP1:
        if len(segs) >= 2:
            out.add(lead + "/".join(segs[:-1]) + "/**")
        else:
            out.update({"**", "/**"})
    if level >= UP2:
        if len(segs) >= 3:
            out.add(lead + "/".join(segs[:-2]) + "/**")
        else:
            out.update({"**", "/**"})
    return out


def matches_any(value: str, patterns: Iterable[str]) -> bool:
    for p in patterns:
        if p == value or fnmatch.fnmatchcase(value, p):
            return True
    return False


def capability_allows_patterns(caps: list[dict[str, str]], resource: str,
                               action: str) -> bool:
    """``capability_allows`` with a pattern resource.

    ``clayseal.core.operations.capability_allows`` compares the resource with
    ``!=``, mirroring the Biscuit authorizer. A pattern grant needs a matcher,
    and it lives here rather than in the shipping primitive because a wildcard
    resource is a benchmark question until it is a token format.
    """
    for cap in caps:
        if not matches_any(resource, [cap.get("resource", "")]):
            continue
        act = cap.get("action", "")
        if act == "*" or act == action:
            return True
    return False


# --------------------------------------------------------------------------- #
# Namespace level: learned from OTHER clean sessions in the same goal bucket
# --------------------------------------------------------------------------- #
def bucket_of(task: BenchmarkTask) -> str:
    return str(task.meta.get("goal_kind") or task.meta.get("source") or "default")


def calibration_indices(tasks: list[BenchmarkTask], seed: int) -> tuple[list[int], list[int]]:
    """Reproduce ``runner._calibration_split`` positionally.

    ``random.shuffle`` consumes only ``len(x)`` and the RNG stream, so shuffling
    the index list with the same seed yields the same permutation the runner
    applies to the task list. Same seed and same clean/attack partition therefore
    means the same split, which is what lets a namespace learned here be scored
    there without leaking.
    """
    clean, rest = [], []
    for i, t in enumerate(tasks):
        (clean if not any(e.label is EventLabel.ATTACK for e in t.events)
         else rest).append(i)
    if len(clean) < 2:
        # Degenerate: the runner cannot hold anything out either, so it scores
        # every task. Learning a namespace from any of them would be learning
        # from data we then score on, and on a corpus where every task carries an
        # attack it would be learning from the attack. ASB, ToolEmu and
        # InjecAgent are all this shape. Return an EMPTY calibration set: the
        # namespace level then adds nothing beyond opening the resource
        # namespace, and the table shows level 3 equal to level 2, which is the
        # honest report of "there was no clean traffic to generalise from".
        return [], list(range(len(tasks)))
    shuffled = list(clean)
    random.Random(seed).shuffle(shuffled)
    half = max(1, len(shuffled) // 2)
    return shuffled[:half], shuffled[half:] + rest


class Namespaces:
    """Per-goal-bucket tool / resource / path surface, from clean traffic only."""

    def __init__(self) -> None:
        self.tools: dict[str, set[str]] = {}
        self.resources: dict[str, set[str]] = {}
        self.path_roots: dict[str, set[str]] = {}
        self.actions: dict[str, set[str]] = {}

    def actions_for(self, bucket: str) -> set[str]:
        return self.actions.get(bucket, set())

    def tools_for(self, bucket: str) -> set[str]:
        return self.tools.get(bucket, set())

    def resources_for(self, bucket: str) -> set[str]:
        return self.resources.get(bucket, set())

    def path_roots_for(self, bucket: str) -> set[str]:
        return self.path_roots.get(bucket, set())


def namespace_from(tasks: list[BenchmarkTask], indices: Iterable[int]) -> Namespaces:
    """Learn each bucket's surface from the calibration tasks.

    Refuses to look at a task that carries an attack event. That is asserted
    rather than assumed, because the shortest path to a fraudulent number here is
    a namespace that quietly excludes the attacker's tools by having seen the
    label.
    """
    ns = Namespaces()
    for i in indices:
        task = tasks[i]
        if any(e.label is EventLabel.ATTACK for e in task.events):
            raise AssertionError(
                f"namespace calibration saw an attack-bearing task ({task.task_id}); "
                "a grant derived from attack traffic is the label, not a policy"
            )
        b = bucket_of(task)
        tools = ns.tools.setdefault(b, set())
        resources = ns.resources.setdefault(b, set())
        roots = ns.path_roots.setdefault(b, set())
        actions = ns.actions.setdefault(b, set())
        tools.update(task.allowed_tools)
        for event in task.events:
            tools.add(event.tool_name)
            resources.add(event.resource)
            actions.add(event.action)
            if event.path and ":" not in event.path.split("/", 1)[0]:
                segs = [s for s in event.path.split("/") if s]
                if segs:
                    lead = "/" if event.path.startswith("/") else ""
                    roots.add(lead + segs[0] + "/**")
        for resource in task.mandate.get("allowed_resources") or ():
            resources.add(str(resource))
    return ns


# --------------------------------------------------------------------------- #
# Applying a level to a task's grant
# --------------------------------------------------------------------------- #
def _scope_paths(mandate: dict[str, Any]) -> list[str]:
    scope = mandate.get("scope")
    if isinstance(scope, dict):
        return [str(p) for p in scope.get("allowed_paths") or ()]
    return [str(p) for p in mandate.get("allowed_paths") or ()]


def _set_scope_paths(mandate: dict[str, Any], paths: list[str]) -> dict[str, Any]:
    out = dict(mandate)
    scope = out.get("scope")
    if isinstance(scope, dict):
        out["scope"] = {**scope, "allowed_paths": paths}
    elif "allowed_paths" in out:
        out["allowed_paths"] = paths
    return out


def generalize_task(
    task: BenchmarkTask,
    *,
    tool_level: int = EXACT,
    path_level: int = EXACT,
    verb_level: int = EXACT,
    namespaces: Namespaces | None = None,
    observed_tools: set[str] | None = None,
    observed_resources: list[str] | None = None,
    observed_paths: list[str] | None = None,
) -> BenchmarkTask:
    """Return ``task`` with its grant restated as patterns at the given levels.

    ``observed_*`` override what the grant is derived FROM, which is how the
    held-out arm works: the instances are half the session's benign events
    rather than the loader's full enumeration. Absent, the task's own declared
    grant is generalised.

    ``tool_level`` covers the tool and resource dimensions (they are 1:1 in every
    loader that names resources ``mcp:tool:<tool>``); ``path_level`` covers
    filesystem scope. They are separate arguments because measurement says they
    behave differently: the friction on tau2 is entirely a tool-dimension
    problem and the containment on RedCode is entirely a path-dimension one.
    """
    bucket = bucket_of(task)
    tools_src = task.allowed_tools if observed_tools is None else observed_tools
    res_src = (observed_resources if observed_resources is not None
               else list(task.mandate.get("allowed_resources") or ()))

    tool_pats: set[str] = set()
    for t in tools_src:
        tool_pats |= tool_patterns(t, tool_level)
    if tool_level >= NAMESPACE and namespaces is not None:
        tool_pats |= namespaces.tools_for(bucket)
    if tool_level >= EVERYTHING:
        tool_pats.add("*")

    res_pats: set[str] = set()
    for r in res_src:
        res_pats |= resource_patterns(r, tool_level)
    if tool_level >= NAMESPACE and namespaces is not None:
        res_pats |= {p for r in namespaces.resources_for(bucket)
                     for p in resource_patterns(r, EXACT)}
    if tool_level >= EVERYTHING:
        res_pats.add("*")

    # Capabilities keep their (resource, action) PAIRING. Crossing every pattern
    # with every observed action would generalise the verb dimension as a side
    # effect of generalising the resource one, so a resource seen only being read
    # would become writable because some other resource was written. That is a
    # different mechanism with a different risk and it does not get to ride along
    # unmeasured. The verb dimension opens only at `everything`, which is the
    # ceiling row and is labelled as one.
    verb_pats: set[str] = set()
    if verb_level >= EVERYTHING:
        verb_pats = {"*"}
    elif verb_level >= NAMESPACE and namespaces is not None:
        verb_pats = set(namespaces.actions_for(bucket))

    caps = [dict(c) for c in task.capabilities]
    if (tool_level > EXACT or verb_pats) and task.capabilities:
        caps = []
        seen: set[tuple[str, str]] = set()

        def _add(resource: str, action: str) -> None:
            if (resource, action) not in seen:
                seen.add((resource, action))
                caps.append({"resource": resource, "action": action})

        for cap in task.capabilities:
            resource = str(cap.get("resource", ""))
            for p in sorted(resource_patterns(resource, tool_level)):
                _add(p, str(cap.get("action", "")))
                for extra in sorted(verb_pats):
                    _add(p, extra)
        if tool_level >= NAMESPACE:
            actions = sorted({str(c.get("action", "")) for c in task.capabilities}
                             | verb_pats)
            for p in sorted(res_pats):
                for a in actions:
                    _add(p, a)

    mandate = dict(task.mandate)
    if mandate.get("allowed_resources") is not None and res_pats:
        mandate["allowed_resources"] = sorted(res_pats)
    if verb_pats and mandate.get("allowed_actions"):
        mandate["allowed_actions"] = (
            [] if "*" in verb_pats
            else sorted(set(mandate["allowed_actions"]) | verb_pats))

    declared_paths = _scope_paths(task.mandate)
    if observed_paths is not None:
        path_pats: set[str] = set()
        for p in observed_paths:
            path_pats |= path_patterns(p, path_level)
        if path_level >= NAMESPACE and namespaces is not None:
            path_pats |= namespaces.path_roots_for(bucket)
        mandate = _set_scope_paths(mandate, sorted(path_pats))
    elif declared_paths and path_level > EXACT:
        path_pats = set()
        for p in declared_paths:
            path_pats |= generalize_declared_path(p, path_level)
        if path_level >= NAMESPACE and namespaces is not None:
            path_pats |= namespaces.path_roots_for(bucket)
        mandate = _set_scope_paths(mandate, sorted(path_pats))

    tools = set(tool_pats) if task.allowed_tools else task.allowed_tools
    return replace(
        task,
        mandate=mandate,
        capabilities=caps,
        allowed_tools=tools,
        tool_patterns=sorted(tool_pats) if tool_pats else None,
        resource_patterns=sorted(res_pats) if res_pats else None,
        meta={**task.meta, "tool_level": tool_level, "path_level": path_level,
              "verb_level": verb_level},
    )


def generalize_corpus(
    tasks: list[BenchmarkTask],
    *,
    tool_level: int = EXACT,
    path_level: int = EXACT,
    verb_level: int = EXACT,
    seed: int = 0,
    paths_from_traffic: bool = False,
) -> list[BenchmarkTask]:
    """Restate every task's declared grant as patterns at the given levels.

    This is the FB(granted) arm: the operator wrote a complete mandate, but wrote
    it as patterns rather than as an enumeration.

    ``paths_from_traffic`` replaces a declared path boundary with one derived from
    the paths clean sessions in the same bucket actually touched, the operator
    writing their file scope from a fortnight of their own logs instead of being
    handed the workspace constant. It is the arm that makes RedCode participate
    in the curve at all, since its declared boundary is a constant no held-out
    split can touch.
    """
    if (tool_level <= EXACT and path_level <= EXACT and verb_level <= EXACT
            and not paths_from_traffic):
        return tasks
    calib, _ = calibration_indices(tasks, seed)
    ns = namespace_from(tasks, calib)
    bucket_paths: dict[str, list[str]] = {}
    if paths_from_traffic:
        for i in calib:
            t = tasks[i]
            for e in t.events:
                if e.path:
                    bucket_paths.setdefault(bucket_of(t), []).append(e.path)
    out = []
    for task in tasks:
        observed_paths = None
        if paths_from_traffic:
            observed_paths = bucket_paths.get(bucket_of(task), [])
        out.append(generalize_task(
            task, tool_level=tool_level, path_level=path_level,
            verb_level=verb_level, namespaces=ns, observed_paths=observed_paths,
        ))
    return out
