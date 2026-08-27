"""When a resource-membership test is entitled to refuse, and when it is not.

THE DEFECT THIS EXISTS TO CLOSE

Two tiers compile a goal into a set of allowed resource CLASSES and refuse an
action whose class is not a member: `IntentEnvelope._membership` in the
authorization path, and `TypedGoalEnvelope.assess` in the behavioural detector.
Both guarded the empty case, so a goal that named no resources refused nothing.
Neither guarded the DISJOINT case.

Disjoint is not a corner. Measured on the `sleight` corpus, every event is
labelled `resource="workspace"` while the goal surface is compiled from file
paths, giving classes `{data, home, net}`. The two vocabularies never intersect,
so both tiers refused every consequential action:

- the intent envelope denied 204 of 311 benign events, 65.6%, and the
  containment that bought was published as a 62-point win;
- the detector blocked 13 of 18 benign trajectories, several at conformal
  p-values of 0.5, 0.7 and 0.9, so no choice of alpha changed the outcome.

Both are deny-all wearing a reason string, and neither reads as one from the
containment column alone. The information needed to decide correctly was
present the whole time in `meta["path"]`, which sat inside the goal surface.

WHAT IS ACTUALLY WRONG

A membership test compares two sets of names, and it means something only when
both sides are drawn from the same vocabulary. An empty surface says nothing.
A populated surface that is disjoint from everything the agent touches also
says nothing, and reading it as "every action violates the goal" is a category
error rather than a strict reading.

This matters far past one corpus. An MCP server free to label its resources how
it likes, a connector that reports an opaque handle, a tool that names a session
rather than a file: any of them, in front of a grant written in paths, produces
total refusal of legitimate work reported as goal violation.

THE RULE

Two readings, then one precondition.

**Read both fields.** An action names its target in `resource` and again in
`meta["path"]`. A match on either is a match, because both describe the same
call and only one of them may be in the grant's vocabulary.

**Earn the authority to refuse.** The tier may refuse only if some action in
the session has matched the surface at least once. Until then the comparison
has never once succeeded and there is no evidence it ever could.

Three properties make this safe rather than merely permissive:

*It is session-level, not per-action.* An attacker cannot buy an abstention by
relabelling a single call, because the test reads the whole trajectory.

*It goes live immediately.* Any session doing the legitimate task touches a
granted resource almost at once, and from that action onward the tier refuses
normally for the rest of the session.

*It only ever removes refusals the tier had no grounds for.* The path scope in
the floor still checks the same path against the task scope, is not
vocabulary-dependent, and contains 100% of surface-leaving attacks across more
than 4,400 events. The evidence is not lost; the tier that could not read it
stops pretending it could.
"""
from __future__ import annotations

import posixpath
from collections.abc import Iterable
from functools import lru_cache

from clayseal.capabilities.monitor.action import Action, resource_class

#: Readings that are not a class. `resource_class("")` returns `none`, and a
#: path that resolves upward or nowhere leaves `..` or `.`. Treating any of them
#: as a class is how a surface comes to hold a name no action should match:
#: a goal granting the relative path `../etc` would put `..` in the surface, and
#: `..` is what EVERY path escaping upward resolves to, so one such grant would
#: admit all of them. On the action side the same entry means a traversal has no
#: usable reading, and `names_a_target` then refuses it rather than passing it.
_NOT_A_CLASS = frozenset({"", "none", "..", "."})


def surface_class(ref: str) -> str:
    """The class of a resource reference, for membership rather than for tokens.

    `action.resource_class` splits on the first separator, so every ABSOLUTE
    path classes to the empty string: `/data/models/x` and `/etc/shadow` are
    indistinguishable there, and both are indistinguishable from nothing. That
    is correct for the scorer, whose token vocabulary must stay small and must
    not change under it, and it is useless for deciding membership.

    So membership gets its own reading, which differs in two respects.

    **A leading separator is stripped**, so `/data/models/x` classes as `data`.

    **A backslash is a separator.** Without that, `..\\..\\etc\\shadow`
    contains no `:` and no `/`, falls through to the `.` split, and classes to
    the empty string, which the caller then reads as "this action names no
    target". This repository has already had one backslash bypass, in the path
    deny-list, found by differential fuzzing; writing a second path reading
    without applying that lesson reintroduced it one module over.

    **Traversal is resolved before the class is taken.** Without that,
    `data/../etc/shadow` classes as `data`, which is in a surface that grants
    `data`, while the file that opens is `/etc/shadow`. That is the classic
    traversal bypass and it was live here: five variants of it passed the tier.
    `normpath` collapses `.` and resolves `..` textually, which is exactly the
    right strength. It cannot follow a symlink, and it must not try: this is a
    pure function of a string, the floor's path scope does the resolvable-path
    check against the real filesystem, and a reading that pretended to resolve
    links would be claiming knowledge it does not have.

    A path that escapes upward resolves to a leading `..`, which is not a class,
    so it is not in any surface. Conservative in the correct direction.

    **A dot is not a separator inside a filename.** `resource_class` splits on
    `.` so that `evil.example` classes as `evil`, which keeps the scorer's token
    vocabulary small and is right for a host. Applied to a path it means
    `data.txt` classes as `data`, so a surface granting the DIRECTORY `data`
    admits a file that merely shares its name and sits beside it. A differential
    against `normpath` reported that on 1,652 of 200,000 generated cases. A
    scheme still goes through `resource_class` and keeps that reading; a
    filesystem path takes its first component whole.

    All four rules exist because anything that reads a path has to agree with
    whatever finally opens it, and every disagreement is somebody's bypass.

    Cached, for the reason `_normalize_scope_path` is: this sits under the
    envelope's per-action membership check, which re-reads the whole trajectory
    on every decision. Profiled at 642,400 calls over 800 decisions on a session
    with roughly 800 distinct paths. The `str()` conversion stays OUTSIDE the
    cache: `lru_cache` hashes its argument before the body runs, so an
    unhashable one raises from the decorator and never reaches the conversion.
    That defect is documented twenty lines from here in `task_scope.py` and it
    is worth not learning a third time.
    """
    return _surface_class(str(ref))


@lru_cache(maxsize=16384)
def _surface_class(text: str) -> str:
    text = text.replace("\\", "/")
    head, sep, _ = text.partition(":")
    if sep and "/" not in head:
        # A scheme is not a path. `resource_class` knows these, and `normpath`
        # would rewrite `repo://a/b` on its way past.
        return resource_class(text)
    if not text:
        return resource_class("")
    normalised = posixpath.normpath(text).lstrip("/")
    if not normalised:
        return resource_class("")
    return normalised.split("/", 1)[0]


def names_a_target(action: Action) -> bool:
    """Did this action name a target at all, readable or not?

    The distinction `resource_readings` cannot carry on its own, and the one
    that decides whether an unclassifiable target is a pass. `.env` names a
    target. An action with no resource and no path does not.
    """
    if str(action.resource or "").strip():
        return True
    return bool(str((action.meta or {}).get("path") or "").strip())


def resource_readings(action: Action) -> tuple[str, ...]:
    """Every class this action's target can be read as, `resource` first.

    An empty tuple does NOT mean the action names no target. It means no field
    produced a usable class, which happens both when nothing was named and when
    something was named that this function could not read: `.env` splits on its
    leading dot and classes to the empty string, and so does any bare `..`.
    Callers must use `names_a_target` to tell those apart, because reading the
    second as the first is a bypass and was one here.
    """
    return _readings(str(action.resource or ""),
                     str((action.meta or {}).get("path") or ""))


@lru_cache(maxsize=16384)
def _readings(resource: str, path: str) -> tuple[str, ...]:
    readings = [surface_class(resource)]
    if path:
        readings.append(surface_class(path))
    seen: set[str] = set()
    return tuple(r for r in readings
                 if r not in _NOT_A_CLASS and not (r in seen or seen.add(r)))


def surface_from(refs) -> frozenset[str]:
    """Compile a goal's resource references into a comparable surface."""
    return frozenset(c for c in (surface_class(r) for r in refs)
                     if c not in _NOT_A_CLASS)


def names_a_readable_target(action: Action) -> bool:
    """Does this action name a target a PATH-shaped surface can judge?

    An action that carries no path and whose resource is a bare word names
    nothing a surface built from file paths can be compared against. `workspace`
    is not a place; it is what a harness or an MCP server calls the session, and
    the surface it is being tested against holds `data`, `home`, `net`.

    This is the residual of the disjoint-vocabulary defect, one level down.
    `surface_is_comparable` asks whether the SESSION ever spoke the surface's
    vocabulary and turns the tier on for the whole session once it has. That is
    right for an action that names a path, and wrong for one that names nothing:
    measured on sleight, 34 benign actions were HARD DENIED on the strength of
    an opaque label, in sessions made comparable by other actions that did carry
    paths.

    A scheme is readable, because `net:evil.example` says where it is going and
    the surface can hold `net`. A path is readable. A bare word with no path is
    not, and refusing on it is refusing for a reason that does not exist.

    It opens no hole that the other tiers do not already cover. An action with
    no path cannot reach a file, so the path scope has nothing to lose; a
    destination lives in the arguments, where the egress tier reads it; and the
    tool itself is still bound by `tools.allow` and by any withdrawal.
    """
    path = str((action.meta or {}).get("path") or "").strip()
    if path:
        return True
    resource = str(action.resource or "").strip()
    return bool(resource) and (":" in resource or "/" in resource
                               or "\\" in resource or "." in resource)


def in_surface(action: Action, surface: frozenset[str]) -> bool:
    """Does any reading of this action name a class the surface allows?

    Delegated to a cached function of the two fields it reads, because the
    envelope's phase assessment re-evaluates membership for EVERY action in the
    trajectory on EVERY decision: profiled at 321,200 calls over 800 decisions,
    which is 84% of the assessment's time. Membership has no cross-action state,
    so the same action re-read at step 800 has the same answer it had at step 1
    and a value-keyed memo is sound. The phase loop around it is order-dependent
    and is deliberately NOT cached here.

    An action that names NO target is in-surface: there is nothing to place
    inside or outside the goal, and refusing it on target grounds would be
    refusing it for a reason that does not exist.

    An action that names a target this function cannot class is NOT in-surface,
    and the difference is the whole point. The first version of this returned
    True for both, so `.env`, `..\\..\\etc\\shadow` and a bare `..` all read
    as "names nothing" and passed the tier outright. That is the same mistake
    this module was written to prevent, one level down: `the server did not say`
    and `the server said no` are different facts, and so are `named nothing` and
    `named something unreadable`. Refusing to guess is what the rest of this
    library does with an input it cannot parse.
    """
    if not names_a_readable_target(action):
        # Nothing a path-shaped surface can judge. See `names_a_readable_target`.
        return True
    return matches_surface(action, surface)


def matches_surface(action: Action, surface: frozenset[str]) -> bool:
    """Does a reading of this action GENUINELY name a class the surface allows?

    Strictly narrower than `in_surface`, which also answers True when the tier
    has to abstain. The two were the same function until abstention existed, and
    conflating them was a real error: `surface_is_comparable` counted an
    abstention as a match, so a session of nothing but opaque labels reported
    itself comparable and turned the tier on with no evidence that it could
    read anything. An abstention is the absence of a judgement, not a positive
    one, and only a positive one may license the tier for the rest of a session.
    """
    return _in_surface(str(action.resource or ""),
                       str((action.meta or {}).get("path") or ""), surface)


@lru_cache(maxsize=16384)
def _in_surface(resource: str, path: str, surface: frozenset[str]) -> bool:
    readings = _readings(resource, path)
    if readings:
        return any(r in surface for r in readings)
    # Nothing readable. Only an action that named NO target at all is a pass.
    return not (resource.strip() or path.strip())


def surface_is_comparable(surface: frozenset[str],
                          actions: Iterable[Action]) -> bool:
    """Has any action in the session spoken the surface's vocabulary?

    False means the tier has no standing to refuse: either the surface is empty
    or it has never once matched, and in both cases a non-match carries no
    information about the goal. See the module docstring for why this is a
    precondition rather than a leniency.
    """
    if not surface:
        return False
    return any(matches_surface(a, surface) for a in actions)
