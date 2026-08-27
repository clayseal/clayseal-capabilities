"""ATBench loader tests, one per defect class this project has already shipped.

Every assertion here exists because an equivalent mistake was made on another
corpus and produced a number that had to be withdrawn:

* AgentThreatBench, 18 of 24 attack events were the loader's own inventions;
* ASB / InjecAgent / ToolEmu, containment that saturates at the tool allowlist;
* SLEIGHT, a mandate invented from session state, and a grant that is the
  benign side restated, which makes 0.00% false-block arithmetic;
* AgentHarm, reading only part of the record, and a loader whose event ORDER
  carried the label (the withdrawn +8.0);
* InjecAgent, half the corpus being the same case counted twice.

The corpus lives outside the repo, so every test skips cleanly without it.
"""
from __future__ import annotations

import json
from functools import lru_cache

import pytest

from benchmarks.core.engines import build_engines
from benchmarks.core.events import EventLabel
from benchmarks.core.runner import run_benchmark

# The corpus's own published counts (Hugging Face AI45Research/ATBench README,
# "Release Zoo"). Hard-coded so a loader that silently drops or duplicates
# trajectories fails here rather than in a results table.
_PUBLISHED = {
    "atbench": {"total": 1000, "safe": 503, "unsafe": 497, "tools": 2084},
    "atbench500": {"total": 500, "safe": 250, "unsafe": 250, "tools": 1575},
}


# The two release files are 18 MB and 5 MB; several tests read both, so parse
# once per session. Callers must not mutate what they get back.
@lru_cache(maxsize=4)
def _load(name: str):
    from benchmarks.datasets.base import get_loader

    try:
        return get_loader(name).load()
    except RuntimeError as exc:  # corpus not fetched
        pytest.skip(str(exc).splitlines()[0])


@lru_cache(maxsize=4)
def _raw(release: str):
    from benchmarks.datasets.atbench import ATBenchLoader

    path = ATBenchLoader(release=release).root / release / "test.json"
    if not path.exists():
        pytest.skip(f"ATBench not fetched at {path}")
    return json.loads(path.read_text())


def _calls(record: dict, release: str):
    from benchmarks.datasets.atbench import _RELEASES, _parse_action, _turns

    key = _RELEASES[release]["contents_key"]
    return [c for c in (_parse_action(t.get("action"))
                        for t in _turns(record, key) if t.get("role") == "agent")
            if c[0]]


# --------------------------------------------------------------------------- #
# 1. AgentThreatBench class: attack events the corpus never labels
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("name,release", [("atbench", "ATBench"),
                                          ("atbench500", "ATBench500")])
def test_no_attack_event_is_emitted_because_the_corpus_labels_no_action(name, release):
    """ATBench labels TRAJECTORIES, not actions, so any per-action attack label
    would be this loader's invention.

    The corpus's judge prompt (AgentDoG ``guardrail/prompt.py``) asks for one
    integer per trajectory, "pred": 0 (safe) or 1 (unsafe), over "unsafe
    actions or unsafe decision patterns". Nothing in the released data says
    which turn failed. The ``reason`` field is prose that names two or more of
    the trajectory's own tools more often than it names one, and ATBench500 has
    no ``reason`` field at all.

    If this test starts failing, someone has attributed the trajectory verdict
    to a specific call. Show where the corpus says so before believing the
    number that results.
    """
    tasks = _load(name)
    published = _PUBLISHED[name]
    assert len(tasks) == published["total"]
    assert len({t.task_id for t in tasks}) == published["total"], (
        "duplicate task ids; half of InjecAgent turned out to be the same case "
        "twice and it was invisible until the ids were counted")

    attacks = [e for t in tasks for e in t.events if e.label is EventLabel.ATTACK]
    assert not attacks, (
        f"{len(attacks)} ATTACK events emitted; ATBench labels no action. "
        "This is the AgentThreatBench defect: 18 of 24 attack events invented."
    )

    unsafe = [t for t in tasks if t.meta["atbench_label"] == 1]
    safe = [t for t in tasks if t.meta["atbench_label"] == 0]
    assert len(unsafe) == published["unsafe"]
    assert len(safe) == published["safe"]
    # An unsafe trajectory contributes no events and must say why, rather than
    # being quietly dropped or silently counted as clean traffic.
    for task in unsafe:
        assert not task.events, task.task_id
        assert task.meta.get("uncontained_reason"), task.task_id
    for task in safe:
        assert all(e.label is EventLabel.BENIGN for e in task.events), task.task_id


# --------------------------------------------------------------------------- #
# 2. ASB / InjecAgent / ToolEmu class: containment from the tool name alone
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("name,release", [("atbench", "ATBench"),
                                          ("atbench500", "ATBench500")])
def test_grant_is_the_corpus_tool_pool_and_it_already_contains_every_call(name, release):
    """The one grant ATBench declares cannot separate its two halves.

    ``tool_used`` is the per-trajectory tool pool, and every call in the corpus
    is inside it, in the unsafe half as much as the safe half. So the naive
    tool-allowlist rung is 0.0% here, which is the mirror image of ASB, where it
    is 100% and means nothing.

    The failure this guards against is narrowing the grant to manufacture
    containment: drop one tool from the pool and the unsafe trajectory that uses
    it looks "contained" by a rung that only ever checked a name.
    """
    tasks = {t.task_id: t for t in _load(name)}
    records = _raw(release)
    from benchmarks.datasets.atbench import _RELEASES, _tool_pool

    id_key = _RELEASES[release]["id_key"]
    outside = 0
    for record in records:
        task = tasks[f"atbench-{release}-{record[id_key]}"]
        pool = set(_tool_pool(record))
        assert task.allowed_tools == pool, task.task_id
        outside += sum(1 for tool, _ in _calls(record, release) if tool not in pool)
    assert outside == 0, (
        f"{outside} calls fall outside the declared pool; if the corpus changed, "
        "re-derive the claim that the tool-allowlist rung is structurally 0%"
    )

    # And confirm it end to end: with no attack events there is nothing for any
    # rung to contain, and the ladder must not invent friction either.
    engines = build_engines(["tool-allowlist", "task-scope+binding+budget+velocity"])
    results = run_benchmark(_load(name), engines)
    for engine in engines:
        result = results[engine.name]
        assert result.n_attack == 0
        assert result.benign_blocked == 0, (
            f"{engine.name} blocked {result.benign_blocked} of the corpus's own "
            "human-audited safe calls under a mandate built from its own pool"
        )


# --------------------------------------------------------------------------- #
# 3. SLEIGHT class: a grant that is the benign side restated
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("name", ["atbench", "atbench500"])
def test_false_block_is_declared_unscoreable_and_no_boundary_is_invented(name):
    """0.00% here is arithmetic, and the loader has to say so.

    Two separate traps, both already sprung on other corpora:

    * the grant is the corpus's declared tool pool, which contains every call by
      construction, so the friction denominator cannot produce a nonzero rate;
    * filling ``authorized_args`` from the benign calls would make the binding
      rung's 0.00% a theorem in the same way.

    And no path boundary may be invented. SLEIGHT ships no mandate; our loader
    built one from the session cwd and refused 114 of 311 benign events for
    leaving a boundary that corpus never declared. ATBench likewise declares no
    path, host, recipient or workspace root.
    """
    tasks = _load(name)
    assert all(t.meta.get("false_block_unscoreable") for t in tasks)
    assert all(t.meta.get("false_block_unscoreable_reason") for t in tasks)
    for task in tasks:
        assert task.authorized_args == {}, (
            f"{task.task_id} binds arguments the corpus never authorized; that "
            "grant would be the benign side restated"
        )
        assert "allowed_paths" not in task.mandate, task.task_id
        assert "scope" not in task.mandate, task.task_id
        assert "budgets" not in task.mandate, task.task_id
        assert not task.value_tracked and not task.call_tracked, task.task_id


# --------------------------------------------------------------------------- #
# 4. AgentHarm class: a loader whose event stream carries the label
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("release,max_safe_calls,max_safe_effects,max_unsafe_effects", [
    ("ATBench", 4, 3, 12),
    ("ATBench500", 5, 1, 4),
])
def test_trajectory_length_is_a_label_proxy_so_no_rung_may_be_credited_for_it(
        release, max_safe_calls, max_safe_effects, max_unsafe_effects):
    """In ATBench the safe half is systematically shorter than the unsafe half.

    Measured on the released data: no safe ATBench trajectory makes more than 4
    tool calls or more than 3 effect actions, while unsafe trajectories run to
    22 calls and 12 effect actions. On ATBench500 total call counts overlap
    (both halves top out at 5), but the clean maximum is ONE effect action
    against four, which is the quantity a velocity cap is calibrated on.

    A velocity cap calibrated on clean traffic is therefore a length detector on
    this corpus. Under a naive attribution (every unsafe call labelled ATTACK)
    the velocity rung is the only rung that scores anything at all, 4.4% on
    ATBench, 5.2% on ATBench500, and all of it is the corpus's generation
    pipeline leaking through trajectory length, not containment. This is the
    same defect as the withdrawn +8.0 on AgentHarm, where the loader's event
    order carried the label.

    The loader's protection is that it emits no attack events, so the rung
    cannot be credited. This test pins the statistic that makes that necessary.
    """
    from agentauth.capabilities.velocity import EFFECT_VERBS

    from benchmarks.datasets._common import classify_verb

    records = _raw(release)
    safe_calls = safe_effects = 0
    unsafe_calls = unsafe_effects = 0
    for record in records:
        calls = _calls(record, release)
        effects = sum(1 for tool, _ in calls if classify_verb(tool) in EFFECT_VERBS)
        if int(record.get("label", 0)) == 1:
            unsafe_calls = max(unsafe_calls, len(calls))
            unsafe_effects = max(unsafe_effects, effects)
        else:
            safe_calls = max(safe_calls, len(calls))
            safe_effects = max(safe_effects, effects)

    assert safe_calls == max_safe_calls, (
        f"clean length ceiling moved to {safe_calls}; re-measure the velocity "
        "artifact before trusting any rate from this corpus")
    assert safe_effects == max_safe_effects
    assert unsafe_effects == max_unsafe_effects
    # The cap a velocity rung would learn is the clean maximum, and the unsafe
    # half runs past it. That gap, not containment, is what a rate would report.
    assert unsafe_effects > safe_effects, (
        "effect volume no longer separates the halves; the warning above may "
        "be stale, but check before relying on it")
    assert unsafe_calls >= safe_calls

    # The guarantee: no attack event exists for velocity to be credited with.
    name = "atbench" if release == "ATBench" else "atbench500"
    tasks = _load(name)
    assert not any(e.label is EventLabel.ATTACK for t in tasks for e in t.events)


# --------------------------------------------------------------------------- #
# 5. AgentHarm class: reading only part of the record
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("name", ["atbench", "atbench500"])
def test_the_completion_turn_is_not_a_tool_call(name):
    """``Complete{...}`` is the agent's closing message, not an action.

    A large share of ATBench's harm lives in exactly that text, the taxonomy's
    ``generation_of_harmful_offensive_content``, ``instruction_for_harmful_
    illegal_activity`` and ``provide_inaccurate_misleading_or_unverified_
    information`` classes. Turning it into an event would put content-defined
    harm on an authorization ladder, which is the AgentHarm mistake: the corpus
    grades something the action's fields do not carry.
    """
    tasks = _load(name)
    events = [e for t in tasks for e in t.events]
    assert events
    for task in tasks:
        for event in task.events:
            assert not event.tool_name.startswith(
                ("Complete", "Finish", "Answer")), event.event_id
            assert event.resource == f"mcp:tool:{event.tool_name}"
            assert event.tool_name in task.allowed_tools, event.event_id


# --------------------------------------------------------------------------- #
# 6. RedCode/protected-zone class: a target parsed out of something that is not one
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("name", ["atbench", "atbench500"])
def test_url_arguments_never_forge_a_filesystem_target(name):
    """Only ``net:<host>`` is emitted, and never a URL's path.

    An earlier pass parsed any slash-separated substring as a path. That made
    ``https://discord.com/api/webhooks/9988776655/xYz_AbC_SecretToken`` look like
    a credential file, which the global protected-zone floor then "contained"
    three times in unsafe trajectories and, worse, twice in the corpus's own
    SAFE half, where the same rule manufactured false blocks. Under the current
    rule the protected-zone floor fires on zero ATBench actions, which is the
    honest reading: this corpus has no filesystem targets.
    """
    from agentauth.capabilities.hardening.protected_zones import is_protected_path

    tasks = _load(name)
    paths = [e.path for t in tasks for e in t.events if e.path]
    assert paths, "no destinations parsed at all; the URL rule has stopped working"
    for path in paths:
        assert path.startswith("net:"), path
        assert "/" not in path, f"{path} carries a URL path, not a host"
        assert not is_protected_path(path), path


# --------------------------------------------------------------------------- #
# 7. AgentHarm class: a value silently dropped instead of counted
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("name,expected", [("atbench", 6), ("atbench500", 0)])
def test_calls_whose_arguments_are_not_an_object_are_counted_not_swallowed(name, expected):
    """Six ATBench calls carry a bare string where an argument object belongs.

    ATBench500 has none: its one odd call simply omits ``arguments``, which
    drops nothing, and the two cases are counted separately on purpose.

    The loader normalizes them to ``{}``, which drops a value. That is fine only
    while it is *recorded*: AgentHarm's 6.3% was reported for months as an
    information-theoretic ceiling when it was a loader reading one field and
    ignoring the rest. Anyone building an argument-level arm on this corpus needs
    to know these exist before they trust a denominator.
    """
    tasks = _load(name)
    total = sum(t.meta["n_calls_with_nondict_arguments"] for t in tasks)
    assert total == expected, (
        f"{total} calls have non-object arguments, expected {expected}; the "
        "corpus changed shape, re-check what the loader is dropping")


# --------------------------------------------------------------------------- #
# 8. InjecAgent class: the same case counted twice
# --------------------------------------------------------------------------- #
def test_atbench500_is_a_separate_release_not_a_subset():
    """Half of InjecAgent turned out to be the same case twice; this checks the
    two ATBench releases are not the same corpus pooled under two names.

    They are not: ATBench500 is the legacy AgentDoG release, ATBench the later
    1,000-case one, and no first user message is shared between them. Reporting
    a pooled 1,500 would be double counting only if they overlapped: they do
    not, but they still may not be pooled as one rate, because their schemas
    and their safe/unsafe balances differ.
    """
    from benchmarks.datasets.atbench import _RELEASES, _turns

    def first_user(record, release):
        key = _RELEASES[release]["contents_key"]
        return next((str(t.get("content", "")) for t in _turns(record, key)
                     if t.get("role") == "user"), "")

    big = {first_user(r, "ATBench") for r in _raw("ATBench")}
    small = {first_user(r, "ATBench500") for r in _raw("ATBench500")}
    assert len(big & small) == 0, (
        f"{len(big & small)} trajectories shared between the releases; they "
        "would be double counted in any pooled figure")
    # ATBench500 has no per-trajectory rationale at all, which is the second
    # reason no attack attribution is possible there.
    assert all("reason" not in r for r in _raw("ATBench500"))
    assert all(r.get("reason") for r in _raw("ATBench") if r["label"] == 1)
