"""AgentDojo loader, real prompt-injection corpus mapped to BenchmarkTask.

AgentDojo (ETH SPY Lab) ships suites (banking, slack, travel, workspace) where
each *user task* has a ground-truth tool-call sequence (the legitimate steps)
and each *injection task* has its own ground-truth sequence (the attacker's
intended steps). We do NOT need to run an LLM: the benchmark is a deterministic
replay of these labeled ground-truth calls through Clay Seal enforcement.

Mapping, per (user_task x injection_task) pair:
  - benign events  = user_task ground-truth calls;
  - attack events  = injection_task ground-truth calls;
  - authorization  = derived from the benign call set (the tools/actions/args
    the user legitimately exercised), so anything the injection needs beyond
    that surface must be granted separately or be contained.

AgentDojo's Python API has shifted across releases, so suite discovery and
ground-truth extraction each try a few known call conventions and fail loudly
with an actionable message. Validated end-to-end on the Azure VM run (see
``benchmarks/azure/run_benchmark.sh``); install with
``pip install 'clayseal[benchmarks]'``.
"""
from __future__ import annotations

from typing import Any

from benchmarks.core.events import BenchmarkEvent, BenchmarkTask, EventLabel

# Verb -> canonical action, so capability/scope checks see a stable action space.
_WRITE_VERBS = ("send", "create", "add", "update", "write", "delete", "transfer",
                "post", "schedule", "share", "book", "pay", "cancel")
_READ_VERBS = ("get", "read", "list", "search", "find", "view", "show")

# Monetary tools whose `amount` argument accumulates against a value ceiling.
# Annotating these lets the stateful budget rung (and the fragmented-overspend
# attack synthesis) exercise aggregate/sub-threshold-splitting on real banking
# transactions, which per-call engines structurally cannot see.
_MONEY_TOOLS = ("send_money", "schedule_transaction",
                "update_scheduled_transaction", "pay", "transfer_money")

# AgentDojo benchmark versions to try, newest first (confirmed against 0.1.35).
_BENCHMARK_VERSIONS = ("v1.2.2", "v1.2.1", "v1.2", "v1.1.2", "v1.1", "v1")


def _action_for(tool_name: str) -> str:
    lowered = tool_name.lower()
    for verb in _WRITE_VERBS:
        if lowered.startswith(verb) or f"_{verb}" in lowered:
            return "transfer" if verb in ("transfer", "pay") else "write"
    for verb in _READ_VERBS:
        if lowered.startswith(verb) or f"_{verb}" in lowered:
            return "read"
    return "call"


def _path_from_args(args: dict[str, Any]) -> str | None:
    for key in ("file_path", "path", "filename", "file"):
        value = args.get(key)
        if isinstance(value, str) and value:
            return value
    return None


def _call_to_event(call: Any, label: EventLabel, event_id: str) -> BenchmarkEvent:
    tool_name = str(getattr(call, "function", None) or getattr(call, "name", ""))
    raw_args = getattr(call, "args", None)
    args = dict(raw_args) if isinstance(raw_args, dict) else {}
    return BenchmarkEvent(
        event_id=event_id,
        tool_name=tool_name,
        resource=f"mcp:tool:{tool_name}",
        action=_action_for(tool_name),
        path=_path_from_args(args),
        args=args,
        label=label,
        meta={"source": "agentdojo"},
    )


def _load_suites() -> dict[str, Any]:
    """Return ``{suite_name: suite}`` across AgentDojo API variants."""
    try:
        import agentdojo  # noqa: F401
    except ImportError as exc:
        raise RuntimeError(
            "agentdojo is not installed. Install the benchmark extra: "
            "pip install 'clayseal[benchmarks]'."
        ) from exc
    # API confirmed against agentdojo 0.1.35 (benchmark versions up to v1.2.2):
    #   get_suites(version) -> dict[str, TaskSuite]
    # Prefer the newest benchmark version, falling back to older pins.
    from agentdojo.task_suite.load_suites import get_suites  # type: ignore

    for version in _BENCHMARK_VERSIONS:
        try:
            suites = get_suites(version)
        except KeyError:
            continue
        if suites:
            return dict(suites)
    raise RuntimeError(
        "agentdojo is installed but exposes none of the expected benchmark "
        f"versions {_BENCHMARK_VERSIONS}. Update _BENCHMARK_VERSIONS in "
        "benchmarks/datasets/agentdojo.py to a version this build ships."
    )


def _ground_truth(task: Any, environment: Any) -> list[Any]:
    """Return a task's ground-truth ``FunctionCall`` list.

    ``BaseUserTask.ground_truth`` / ``BaseInjectionTask.ground_truth`` take the
    pre-environment and return ``list[FunctionCall]`` (each has ``.function`` and
    ``.args``). A task whose ground truth raises on the clean environment is
    skipped rather than aborting the run.
    """
    gt = getattr(task, "ground_truth", None)
    if gt is None:
        return []
    try:
        result = gt(environment)
        return list(result) if result else []
    except Exception:  # noqa: BLE001 - task can't produce a trace; skip it
        return []


def _value_annotation(suite_name: str,
                      benign: list[BenchmarkEvent]) -> tuple[dict, list[dict]]:
    """For a monetary suite, derive `value_tracked` + a usd budget from the
    benign spend. The ceiling is set above the legitimate total so benign never
    false-blocks, while a fragmented-overspend split (2 x 0.6*ceiling) exceeds
    it. Returns ({} , []) for non-monetary suites, leaving them unchanged."""
    if suite_name != "banking":
        return {}, []
    money = [e for e in benign if e.tool_name in _MONEY_TOOLS]
    tools = {e.tool_name for e in money} or {"send_money"}
    value_tracked = {t: ("amount", "usd_payout") for t in tools}
    benign_sum = sum(
        float(e.args.get("amount") or 0.0)
        for e in money if isinstance(e.args, dict)
    )
    limit = max(benign_sum * 1.5, 100.0)
    budgets = [{"budget_id": "usd_payout", "budget_type": "usd_limit",
                "unit": "USD", "limit": limit, "remaining": limit}]
    return value_tracked, budgets


def _authorization_from(benign: list[BenchmarkEvent],
                        suite_name: str = "") -> dict[str, Any]:
    allowed_tools = {e.tool_name for e in benign}
    resources = sorted({e.resource for e in benign})
    actions = sorted({e.action for e in benign})
    capabilities = [
        {"resource": r, "action": a}
        for r, a in sorted({(e.resource, e.action) for e in benign})
    ]
    authorized_args: dict[str, list[dict]] = {}
    for e in benign:
        if e.args:
            authorized_args.setdefault(e.tool_name, []).append(dict(e.args))
    value_tracked, budgets = _value_annotation(suite_name, benign)
    mandate = {
        "grant_id": "agentdojo-grant",
        "issuer": "did:clayseal:agentdojo",
        "issued_at": "2026-07-21T00:00:00+00:00",
        "expires_at": "2026-07-22T00:00:00+00:00",
        "allowed_actions": actions,
        "allowed_resources": resources,
    }
    if budgets:
        mandate["budgets"] = budgets
    return {
        "allowed_tools": allowed_tools,
        "capabilities": capabilities,
        "authorized_args": authorized_args,
        "value_tracked": value_tracked,
        "mandate": mandate,
    }


class AgentDojoLoader:
    name = "agentdojo"

    def __init__(self, *, suites: list[str] | None = None,
                 injections_per_task: int = 1) -> None:
        self._suite_filter = set(suites) if suites else None
        self._injections_per_task = max(1, injections_per_task)

    def load(self, *, limit: int | None = None) -> list[BenchmarkTask]:
        suites = _load_suites()
        tasks: list[BenchmarkTask] = []
        for suite_name, suite in suites.items():
            if self._suite_filter and suite_name not in self._suite_filter:
                continue
            environment = _make_environment(suite)
            user_tasks = _items(getattr(suite, "user_tasks", {}))
            injection_tasks = _items(getattr(suite, "injection_tasks", {}))
            for user_id, user_task in user_tasks:
                benign = [
                    _call_to_event(call, EventLabel.BENIGN, f"{suite_name}:{user_id}:b{i}")
                    for i, call in enumerate(_ground_truth(user_task, environment))
                ]
                if not benign:
                    continue
                auth = _authorization_from(benign, suite_name)
                for inj_id, inj_task in injection_tasks[: self._injections_per_task]:
                    attack = [
                        _call_to_event(call, EventLabel.ATTACK,
                                       f"{suite_name}:{user_id}:{inj_id}:a{i}")
                        for i, call in enumerate(_ground_truth(inj_task, environment))
                    ]
                    if not attack:
                        continue
                    tasks.append(BenchmarkTask(
                        task_id=f"{suite_name}:{user_id}:{inj_id}",
                        summary=str(getattr(user_task, "PROMPT", user_id)),
                        events=benign + attack,
                        meta={
                            "suite": suite_name,
                            "injection": inj_id,
                            "injection_goal": str(getattr(inj_task, "GOAL", "")),
                        },
                        **auth,
                    ))
                    if limit and len(tasks) >= limit:
                        return tasks
        return tasks


def _items(collection: Any) -> list[tuple[str, Any]]:
    if isinstance(collection, dict):
        return list(collection.items())
    return [(str(getattr(t, "ID", i)), t) for i, t in enumerate(collection or [])]


def _make_environment(suite: Any) -> Any:
    """Fresh, un-injected pre-environment for ground-truth extraction.

    ``TaskSuite.load_and_inject_default_environment({})`` returns a clean env of
    the suite's ``environment_type``; the empty injection map means no attacker
    text is placed, which is what we want when reading deterministic traces.
    """
    try:
        return suite.load_and_inject_default_environment({})
    except Exception:  # noqa: BLE001 - extraction tolerates a missing env
        return None
