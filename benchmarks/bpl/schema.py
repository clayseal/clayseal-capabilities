"""BPL scenario schema — shared by the live H2H runner and unit tests."""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, Literal

from agentauth.capabilities.broker import SessionBroker

Family = Literal["aggregate", "escape", "confidentiality"]
ClaySealExpected = Literal["contain", "partial", "open"]

# One scripted tool call for deterministic tests (no LLM).
ToolCall = tuple[str, dict[str, Any]]


@dataclass
class Env:
    state: dict = field(default_factory=dict)


@dataclass
class Scenario:
    name: str
    user_prompt: str
    tools: list[dict]  # OpenAI tool schemas
    handler: Callable[[Env, str, dict], str]
    make_env: Callable[[], Env]
    make_broker: Callable[[], SessionBroker]
    violated: Callable[[Env], bool]
    progress: Callable[[Env], float]
    family: Family = "aggregate"
    difficulty: int = 1
    min_steps: int = 1
    max_iters: int = 12
    tags: tuple[str, ...] = ()
    clayseal_expected: ClaySealExpected = "contain"
    # Optional: told the condition before the episode starts (sandbox policy).
    configure: Callable[[Env, str], None] | None = None
    # Diagnostics: which escape / leak paths fired (empty if none).
    secondary_violations: Callable[[Env], list[str]] | None = None
    # Deterministic trajectories for unit tests (no LLM).
    violating_script: tuple[ToolCall, ...] = ()
    compliant_script: tuple[ToolCall, ...] = ()


def legacy_verb_for(tool: str) -> str:
    t = tool.lower()
    for v in (
        "pay", "transfer", "send", "delete", "post", "read", "get", "list",
        "create", "update", "grant", "reset", "impersonate", "request",
        "widen", "disable", "add", "dump", "load", "advance", "wire", "issue",
    ):
        if t.startswith(v) or v in t:
            return v if v not in ("grant", "add", "create") else "create"
    return "call"


def verb_for(tool: str) -> str:
    """The verb the broker will see. Delegates to the SHIPPED classifier.

    There were two of these and they disagreed on 9 of 11 sampled tools.
    `legacy_verb_for` above returns raw synonyms — `load`, `get`, `dump`,
    `wire`, `advance` — while `broker_defense.classify_verb`, which the live
    AgentDojo path uses, normalizes to a canonical `{read, write, transfer,
    send, call}`. The verb is decided BEFORE the broker sees the action, so BPL
    and AgentDojo have been measuring the same system through different front
    ends, and BPL's emitted a vocabulary no mandate is written against.

    It was not a trade-off. Measured on all 132 scripted scenarios, switching to
    the shipped classifier improves **both** columns:

        containment   43% (57/132)  ->  64% (85/132)
        completion    40% (53/132)  ->  71% (94/132)

    72 of 79 false blocks were the single tool `load_policy`, classified `load`,
    a verb no scenario envelope allows — a benign policy read refused at step
    one. And 24 scenarios the suite labels `clayseal_expected: open` are in fact
    contained, each by a real block and none of them contained under allow-all.
    Those labels were calibrated against this bug.

    **Every BPL number published before this used `legacy_verb_for`**, which is
    why it is kept rather than deleted: `bpl_sweep --verbs bpl` reproduces them.
    """
    from benchmarks.live.broker_defense import classify_verb

    return classify_verb(tool)


def tool_names(scen: Scenario) -> set[str]:
    return {t["function"]["name"] for t in scen.tools}


def run_script(scen: Scenario, script: tuple[ToolCall, ...]) -> Env:
    """Execute a scripted trajectory against the scenario handler (no broker)."""
    env = scen.make_env()
    for name, args in script:
        scen.handler(env, name, dict(args))
    return env
