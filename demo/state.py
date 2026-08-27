"""The event stream and the pure reducer every renderer reads from.

Keeping the reducer pure is what makes the demo testable: feed it canned events,
assert the resulting state, no terminal and no sandbox required. It is also what
keeps the two renderers honest, `plain.py` and `tui.py` read `AppState` and
nothing else, hold no parsing logic of their own, and therefore cannot disagree
about what happened.

TWO FORGERY BOUNDARIES, ENFORCED HERE RATHER THAN IN A RENDERER:

1. A policy line only becomes a verdict if it arrived on iVisor's trace fd
   (`verified=True`). Guest fds are virtualized and only 0/1/2 exist, so a host
   fd >= 3 is unreachable from inside the guest.
2. A policy-shaped line the guest printed to its own stdout/stderr increments
   `forgery_attempts`, renders on the AGENT side, and can never satisfy or
   falsify an expectation.

Because there is exactly one code path into `state.verdicts` and it requires
`verified`, a renderer bug cannot merge the agent's account with the evidence.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

from agentauth.capabilities.sandbox.verdicts import (
    POLICY_PREFIX,
    PolicyEvent,
    Verdict,
    parse_policy_line,
)

# --------------------------------------------------------------------------- #
# Events, the one ordered stream. Recording is just serializing this.
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class Event:
    at_ms: int = 0

    @property
    def kind(self) -> str:
        return type(self).__name__

    def to_dict(self) -> dict[str, Any]:
        out = {"kind": self.kind}
        for key, value in vars(self).items():
            out[key] = list(value) if isinstance(value, tuple) else value
        return out


@dataclass(frozen=True)
class AgentSaid(Event):
    text: str = ""


@dataclass(frozen=True)
class AgentToolCall(Event):
    step: int = 0
    call_id: str = ""
    tool: str = ""
    args: dict = field(default_factory=dict)


@dataclass(frozen=True)
class AgentToolResult(Event):
    step: int = 0
    call_id: str = ""
    text: str = ""
    ok: bool = True


@dataclass(frozen=True)
class BrokerDecided(Event):
    step: int = 0
    tool: str = ""
    outcome: str = ""            # ALLOW | DENY | STEP_UP
    layer: str = ""
    reasons: tuple[str, ...] = ()


@dataclass(frozen=True)
class VerdictLine(Event):
    """One `ivisor: policy ...` line. `verified` is the whole trust question."""

    step: int = 0
    raw: str = ""
    verified: bool = False


@dataclass(frozen=True)
class GuestOutput(Event):
    step: int = 0
    stream: str = "stdout"
    text: str = ""


@dataclass(frozen=True)
class EpochOpened(Event):
    """A policy recompile. `digest` is the identity of the compiled policy."""

    index: int = 0
    level: int = 0
    level_name: str = ""
    why: tuple[str, ...] = ()
    digest: str = ""
    allow: tuple[str, ...] = ()
    staged: int = 0
    carry_forward: tuple[str, ...] = ()
    enforced_at: dict = field(default_factory=dict)
    config_text: str = ""
    changed: bool = True         # False => same capabilities, digest unchanged


@dataclass(frozen=True)
class Note(Event):
    text: str = ""


@dataclass(frozen=True)
class RunEnd(Event):
    exit_kind: str = ""
    code: int | None = None


_EVENT_TYPES = {cls.__name__: cls for cls in (
    AgentSaid, AgentToolCall, AgentToolResult, BrokerDecided, VerdictLine,
    GuestOutput, EpochOpened, Note, RunEnd)}

_TUPLE_FIELDS = {"why", "allow", "carry_forward", "reasons"}


def event_from_dict(raw: dict) -> Event:
    """Rebuild an event from its recorded form. Unknown kinds raise."""
    data = dict(raw)
    cls = _EVENT_TYPES[data.pop("kind")]
    for key in _TUPLE_FIELDS & set(data):
        data[key] = tuple(data[key])
    return cls(**data)


# --------------------------------------------------------------------------- #
# Rendered lines, what the panes hold
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class Rendered:
    at_ms: int
    event: PolicyEvent

    @property
    def verdict(self) -> str:
        return self.event.verdict.value

    def line(self) -> str:
        return self.event.summary()


@dataclass(frozen=True)
class AgentLine:
    at_ms: int
    kind: str                     # said | tool_call | tool_result | blocked | forged
    text: str


@dataclass(frozen=True)
class BrokerLine:
    at_ms: int
    step: int
    tool: str
    outcome: str
    layer: str
    reasons: tuple[str, ...]


@dataclass
class EpochLine:
    # Mutable: `allows`/`denies` accumulate as verdicts arrive under this epoch,
    # which is what lets the rail show that a destination was admitted under one
    # policy and refused under the next.
    index: int
    level: int
    level_name: str
    why: tuple[str, ...]
    digest: str
    allow: tuple[str, ...]
    staged: int
    carry_forward: tuple[str, ...]
    enforced_at: dict
    config_text: str
    changed: bool
    allows: int = 0
    denies: int = 0


@dataclass
class Counters:
    allow: int = 0
    deny: int = 0
    miss: int = 0
    broker_allow: int = 0
    broker_deny: int = 0
    broker_step_up: int = 0


# --------------------------------------------------------------------------- #
# State
# --------------------------------------------------------------------------- #


@dataclass
class AppState:
    # LEFT, the agent's own account. Untrusted by construction.
    agent: list[AgentLine] = field(default_factory=list)

    # RIGHT, verified only. Nothing the agent authored can reach these.
    verdicts: list[Rendered] = field(default_factory=list)
    watched_misses: list[Rendered] = field(default_factory=list)

    # Guest-authored policy-shaped lines: kept, counted, never evidence.
    claims: list[Rendered] = field(default_factory=list)
    forgery_attempts: int = 0
    raw: list[str] = field(default_factory=list)

    broker: list[BrokerLine] = field(default_factory=list)
    epochs: list[EpochLine] = field(default_factory=list)
    counters: Counters = field(default_factory=Counters)

    level: int = 0
    level_name: str = "BASELINE"
    exit_kind: str | None = None
    exit_code: int | None = None
    finished: bool = False
    steps: int = 0

    # Configuration the reducer needs, carried on the state so `apply` stays a
    # two-argument pure function.
    watch: tuple[str, ...] = ()
    expectations: list = field(default_factory=list)

    def all_met(self) -> bool:
        return all(e.met for e in self.expectations)

    def unmet(self) -> list:
        return [e for e in self.expectations if not e.met]

    def reconciliation(self) -> tuple[int, int, int]:
        """(tool calls the agent claims, broker decisions, verified verdicts).

        A gap between the first and the last is the point of the whole display:
        the agent narrates a handful of calls; the host recorded what actually
        reached the kernel.
        """
        claimed = sum(1 for a in self.agent if a.kind == "tool_call")
        return claimed, len(self.broker), len(self.verdicts)

    def current_epoch(self) -> EpochLine | None:
        return self.epochs[-1] if self.epochs else None


# --------------------------------------------------------------------------- #
# The reducer
# --------------------------------------------------------------------------- #


def apply(state: AppState, ev: Event) -> None:
    """Fold one event into the state. Deterministic: no clock, no I/O."""
    if isinstance(ev, VerdictLine):
        _apply_verdict(state, ev)
    elif isinstance(ev, GuestOutput):
        _apply_guest_output(state, ev)
    elif isinstance(ev, AgentSaid):
        state.agent.append(AgentLine(ev.at_ms, "said", ev.text))
        for expect in state.expectations:
            expect.on_agent(ev.text)
    elif isinstance(ev, AgentToolCall):
        state.agent.append(AgentLine(
            ev.at_ms, "tool_call", f"{ev.tool}({_render_args(ev.args)})"))
        state.steps = max(state.steps, ev.step + 1)
    elif isinstance(ev, AgentToolResult):
        kind = "tool_result" if ev.ok else "blocked"
        state.agent.append(AgentLine(ev.at_ms, kind, _clip(ev.text)))
    elif isinstance(ev, BrokerDecided):
        _apply_broker(state, ev)
    elif isinstance(ev, EpochOpened):
        _apply_epoch(state, ev)
    elif isinstance(ev, Note):
        state.agent.append(AgentLine(ev.at_ms, "note", ev.text))
    elif isinstance(ev, RunEnd):
        state.exit_kind, state.exit_code = ev.exit_kind, ev.code
        state.finished = True


def _apply_verdict(state: AppState, ev: VerdictLine) -> None:
    parsed = parse_policy_line(ev.raw, verified=ev.verified, at_ms=ev.at_ms)
    if parsed is None:
        state.raw.append(ev.raw)
        return
    if not parsed.verified:
        # Well-formed, and worthless: the guest wrote it. Counted so the display
        # can show that a forgery was attempted, never scored.
        state.forgery_attempts += 1
        state.claims.append(Rendered(ev.at_ms, parsed))
        state.agent.append(AgentLine(ev.at_ms, "forged", parsed.summary()))
        return

    rendered = Rendered(ev.at_ms, parsed)
    if parsed.verdict is Verdict.MISS:
        state.counters.miss += 1
        # A miss is not a refusal. CPython startup alone probes hundreds of
        # absent paths, so only watched subjects are surfaced.
        if _watched(state, parsed):
            state.watched_misses.append(rendered)
    else:
        # Everything is counted; only high-rate noise is held back from the
        # pane. A DENIAL is never noise, and neither is anything on the network,
        # so the filter applies solely to permitted filesystem reads, of which
        # a CPython start makes hundreds before the agent does anything at all.
        if _displayable(state, parsed):
            state.verdicts.append(rendered)
        if parsed.verdict is Verdict.ALLOW:
            state.counters.allow += 1
        else:
            state.counters.deny += 1
        epoch = state.current_epoch()
        if epoch is not None:
            if parsed.verdict is Verdict.ALLOW:
                epoch.allows += 1
            else:
                epoch.denies += 1

    for expect in state.expectations:
        expect.on_verdict(parsed, state)


def _apply_guest_output(state: AppState, ev: GuestOutput) -> None:
    for line in ev.text.splitlines():
        if POLICY_PREFIX in line:
            parsed = parse_policy_line(line.strip(), verified=False)
            if parsed is not None:
                state.forgery_attempts += 1
                state.claims.append(Rendered(ev.at_ms, parsed))
                state.agent.append(
                    AgentLine(ev.at_ms, "forged", parsed.summary()))
                continue
        if line.strip():
            state.raw.append(line)


def _apply_broker(state: AppState, ev: BrokerDecided) -> None:
    state.broker.append(BrokerLine(ev.at_ms, ev.step, ev.tool, ev.outcome,
                                   ev.layer, tuple(ev.reasons)))
    if ev.outcome == "ALLOW":
        state.counters.broker_allow += 1
    elif ev.outcome == "DENY":
        state.counters.broker_deny += 1
    else:
        state.counters.broker_step_up += 1
    for expect in state.expectations:
        expect.on_broker(ev.outcome, ev.tool, state)


def _apply_epoch(state: AppState, ev: EpochOpened) -> None:
    state.level, state.level_name = ev.level, ev.level_name
    state.epochs.append(EpochLine(
        index=ev.index, level=ev.level, level_name=ev.level_name,
        why=tuple(ev.why), digest=ev.digest, allow=tuple(ev.allow),
        staged=ev.staged, carry_forward=tuple(ev.carry_forward),
        enforced_at=dict(ev.enforced_at), config_text=ev.config_text,
        changed=ev.changed))
    for expect in state.expectations:
        expect.on_epoch(ev.level, state)


def _watched(state: AppState, parsed: PolicyEvent) -> bool:
    subject = parsed.subject()
    return any(needle in subject for needle in state.watch)


def _displayable(state: AppState, parsed: PolicyEvent) -> bool:
    """Whether a non-miss verdict belongs in the pane.

    Denials and network verdicts always do. A permitted filesystem read only
    does if it names a watched subject, because the guest's interpreter reads
    hundreds of library files before the agent's first instruction and those
    would bury the handful of lines that carry the argument.
    """
    if parsed.verdict is not Verdict.ALLOW:
        return True
    if not parsed.event.startswith("fs."):
        return True
    return not state.watch or _watched(state, parsed)


def _render_args(args: dict) -> str:
    return ", ".join(f"{k}={_clip(str(v), 40)}" for k, v in args.items())


def _clip(text: str, limit: int = 90) -> str:
    flat = " ".join(str(text).split())
    return flat if len(flat) <= limit else flat[:limit - 1] + "…"


def dumps_event(ev: Event) -> str:
    return json.dumps(ev.to_dict(), sort_keys=True)
