"""Streaming line renderer, stdlib only, and the demo's regression gate.

Shares the reducer with the TUI so the two can never disagree about what
happened: this module decides nothing, parses nothing, and counts nothing. It
prints what the reducer already worked out, then returns 0 if every expectation
holds and 1 otherwise, which is what makes the demo gate-able in CI rather than
just watchable.
"""
from __future__ import annotations

import sys
from dataclasses import dataclass

from demo.state import (
    AgentSaid,
    AgentToolCall,
    AgentToolResult,
    AppState,
    BrokerDecided,
    EpochOpened,
    Event,
    GuestOutput,
    Note,
    RunEnd,
    VerdictLine,
    apply,
)

RESET = "\033[0m"
DIM = "\033[2m"
BOLD = "\033[1m"
RED = "\033[31m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
BLUE = "\033[34m"
CYAN = "\033[36m"


@dataclass
class PlainRenderer:
    state: AppState
    color: bool = True
    stream: object = None

    def __post_init__(self) -> None:
        self.stream = self.stream or sys.stdout
        self._t0: int | None = None

    # -- colour helpers ---------------------------------------------------- #
    def _c(self, text: str, code: str) -> str:
        return f"{code}{text}{RESET}" if self.color else text

    def _emit(self, text: str) -> None:
        print(text, file=self.stream, flush=True)

    def _clock(self, at_ms: int) -> str:
        if self._t0 is None:
            self._t0 = at_ms
        return f"{(at_ms - self._t0) / 1000:6.2f}s"

    # -- lifecycle --------------------------------------------------------- #
    def header(self, scen, provider: str, model: str) -> None:
        self._emit(self._c(f"=== {scen.title} ===", BOLD))
        for line in _wrap(scen.blurb, 78):
            self._emit(self._c(f"    {line}", DIM))
        self._emit(self._c(f"    scenario={scen.name} provider={provider}"
                           f"{f' model={model}' if model else ''}", DIM))
        self._emit("")

    def on_event(self, ev: Event) -> None:
        """Fold, then print. The reducer runs first so the line reflects state."""
        apply(self.state, ev)
        line = self._line(ev)
        if line:
            self._emit(line)

    def _line(self, ev: Event) -> str | None:
        clock = self._clock(ev.at_ms)
        if isinstance(ev, EpochOpened):
            return self._epoch_lines(clock, ev)
        if isinstance(ev, AgentToolCall):
            call = self.state.agent[-1].text
            return f"{clock} {self._c('[agent]', CYAN)}  {call}"
        if isinstance(ev, AgentToolResult):
            body = self.state.agent[-1].text
            colour = CYAN if ev.ok else YELLOW
            return f"{clock} {self._c('[agent]', colour)}  -> {body}"
        if isinstance(ev, AgentSaid):
            return f"{clock} {self._c('[agent]', CYAN)}  \"{self.state.agent[-1].text}\""
        if isinstance(ev, BrokerDecided):
            colour = GREEN if ev.outcome == "ALLOW" else RED
            reasons = f"  {'; '.join(ev.reasons)}" if ev.reasons else ""
            return (f"{clock} {self._c('[broker]', colour)} "
                    f"{ev.outcome:<7} {ev.tool}{self._c(reasons, DIM)}")
        if isinstance(ev, VerdictLine):
            return self._verdict_line(clock, ev)
        if isinstance(ev, GuestOutput):
            return None                      # kept in state.raw, not streamed
        if isinstance(ev, Note):
            return f"{clock} {self._c('[demo]', BLUE)}   {ev.text}"
        if isinstance(ev, RunEnd):
            return f"{clock} {self._c('[demo]', BLUE)}   run {ev.exit_kind}"
        return None

    def _verdict_line(self, clock: str, ev: VerdictLine) -> str | None:
        if not ev.verified:
            # A guest-authored claim. Shown on the agent's side, never scored.
            claim = self.state.claims[-1] if self.state.claims else None
            if claim is None:
                return None
            return (f"{clock} {self._c('[agent]', YELLOW)}  "
                    f"{self._c('forged verdict, not counted:', YELLOW)} "
                    f"{claim.line()}")
        if not self.state.verdicts or self.state.verdicts[-1].at_ms != ev.at_ms:
            # A miss, or an unparseable line: neither is a refusal.
            if self.state.watched_misses and self.state.watched_misses[-1].at_ms == ev.at_ms:
                miss = self.state.watched_misses[-1]
                return (f"{clock} {self._c('[host]', DIM)}   "
                        f"{self._c('miss ', DIM)} {miss.event.event} "
                        f"{miss.event.subject()}  "
                        f"{self._c('(absent, not refused)', DIM)}")
            return None
        rendered = self.state.verdicts[-1]
        deny = rendered.verdict == "deny"
        label = self._c("DENY ", RED) if deny else self._c("allow", GREEN)
        return (f"{clock} {self._c('[host]', BOLD)}   {label} "
                f"{rendered.event.event} {rendered.event.subject()}"
                f"{self._c(_reason(rendered), DIM)}")

    def _epoch_lines(self, clock: str, ev: EpochOpened) -> str:
        head = (f"{clock} {self._c(f'[epoch {ev.index}]', BOLD)} "
                f"{ev.level_name:<11} {ev.digest[:6]}")
        if not ev.changed:
            # The visible proof that exposure alone cost the agent nothing.
            head += self._c("  (digest unchanged, noticed, nothing revoked)", DIM)
            return head
        allow = ",".join(ev.allow) or "(none)"
        head += f"  allow=[{allow}]"
        if ev.staged:
            head += f" staged={ev.staged}"
        for reason in ev.why:
            head += "\n" + self._c(f"         why: {reason}", YELLOW)
        return head

    # -- summary ----------------------------------------------------------- #
    def summary(self) -> int:
        state = self.state
        self._emit("")
        claimed, brokered, verified = state.reconciliation()
        self._emit(self._c("reconciliation", BOLD))
        self._emit(f"  agent claimed {claimed} tool call(s); "
                   f"broker decided {brokered}; host recorded {verified} verdict(s)")
        if state.forgery_attempts:
            self._emit(self._c(
                f"  {state.forgery_attempts} forged verdict line(s) from the guest, "
                "none counted", YELLOW))

        self._emit("")
        self._emit(self._c("policy epochs", BOLD))
        for epoch in state.epochs:
            allow = ",".join(epoch.allow) or "(none)"
            note = "" if epoch.changed else "  (unchanged)"
            self._emit(f"  #{epoch.index} {epoch.level_name:<11} {epoch.digest[:6]}"
                       f"  allow=[{allow}]  {epoch.allows} allow / {epoch.denies} deny"
                       f"{note}")
            for reason in epoch.why:
                self._emit(self._c(f"       why: {reason}", DIM))

        self._emit("")
        self._emit(self._c("expectations", BOLD))
        for expect in state.expectations:
            mark = self._c("[x]", GREEN) if expect.met else self._c("[ ]", YELLOW)
            self._emit(f"  {mark} {expect.describe()}")
            if not expect.met and expect.explain():
                self._emit(self._c(f"      {expect.explain()}", DIM))

        counters = state.counters
        self._emit("")
        self._emit(f"{counters.allow} allow · {counters.deny} deny · "
                   f"{counters.miss} miss · {state.forgery_attempts} forgery attempt(s)")

        if state.all_met():
            return 0
        self._emit(self._c(
            "\nsome expectations were not met, with a live model this can simply "
            "mean it declined the task; try --provider mock", YELLOW))
        return 1


def _reason(rendered) -> str:
    event = rendered.event
    for key in ("reason", "errno", "status"):
        value = event.get(key)
        if value:
            return f"  ({value})"
    return ""


def _wrap(text: str, width: int) -> list[str]:
    words, lines, current = text.split(), [], ""
    for word in words:
        if len(current) + len(word) + 1 > width:
            lines.append(current)
            current = word
        else:
            current = f"{current} {word}".strip()
    if current:
        lines.append(current)
    return lines
