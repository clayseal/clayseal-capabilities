"""The live two-pane view. The only module in the demo that imports `rich`.

THE TWO PANES ARE NEVER MERGED, and that is structural rather than stylistic.
The left pane renders `state.agent`; the right renders `state.verdicts`. The only
path into `state.verdicts` requires `verified=True` (see `state._apply_verdict`),
so a policy-shaped line the guest printed lands on the LEFT, marked as a forgery
attempt. A rendering bug cannot merge the two, because this module has nothing
to merge and no parsing of its own, every decision was already made by the
reducer that `--plain` also uses.

The epoch rail is the third element and never scrolls away: it is where the
demo's argument actually appears, as a digest that stays the same when the agent
merely reads something suspicious and changes when it acts on it.
"""
from __future__ import annotations

import queue
import threading
import traceback
from dataclasses import dataclass, field

from rich.console import Console
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from demo.state import AppState, Event, apply

PANES = ("verdicts", "broker", "config", "audit", "raw")
_LEVEL_STYLE = {"BASELINE": "green", "SUSPECT": "yellow",
                "CONTAINED": "dark_orange", "QUARANTINED": "red"}


@dataclass
class TuiState:
    pane: str = "verdicts"
    follow: bool = True
    quit: bool = False
    keys: queue.Queue = field(default_factory=queue.Queue)


def _agent_pane(state: AppState) -> Panel:
    body = Text()
    for line in state.agent[-200:]:
        if line.kind == "tool_call":
            body.append("> ", "bold cyan")
            body.append(line.text + "\n", "cyan")
        elif line.kind == "tool_result":
            body.append("  " + line.text + "\n", "grey62")
        elif line.kind == "blocked":
            body.append("  " + line.text + "\n", "yellow")
        elif line.kind == "forged":
            body.append("! forged  ", "bold yellow")
            body.append(line.text + "\n", "yellow")
        elif line.kind == "note":
            body.append("  " + line.text + "\n", "blue")
        else:
            body.append('"' + line.text + '"\n', "bold white")
    return Panel(body, title="AGENT · its own account, untrusted",
                 border_style="cyan")


def _verdict_pane(state: AppState) -> Panel:
    body = Text()
    for rendered in state.verdicts[-200:]:
        event = rendered.event
        if rendered.verdict == "deny":
            body.append("DENY  ", "bold red")
        else:
            body.append("allow ", "green")
        body.append(f"{event.event:<12} ", "white")
        body.append(event.subject(), "grey70")
        reason = event.get("reason") or event.get("errno")
        if reason:
            body.append(f"  ({reason})", "grey50")
        body.append("\n")
    for miss in state.watched_misses[-20:]:
        body.append("miss  ", "grey50")
        body.append(f"{miss.event.event:<12} {miss.event.subject()}", "grey50")
        body.append("  (absent, not refused)\n", "grey37")
    counters = state.counters
    title = (f"HOST · verified, out-of-band fd · "
             f"{counters.allow} allow · {counters.deny} deny")
    return Panel(body, title=title, border_style="white")


def _broker_pane(state: AppState) -> Panel:
    body = Text()
    for line in state.broker[-200:]:
        style = "green" if line.outcome == "ALLOW" else "red"
        body.append(f"{line.outcome:<8}", style)
        body.append(f"{line.tool:<16}", "white")
        body.append(f"{line.layer}\n", "grey62")
        for reason in line.reasons:
            body.append(f"         {reason}\n", "grey50")
    return Panel(body, title="BROKER · tool-level decisions", border_style="magenta")


def _config_pane(state: AppState) -> Panel:
    epoch = state.current_epoch()
    if epoch is None:
        return Panel(Text("no policy compiled yet"), title="CONFIG")
    body = Text()
    body.append("reproduce this run by hand:\n", "grey62")
    body.append("  ivisor --config <run>/ivisor.conf run <elf>\n\n", "grey50")
    body.append(epoch.config_text, "white")
    body.append("\nenforced at\n", "grey62")
    for name, where in sorted(epoch.enforced_at.items()):
        style = "white" if where == "ivisor" else "grey50"
        body.append(f"  {name:<16} {where}\n", style)
    return Panel(body, title=f"CONFIG · epoch {epoch.index} · {epoch.digest[:12]}",
                 border_style="white")


def _audit_pane(state: AppState) -> Panel:
    claimed, brokered, verified = state.reconciliation()
    body = Text()
    body.append("reconciliation\n", "bold")
    body.append(f"  agent claimed   {claimed} tool call(s)\n", "cyan")
    body.append(f"  broker decided  {brokered}\n", "magenta")
    body.append(f"  host recorded   {verified} verdict(s)\n", "white")
    body.append(f"\nforgery attempts  {state.forgery_attempts}\n",
                "yellow" if state.forgery_attempts else "grey50")
    body.append(f"misses (counted)  {state.counters.miss}\n", "grey50")
    body.append("\nAML: none, this scenario has no destructive verb and never\n"
                "reaches five distinct egress targets, so the typologies that\n"
                "exist cannot fire. Nothing here depends on them.\n", "grey50")
    return Panel(body, title="AUDIT", border_style="white")


def _raw_pane(state: AppState) -> Panel:
    body = Text("\n".join(state.raw[-100:]), "grey58")
    return Panel(body, title="RAW guest output · not evidence",
                 border_style="grey50")


def _rail(state: AppState) -> Panel:
    table = Table.grid(padding=(0, 2))
    table.add_column(justify="right")
    table.add_column()
    table.add_column()
    table.add_column()
    for epoch in state.epochs:
        style = _LEVEL_STYLE.get(epoch.level_name, "white")
        allow = ",".join(epoch.allow) or "(none)"
        detail = (f"allow=[{allow}]" if epoch.changed
                  else "digest unchanged, noticed, nothing revoked")
        table.add_row(
            Text(f"#{epoch.index}", "grey62"),
            Text(epoch.level_name, style),
            Text(epoch.digest[:6], "grey62"),
            Text(f"{detail}   {epoch.allows} allow / {epoch.denies} deny",
                 "white" if epoch.changed else "grey50"))
        for reason in epoch.why:
            table.add_row("", "", "", Text(f"why: {reason}", "yellow"))
    return Panel(table, title="POLICY EPOCHS", border_style="blue")


def _expectations(state: AppState) -> Panel:
    table = Table.grid(padding=(0, 2))
    table.add_column()
    table.add_column()
    for expect in state.expectations:
        mark = Text("[x]", "green") if expect.met else Text("[ ]", "yellow")
        table.add_row(mark, Text(expect.describe(),
                                 "white" if expect.met else "grey62"))
    return Panel(table, title="EXPECTED", border_style="green")


def _header(state: AppState, scen, provider: str, model: str) -> Panel:
    level = state.level_name
    text = Text()
    text.append(scen.title + "\n", "bold")
    text.append(f"provider={provider}", "grey62")
    if model and model != "-":
        text.append(f"  model={model}", "grey62")
    text.append(f"  step {state.steps}   ", "grey62")
    text.append(f"LEVEL: {level}", _LEVEL_STYLE.get(level, "white"))
    return Panel(text, border_style="white")


def _render(state: AppState, tui: TuiState, scen, provider: str,
            model: str) -> Layout:
    layout = Layout()
    layout.split_column(
        Layout(_header(state, scen, provider, model), size=4),
        Layout(_rail(state), size=max(5, 3 + len(state.epochs) * 2)),
        Layout(name="panes"),
        Layout(_expectations(state), size=len(state.expectations) + 2),
        Layout(Text(" [v]erdicts [b]roker [c]onfig [a]udit [r]aw   [q]uit",
                    "grey50"), size=1))
    right = {"verdicts": _verdict_pane, "broker": _broker_pane,
             "config": _config_pane, "audit": _audit_pane,
             "raw": _raw_pane}[tui.pane](state)
    layout["panes"].split_row(Layout(_agent_pane(state)), Layout(right))
    return layout


def _key_reader(tui: TuiState) -> None:
    """Raw-mode key reader. Skipped when stdin is not a terminal."""
    import select
    import sys
    import termios
    import tty

    if not sys.stdin.isatty():
        return
    fd = sys.stdin.fileno()
    saved = termios.tcgetattr(fd)
    try:
        tty.setcbreak(fd)
        while not tui.quit:
            if select.select([sys.stdin], [], [], 0.2)[0]:
                tui.keys.put(sys.stdin.read(1))
    except (OSError, ValueError):
        # stdin closed or reassigned mid-run; the demo keeps rendering without
        # key handling rather than taking the run down with it.
        return
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, saved)


def run_tui(config, state: AppState, *, recorder=None) -> int:
    """Drive the loop on a worker thread and render frames as events arrive."""
    from demo.loop import run_demo

    scen = config.scenario
    tui = TuiState()
    events: queue.Queue = queue.Queue()

    def emit(event: Event) -> None:
        if recorder is not None:
            recorder.push(event)
        events.put(event)

    # A worker exception must never be silent. The loop runs on a thread, and
    # the Live display owns the alternate screen, so an uncaught traceback would
    # be painted over and lost, leaving a clean-looking summary in which simply
    # nothing happened. An API auth failure looked exactly like a model that
    # declined the task. Capture it and report it after the screen is released.
    failure: list[BaseException] = []

    def _drive() -> None:
        try:
            run_demo(config, emit)
        except BaseException as exc:      # noqa: BLE001 - re-raised to the caller
            failure.append(exc)

    worker = threading.Thread(target=_drive, daemon=True)
    keys = threading.Thread(target=_key_reader, args=(tui,), daemon=True)
    console = Console()

    worker.start()
    keys.start()
    try:
        with Live(console=console, refresh_per_second=8, screen=True) as live:
            while worker.is_alive() or not events.empty():
                # Drain, then draw once: a burst of hundreds of library-read
                # verdicts should cost one frame, not hundreds.
                drained = False
                while True:
                    try:
                        apply(state, events.get_nowait())
                        drained = True
                    except queue.Empty:
                        break
                while not tui.keys.empty():
                    _handle_key(tui, tui.keys.get_nowait())
                    drained = True
                if tui.quit:
                    break
                live.update(_render(state, tui, scen, config.provider.name,
                                    config.provider.model))
                if not drained:
                    worker.join(timeout=0.1)
            live.update(_render(state, tui, scen, config.provider.name,
                                config.provider.model))
    finally:
        tui.quit = True
        if recorder is not None:
            recorder.close()

    if failure:
        console.print("[bold red]the run failed before it finished.[/bold red] "
                      "Nothing below is a verdict on the agent or the sandbox:")
        console.print("".join(traceback.format_exception(failure[0])).rstrip())
        return 2

    _print_summary(console, state)
    return 0 if state.all_met() else 1


def _handle_key(tui: TuiState, key: str) -> None:
    lookup = {"v": "verdicts", "b": "broker", "c": "config", "a": "audit",
              "r": "raw"}
    if key in lookup:
        tui.pane = lookup[key]
    elif key in ("q", "\x03"):
        tui.quit = True


def _print_summary(console: Console, state: AppState) -> None:
    console.print(_expectations(state))
    unmet = state.unmet()
    if not unmet:
        console.print("[green]all expectations held[/green]")
        return

    # Distinguish "the agent did the task and was contained" from "the agent
    # never did anything". Both leave expectations unmet, and only the first is
    # a result. Saying "it declined the bait" when no tool call ever happened
    # sends you looking at the model instead of at the harness.
    if not state.agent or not state.epochs:
        console.print("[bold yellow]the agent made no tool calls at all.[/bold "
                      "yellow] That is a harness or provider problem, not a "
                      "containment result, rerun with --plain to see the error.")
    for expect in unmet:
        note = f", {expect.explain()}" if expect.explain() else ""
        console.print(f"[yellow]not met:[/yellow] {expect.describe()}{note}")
