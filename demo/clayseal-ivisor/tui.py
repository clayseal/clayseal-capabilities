"""Live console UI for the Arena, built with rich.

Runs the real scenario under iVisor on a worker thread and renders its frames
into a panelled layout that updates as verdicts stream in. Same instrument, same
palette as the containment report: dense, monospace, colour only on the block.
"""

from __future__ import annotations

import threading
import time
from pathlib import Path

import arena
from rich.align import Align
from rich.console import Group
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.text import Text

# palette (mirrors report.html)
ACCENT = "#35b6a8"
BLOCK = "#e5484d"
ALLOW = "#4b9a5e"
FLOOR = "#e0a02f"
MUTED = "#6f7d83"
INK = "#cdd6d9"
BORDER = "#2b3a40"


def _brand() -> Text:
    t = Text()
    t.append("CLAY SEAL ", style=f"bold {INK}")
    t.append("× ", style=f"bold {ACCENT}")
    t.append("iVISOR", style=f"bold {INK}")
    t.append("   live containment", style=MUTED)
    return t


def _header() -> Panel:
    right = Text("Apple Silicon · Hypervisor.framework · policy channel fd 3", style=MUTED)
    grid = Text.assemble(_brand())
    body = Layout()
    return Panel(Align.left(grid), style="none", border_style=BORDER,
                 subtitle=right, subtitle_align="right", padding=(0, 1))


def _scenario_panel(scen) -> Panel:
    t = Text()
    t.append(scen.id + "\n", style=MUTED)
    t.append(scen.name + "\n\n", style=f"bold {INK}")
    t.append(scen.premise + "\n\n", style=INK)
    t.append("ATT&CK\n", style=MUTED)
    for a in scen.attack:
        t.append("  " + a + "\n", style=ACCENT)
    t.append("\nsealed capability\n", style=MUTED)
    t.append("  egress  " + ", ".join(sorted(scen.capability.egress_hosts)) + "\n", style=INK)
    t.append("  write   /work\n", style=INK)
    if scen.capability.egress_budget:
        t.append(f"  budget  {scen.capability.egress_budget} outbound connects\n", style=INK)
    t.append("\nstar layer\n", style=MUTED)
    t.append("  " + scen.star + "\n", style=f"bold {FLOOR}")
    return Panel(t, title=Text("scenario", style=MUTED), border_style=BORDER,
                 title_align="left", padding=(1, 2))


def _counters(run) -> tuple[int, int, int, int, int]:
    observed = blocked = floor = bpl = beh = 0
    for f in list(run.frames):
        if f["src"] == "sandbox":
            observed += 1
            k = f.get("kind")
            if k in ("block", "bpl-block", "floor-block"):
                blocked += 1
            if k == "floor-block":
                floor += 1
            if k == "bpl-block":
                bpl += 1
                beh += 1
        elif f["src"] == "floor":
            blocked += 1
            floor += 1
    return observed, blocked, floor, bpl, beh


def _verdict_panel(run, done: bool) -> Panel:
    observed, blocked, floor, bpl, beh = _counters(run)
    t = Text()

    def row(label, val, style=INK):
        t.append(f"{val:>4}", style=f"bold {style}")
        t.append(f"  {label}\n", style=MUTED)

    row("actions observed", observed)
    row("blocked", blocked, BLOCK if blocked else INK)
    row("at syscall floor", floor)
    row("by behavioral limit", bpl, FLOOR if bpl else INK)
    if beh:
        row("caught beyond floor", beh, ACCENT)
    t.append("\n")
    if done:
        if getattr(run.scen, "benign", False):
            tag = " TASK PERMITTED IN FULL " if blocked == 0 else " UNEXPECTED BLOCK "
            t.append(tag, style=f"bold {'black on ' + ALLOW if blocked == 0 else 'white on ' + BLOCK}")
            t.append("\n legitimate work · no false positives", style=MUTED)
            t.append("\n")
        ok, _ = run.log.verify()
        t.append(" DECISION LOG VERIFIED " if ok else " LOG CHECK FAILED ",
                 style=f"bold {'black on ' + ALLOW if ok else 'white on ' + BLOCK}")
        t.append(f"\n {len(run.log.records())} hash-chained receipts", style=MUTED)
    else:
        t.append(" sealing decisions… ", style=f"black on {ACCENT}")
    return Panel(t, title=Text("verdict", style=MUTED), border_style=BORDER,
                 title_align="left", padding=(1, 2))


def _oneline(text: Text) -> Text:
    text.no_wrap = True
    text.overflow = "ellipsis"
    return text


def _feed_lines(frames, height: int) -> Group:
    frames = list(frames)
    out: list[Text] = []
    for f in frames:
        src = f["src"]
        if src == "agent":
            line = Text.assemble(("A ", MUTED), (f.get("text", ""), MUTED))
        elif src == "floor":
            line = Text.assemble(("F ", BLOCK), (" FLOOR ", f"bold white on {BLOCK}"),
                                 (" " + f.get("text", ""), FLOOR))
        else:  # sandbox
            k = f.get("kind")
            raw = f.get("raw", "")
            if k == "bpl-block":
                line = Text.assemble(("S ", BLOCK), (" BPL BLOCK ", f"bold black on {FLOOR}"),
                                     (" " + raw, INK))
            elif k in ("block", "floor-block"):
                line = Text.assemble(("S ", BLOCK), (" BLOCK ", f"bold white on {BLOCK}"),
                                     (" " + raw, INK))
            elif k == "routine":
                continue
            else:
                line = Text.assemble(("S ", ACCENT), (raw, MUTED))
        out.append(_oneline(line))
        if src == "sandbox" and f.get("kind") in ("block", "bpl-block", "floor-block"):
            reasons = (f.get("clay") or {}).get("reasons") or []
            if reasons:
                out.append(_oneline(Text("    ↳ Clay Seal " + f["clay"]["layer"] + ": "
                                         + "; ".join(reasons), style=BLOCK)))
    tail = out[-height:] if height > 0 else out
    if not tail:
        return Group(Text("waiting for the agent to act…", style=MUTED))
    return Group(*tail)


def _layout(scen, run, done, height) -> Layout:
    root = Layout()
    root.split_column(
        Layout(_header(), name="head", size=3),
        Layout(name="body"),
        Layout(_footer(), name="foot", size=3),
    )
    feed_h = max(6, height - 3 - 3 - 2)
    root["body"].split_row(
        Layout(Panel(_feed_lines(run.frames, feed_h),
                     title=Text("event stream   A agent · S iVisor verdict · F floor", style=MUTED),
                     title_align="left", border_style=BORDER, padding=(0, 1)),
               name="feed", ratio=2),
        Layout(name="side", ratio=1),
    )
    root["side"].split_column(
        Layout(_scenario_panel(scen), name="scen"),
        Layout(_verdict_panel(run, done), name="verdict", size=13),
    )
    return root


def _footer() -> Panel:
    t = Text.assemble(
        ("fd 3 is unreachable from the guest, every verdict above is iVisor's own output the agent cannot forge", MUTED),
    )
    return Panel(t, border_style=BORDER, padding=(0, 1))


def run_live(scen, ivdir: Path) -> None:
    from rich.console import Console
    console = Console()
    # pre-build silently so cargo can never paint over the live layout
    import os
    import subprocess
    subprocess.run(["cargo", "build", "-q", "-p", "ivisor", "--bin", "ivisor"],
                   cwd=ivdir, env=dict(os.environ), check=True, capture_output=True)

    run = arena.LiveRun(scen)
    run.quiet = True
    worker = threading.Thread(target=run.run, args=(ivdir,), daemon=True)
    worker.start()

    h = console.size.height
    with Live(_layout(scen, run, False, h), console=console, refresh_per_second=14,
              screen=True) as live:
        while worker.is_alive():
            live.update(_layout(scen, run, False, console.size.height))
            time.sleep(0.07)
        live.update(_layout(scen, run, True, console.size.height))
        time.sleep(1.4)   # let the final frame land before leaving the alt screen

    # persist the full result so `arena.py review` can show it later
    _persist(run)

    observed, blocked, floor, bpl, beh = _counters(run)
    ok, _ = run.log.verify()
    status = ("permitted" if getattr(scen, "benign", False) and blocked == 0
              else f"{blocked} blocked")
    res = Text.assemble(
        (f"  {scen.id}  ", f"bold {INK}"),
        (status, ALLOW if (getattr(scen, "benign", False) and blocked == 0) else (BLOCK if blocked else MUTED)),
        (f"   ({floor} floor · {bpl} behavioral)   ", MUTED),
        ("decision log " + ("VERIFIED" if ok else "FAILED"), ALLOW if ok else BLOCK),
        ("     python arena.py review " + scen.id, MUTED),
    )
    console.print(res)


def _persist(run) -> None:
    import json
    rec = arena.build_record(run)
    store = Path(arena.__file__).parent / "results.json"
    data = {}
    if store.exists():
        try:
            data = {r["id"]: r for r in json.loads(store.read_text())}
        except Exception:
            data = {}
    data[run.scen.id] = rec
    # keep roster order
    order = [s.id for s in __import__("scenarios").ROSTER]
    ordered = [data[i] for i in order if i in data]
    store.write_text(json.dumps(ordered, indent=1))


# --- review: render saved results inline (persists in scrollback) ----------
def _status_rule(console, rec) -> None:
    from rich.rule import Rule
    benign = rec.get("benign") or not rec.get("attack")
    blocked = rec["summary"]["blocked"]
    if benign and blocked == 0:
        label, col = "PERMITTED", ALLOW
    elif blocked:
        label, col = "CONTAINED", ALLOW
    else:
        label, col = "REVIEW", FLOOR
    console.print(Rule(Text.assemble((f" {rec['id']}  {rec['name']}  ", f"bold {INK}"),
                                     (f"[{label}] ", f"bold {col}")), style=BORDER, align="left"))


def _verdict_line(rec):
    s = rec["summary"]
    t = Text()
    t.append(f"  observed {s['observed']}", style=MUTED)
    t.append(f"   blocked {s['blocked']}", style=BLOCK if s["blocked"] else MUTED)
    t.append(f"   floor {s['floor_blocks']}", style=MUTED)
    t.append(f"   behavioral {s['bpl_blocks']}", style=FLOOR if s["bpl_blocks"] else MUTED)
    if s.get("behavioral_catches"):
        t.append(f"   caught-beyond-floor {s['behavioral_catches']}", style=ACCENT)
    ok = rec["log"]["verified"]
    t.append(f"   decision log {'VERIFIED' if ok else 'FAILED'}", style=ALLOW if ok else BLOCK)
    t.append(f"  ({rec['log']['receipts']} receipts)", style=MUTED)
    return t


def render_review(records, console=None) -> None:
    from rich.console import Console
    console = console or Console()
    for rec in records:
        console.print()
        _status_rule(console, rec)
        # scenario line
        att = "  ".join(rec["attack"]) if rec["attack"] else "no attack · legitimate work"
        console.print(Text.assemble(("  ", ""), (rec["premise"], INK)))
        console.print(Text.assemble(("  ATT&CK  ", MUTED), (att, ACCENT)))
        sealed = rec["sealed"]
        cap = f"egress={{{', '.join(sealed['egress'])}}}  write=/work" + (
            f"  egress-budget={sealed['egress_budget']}" if sealed.get("egress_budget") else "")
        console.print(Text.assemble(("  sealed  ", MUTED), (cap, MUTED)))
        console.print(Panel(_feed_lines(rec["frames"], 0),
                            title=Text("event log   A agent · S iVisor verdict · F floor", style=MUTED),
                            title_align="left", border_style=BORDER, padding=(0, 1)))
        console.print(_verdict_line(rec))
