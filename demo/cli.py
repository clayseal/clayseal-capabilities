"""Command line for the demo.

    python -m demo run ticket-triage --provider mock --plain
    python -m demo replay demo/sessions/ticket-triage-mock.jsonl --plain
    python -m demo config --level contained

`rich` is imported lazily and only for the live TUI, so every other path, and
the whole test suite, works with it absent.
"""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from demo.escalation import Level, policy_for
from demo.record import Header, Recorder, load, replay
from demo.scenario import SCENARIOS
from demo.state import AppState

_LEVELS = {level.name.lower(): level for level in Level}


def _default_run_root() -> Path:
    return Path(os.environ.get("IVISOR_RUN_ROOT", ".demo-runs"))


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="demo", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    run = sub.add_parser("run", help="run the demo")
    run.add_argument("scenario", nargs="?", default="ticket-triage",
                     choices=sorted(SCENARIOS))
    run.add_argument("--provider", default="mock",
                     help="mock | benign | openai | azure | live")
    run.add_argument("--model", default="gpt-4o-mini-2024-07-18")
    run.add_argument("--gate", default="broker", choices=("broker", "none"),
                     help="'none' removes the host gate so the sandbox is the "
                          "only thing standing between the agent and the exfil")
    run.add_argument("--plain", action="store_true",
                     help="streaming lines instead of the live TUI")
    run.add_argument("--no-color", action="store_true")
    run.add_argument("--record", metavar="FILE")
    run.add_argument("--run-root", default=None)
    run.add_argument("--ivisor-bin", default=os.environ.get("IVISOR_BIN"))
    run.add_argument("--rootfs", default=os.environ.get("IVISOR_ROOTFS"))
    run.add_argument("--fake-guest", action="store_true",
                     help="drive the fake sentry (no HVF, no signing)")
    run.add_argument("--max-turns", type=int, default=14)

    rep = sub.add_parser("replay", help="replay a recorded session")
    rep.add_argument("path")
    rep.add_argument("--speed", type=float, default=1.0)
    rep.add_argument("--plain", action="store_true")
    rep.add_argument("--no-color", action="store_true")

    cfg = sub.add_parser("config", help="print the compiled policy at a level")
    cfg.add_argument("--level", default="baseline", choices=sorted(_LEVELS))
    cfg.add_argument("--scenario", default="ticket-triage",
                     choices=sorted(SCENARIOS))
    cfg.add_argument("--rootfs", default=os.environ.get("IVISOR_ROOTFS", "/rootfs"))
    cfg.add_argument("--run-root", default=None)
    return parser


def _cmd_config(args) -> int:
    from demo.epoch import open_epoch

    scen = SCENARIOS[args.scenario]()
    level = _LEVELS[args.level]
    caps = policy_for(level, scen.seal())
    run_root = Path(args.run_root) if args.run_root else _default_run_root()
    epoch = open_epoch(caps, level=level, index=int(level), run_root=run_root,
                       rootfs=args.rootfs, scenario=scen, prev=None)
    print(f"# level {level.name}, digest {epoch.digest}")
    print(f"# {caps.summary()}")
    print(f"# staged into the guest namespace: {len(epoch.base_files)} file(s)")
    for name, where in sorted(caps.enforced_at.items()):
        print(f"#   {name:<16} enforced at: {where}")
    print()
    print(epoch.config_text, end="")
    return 0


def _cmd_replay(args) -> int:
    header, events = load(args.path)
    scen = SCENARIOS.get(header.scenario, SCENARIOS["ticket-triage"])()
    state = AppState(watch=scen.watch, expectations=scen.expectations)

    from demo.render.plain import PlainRenderer
    renderer = PlainRenderer(state=state, color=not args.no_color)
    # Never present a recording as live containment.
    renderer.header(scen, f"replay({header.provider})", header.model)
    replay(events, renderer.on_event, speed=args.speed)
    return renderer.summary()


def _cmd_run(args) -> int:
    from demo.loop import RunConfig, run_demo
    from demo.providers import build_provider

    scen = SCENARIOS[args.scenario]()
    rootfs = args.rootfs
    ivisor_bin = args.ivisor_bin
    if args.fake_guest:
        # --fake-guest FORCES the fake, overriding IVISOR_BIN. Deferring to the
        # environment here would silently hand the real sentry a JSON script as
        # its ELF whenever IVISOR_BIN happened to be exported, which is exactly
        # what happens when the e2e tests and the CLI tests share a shell.
        ivisor_bin = str(Path(__file__).resolve().parents[1]
                         / "python" / "tests" / "fakes" / "fake_ivisor.py")
        rootfs = rootfs or "/fake-rootfs"
    if not ivisor_bin or not rootfs:
        print("error: need --ivisor-bin and --rootfs (or IVISOR_BIN/IVISOR_ROOTFS), "
              "or pass --fake-guest to drive the fake sentry", file=sys.stderr)
        return 2

    provider = build_provider(args.provider, scen, model=args.model)
    state = AppState(watch=scen.watch, expectations=scen.expectations)
    recorder = None
    if args.record:
        recorder = Recorder(args.record, Header(scenario=scen.name,
                                                provider=provider.name,
                                                model=provider.model))

    config = RunConfig(
        scenario=scen, provider=provider, gate=args.gate,
        run_root=Path(args.run_root) if args.run_root else _default_run_root(),
        ivisor_bin=ivisor_bin, rootfs=rootfs, max_turns=args.max_turns,
        fake_guest=args.fake_guest)

    if args.plain or not sys.stdout.isatty():
        from demo.render.plain import PlainRenderer
        renderer = PlainRenderer(state=state, color=not args.no_color)
        renderer.header(scen, provider.name, provider.model)

        def emit(event):
            if recorder is not None:
                recorder.push(event)
            renderer.on_event(event)

        try:
            run_demo(config, emit)
        finally:
            if recorder is not None:
                recorder.close()
        return renderer.summary()

    try:
        from demo.render.tui import run_tui
    except ImportError:
        print("error: the live TUI needs rich, pip install -e '.[demo]', "
              "or pass --plain", file=sys.stderr)
        return 2
    return run_tui(config, state, recorder=recorder)


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv if argv is not None else sys.argv[1:])
    if args.command == "config":
        return _cmd_config(args)
    if args.command == "replay":
        return _cmd_replay(args)
    return _cmd_run(args)


if __name__ == "__main__":
    raise SystemExit(main())
