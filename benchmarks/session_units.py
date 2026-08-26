"""The same run, in the two units, because each one flatters a different side.

    python -m benchmarks.session_units

Every containment number in this repository is per EVENT: of the attack actions,
how many were stopped. That unit is not wrong, and it is not what a deployment
experiences either, and the direction of the error is opposite on each side of
the ledger.

**Per-event containment UNDERSTATES protection.** An attack of five actions
whose first action is refused scores 1 of 5, 20%. In a live run the agent is
stopped and the other four never happen. Measured here: sleight goes from 37.7%
to 78.0% and AgentHarm from 31.6% to 46.2% when the question becomes "was this
attack stopped at all".

**Per-event cost UNDERSTATES disruption**, for the mirror reason. A session of
twenty benign actions with one refusal scores 5%, and the task it was doing may
be dead. Measured here: sleight's benign cost goes from 14.1% of events to
**46.5% of sessions**, and AgentHarm's from 6.3% to 10.2%.

So neither unit is the answer and reporting either alone picks a side. The event
pair is the optimistic read of protection and the optimistic read of cost; the
session pair is the pessimistic read of both. A deployment sits between them and
the honest thing is to publish the pair.

## What "stopped" does not mean

It does not mean nothing happened. On AgentHarm **113 attack actions ran before
the first refusal** across the sessions that were eventually stopped, so a
session counted as contained here still did part of what it set out to do. The
distribution of where the first stop lands is reported for that reason: on
sleight 18 of 32 stops land on the attack's FIRST action, on AgentHarm only 4 of
74 do.
"""
from __future__ import annotations

import argparse
import sys
from collections import Counter
from dataclasses import dataclass, field

from benchmarks.core.events import EventLabel
from benchmarks.coverage import IN_SURFACE, TaskSurface


@dataclass
class Units:
    event_attack: list[int] = field(default_factory=lambda: [0, 0])   # hit, total
    event_benign: list[int] = field(default_factory=lambda: [0, 0])
    session_attack: list[int] = field(default_factory=lambda: [0, 0])
    session_benign: list[int] = field(default_factory=lambda: [0, 0])
    ran_before_stop: int = 0
    first_stop: Counter = field(default_factory=Counter)


def measure(corpus: str, limit: int | None = 4000) -> Units:
    from benchmarks.core.stack_engine import DeployableStackEngine
    from benchmarks.datasets.base import get_loader

    tasks = get_loader(corpus).load(limit=limit)
    engine = DeployableStackEngine(name="units", treat_step_up="block")
    units = Units()
    for task in tasks:
        surface = TaskSurface.of(task)
        engine.reset()
        attack: list[bool] = []
        benign: list[bool] = []
        for event in task.events:
            blocked = not engine.decide(task, event).allowed
            if event.label is EventLabel.ATTACK and \
                    surface.classify(event)[0] == IN_SURFACE:
                attack.append(blocked)
            elif event.label is EventLabel.BENIGN:
                benign.append(blocked)

        if benign:
            units.event_benign[0] += sum(benign)
            units.event_benign[1] += len(benign)
            units.session_benign[0] += int(any(benign))
            units.session_benign[1] += 1
        if attack:
            units.event_attack[0] += sum(attack)
            units.event_attack[1] += len(attack)
            units.session_attack[1] += 1
            if any(attack):
                units.session_attack[0] += 1
                first = min(i for i, b in enumerate(attack) if b)
                units.ran_before_stop += first
                units.first_stop[min(first, 3)] += 1
    return units


def _rate(pair: list[int]) -> str:
    hit, total = pair
    return f"{hit}/{total} ({hit / total:.1%})" if total else "n/a"


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--datasets", default="agentharm,sleight")
    p.add_argument("--limit", type=int, default=4000)
    args = p.parse_args(argv if argv is not None else sys.argv[1:])

    print("# The same run, in the two units\n")
    print("STATUS: current\n")
    print("```bash")
    print(f"python -m benchmarks.session_units --datasets {args.datasets}")
    print("```\n")
    print("Per event is the optimistic read of protection and of cost. Per "
          "session is the\npessimistic read of both. A deployment sits between "
          "them.\n")
    print("| corpus | unit | in-surface contained | benign disrupted |")
    print("| --- | --- | --- | --- |")
    for corpus in [d.strip() for d in args.datasets.split(",") if d.strip()]:
        try:
            units = measure(corpus, args.limit)
        except (KeyError, RuntimeError) as exc:
            print(f"| {corpus} | _skipped: {str(exc).splitlines()[0][:40]}_ | | |")
            continue
        print(f"| {corpus} | per event | {_rate(units.event_attack)} | "
              f"{_rate(units.event_benign)} |")
        print(f"| {corpus} | **per session** | **{_rate(units.session_attack)}** "
              f"| **{_rate(units.session_benign)}** |")
        print(f"| {corpus} | _actions that ran before the first stop_ | "
              f"_{units.ran_before_stop}_ | _first stop at action "
              f"{dict(sorted(units.first_stop.items()))}_ |")
    print("\nA session counted as contained still did part of what it set out "
          "to do: the\nmiddle row is protection at its most generous and the "
          "italic row is what that\ngenerosity costs in actions that already "
          "ran.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
