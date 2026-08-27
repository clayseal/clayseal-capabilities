"""Can this corpus evaluate the layer we are about to claim a number for?

    python -m benchmarks.adequacy
    python -m benchmarks.adequacy --corpora redcode sleight

Every benchmark in this repo answers "how did the system score". None of them
answers the prior question: **is this corpus even capable of exercising the
mechanism under test?** That question has teeth, because the answer here is
frequently no, and a corpus that cannot exercise a mechanism does not return a
low score, it returns a *plausible* one.

Three findings from this session motivated the module, each of which cost real
work to discover and each of which is a property of the data rather than of the
model:

1. **tau2, BFCL, ToolEmu and ATIF carry zero attack events.** Their "attack"
   trajectory is the benign one unchanged, so every scorer including a perfect
   one scores AUC 0.500. `run_detector_benchmark` reports that as containment
   0.00%, which reads as four detector failures where there was nothing to catch.

2. **RedCode attack tasks are single-event.** 718 of them, median length 1, and
   **zero** contain any benign event. So a trajectory layer has no sequence to
   model, and "median steps-to-detect = 1", which this session reported, is
   arithmetic, not early detection.

3. **Provenance is anti-correlated with the label on RedCode**: 83.7% of benign
   actions are taint-derived against 0.0% of attack actions, because an attack
   trajectory that begins cold never had a preceding read to taint it. A
   provenance channel fit on this corpus would learn to flag *untainted*
   actions and would score well doing it.

None of these is visible from a results table. All three are visible here, from
benign structure alone, before a single number is quoted.

## The columns

    sessions        tasks with >1 event, a trajectory layer needs a trajectory
    median len      median events per task
    ctx tasks       tasks holding BOTH benign and attack events; below this the
                    attack has no session context and taint is degenerate
    obs/target      observations per distinct target (the density's governing
                    variable; ~5 is the floor, see concentration.py)
    taint gap       benign taint rate minus attack taint rate. Near zero means no
                    signal; NEGATIVE means the corpus rewards an inverted
                    detector, which is worse than useless

## The verdicts

Per layer, a corpus is `ok` when it can exercise the mechanism, `weak` when it
can but marginally, and `unusable` when a number produced from it would be an
artifact. `unusable` is not a criticism of the corpus, RedCode is an excellent
per-action authorization benchmark and was never built to evaluate a behavioral
layer. It is a statement about which claims it can carry.
"""
from __future__ import annotations

import argparse
import json
import statistics
import sys
from pathlib import Path

from clayseal.capabilities.monitor.scoring.target import action_target
from benchmarks.core.detector_eval import task_to_trajectories
from benchmarks.core.opmetrics import partial_auc
from benchmarks.core.events import EventLabel
from benchmarks.datasets.base import get_loader

DEFAULT_CORPORA = ["redcode", "sleight", "ipi_coding", "agent_threat_bench",
                   "agentharm", "toolemu", "tau2", "bfcl", "atif", "asb",
                   "injecagent"]

LAYERS = ("per-action", "trajectory", "density", "provenance")


def profile(corpus: str, tasks=None) -> dict:
    """``tasks`` may be supplied directly so a synthesized corpus can be
    checked BEFORE it is registered as a loader, the acceptance test is
    meant to run before a corpus is wired, not after."""
    tasks = list(tasks) if tasks is not None else list(get_loader(corpus).load())
    n_tasks = len(tasks)
    lengths, ctx_tasks, attack_events, benign_events = [], 0, 0, 0
    benign_lengths: list[float] = []
    attack_lengths: list[float] = []
    targets, distinct = 0, set()
    b_taint = b_tot = a_taint = a_tot = 0

    for task in tasks:
        labels = {e.label for e in task.events}
        lengths.append(len(task.events))
        if EventLabel.BENIGN in labels and EventLabel.ATTACK in labels:
            ctx_tasks += 1
        attack_events += sum(1 for e in task.events if e.label is EventLabel.ATTACK)
        benign_events += sum(1 for e in task.events if e.label is EventLabel.BENIGN)
        try:
            benign, attack = task_to_trajectories(task)
        except Exception:
            continue
        for action in benign.actions:
            target = action_target(action)
            if target:
                targets += 1
                distinct.add(target)
            b_tot += 1
            b_taint += bool(action.derived_from)
        if benign.actions:
            benign_lengths.append(float(len(benign.actions)))
        if EventLabel.ATTACK in labels:
            if attack.actions:
                attack_lengths.append(float(len(attack.actions)))
            tail = attack.actions[len(benign.actions):] or attack.actions
            for action in tail:
                a_tot += 1
                a_taint += bool(action.derived_from)

    # Shortcut check: can trajectory LENGTH alone separate benign from attack?
    # A synthesized variant is ``benign_events + attack_events``, so it is
    # strictly longer than the benign trajectory it is scored against, and on a
    # corpus of short sessions that difference is the label. BFCL is median
    # length 1, so its synthesized form scores AUC 1.000 on length alone, every
    # other row on such a table is unreadable. This is computable with no model
    # at all and belongs in the acceptance test rather than being discovered by a
    # control row three experiments later.
    shortcut = partial_auc(benign_lengths, attack_lengths, 1.0,
                           standardized=False) if attack_lengths else None
    if shortcut is not None:
        shortcut = max(shortcut, 1 - shortcut)  # either direction is a shortcut

    sessions = sum(1 for n in lengths if n > 1)
    b_rate = b_taint / b_tot if b_tot else None
    a_rate = a_taint / a_tot if a_tot else None
    return {
        "corpus": corpus,
        "tasks": n_tasks,
        "sessions": sessions,
        "session_frac": sessions / n_tasks if n_tasks else 0.0,
        "median_len": statistics.median(lengths) if lengths else 0,
        "ctx_tasks": ctx_tasks,
        "attack_events": attack_events,
        "benign_events": benign_events,
        "obs_per_target": targets / len(distinct) if distinct else 0.0,
        "benign_taint": b_rate,
        "attack_taint": a_rate,
        "taint_gap": (None if b_rate is None or a_rate is None
                      else a_rate - b_rate),
        "length_shortcut": shortcut,
    }


def verdicts(p: dict) -> dict[str, tuple[str, str]]:
    """(status, reason) per layer. Thresholds are stated, not tuned."""
    out: dict[str, tuple[str, str]] = {}

    # A length shortcut poisons EVERY layer at once, so it is checked first and
    # short-circuits the rest. There is no point asking whether the density can
    # be evaluated on a corpus where counting actions already scores 1.000.
    shortcut = p.get("length_shortcut")
    if shortcut is not None and shortcut >= 0.75 and p["attack_events"]:
        reason = (f"trajectory LENGTH alone separates benign from attack at "
                  f"AUC {shortcut:.3f}; any score here is partly counting")
        return {layer: ("unusable", reason) for layer in LAYERS}

    # Per-action authorization: needs attack events and benign events. That is all.
    if not p["attack_events"]:
        out["per-action"] = ("unusable", "no attack events")
    elif not p["benign_events"]:
        out["per-action"] = ("weak", "no benign side; friction unmeasurable")
    else:
        out["per-action"] = ("ok", "")

    # Trajectory / sequence: needs multi-event tasks on the attack side.
    if not p["attack_events"]:
        out["trajectory"] = ("unusable", "no attack events")
    elif p["median_len"] <= 1:
        out["trajectory"] = ("unusable",
                             f"median task is {p['median_len']:.0f} event(s); "
                             "there is no sequence to model")
    elif p["session_frac"] < 0.5:
        out["trajectory"] = ("weak",
                             f"only {p['session_frac']:.0%} of tasks are sessions")
    else:
        out["trajectory"] = ("ok", "")

    # Density: needs repeated targets.
    if not p["attack_events"]:
        out["density"] = ("unusable", "no attack events")
    elif p["obs_per_target"] < 5.0:
        out["density"] = ("weak" if p["obs_per_target"] >= 3.0 else "unusable",
                          f"{p['obs_per_target']:.1f} observations per distinct "
                          "target; needs 5")
    else:
        out["density"] = ("ok", "")

    # Provenance: needs attacks that occur INSIDE a session with prior context.
    gap = p["taint_gap"]
    if not p["attack_events"]:
        out["provenance"] = ("unusable", "no attack events")
    elif not p["ctx_tasks"]:
        out["provenance"] = ("unusable",
                             "no task holds both benign and attack events; "
                             "attacks begin cold and are never taint-derived")
    elif gap is not None and gap < 0:
        out["provenance"] = ("unusable",
                             f"taint gap {gap:+.0%}: the corpus rewards an "
                             "INVERTED detector")
    elif gap is not None and abs(gap) < 0.10:
        out["provenance"] = ("unusable", f"taint gap {gap:+.0%}: no signal")
    else:
        out["provenance"] = ("ok", "")
    return out


_MARK = {"ok": "ok", "weak": "weak", "unusable": "NO"}


def render(rows: list[tuple[dict, dict]]) -> str:
    head = (f"{'corpus':<20}{'tasks':>7}{'sess%':>7}{'med':>5}{'ctx':>6}"
            f"{'obs/tgt':>9}{'taint gap':>11}{'len AUC':>9}  " +
            "".join(f"{layer:>12}" for layer in LAYERS))
    lines = ["corpus adequacy, what each corpus can evaluate",
             "=" * len(head), "", head, "-" * len(head)]
    for p, v in rows:
        gap = "-" if p["taint_gap"] is None else f"{p['taint_gap']:+.0%}"
        shortcut = p.get("length_shortcut")
        cut = "-" if shortcut is None else f"{shortcut:.3f}"
        lines.append(
            f"{p['corpus']:<20}{p['tasks']:>7}{p['session_frac']:>7.0%}"
            f"{p['median_len']:>5.0f}{p['ctx_tasks']:>6}"
            f"{p['obs_per_target']:>9.1f}{gap:>11}{cut:>9}  "
            + "".join(f"{_MARK[v[layer][0]]:>12}" for layer in LAYERS)
        )
    lines.append("")
    lines.append("reasons:")
    seen = set()
    for p, v in rows:
        for layer in LAYERS:
            status, reason = v[layer]
            if status == "ok" or not reason:
                continue
            key = (p["corpus"], layer)
            if key in seen:
                continue
            seen.add(key)
            lines.append(f"  {p['corpus']:<20}{layer:<12}{reason}")
    return "\n".join(lines)


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--corpora", nargs="*", default=DEFAULT_CORPORA)
    p.add_argument("--json", type=Path, default=None)
    args = p.parse_args(argv)

    rows = []
    for corpus in args.corpora:
        try:
            prof = profile(corpus)
        except Exception as exc:
            print(f"{corpus}: unavailable ({str(exc)[:70]})", file=sys.stderr)
            continue
        rows.append((prof, verdicts(prof)))
    print(render(rows))

    usable = {layer: sum(1 for _, v in rows if v[layer][0] == "ok")
              for layer in LAYERS}
    print("\ncorpora able to evaluate each layer, of "
          f"{len(rows)} surveyed:")
    for layer in LAYERS:
        print(f"  {layer:<12}{usable[layer]}")

    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(json.dumps(
            [{**p, "verdicts": {k: list(x) for k, x in v.items()}}
             for p, v in rows], indent=2))
        print(f"\nwrote {args.json}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
