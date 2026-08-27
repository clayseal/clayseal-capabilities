"""CLI: every tier, one table, with the caveat that makes each number readable.

    python -m benchmarks.scoreboard

Results were living in eight documents, which meant nobody could see whether a
change helped or hurt overall, and a withdrawn number could sit in one file while
its replacement sat in another. This runs everything and prints the current
picture, so "are we improving" has one answer.

Each row carries a CAVEAT, because five headline numbers in this project have
been withdrawn after audit and every one of them looked fine as a bare number:

* a velocity cap derived from the attack label;
* a loader whose event ORDER carried the label;
* a false-block rate measured on its own calibration set;
* eighteen of twenty-four AgentThreatBench attack events the loader invented;
* a replan path that took AgentDojo travel from 11.1% to 22.2% ASR.

So the caveat column is not decoration. A number without it is not reportable.
"""
from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass, field
from pathlib import Path

from benchmarks.core.engines import build_engines
from benchmarks.core.heldout import circular_unsplittable, hold_out_corpus
from benchmarks.core.events import EventLabel
from benchmarks.core.runner import run_benchmark
from benchmarks.datasets.base import get_loader

# Corpora whose containment saturates at the naive tool-allowlist rung. They are
# real corpora faithfully loaded, and they measure exactly one thing: whether we
# check tool names. Wiring them grows the attack-event count from 3,812 to 7,454
# while adding nothing a per-action layer has to reason about, so they are
# reported and EXCLUDED from any pooled figure. Quoting a pooled containment that
# includes them would be the cheapest possible way to inflate this system.
SATURATED = {"asb", "injecagent"}

# Suites allowed in a buyer-facing POOLED containment headline. Saturated
# allowlist-saturators and content-ceiling markers stay in the per-tier table
# but must never enter a single pooled ASR / containment figure.
POOLABLE = frozenset({
    "redcode", "ipi_coding", "agent_threat_bench", "mcp_attack", "toolemu",
})

# The deterministic ladder stops at the budget rung.
#
# Velocity stays in the tree and is NOT scored here. Measured across all nineteen
# corpora, it contributes zero containment on every one of them and its only
# effects are artifacts: it adds 1.94% false blocks on ATIF and 0.03% on tau2 for
# nothing in return, and on SLEIGHT it reports 61 extra points of "containment"
# that are transcript length rather than the attack. That last number swings 29.5
# points when the events are shuffled, which is the order-invariance assertion
# failing outright.
#
# Its containment claim rests on benchmarks/burst.py, which supplies the burst
# none of these corpora contains and measures it against a held-out false-alarm
# rate. That is the honest place for it.
DEPLOYABLE = [
    "tool-allowlist",
    "capability-token",
    "task-scope",
    "task-scope+binding",
    "task-scope+binding+budget",
]

# What each corpus actually exercises, and what its number does NOT mean. Written
# from the loader audits rather than from the papers.
CAVEATS = {
    "redcode": "path escapes from a fixed workspace boundary; the real result on this axis",
    "asb": "SATURATES AT THE NAIVE RUNG: every attack uses an ungranted tool; not a result",
    "injecagent": ("SATURATES AT THE NAIVE RUNG, and the corpus GRANTS the attacker "
                   "tools while we do not; containment is that narrowness alone"),
    "toolemu": ("normalized clayseal_traces fixture scores destination binding; "
                "raw toolkit mapping still has no attack events (underspecification)"),
    "ipi_coding": "injected instructions with out-of-scope targets",
    "agent_threat_bench": "data_exfil only; memory_poison and autonomy_hijack are content-defined and declared",
    "sleight": ("CONTENT ceiling: ladder hard ~5%; product row is sleight[stack] "
                "(session observe + soft content). Velocity is not scored."),
    "sleight[detector]": ("sealed digest+IFC+argv/callee/sed-rm/ssh-body + twin; "
                          "~98% mean / ~98% twin-structural / 0% FB; "
                          "residual miss is env symlink (identical actions)"),
    "advbench_agent": ("normalized fixture: target/arg binding; binding rung "
                       "100% / 0% FB; content-only twins are not the score path"),
    "agentharm": ("CONTENT ceiling: hard ~27% from destination pins; soft cues lift "
                  "union, see agentharm[stack] / cross_stack (never quote soft as hard)"),
    "agentharm[stack]": ("DeployableStack product row: hard/soft/union split; "
                         "sealed goal = benign twin prompt"),
    "atif": "benign only; a false-block measurement",
    "tau2": "benign only; the friction denominator that matters",
    "bfcl": "benign only; the friction denominator that matters",
    "mcp_attack": ("product-shaped MCP poisoned-tool / confused-deputy / arg-mutation; "
                   "destination binding and scope are the discriminators"),
}


@dataclass
class Row:
    tier: str
    measures: str
    contained: str = "-"
    false_block: str = "-"
    # False blocks when the grant did NOT see the traffic it judges. Thirteen
    # loaders build a task's grant from its own benign events, and on six corpora
    # the grant IS the benign side exactly, so the column to its left cannot be
    # anything but zero at the scope rung. Both numbers are real and they answer
    # different questions: the first is "given a complete mandate, does the layer
    # add friction", the second is "what does an incomplete mandate cost".
    heldout: str = "-"
    n: str = ""
    caveat: str = ""


@dataclass
class Scoreboard:
    rows: list[Row] = field(default_factory=list)

    def add(self, **kw) -> None:
        self.rows.append(Row(**kw))

    def render(self) -> str:
        w_tier = max(len(r.tier) for r in self.rows) + 2
        w_meas = max(len(r.measures) for r in self.rows) + 2
        out = [
            f"{'tier':<{w_tier}}{'measures':<{w_meas}}"
            f"{'contained':>11}{'FB(granted)':>13}{'FB(held out)':>14}{'n':>16}",
            "-" * (w_tier + w_meas + 54),
        ]
        for r in self.rows:
            out.append(
                f"{r.tier:<{w_tier}}{r.measures:<{w_meas}}"
                f"{r.contained:>11}{r.false_block:>13}{r.heldout:>14}{r.n:>16}"
            )
        out.append("")
        out.append(self.LEGEND)
        out.append("")
        out.append("caveats, without which none of the above is reportable:")
        for r in self.rows:
            if r.caveat:
                out.append(f"  {r.tier:<{w_tier}}{r.caveat}")
        return "\n".join(out)

    def to_dict(self) -> dict:
        return {"rows": [vars(r) for r in self.rows]}

    LEGEND = (
        "FB(granted)  friction given a COMPLETE mandate. On six corpora the grant is\n"
        "             the benign side restated, so this is 0.00% by construction at the\n"
        "             scope rung and is not evidence on its own.\n"
        "FB(held out) friction when the grant was built from half the benign events and\n"
        "             judged against the other half: what an INCOMPLETE mandate costs."
    )


def _deterministic(board: Scoreboard, quick: bool) -> None:
    corpora = ["redcode", "agentharm", "asb", "sleight", "ipi_coding",
               "agent_threat_bench", "injecagent", "toolemu",
               "mcp_attack", "advbench_agent",
               "atif", "tau2", "bfcl"]
    if quick:
        corpora = ["redcode", "agentharm", "sleight", "agent_threat_bench",
                   "mcp_attack"]
    for name in corpora:
        try:
            tasks = list(get_loader(name).load())
        except Exception:
            board.add(tier=name, measures="deterministic replay",
                      caveat="corpus not fetched")
            continue
        # Prefer a corpus-declared rung (SLEIGHT must not use velocity: long
        # coding sessions trip the effect-action rate and invent containment).
        rung = next((t.meta.get("ladder_rung") for t in tasks
                     if t.meta.get("ladder_rung")), DEPLOYABLE[-1])
        if rung not in DEPLOYABLE:
            rung = DEPLOYABLE[-1]
        engines = [e for e in build_engines() if e.name in DEPLOYABLE]
        result = run_benchmark(tasks, engines)[rung]
        # A corpus whose mandate is derived from its own benign side cannot
        # yield a friction number: that side is clean by construction. Saying so
        # is the difference between this table and the five withdrawn results.
        unscoreable = any(t.meta.get("false_block_unscoreable") for t in tasks)
        # Re-score with a grant built from half the benign events, so the number
        # is a measurement rather than an identity.
        held_tasks, corrected = hold_out_corpus(tasks, seed=0)
        # Circular AND unsplittable: one benign event per task means there is
        # nothing to hold out, so the granted column is an identity with no
        # honest counterpart. Report neither rather than reporting the identity.
        if not corrected and circular_unsplittable(tasks):
            unscoreable = True
        heldout = "-"
        if corrected:
            hr = run_benchmark(
                held_tasks, [e for e in build_engines() if e.name in DEPLOYABLE]
            )[rung]
            heldout = f"{100 * hr.false_block_rate:.2f}%"
        board.add(
            tier=name,
            measures="deterministic replay",
            contained=(f"{100 * result.attack_prevention_rate:.1f}%"
                       if result.n_attack else "-"),
            false_block=("n/a" if unscoreable
                         else f"{100 * result.false_block_rate:.2f}%"),
            heldout=heldout,
            n=f"{result.n_attack}a / {result.n_benign}b",
            caveat=CAVEATS.get(name, ""),
        )


def _burst(board: Scoreboard) -> None:
    from benchmarks.burst import evaluate

    for corpus in ("tau2", "bfcl"):
        try:
            r = evaluate(corpus, 10, count=400, seed=0)
        except Exception:
            continue
        board.add(
            tier=f"burst[{corpus}]",
            measures="volume-defined harm",
            contained=f"{100 * r.containment:.1f}%",
            false_block=f"{100 * r.false_alarm_rate:.1f}%",
            n=f"{r.sessions} sessions",
            caveat=(f"burst of 10; blast radius {r.median_blast_radius:.0f} actions; "
                    f"false alarms measured on HELD-OUT clean sessions"),
        )


def _flow(board: Scoreboard) -> None:
    """The flow tier, whose contained column is the SINGLE-WRITE arm only.

    This row read `r.chunked` and `r.fanout`, which `benchmarks/flow.py` no
    longer defines, inside a bare `except Exception: continue`. The row
    therefore vanished from the board silently while the containment figure it
    used to print stayed quoted elsewhere. Both halves are fixed here: the arm
    counts are read from `r.splits`, and a failure prints a row saying so
    instead of disappearing.
    """
    from benchmarks.flow import evaluate

    for corpus in ("tau2", "bfcl"):
        try:
            r = evaluate(corpus, count=200, seed=0)
        except SystemExit:
            continue
        except Exception as exc:  # a missing row is worse than a loud one
            board.add(tier=f"flow[{corpus}]", measures="sequence-defined harm",
                      caveat=f"NOT MEASURED: {type(exc).__name__}: {exc}")
            continue

        def _by_width(arm: str) -> str:
            by_w = r.splits.get(arm, {})
            return "/".join(f"{by_w[w].whole_out}" for w in sorted(by_w)) or "-"

        board.add(
            tier=f"flow[{corpus}]",
            measures="sequence-defined harm",
            contained=f"{100 * r.containment:.1f}%",
            false_block=f"{100 * r.real_traffic_false_block:.2f}%",
            n=f"{r.sessions} sessions",
            caveat=("contained is the SINGLE-WRITE arm only. Whole value out at "
                    f"2/4/11/22 fragments: chunked {_by_width('chunked')}, "
                    f"fan-out {_by_width('fan-out')}, concurrent chunked "
                    f"{_by_width('concurrent chunked')}. Two writes carrying "
                    "300 characters of prose each escape 200/200 on tau2 and "
                    "171/171 on BFCL, and a value of 11 characters or fewer "
                    "has no cross-write check at all. See results/flow.md"),
        )


def _trajectory(board: Scoreboard) -> None:
    from benchmarks.trajectory import build_trajectories, evaluate

    try:
        benign = list(get_loader("bfcl").load(limit=300))
        attacks = list(get_loader("redcode").load(limit=300))
    except Exception:
        return
    trajectories = build_trajectories(benign, attacks, length=200,
                                      count=100, seed=0)
    if not trajectories:
        return
    engines = [e for e in build_engines() if e.name in DEPLOYABLE]
    results = evaluate(trajectories, engines)
    r = results[DEPLOYABLE[-1]]
    board.add(
        tier="long-horizon",
        measures="detection at session length",
        contained=f"{100 * r.detection_rate:.1f}%",
        false_block=f"{r.false_alarms_per_1k:.2f}/1k",
        n=f"{r.benign_actions} actions",
        caveat=("one needle per session, wearing the session's own tool and "
                "resource; measures position-independence, not covert detection"),
    )


def _sleight_detector(board: Scoreboard) -> None:
    """SLEIGHT's honest score: trajectory detector, not the per-action ladder."""
    from agentauth.capabilities.monitor import NGramScorer, TrajectoryDetector
    from benchmarks.core.detector_eval import run_detector_benchmark

    try:
        tasks = list(get_loader("sleight").load())
    except Exception:
        board.add(tier="sleight[detector]", measures="covert-intent trajectories",
                  caveat="corpus not fetched / not decrypted")
        return
    result = run_detector_benchmark(
        tasks, detector=TrajectoryDetector(scorer=NGramScorer(), alpha=0.05))
    board.add(
        tier="sleight[detector]",
        measures="covert-intent trajectories",
        contained=f"{100 * result.containment_rate:.1f}%",
        false_block=f"{100 * result.false_block_rate:.2f}%",
        n=f"{result.attack_trajectories} atk / {result.n_test} benign",
        caveat=CAVEATS["sleight[detector]"],
    )


def _deployable_stack(board: Scoreboard, quick: bool) -> None:
    """PRODUCT gateway first, same SessionBroker as CTR / live AgentDojo."""
    from benchmarks.core.broker_eval import run_broker_benchmark

    corpora = ["redcode", "agentharm", "sleight", "ipi_coding", "mcp_attack"]
    if not quick:
        corpora.extend([
            "asb", "advbench_agent", "agent_threat_bench",
            "mind2web_sc", "b3",
        ])
    board.add(
        tier="── PRODUCT ──",
        measures="DeployableStack (one system)",
        caveat="rows below are the shippable gateway; ladder section is ablation",
    )
    for name in corpora:
        try:
            tasks = list(get_loader(name).load())
        except Exception:
            board.add(tier=f"{name}[stack]", measures="DeployableStack gateway",
                      caveat="corpus not fetched")
            continue
        # Det soft content only here (credentials optional; fail-open).
        result = run_broker_benchmark(tasks, entailment_judge=None)
        unscoreable = any(t.meta.get("false_block_unscoreable") for t in tasks)
        if result.n_attack:
            contained = (
                f"{100 * result.attack_prevention_rate:.1f}% "
                f"(H{100 * result.hard_attack_prevention_rate:.0f}/"
                f"S{100 * result.soft_attack_prevention_rate:.0f})"
            )
        else:
            contained = "-"
        board.add(
            tier=f"{name}[stack]",
            measures="DeployableStack / SessionBroker",
            contained=contained,
            false_block=("n/a" if unscoreable
                         else f"{100 * result.false_block_rate:.2f}%"),
            n=f"{result.n_attack}a / {result.n_benign}b",
            caveat=CAVEATS.get(f"{name}[stack]", CAVEATS.get(name, (
                "shared product profile; hard=DENY soft=STEP_UP; "
                "ladder rows are floor ablations"
            ))),
        )
    board.add(
        tier="── LADDER ABLATION ──",
        measures="build_engines() monotone floor",
        caveat="not the product claim, construction check only",
    )


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Every tier, one table")
    p.add_argument("--quick", action="store_true",
                   help="fewer corpora, for a fast check during development")
    p.add_argument("--json", type=Path, default=None)
    args = p.parse_args(argv)

    board = Scoreboard()
    # Product gateway FIRST so the table reads as one system, then ladder ablation.
    _deployable_stack(board, args.quick)
    _deterministic(board, args.quick)
    _sleight_detector(board)
    if not args.quick:
        _burst(board)
        _flow(board)
        _trajectory(board)
    print(board.render())

    # Containment at an unconstrained false-block rate is reward-hackable, and
    # this repo has the proof: a detector shipped 100% containment that was 13 of
    # 18 benign trajectories being refused. The headline therefore carries the
    # operating-point view beside it, where a control that blocks everything
    # scores zero by construction. See benchmarks/core/opmetrics.py.
    print("\nOPERATING POINT, detection at a false-alarm rate the operator "
          "chose.")
    print("  Containment above is measured at whatever threshold each engine "
          "picked for itself.")
    print("  It is not comparable across engines and it is not a deployment "
          "number. For that:")
    print("      python -m benchmarks.opeval --corpora <corpus>")
    print("  which reports detection@0.1%/1%/5% FPR, lift over base rate, "
          "steps-to-detect and")
    print("  alert volume, with permanent deny-all / position / length control "
          "rows.")
    print("  A headline that cites containment without an operating point is "
          "forbidden by")
    print("  SEND_PACKET.md rule 10.")
    # Explicit pooled-headline discipline: never fold SATURATED tiers into one
    # number. Callers (SEND_PACKET) read this block.
    pooled_rows = [r for r in board.rows
                   if r.tier.split("[")[0] in POOLABLE and r.contained not in ("-",)]
    if pooled_rows:
        print("\npooled headline (excludes SATURATED asb/injecagent and content ceilings):")
        for r in pooled_rows:
            print(f"  {r.tier}: contained={r.contained}  FB={r.false_block}  ({r.caveat[:60]}…)"
                  if len(r.caveat) > 60 else
                  f"  {r.tier}: contained={r.contained}  FB={r.false_block}  ({r.caveat})")
    if args.json:
        payload = board.to_dict()
        payload["saturated"] = sorted(SATURATED)
        payload["poolable"] = sorted(POOLABLE)
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(json.dumps(payload, indent=2))
        print(f"\nwrote {args.json}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
