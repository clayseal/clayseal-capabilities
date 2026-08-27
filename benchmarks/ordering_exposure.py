"""How much of each corpus's containment is available from event ORDER alone.

    python -m benchmarks.ordering_exposure

## The question

Every containment table in `benchmarks/results/new-suites/` reports what a rung
caught and what it wrongly blocked. Neither column can show the failure mode this
module measures: a corpus that replays a benign prefix and then an attack suffix
can be "contained" by counting. Block late events and the attack share falls,
because the attack events are the late ones. No tool, path, destination or policy
is read.

Every stateful rung is exposed to this. `deny-all` is a permanent row because a
containment number that does not beat it is not a measurement; this is the same
argument on the axis of order, and it needs its own control for the same reason.

## The comparison, and why friction has to be matched

Counting can always reach 100% containment by blocking everything, so a control
is only informative at a friction budget. For each corpus this takes the best
real rung, reads its false-block rate, and asks what a pure position cut achieves
**without exceeding that same false-block rate**. A rung that cannot beat
counting under its own friction budget is reporting the order of the corpus.

Comparing at unmatched friction is how this analysis first went wrong: on SLEIGHT
a cut at k=8 reaches 71.3% against the rung's 65.9% and looks decisive, but it
spends 20.9% false-block against the rung's 16.1%. Matched, the rung wins by ten
points. The unmatched number flattered the conclusion we were already forming.

## What it found

Four corpora are EXPOSED: `agent_threat_bench`, `asb`, `injecagent` and
`ipi_coding` all report 100% containment that a position cut also reaches at the
same zero false-block. That does not make the rungs wrong. It makes those
corpora unable to distinguish a rung from counting, so their 100% is not evidence
for the mechanism, and citing it as such would be citing the corpus's shape.

The corpora that discriminate do so decisively, which is what keeps the control
honest: RedCode 100% against counting's 0%, AgentDojo 100% against 3.9%,
mind2web_sc 98% against 0%. On those, order carries no signal at all.

SLEIGHT sits in between and is the reason this module exists: 65.9% against
counting's 55.8%, so most of what its table credits to the rate limit is
transcript order.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from statistics import median

from benchmarks.core.engines import LADDER, build_engines
from benchmarks.core.events import EventLabel
from benchmarks.core.runner import run_benchmark
from benchmarks.datasets.base import available_datasets, get_loader

#: `allow-all` and `deny-all` are the trivial controls and are never "the best
#: rung": one contains nothing, the other blocks everything.
REAL_RUNGS = [n for n in LADDER if n not in ("allow-all", "deny-all")]


def counting_at_budget(attack_pos: list[int], benign_pos: list[int],
                       budget: float, max_k: int = 60) -> tuple[float, int | None]:
    """Best containment a pure position cut reaches without exceeding `budget`."""
    best, best_k = 0.0, None
    for k in range(max_k + 1):
        friction = sum(1 for p in benign_pos if p >= k) / len(benign_pos)
        if friction > budget + 1e-9:
            continue
        caught = sum(1 for p in attack_pos if p >= k) / len(attack_pos)
        if caught > best:
            best, best_k = caught, k
    return best, best_k


def measure(name: str, limit: int = 400) -> dict | None:
    tasks = get_loader(name).load(limit=limit)
    if not tasks:
        return None
    attack_pos = [i for t in tasks for i, e in enumerate(t.events)
                  if e.label is EventLabel.ATTACK]
    benign_pos = [i for t in tasks for i, e in enumerate(t.events)
                  if e.label is EventLabel.BENIGN]
    if not attack_pos or not benign_pos:
        return None

    results = run_benchmark(tasks, build_engines(REAL_RUNGS))
    best = max(results.values(),
               key=lambda r: (r.attack_prevention_rate - r.false_block_rate))
    counted, k = counting_at_budget(attack_pos, benign_pos, best.false_block_rate)
    return {
        "corpus": name,
        "tasks": len(tasks),
        "median_benign_index": median(benign_pos),
        "median_attack_index": median(attack_pos),
        "best_rung": best.engine,
        "containment": best.attack_prevention_rate,
        "false_block": best.false_block_rate,
        "counting_at_same_false_block": counted,
        "cut": k,
        # A corpus is EXPOSED when counting alone matches the rung under the
        # rung's own friction budget. The rung may still be right; the corpus
        # cannot show it.
        #
        # A corpus where the best rung contains NOTHING is excluded from that
        # verdict rather than counted as exposed. Counting ties at zero there,
        # which is arithmetic and not a finding, and folding it in inflated the
        # exposed count from four to five.
        "exposed": (best.attack_prevention_rate > 0.0
                    and counted >= best.attack_prevention_rate - 1e-9),
        "no_signal": best.attack_prevention_rate == 0.0,
    }


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--json", type=Path, default=None)
    p.add_argument("--limit", type=int, default=400)
    args = p.parse_args(argv)

    rows, skipped, unpaired = [], [], []
    for name in sorted(available_datasets()):
        try:
            row = measure(name, limit=args.limit)
        except Exception as exc:                           # noqa: BLE001
            # Almost always an unfetched external corpus, but SAY which and why.
            # A screen that silently covers eleven corpora and reports on three
            # reads exactly like one that covered all fourteen.
            skipped.append(f"{name} ({type(exc).__name__})")
            continue
        if row:
            rows.append(row)
        else:
            # Loaded fine, but carries only one label, so there is no benign
            # side to place an attack against and the question does not arise.
            # Reported rather than dropped, because "not applicable" and
            # "not run" look identical in a table that omits both.
            unpaired.append(name)

    print("| corpus | med benign idx | med attack idx | best rung | containment | "
          "false-block | counting at same false-block | verdict |")
    print("| --- | ---: | ---: | --- | ---: | ---: | ---: | --- |")
    for r in rows:
        print(f"| {r['corpus']} | {r['median_benign_index']:.0f} | "
              f"{r['median_attack_index']:.0f} | `{r['best_rung']}` | "
              f"{100 * r['containment']:.1f}% | {100 * r['false_block']:.1f}% | "
              f"{100 * r['counting_at_same_false_block']:.1f}% | "
              f"{'no signal' if r['no_signal'] else '**EXPOSED**' if r['exposed'] else 'discriminates'} |")

    exposed = [r["corpus"] for r in rows if r["exposed"]]
    print(f"\n{len(exposed)} of {len(rows)} corpora are ordering-exposed: "
          f"{', '.join(exposed) if exposed else 'none'}.")
    print("An exposed corpus cannot distinguish a rung from counting. That is a "
          "statement about the corpus, not about the rung.")
    total = len(rows) + len(skipped) + len(unpaired)
    if unpaired:
        print(f"\nNot applicable ({len(unpaired)}): {', '.join(unpaired)}. "
              f"Single-label corpora, so there is no benign side to place an "
              f"attack against.")
    if skipped:
        print(f"\nNot screened ({len(skipped)}): {', '.join(skipped)}.")
    print(f"\nCoverage of this analysis: {len(rows)} screened, "
          f"{len(unpaired)} not applicable, {len(skipped)} not runnable, "
          f"of {total} registered corpora.")

    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(json.dumps(rows, indent=2))
        print(f"\nwrote {args.json}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
