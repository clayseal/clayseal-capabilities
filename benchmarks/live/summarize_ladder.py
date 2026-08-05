"""Summarize the model-ladder traces into the table we can actually publish.

    python -m benchmarks.live.summarize_ladder --suite banking

Reports, per model and ablation:

* **baseline** utility under `none`, the ceiling any defense is measured against;
* **autonomous** utility, the pessimistic number where a step-up counts as failure;
* **supervised** utility, where a step-up is a human confirmation that succeeds;
* **false-block**, defense-caused HARD DENY only, paired per task so a task that
  also failed undefended is not charged to the defense;
* **endorsement rate**, step-ups per task.

That last column exists because the 2026 adaptive-evaluation work (arXiv
2606.26479) names approval fatigue as an attack surface: a defense that reaches
0% ASR by asking the human to confirm everything has relocated the
vulnerability, not removed it. Publishing supervised utility without its
endorsement rate is publishing half the number, so this tool refuses to print
one without the other.

Rates carry Wilson intervals. At n=8 per suite a single task is worth 12.5
points, and a bare point estimate at that sample size invites exactly the
over-reading docs/methodology_audit.md warns about.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from benchmarks.core.stats import proportion_ci

RESULTS = Path(__file__).resolve().parent.parent / "results" / "model-ladder"


def summarize(trace: dict) -> dict:
    """Per-ablation counts, paired against `none` on the same task."""
    ablations = [a for a in next(iter(trace.values())) if a != "none"]
    baseline_ok = sum(1 for t in trace.values() if t.get("none", {}).get("success"))
    n = len(trace)

    rows = {}
    for ablation in ablations:
        autonomous = deny_loss = stepup_loss = other_loss = stepups = 0
        for task in trace.values():
            here = task.get(ablation)
            if here is None:
                continue
            stepups += here.get("n_stepup", 0)
            if here.get("success"):
                autonomous += 1
                continue
            # A failure only counts against the defense if the same task
            # succeeded undefended. Otherwise the agent simply could not do it.
            if not task.get("none", {}).get("success"):
                other_loss += 1
            elif here.get("n_deny", 0):
                deny_loss += 1
            elif here.get("n_stepup", 0):
                stepup_loss += 1
            else:
                other_loss += 1
        rows[ablation] = {
            "n": n,
            "baseline": baseline_ok,
            "autonomous": autonomous,
            "supervised": autonomous + stepup_loss,
            "false_block": deny_loss,
            "not_defense_caused": other_loss,
            "stepups": stepups,
        }
    return rows


def render(model: str, rows: dict) -> str:
    lines = [f"### {model}", ""]
    header = ["Ablation", "Baseline", "Autonomous", "Supervised",
              "False-block (hard DENY)", "Endorsements/task", "Agent-caused losses"]
    lines.append("| " + " | ".join(header) + " |")
    lines.append("| " + " | ".join("---" for _ in header) + " |")
    for ablation, r in rows.items():
        n = r["n"] or 1
        auto = proportion_ci(r["autonomous"], n)
        sup = proportion_ci(r["supervised"], n)
        fb = proportion_ci(r["false_block"], n)
        lines.append("| " + " | ".join([
            ablation,
            f"{r['baseline']}/{n} ({r['baseline']/n:.0%})",
            auto.render(),
            sup.render(),
            fb.render(),
            f"{r['stepups']/n:.2f}",
            str(r["not_defense_caused"]),
        ]) + " |")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Summarize model-ladder traces")
    p.add_argument("--suite", default="banking")
    p.add_argument("--dir", type=Path, default=RESULTS)
    args = p.parse_args(argv if argv is not None else sys.argv[1:])

    traces = sorted(args.dir.glob(f"{args.suite}-*-trace.json"))
    if not traces:
        print(f"no traces in {args.dir} for suite {args.suite}", file=sys.stderr)
        return 2

    print(f"# Live tier — {args.suite}, paired per-task attribution\n")
    print("Brackets are 95% Wilson intervals. _Baseline_ is utility with no defense, the "
          "ceiling. _False-block_ counts only hard DENYs on tasks that succeeded undefended, "
          "so a task the agent failed on its own is never charged to the defense. "
          "_Endorsements/task_ is the step-up rate: supervised utility is only meaningful "
          "beside it, because a defense that confirms everything has moved the problem to "
          "the human rather than solved it.\n")

    for trace_path in traces:
        model = trace_path.stem.removeprefix(f"{args.suite}-").removesuffix("-trace")
        try:
            trace = json.loads(trace_path.read_text())
        except json.JSONDecodeError:
            print(f"### {model}\n\n_trace unreadable (run failed)_\n")
            continue
        if not trace:
            print(f"### {model}\n\n_no tasks completed_\n")
            continue
        print(render(model, summarize(trace)))
        print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
