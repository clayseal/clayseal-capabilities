"""Summarize the model-ladder traces into the table we can actually publish.

    python -m benchmarks.live.summarize_ladder --suite banking

Reports, per model and ablation:

* **baseline** utility under `none`, the ceiling any defense is measured against;
* **autonomous** utility, the pessimistic number where a step-up counts as failure;
* **supervised_counterfactual** utility, where a step-up is ASSUMED to be a
  human confirmation that succeeds. It is arithmetic, not a measurement: it
  assumes the human approved AND that the task then succeeded, and neither
  was ever checked. `LiveBrokerHarness.gate_with_supervision` plus a real
  approver produces the measured column; the delta is a finding in itself
  and is likely negative, because a resumed run can still fail downstream;
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
            # RENAMED, deliberately. This is arithmetic: it adds the step-up
            # losses back and assumes both that a human would have approved and
            # that the task then succeeded. Neither was ever checked. The
            # measured column comes from `gate_with_supervision` with a real
            # approver, and the delta between the two is a publishable finding
            # likely negative, because a resumed run can still fail downstream.
            "supervised_counterfactual": autonomous + stepup_loss,
            "false_block": deny_loss,
            "not_defense_caused": other_loss,
            "stepups": stepups,
        }
    return rows


def action_level(trace: dict) -> dict:
    """Per-action friction, which is far less noisy than task-binary utility.

    Task-binary scoring makes one task worth 12.5 points at n=8, and that
    granularity is most of why our live numbers swing between runs: a task
    completing nine of ten steps scores identically to one that does nothing.
    Counting decisions instead gives a denominator in the hundreds on the same
    data, so a difference of a few points becomes readable without buying more
    inference. It answers a slightly different question, "what fraction of the
    agent's attempted actions did we block" rather than "what fraction of jobs
    finished", and both belong in the table.
    """
    out = {}
    ablations = [a for a in next(iter(trace.values())) if a != "none"]
    for ablation in ablations:
        denies = stepups = 0
        for task in trace.values():
            here = task.get(ablation) or {}
            denies += here.get("n_deny", 0)
            stepups += here.get("n_stepup", 0)
        out[ablation] = {"denies": denies, "stepups": stepups}
    return out


def render(model: str, rows: dict) -> str:
    lines = [f"### {model}", ""]
    header = ["Ablation", "Baseline", "Autonomous", "Supervised",
              "False-block (hard DENY)", "Endorsements/task", "Agent-caused losses"]
    lines.append("| " + " | ".join(header) + " |")
    lines.append("| " + " | ".join("---" for _ in header) + " |")
    for ablation, r in rows.items():
        n = r["n"] or 1
        auto = proportion_ci(r["autonomous"], n)
        sup = proportion_ci(r["supervised_counterfactual"], n)
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


def matrix(directory: Path, suites: list[str], ablation: str) -> str:
    """One ablation across every model and suite.

    The per-suite tables answer "what does this cost here"; this answers
    "does the result survive changing the model", which is the question a
    single-model number cannot address. Cells are autonomous utility over the
    undefended baseline for that model and suite, because a bare utility figure
    is unreadable when baselines differ by 60 points across models.
    """
    data: dict[str, dict[str, str]] = {}
    for path in sorted(directory.glob("*-trace.json")):
        stem = path.stem.removesuffix("-trace")
        suite = next((s for s in suites if stem.startswith(f"{s}-")), None)
        if suite is None:
            continue
        model = stem[len(suite) + 1:]
        try:
            rows = summarize(json.loads(path.read_text()))
        except (json.JSONDecodeError, StopIteration):
            continue
        row = rows.get(ablation)
        if not row or not row["n"]:
            continue
        data.setdefault(model, {})[suite] = (
            f"{row['autonomous'] / row['n']:.0%} / {row['baseline'] / row['n']:.0%}"
        )

    lines = [f"### `{ablation}`, autonomous utility / undefended baseline", ""]
    header = ["Model", *suites]
    lines.append("| " + " | ".join(header) + " |")
    lines.append("| " + " | ".join("---" for _ in header) + " |")
    for model in sorted(data):
        lines.append("| " + " | ".join([model, *(data[model].get(s, "-") for s in suites)]) + " |")
    lines += [
        "",
        "Each cell is utility under the defense over utility with no defense at all, on the "
        "same tasks. Reading the left number alone compares models, not defenses: these "
        "baselines span a wide range, so a low cell can mean a weak agent rather than an "
        "expensive defense.",
    ]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Summarize model-ladder traces")
    p.add_argument("--suite", default="banking")
    p.add_argument("--dir", type=Path, default=RESULTS)
    p.add_argument("--matrix", action="store_true",
                   help="cross-model view: one ablation across every model and suite")
    p.add_argument("--suites", default="banking,slack,travel,workspace")
    p.add_argument("--ablation", default="envelope")
    args = p.parse_args(argv if argv is not None else sys.argv[1:])

    if args.matrix:
        suites = [s.strip() for s in args.suites.split(",") if s.strip()]
        print("# Live tier, cross-model matrix\n")
        for ablation in ("envelope", "envelope-taint", "oracle-envelope-egress"):
            print(matrix(args.dir, suites, ablation))
            print()
        return 0

    traces = sorted(args.dir.glob(f"{args.suite}-*-trace.json"))
    if not traces:
        print(f"no traces in {args.dir} for suite {args.suite}", file=sys.stderr)
        return 2

    print(f"# Live tier, {args.suite}, paired per-task attribution\n")
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
        actions = action_level(trace)
        if any(v["denies"] or v["stepups"] for v in actions.values()):
            print("Action-level counts (same runs, less noisy denominator):\n")
            print("| Ablation | hard DENYs | step-ups |")
            print("| --- | --: | --: |")
            for ablation, v in actions.items():
                print(f"| {ablation} | {v['denies']} | {v['stepups']} |")
            print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
