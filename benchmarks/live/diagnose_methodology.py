"""Methodological audit of the utility measurement.

Two flaws in how we currently read clean-utility loss:

  1. We count STEP_UP as failure. STEP_UP is a human confirmation that succeeds
     in deployment; only a hard DENY of a benign action is an unrecoverable
     false-positive. Conflating them reports the pessimistic autonomous number.
  2. We never check causation. A clean task can fail because the agent is bad
     (baseline utility is only ~60%), NOT because the defense blocked anything.
     Attributing every clean failure to the defense overstates its utility cost.

This runs each CLEAN task under `none` and under each defense on the SAME task,
so we can measure, per task:

  * defense-caused loss = succeeded under `none` but failed under the defense
    (this is the only loss the defense is actually responsible for)
  * of those, how many had a hard DENY of a benign call (real false-positive)
    vs only a STEP_UP (recoverable by a human confirmation)
  * supervised utility  = autonomous successes + step-up-recoverable losses

It also splits DENY vs STEP_UP and attributes each to its layer, and dumps the
raw per-task trace to JSON for deeper analysis.
"""
from __future__ import annotations

import argparse
import json
import statistics
import sys
from collections import Counter, defaultdict

import tempfile

from agentdojo.benchmark import get_suite, run_task_without_injection_tasks
from agentdojo.logging import OutputLogger

from benchmarks.live.run_agentdojo import build_pipeline, _oracle_map, _recipient_map
from benchmarks.live.planner import LLMPlanner
from benchmarks.live.diagnose import _gt_map, _label


def run(suite_name, model, n_user, ablations, out_path):
    from openai import OpenAI
    client = OpenAI()
    llm_planner = LLMPlanner(client, model)
    suite = get_suite("v1.2.2", suite_name)
    user_ids = list(suite.user_tasks)[:n_user]
    legit_by_query = _gt_map(suite, user_ids, suite.user_tasks)
    labelctx = (legit_by_query, set(), set())  # clean pass: no attack labels needed
    oracle_map = _oracle_map(suite, user_ids)
    recipient_map = _recipient_map(suite, user_ids)
    from benchmarks.live.run_agentdojo import OraclePlanner
    oracle_planner = OraclePlanner(oracle_map)
    planners = {"envelope": llm_planner, "envelope-taint": llm_planner,
                "oracle-envelope-egress": oracle_planner}

    # per_task[query][ablation] = {"success": bool, "deny": [...], "stepup": [...]}
    per_task: dict = defaultdict(dict)
    logdir = tempfile.mkdtemp(prefix="adojo-diag-")
    for ab in ["none"] + ablations:
        pipe, harness = build_pipeline(model, ab, planners.get(ab), recipient_map)
        for uid in user_ids:
            task = suite.user_tasks[uid]
            query = str(getattr(task, "PROMPT", uid))
            start = len(harness.decisions) if harness else 0
            with OutputLogger(logdir, live=None):
                cu, _ = run_task_without_injection_tasks(suite, pipe, task, None, True)
            decs = harness.decisions[start:] if harness else []
            legit_deny, legit_stepup = [], []
            for r in decs:
                if _label(r, labelctx) == "attack":
                    continue  # clean pass, ignore any mislabeled
                if r["outcome"] == "DENY":
                    legit_deny.append(r)
                elif r["outcome"] == "STEP_UP":
                    legit_stepup.append(r)
            per_task[query][ab] = {"success": bool(cu),
                                   "deny": legit_deny, "stepup": legit_stepup}
        print(f"  ran {ab}")

    _report(ablations, per_task, out_path)


def _report(ablations, per_task, out_path):
    queries = list(per_task)
    print(f"\n=== methodological audit ({len(queries)} clean tasks) ===\n")
    base_success = {q: per_task[q].get("none", {}).get("success", False) for q in queries}
    n_base = sum(base_success.values())
    print(f"baseline (none) clean success: {n_base}/{len(queries)} "
          f"({n_base/len(queries)*100:.0f}%)  <- ceiling for any defense\n")

    for ab in ablations:
        auto = deny_caused = stepup_caused = other_caused = 0
        deny_layers, stepup_layers = Counter(), Counter()
        for q in queries:
            rec = per_task[q].get(ab)
            if not rec:
                continue
            if rec["success"]:
                auto += 1
                continue
            # this task failed under the defense. was the defense the cause?
            if not base_success[q]:
                other_caused += 1  # also failed with no defense -> agent, not us
                continue
            if rec["deny"]:
                deny_caused += 1
                for r in rec["deny"]:
                    deny_layers[r["layer"]] += 1
            elif rec["stepup"]:
                stepup_caused += 1
                for r in rec["stepup"]:
                    stepup_layers[r["layer"]] += 1
            else:
                other_caused += 1  # defense allowed everything, task still failed
        n = len(queries)
        supervised = auto + stepup_caused  # step-ups recover with a human yes
        print(f"── {ab} ──")
        print(f"  autonomous success   {auto}/{n} ({auto/n*100:.0f}%)")
        print(f"  supervised success   {supervised}/{n} ({supervised/n*100:.0f}%)"
              f"   (+{stepup_caused} step-up-recoverable)")
        print(f"  defense-caused HARD DENY loss : {deny_caused}  layers={dict(deny_layers)}")
        print(f"  defense-caused STEP-UP loss   : {stepup_caused}  layers={dict(stepup_layers)}")
        print(f"  NOT defense-caused (agent/none): {other_caused}")
        print()

    with open(out_path, "w") as f:
        json.dump({q: {ab: {"success": per_task[q][ab]["success"],
                            "n_deny": len(per_task[q][ab]["deny"]),
                            "n_stepup": len(per_task[q][ab]["stepup"]),
                            "deny": [{"tool": r["tool"], "layer": r["layer"],
                                      "reason": r["reason"]} for r in per_task[q][ab]["deny"]]}
                       for ab in per_task[q]}
                   for q in queries}, f, indent=1)
    print(f"raw per-task trace dumped to {out_path}")


def main(argv=None):
    p = argparse.ArgumentParser()
    p.add_argument("--suite", default="banking")
    p.add_argument("--model", default="gpt-4o-mini-2024-07-18")
    p.add_argument("--n-user", type=int, default=8)
    p.add_argument("--ablations", default="envelope,envelope-taint,oracle-envelope-egress")
    p.add_argument("--out", default="/tmp/methodology_trace.json")
    args = p.parse_args(argv if argv is not None else sys.argv[1:])
    print("=== Methodological audit: paired per-task utility attribution ===")
    run(args.suite, args.model, args.n_user,
        [a.strip() for a in args.ablations.split(",")], args.out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
