"""Head-to-head matrix: multi-model x multi-suite x multi-repeat, reporting the
metric triple (ASR, utility-under-attack, friction) with mean and spread across
repeats, for the deployable Clay Seal path against AgentDojo's published built-in
defenses under one protocol.

This is the shared-protocol, multi-seed, deployable-path evaluation the SOTA bar
demands (arXiv:2606.26479, arXiv:2505.18333): same models, same attack, same
suites, same metrics for every defense, repeats for confidence, and the DEPLOYABLE
provenance path (not the oracle) as the headline. CaMeL / Progent are not built-in
AgentDojo defenses; adding them is a separate integration (their repos + a py3.12
env) tracked in docs/head_to_head_plan.md.

    # validate the plan without any API calls or the live stack (runs anywhere):
    python -m benchmarks.live.run_matrix --dry-run
    # small live pilot (needs OPENAI_API_KEY and the py3.12 agentdojo env):
    OPENAI_API_KEY=... python -m benchmarks.live.run_matrix --pilot --out results/matrix
    # full matrix (long; run on a VM):
    OPENAI_API_KEY=... python -m benchmarks.live.run_matrix --out results/matrix
"""
from __future__ import annotations

import argparse
import json
import statistics
import sys
from pathlib import Path

# Defenses under one protocol: undefended baseline, AgentDojo's three published
# built-ins, and the deployable Clay Seal path (provenance-seeded, NOT oracle).
DEFAULT_ABLATIONS = [
    "none",
    "builtin:tool_filter",
    "builtin:spotlighting_with_delimiting",
    "builtin:repeat_user_prompt",
    "envelope-taint",
    "envelope-taint-graduated",
]
DEPLOYABLE = {"envelope-taint", "envelope-taint-graduated"}  # never use the oracle map
KNOWN_ABLATION_PREFIXES = ("none", "floor", "envelope", "oracle", "builtin:")
DEFAULT_MODELS = ["gpt-4o-mini-2024-07-18", "gpt-4o-2024-05-13"]
DEFAULT_SUITES = ["banking", "slack", "travel", "workspace"]
DEFAULT_ATTACKS = ["important_instructions", "envelope_aware"]  # static + defense-aware


def _valid_ablation(ab: str) -> bool:
    return any(ab == p or ab.startswith(p) for p in KNOWN_ABLATION_PREFIXES)


def plan(models, suites, ablations, attacks, n_user, n_inj, repeats):
    cells = []
    for model in models:
        for suite in suites:
            for attack in attacks:
                for rep in range(repeats):
                    cells.append(dict(model=model, suite=suite, attack=attack, rep=rep))
    api_calls = len(cells) * len(ablations) * (n_user + n_user * n_inj)  # clean + attacked
    return cells, api_calls


def aggregate(rows: list[dict]) -> dict:
    """Mean and spread of the metric triple across repeats of one config cell."""
    def ms(key):
        vals = [r[key] for r in rows if key in r]
        if not vals:
            return None
        return dict(mean=statistics.fmean(vals),
                    sd=(statistics.pstdev(vals) if len(vals) > 1 else 0.0), n=len(vals))
    return {"asr": ms("asr"), "utility_under_attack": ms("utility_under_attack"),
            "clean_utility": ms("clean_utility"), "friction": ms("friction")}


def run_live(models, suites, ablations, attacks, n_user, n_inj, repeats, out_dir):
    from benchmarks.live.run_agentdojo import run  # lazy: needs agentdojo (py3.12)

    out_dir.mkdir(parents=True, exist_ok=True)
    raw: dict = {}
    for model in models:
        for suite in suites:
            for attack in attacks:
                for rep in range(repeats):
                    key = f"{model}|{suite}|{attack}|r{rep}"
                    print(f"\n### {key}")
                    try:
                        res = run(suite, model, n_user, n_inj, ablations, attack)
                    except Exception as exc:  # keep the matrix going; record the failure
                        print(f"  FAILED: {type(exc).__name__}: {exc}", file=sys.stderr)
                        raw[key] = {"error": f"{type(exc).__name__}: {exc}"}
                        continue
                    raw[key] = res
                    (out_dir / "raw.json").write_text(json.dumps(raw, indent=2))
    # Aggregate across repeats per (model, suite, attack, ablation).
    agg: dict = {}
    for key, res in raw.items():
        if "error" in res:
            continue
        model, suite, attack, _ = key.split("|")
        for ab, metrics in res.items():
            agg.setdefault(f"{model}|{suite}|{attack}|{ab}", []).append(metrics)
    summary = {k: aggregate(v) for k, v in agg.items()}
    (out_dir / "summary.json").write_text(json.dumps(summary, indent=2))
    _write_markdown(summary, out_dir / "summary.md")
    print(f"\nwrote {out_dir}/summary.json and summary.md")
    return summary


def _write_markdown(summary: dict, path: Path) -> None:
    lines = ["# Head-to-head matrix (ASR / utility-under-attack / friction)", "",
             "Mean across repeats; +-sd. Deployable Clay Seal path is provenance-seeded, not oracle.", "",
             "| model | suite | attack | defense | ASR | util-under-attack | friction/task |",
             "|---|---|---|---|--:|--:|--:|"]
    for key in sorted(summary):
        model, suite, attack, ab = key.split("|")
        s = summary[key]
        def cell(m):
            return f"{m['mean']*100:.1f}±{m['sd']*100:.1f}" if m else "-"
        fr = s["friction"]
        frc = f"{fr['mean']:.2f}±{fr['sd']:.2f}" if fr else "-"
        lines.append(f"| {model} | {suite} | {attack} | {ab} | {cell(s['asr'])} | "
                     f"{cell(s['utility_under_attack'])} | {frc} |")
    path.write_text("\n".join(lines) + "\n")


def main(argv=None):
    p = argparse.ArgumentParser(description="Clay Seal head-to-head benchmark matrix")
    p.add_argument("--models", default=",".join(DEFAULT_MODELS))
    p.add_argument("--suites", default=",".join(DEFAULT_SUITES))
    p.add_argument("--ablations", default=",".join(DEFAULT_ABLATIONS))
    p.add_argument("--attacks", default=",".join(DEFAULT_ATTACKS))
    p.add_argument("--n-user", type=int, default=6)
    p.add_argument("--n-inj", type=int, default=3)
    p.add_argument("--repeats", type=int, default=3)
    p.add_argument("--out", type=Path, default=Path("benchmarks/results/matrix"))
    p.add_argument("--dry-run", action="store_true", help="validate config + print plan, no API calls")
    p.add_argument("--pilot", action="store_true", help="tiny: n_user=2 n_inj=1 repeats=1 one model")
    args = p.parse_args(argv if argv is not None else sys.argv[1:])

    models = [m.strip() for m in args.models.split(",") if m.strip()]
    suites = [s.strip() for s in args.suites.split(",") if s.strip()]
    ablations = [a.strip() for a in args.ablations.split(",") if a.strip()]
    attacks = [a.strip() for a in args.attacks.split(",") if a.strip()]
    n_user, n_inj, repeats = args.n_user, args.n_inj, args.repeats
    if args.pilot:
        models, n_user, n_inj, repeats = models[:1], 2, 1, 1

    bad = [a for a in ablations if not _valid_ablation(a)]
    if bad:
        print(f"error: unknown ablation(s): {bad}", file=sys.stderr)
        return 2
    cells, api_calls = plan(models, suites, ablations, attacks, n_user, n_inj, repeats)
    deployable = sorted(set(ablations) & DEPLOYABLE)
    print("=== Clay Seal head-to-head matrix ===")
    print(f"models   : {models}")
    print(f"suites   : {suites}")
    print(f"attacks  : {attacks}  (static + defense-aware)")
    print(f"defenses : {ablations}")
    print(f"           deployable (no oracle): {deployable}")
    print(f"n_user={n_user} n_inj={n_inj} repeats={repeats}")
    print(f"config cells: {len(cells)}  ->  ~{api_calls} agent runs "
          f"(x model tool-calls). Rough; excludes retries.")
    if args.dry_run:
        print("\n[dry-run] config valid; no API calls made.")
        return 0
    run_live(models, suites, ablations, attacks, n_user, n_inj, repeats, args.out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
