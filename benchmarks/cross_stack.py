"""Cross-corpus measurement on the shared DeployableStack.

One system, every corpus: SessionBroker via ``DeployableStack`` (same profile
as CTR ``shared_stack`` arms and live AgentDojo). Ladder engines remain an
ablation / monotone construction check — not the headline product number.

    python -m benchmarks.cross_stack
    python -m benchmarks.cross_stack --quick
    python -m benchmarks.cross_stack --json benchmarks/results/cross_stack.json
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from benchmarks.core.broker_eval import STACK_NAME, run_broker_benchmark
from benchmarks.core.engines import build_engines
from benchmarks.core.runner import run_benchmark
from benchmarks.datasets import get_loader

# Full DeployableStack table. ``--quick`` uses the first five (content + target).
CORPORA = [
    "redcode",
    "agentharm",
    "sleight",
    "ipi_coding",
    "mcp_attack",
    "asb",
    "advbench_agent",
    "agent_threat_bench",
    "mind2web_sc",
    "b3",
]

# How to read a row: allowlist-saturated target escapes vs content/covert harm.
CORPUS_TAG = {
    "redcode": "TARGET",
    "ipi_coding": "TARGET",
    "mcp_attack": "TARGET",
    "asb": "SATURATED",
    "advbench_agent": "SATURATED",
    "agent_threat_bench": "SATURATED",
    "agentharm": "CONTENT",
    "sleight": "CONTENT",
    "mind2web_sc": "HONESTY",
    "b3": "HONESTY",  # constructed TI tool-calls; not b3's own LLM refusal scorer
}

LADDER_TOP = "task-scope+binding+budget"

# Corpora that enable surprise-egress declaration (goal must not already
# request send/post/upload — see SessionBroker.require_declaration_for_egress).
EGRESS_DECLARATION_CORPORA = frozenset({
    "agentharm",
    "mcp_attack",
    "advbench_agent",
})


def evaluate(
    corpora: list[str],
    *,
    entailment: bool = True,
    require_declaration_for_egress: bool | None = None,
) -> dict:
    from agentauth.capabilities.monitor.llm_clients import default_entailment_judge

    judge = default_entailment_judge() if entailment else None
    rows = []
    for name in corpora:
        try:
            tasks = list(get_loader(name).load())
        except Exception as exc:
            rows.append({
                "corpus": name,
                "tag": CORPUS_TAG.get(name, ""),
                "error": str(exc),
            })
            continue
        ladder = run_benchmark(
            tasks, [e for e in build_engines() if e.name == LADDER_TOP]
        )[LADDER_TOP]
        # Default OFF: even the refined surprise-egress gate still soft-FBs
        # some MCP/AdvBench benign sends. Opt in per corpus via True, or pass
        # require_declaration_for_egress=False explicitly.
        if require_declaration_for_egress is None:
            egress_decl = False
        elif require_declaration_for_egress is True:
            egress_decl = name in EGRESS_DECLARATION_CORPORA
        else:
            egress_decl = False
        stack = run_broker_benchmark(
            tasks,
            entailment_judge=judge,
            require_declaration_for_egress=egress_decl,
        )
        rows.append({
            "corpus": name,
            "tag": CORPUS_TAG.get(name, ""),
            "profile": STACK_NAME,
            "n_attack": stack.n_attack,
            "n_benign": stack.n_benign,
            "stack_union": round(stack.attack_prevention_rate, 4),
            "stack_hard": round(stack.hard_attack_prevention_rate, 4),
            "stack_soft": round(stack.soft_attack_prevention_rate, 4),
            "stack_false_block": round(stack.false_block_rate, 4),
            "stack_hard_fb": round(stack.hard_false_block_rate, 4),
            "stack_soft_fb": round(stack.soft_false_block_rate, 4),
            "ladder_contained": round(ladder.attack_prevention_rate, 4),
            "ladder_false_block": round(ladder.false_block_rate, 4),
            "entailment_judge": judge is not None,
            "require_declaration_for_egress": egress_decl,
        })
    note = (
        "SessionBroker via DeployableStack. "
        "hard = DENY (floor/declaration); soft = STEP_UP (content/sealed-plan); "
        "union = autonomous halt. Never quote soft as hard ASR. "
        "Tags: TARGET = path/dest escape; SATURATED = allowlist-shaped (~100% hard); "
        "CONTENT = meaning/covert; HONESTY = under-scored / constructed-event rows. "
        "AgentLeak is a flow probe (see `python -m benchmarks.agentleak_flow`), "
        "not a ladder ATTACK-event headline. "
        "ladder_* is the monotone floor ablation."
    )
    return {
        "profile": STACK_NAME,
        "note": note,
        "rows": rows,
    }


def _youden(row: dict) -> str:
    """Containment + completion - 1, the score neither trivial control wins.

    Both columns are already in this table and each is trivially winnable
    alone: refuse everything for Union, allow everything for FB. J is 0 for
    both — refuse-all gives 1 + 0 - 1, allow-all gives 0 + 1 - 1 — so a row
    near zero achieved nothing however good either half looks.

    Folded in here rather than computed by a second harness. It was briefly a
    separate module (`joint_external.py`) recomputing these same numbers from
    the same `run_broker_benchmark` call, which is the duplication this project
    keeps paying for: two paths to one measurement drift, and then a benchmark
    is scoring a copy of the system.
    """
    if not row.get("n_attack"):
        return "—"      # no attacks: containment undefined, so J is too
    contained = row["stack_union"]
    completed = 1.0 - row["stack_hard_fb"] - row["stack_soft_fb"]
    return f"{contained + completed - 1:.2f}"


def render(payload: dict) -> str:
    lines = [
        "# Cross-stack generalizability",
        "",
        payload["note"],
        "",
        "| Corpus | Tag | Hard | Soft | Union | FB (h/s) | J | Ladder | n |",
        "| --- | --- | --: | --: | --: | --: | --: | --: | --- |",
    ]
    for r in payload["rows"]:
        tag = r.get("tag") or ""
        if "error" in r:
            lines.append(
                f"| {r['corpus']} | {tag} | — | — | — | — | — | — | "
                f"{r['error'][:40]} |"
            )
            continue
        lines.append(
            f"| {r['corpus']} | {tag} | {100 * r['stack_hard']:.1f}% | "
            f"{100 * r['stack_soft']:.1f}% | "
            f"{100 * r['stack_union']:.1f}% | "
            f"{100 * r['stack_hard_fb']:.1f}/{100 * r['stack_soft_fb']:.1f}% | "
            f"{_youden(r)} | "
            f"{100 * r['ladder_contained']:.1f}% | "
            f"{r['n_attack']}a/{r['n_benign']}b |"
        )
    lines.append("")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--quick", action="store_true")
    p.add_argument("--no-entailment", action="store_true",
                   help="disable LLM entailment (det soft content still on)")
    p.add_argument(
        "--egress-declaration",
        action="store_true",
        help="enable surprise-egress declaration STEP_UP on EGRESS_DECLARATION_CORPORA",
    )
    p.add_argument("--json", type=Path, default=None)
    p.add_argument("--md", type=Path,
                   default=Path("benchmarks/results/cross_stack.md"))
    args = p.parse_args(argv)
    corpora = CORPORA[:5] if args.quick else CORPORA
    egress = True if args.egress_declaration else False
    payload = evaluate(
        corpora,
        entailment=not args.no_entailment,
        require_declaration_for_egress=egress,
    )
    text = render(payload)
    print(text)
    if args.md:
        args.md.parent.mkdir(parents=True, exist_ok=True)
        args.md.write_text(text)
        print(f"wrote {args.md}", file=sys.stderr)
    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(json.dumps(payload, indent=2))
        print(f"wrote {args.json}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
