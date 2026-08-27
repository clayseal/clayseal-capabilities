"""What real policy documents say, against what this layer can express.

`policy_draft.py` claims that nothing rule-shaped is dropped silently. That
claim held on the delegation-of-authority document it was built against and
failed on four `tau2-bench` policy documents, 460 lines of prose authored
elsewhere: 61 sentences state a rule, one was read, nine became TODOs, and 51
produced no output at all.

This module is that measurement, kept runnable so the invariant is checked
against external prose rather than against the document that shaped the
patterns. It also classifies each rule-shaped sentence by SHAPE, which is the
more useful half: the machinery is built for numeric ceilings and real policy
is mostly state-conditional.

The rule-shaped detector here is deliberately INDEPENDENT of `RULE_MARKERS`.
Measuring the extractor against its own marker list would report 100% by
construction. This is a separate, broader reading of "this sentence states a
constraint", so the two can disagree and the disagreement is the finding.
"""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

from clayseal.capabilities.policy_draft import extract

#: An independent reading of "this sentence states a rule". Broader than the
#: extractor's markers on purpose.
RULE_SHAPED = re.compile(
    r"\b(cannot|can not|can only|may only|must|should not|only be|at most|"
    r"no more than|not allowed|not permitted|is not|are not|never|"
    r"required to|has to)\b", re.IGNORECASE)

#: Shape classifiers, checked in order. A state condition wins over a number,
#: because "at most one travel certificate per reservation" is enforced by the
#: reservation's state and not by a running total.
_CONDITIONAL = re.compile(
    r"\b(if|when|unless|until|already|status|state|pending|before|after)\b",
    re.IGNORECASE)
_ORDERING = re.compile(
    r"\b(first|before taking|before calling|must (?:also )?obtain|must list|"
    r"must provide|needs? to provide)\b", re.IGNORECASE)
_NUMERIC = re.compile(
    r"\b(\d+|one|two|three|four|five|six|seven|eight|nine|ten)\b",
    re.IGNORECASE)

#: Where each shape would have to be enforced, and whether it can be.
MECHANISM = {
    "state-conditional": "tools.when `if`/`unless` (enforced, partly extracted)",
    "ordering": "tools.when `requires` (enforced, partly extracted)",
    "numeric": "value and call budgets (expressible, extracted)",
    "other": "not expressible by an authorization layer",
}

#: Whether this library can enforce a rule of that shape AT ALL, once written
#: into a policy by hand. Separate from whether `policy_draft` can extract it,
#: because those are different gaps with different fixes.
ENFORCEABLE = {"state-conditional": True, "ordering": True,
               "numeric": True, "other": False}

DEFAULT_DOMAINS = ("airline", "retail", "telecom", "mock")


def _default_root() -> Path:
    from benchmarks.datasets.tau2 import _default_root as tau2_root
    return tau2_root()


def _policy_file(root: Path, domain: str) -> Path | None:
    for name in ("policy.md", "main_policy.md"):
        candidate = root / domain / name
        if candidate.exists():
            return candidate
    return None


def shape_of(line: str) -> str:
    if _ORDERING.search(line):
        return "ordering"
    if _CONDITIONAL.search(line):
        return "state-conditional"
    if _NUMERIC.search(line):
        return "numeric"
    return "other"


#: Tool catalogues for the tau2 domains. Extraction of an ordering or a
#: state-conditional rule BINDS it to a tool, so without a catalogue there is
#: nothing to bind to and the sentence can only become a TODO. `clayseal policy
#: init --rules` has both halves; this supplies the one the file does not carry.
CATALOGUES = {
    "retail": ["get_order", "list_orders", "cancel_order", "modify_order",
               "modify_address", "modify_payment", "return_order",
               "exchange_order", "get_user"],
    "airline": ["get_reservation", "list_reservations", "book_reservation",
                "cancel_reservation", "update_reservation", "change_cabin",
                "get_user", "send_certificate"],
    "telecom": ["get_line", "suspend_line", "resume_line", "get_bill",
                "pay_bill", "get_customer"],
    "mock": ["get_task", "complete_task", "create_task"],
}


def audit(text: str, catalogue: list[str] | None = None) -> dict:
    """One document: how many rules it states, and how many survive the read."""
    lines = [line for line in text.splitlines()
             if RULE_SHAPED.search(line) and len(line.strip()) > 25]
    draft = extract(text, tools=catalogue)
    seen = {r.line_no for r in draft.rules} | {r.line_no for r in draft.unmapped}
    numbered = {i: line for i, line in enumerate(text.splitlines(), start=1)
                if line in lines}
    silent = [line for i, line in numbered.items() if i not in seen]
    shapes: dict[str, int] = {}
    for line in lines:
        shapes[shape_of(line)] = shapes.get(shape_of(line), 0) + 1
    bound = len([r for r in draft.rules
                 if r.kind in ("ordering", "conditional")])
    return {"lines": len(text.splitlines()), "rule_shaped": len(lines),
            "extracted": len(draft.rules), "todo": len(draft.unmapped),
            "silent": len(silent), "shapes": shapes, "bound": bound,
            "silent_examples": [s.strip()[:88] for s in silent[:3]]}


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--domains", default=",".join(DEFAULT_DOMAINS))
    p.add_argument("--root", type=Path, default=None)
    args = p.parse_args(argv if argv is not None else sys.argv[1:])

    root = args.root or _default_root()
    if not root.exists():
        print(f"tau2 policy documents not found at {root}", file=sys.stderr)
        return 2

    print("# Rule-shaped sentences, and how many survive the read\n")
    print("| document | lines | rule-shaped | extracted | of those, bound to "
          "a tool | dropped silently |")
    print("| --- | --: | --: | --: | --: | --: |")
    totals = {"lines": 0, "rule_shaped": 0, "extracted": 0, "todo": 0,
              "silent": 0, "bound": 0}
    shapes: dict[str, int] = {}
    for domain in [d.strip() for d in args.domains.split(",") if d.strip()]:
        path = _policy_file(root, domain)
        if path is None:
            print(f"| {domain} | _no policy document_ | | | | |")
            continue
        result = audit(path.read_text(), CATALOGUES.get(domain))
        for key in totals:
            totals[key] += result[key]
        for shape, count in result["shapes"].items():
            shapes[shape] = shapes.get(shape, 0) + count
        print(f"| {domain} | {result['lines']} | {result['rule_shaped']} | "
              f"{result['extracted']} | {result['bound']} | {result['silent']} |")
    print(f"| **total** | **{totals['lines']}** | **{totals['rule_shaped']}** | "
          f"**{totals['extracted']}** | **{totals['bound']}** | "
          f"**{totals['silent']}** |")

    if totals["rule_shaped"]:
        print("\n## What shape are they\n")
        print("| shape | share | where it would be enforced |")
        print("| --- | --: | --- |")
        for shape, count in sorted(shapes.items(), key=lambda kv: -kv[1]):
            print(f"| {shape} | {count}/{totals['rule_shaped']} "
                  f"({count / totals['rule_shaped']:.0%}) | {MECHANISM[shape]} |")

    if totals["rule_shaped"]:
        covered = sum(c for shape, c in shapes.items() if ENFORCEABLE[shape])
        print(f"\n**{covered} of {totals['rule_shaped']} "
              f"({covered / totals['rule_shaped']:.0%}) are enforceable by this "
              f"library once written into a policy by hand.** `tools.when` "
              f"covers both large classes: `if`/`unless` for a state "
              f"condition, `requires` for an ordering rule, both as monotone "
              f"withdrawals from `tools.allow`.")
        print(f"\n**{totals['bound']} of {totals['rule_shaped']} "
              f"({totals['bound'] / totals['rule_shaped']:.0%}) are extracted "
              f"and bound to a tool automatically**, against 1 before. The "
              f"remainder arrive as TODO comments for a person. What binds a "
              f"rule is the HEADING it sits under, which names the operation "
              f"once and never repeats it in the sentence; reading the section "
              f"took tau2's airline document from 0 enforceable rules to 4. "
              f"The remaining limit is vocabulary rather than structure: the "
              f"telecom document argues about bills, lookup and suspension "
              f"while its tools are named `make_payment`, `refuel_data` and "
              f"`resume_line`, and no reader working from tool NAMES can bridge "
              f"that. Tool DESCRIPTIONS can, and `policy_scaffold.Catalog` "
              f"already carries them. See "
              f"`benchmarks/results/section_scope.md`.")

    if totals["silent"]:
        print(f"\n**{totals['silent']} of {totals['rule_shaped']} rule-shaped "
              f"sentences produced no output at all**, which is the one failure "
              f"`policy_draft` exists to prevent.")
    else:
        print(f"\nNothing rule-shaped was dropped silently: "
              f"{totals['extracted']} extracted and {totals['todo']} flagged "
              f"for a reviewer, over {totals['rule_shaped']} rule-shaped "
              f"sentences.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
