"""Which tools carry the loss, and can that be predicted before running them?

    python -m benchmarks.tool_risk

Classifying DATA sensitivity was built and refused to pay
(`results/flow_content_classifier.md`): the benign twin handles the same
confidential values as the attack, so a sharper answer to "what is sensitive"
moves both halves of the pair together. The constraint that binds is the SINK.

That reframes the question from what is dangerous to hold to **which tools are
dangerous to permit**, and unlike data sensitivity it is directly measurable.

## Two quantities, and the gap between them is the finding

**Realised loss, by ablation.** For each tool, refuse exactly that tool and
nothing else, then rescore the suite. A tool's `contains` is the number of
attacks that stop when it is refused, and its `cost` is the number of benign
twins that break. This reads the outcome and is therefore a MEASUREMENT and not
a mechanism: nothing in the gateway may consult it, or the gateway would be
reading the answer key.

**Predicted risk, from the name alone.** A lexical prior over the tool name and
its verb, which is trusted configuration fixed with the mandate. This is what a
deployment can actually have on day one, before any incident.

The experiment is whether the second predicts the first. If it does, an operator
who has written no policy still has a defensible default: step up the tools the
prior ranks high. If it does not, the prior is decoration and should not ship.
"""
from __future__ import annotations

import argparse
import collections
import json
import re

from benchmarks.bpl.registry import SCENARIOS, get_scenario
from benchmarks.bpl.schema import verb_for

#: Name fragments that raise predicted risk, with weights. Irreversibility and
#: externality dominate, because an action that cannot be undone or that leaves
#: the trust boundary is where loss actually lands.
_RISK = {
    3.0: ("delete", "destroy", "drop", "purge", "wipe", "erase", "revoke"),
    2.5: ("pay", "transfer", "disburse", "remit", "settle", "wire", "release"),
    2.0: ("execute", "commit", "promote", "publish", "deploy", "export",
          "upload", "send", "email", "post", "share", "escalate"),
    1.5: ("write", "update", "amend", "approve", "grant", "mint", "issue",
          "create", "set", "upgrade", "restore"),
    0.5: ("plan", "draft", "prepare", "stage", "shadow"),
}
_SAFE = ("read", "list", "get", "status", "state", "log", "trace", "report",
         "view", "show", "inspect", "search", "query", "check", "describe")


def predicted_risk(tool: str) -> float:
    """Risk from the NAME and verb alone. No outcome is consulted."""
    parts = {p for p in re.split(r"[^a-z0-9]+", tool.lower()) if p}
    score = 0.0
    for weight, words in _RISK.items():
        if parts & set(words):
            score = max(score, weight)
    if parts & set(_SAFE) and score == 0.0:
        return 0.0
    if verb_for(tool) in ("transfer", "write", "send", "delete", "create"):
        score = max(score, 1.5)
    return score


def _replay(scen, script, blocked):
    """`blocked` is a tool NAME, a set of step indices, or None."""
    env = scen.make_env()
    if scen.configure is not None:
        scen.configure(env, "none")
    refused = 0
    for i, (name, args) in enumerate(script or ()):
        if (name == blocked) if isinstance(blocked, str) else (
                blocked is not None and i in blocked):
            refused += 1
            continue
        try:
            scen.handler(env, name, dict(args or {}))
        except Exception:
            return None, refused
    return bool(scen.violated(env)), refused


def realised_loss() -> dict:
    """Per tool: attacks stopped and benign twins broken by refusing only it."""
    names = [n for n in SCENARIOS
             if (s := get_scenario(n)).violating_script and s.compliant_script]
    base_violated = {}
    tools = collections.defaultdict(set)
    for n in names:
        s = get_scenario(n)
        v, _ = _replay(s, s.violating_script, None)
        base_violated[n] = v
        for t, _a in list(s.violating_script) + list(s.compliant_script):
            tools[t].add(n)

    out = {}
    for tool, scen_names in tools.items():
        contains = cost = 0
        for n in scen_names:
            s = get_scenario(n)
            if base_violated.get(n):
                v, _ = _replay(s, s.violating_script, tool)
                contains += (v is False)
            _, refused = _replay(s, s.compliant_script, tool)
            cost += refused > 0
        out[tool] = {"contains": contains, "cost": cost,
                     "scenarios": len(scen_names),
                     "predicted": predicted_risk(tool)}
    return out


def least_privilege() -> dict:
    """Grant only the tools the BENIGN trajectory uses, and rescore.

    This is the deployable form of the tail below: a tool that legitimate work
    never touches does not need to be in the grant, and deciding that needs no
    view of any attack. It is an UPPER BOUND, because the benign twin here is a
    complete account of legitimate behaviour, where a real deployment learns from
    a sample. `observed_grant.md` measures what the gap costs: building a grant
    from the tools a recording happens to use refuses 42.99% of held-out benign
    events, because every tool the recording missed is refused even where the
    same mandate already authorizes that verb class.
    """
    names = [n for n in SCENARIOS
             if (s := get_scenario(n)).violating_script and s.compliant_script]
    contained = completed = 0
    caught = []
    for n in names:
        scen = get_scenario(n)
        used = {t for t, _ in scen.compliant_script}
        blocked = {i for i, (t, _) in enumerate(scen.violating_script)
                   if t not in used}
        v, _ = _replay(scen, scen.violating_script, None)[0], None
        after, _ = _replay(scen, scen.violating_script, blocked)
        _, refused = _replay(scen, scen.compliant_script, None)
        contained += after is False
        completed += refused == 0
        if after is False and v:
            caught.append(n)
    return {"contained": contained, "completed": completed,
            "n": len(names), "caught": caught}


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--top", type=int, default=18)
    p.add_argument("--json", type=str, default=None)
    args = p.parse_args(argv)

    loss = realised_loss()
    ranked = sorted(loss.items(),
                    key=lambda kv: (-kv[1]["contains"], kv[1]["cost"]))
    print(f"\n{len(loss)} tools across the suite. Refusing exactly one tool:\n")
    print(f"{'tool':30} {'contains':>9} {'benign cost':>12} {'predicted':>10}")
    for tool, r in ranked[:args.top]:
        print(f"{tool:30} {r['contains']:>9} {r['cost']:>12} {r['predicted']:>10.1f}")

    # Does the name-only prior rank the same tools the ablation does?
    carriers = [t for t, r in loss.items() if r["contains"] > 0]
    inert = [t for t, r in loss.items() if r["contains"] == 0]
    import statistics
    mc = statistics.mean(loss[t]["predicted"] for t in carriers) if carriers else 0
    mi = statistics.mean(loss[t]["predicted"] for t in inert) if inert else 0
    print(f"\ntools that carry loss   : {len(carriers):3}  mean predicted risk {mc:.2f}")
    print(f"tools that carry none   : {len(inert):3}  mean predicted risk {mi:.2f}")

    # Rank-free and threshold-free: probability a loss-carrying tool outranks an
    # inert one, which is the AUC of the prior as a detector.
    pairs = wins = 0
    for a in carriers:
        for b in inert:
            pairs += 1
            pa, pb = loss[a]["predicted"], loss[b]["predicted"]
            wins += 1.0 if pa > pb else (0.5 if pa == pb else 0.0)
    if pairs:
        print(f"AUC of the name-only prior: {wins/pairs:.3f}  "
              f"(0.5 is chance, over {pairs} pairs)")

    lp = least_privilege()
    print("\nLEAST PRIVILEGE, granting only the tools benign work uses:")
    print(f"  contained {lp['contained']} of {lp['n']}, completed "
          f"{lp['completed']}, at zero benign cost by construction.")
    print("  This is an UPPER BOUND. The benign twin is a complete account of")
    print("  legitimate behaviour; a deployment learns from a sample, and")
    print("  observed_grant.md measures that gap at 42.99% held-out false blocks.")

    if args.json:
        with open(args.json, "w") as fh:
            json.dump({"per_tool": loss, "least_privilege": lp}, fh, indent=2)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
