"""Their rules, their traffic, our gateway.

    python -m benchmarks.tau2_policy_enforcement

`external_corpora_structure.md` states the objection this file exists for. The
surface-leaving claim has independent multi-corpus support; the AGGREGATE claim
has a purpose-built suite written here, and no external corpus carries the input
it needs. Anyone quoting the BPL numbers as externally validated would be wrong.

`tau2-bench` is the closest thing to the missing instrument, and until now it was
unusable for it: its rules are prose, and compiling them would have been ours.
Three things changed. `policy_draft` reads a rule out of prose and cites the line
it came from. `tools.when` expresses the two shapes that prose actually uses,
ordering and state conditions, which no ceiling could. And a catalogue binds a
rule to the tools it names.

So the whole chain is now theirs except the mechanism:

- the RULES come from `domains/<d>/policy.md`, written by the tau2 authors;
- the TRAFFIC is `evaluation_criteria.actions`, which is that benchmark's own
  ground truth for what a correct agent does on each task;
- the only thing this repository contributes is the compiler and the gateway.

## What this measures, and what it deliberately does not

**Friction**, which is the half that needs no judgement. Every action replayed
here is one tau2 says a correct agent takes, so **every block is a false block**.
There is no labelling to argue about and no scenario anyone here wrote.

It does NOT measure containment. Doing that means constructing the violating
call, and while the rule and the state would be theirs, the act of calling the
tool would be ours, which is the objection this file exists to answer arriving
one level down. `tau2` scores whether the AGENT refuses; a gateway is a different
question and needs a corpus that carries the attempted call.
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

from clayseal.capabilities.monitor.action import Action
from clayseal.capabilities.policy import load_policy_text
from clayseal.capabilities.policy_draft import extract, to_yaml

DOMAINS = ("retail", "airline", "telecom")


def _root() -> Path:
    from benchmarks.datasets.tau2 import _default_root

    return _default_root()


def _policy_file(domain: str) -> Path | None:
    for name in ("policy.md", "main_policy.md"):
        candidate = _root() / domain / name
        if candidate.exists():
            return candidate
    return None


def catalogue(domain: str) -> list[str]:
    """Every tool the domain's own tasks call. Read, not guessed."""
    tasks = json.loads((_root() / domain / "tasks.json").read_text())
    names = {str(a.get("name")) for task in tasks
             for a in (task.get("evaluation_criteria") or {}).get("actions") or []
             if a.get("name")}
    return sorted(names)


def compile_policy(domain: str, tools: list[str]):
    """Their prose into a grant, with only the mechanical gaps filled.

    The reviewer step a real deployment performs is reduced here to the two
    declarations the document cannot carry: which tools have an effect, and that
    none of them takes a filesystem path. Nothing about the RULES is touched, so
    a rule that is wrong is wrong because the extractor read it wrongly.
    """
    document = _policy_file(domain)
    if document is None:
        return None
    draft = extract(document.read_text(), tools=tools)
    rendered = to_yaml(draft, goal_id=f"tau2-{domain}",
                       goal_summary=f"Handle {domain} requests for the customer",
                       tools=tools)
    reads = [t for t in tools if t.split("_")[0] in
             {"get", "list", "find", "search", "calculate", "think", "transfer"}]
    effects = ", ".join(
        f"{t}: {'read' if t in reads else 'write'}" for t in tools)
    rendered = rendered.replace(
        "  # TODO: declare each tool's effect and mark the harmless ones.\n"
        "  # effects:  {pay_vendor: transfer, send_email: send}\n"
        "  # harmless: []",
        f"  effects: {{{effects}}}\n"
        f"  harmless: [{', '.join(reads)}]")
    rendered += f"\npaths: {{pathless: [{', '.join(tools)}]}}\n"
    # The BENCHMARK profile, because the SUPERVISED one refuses to build at all
    # here, and the reason is itself a result: `modify_pending_order_payment`
    # moves money and **tau2's policy document names no ceiling for it**, so a
    # grant compiled from that document leaves it uncounted. That is the finding
    # `external_corpora_structure.md` measured from the other side, 0 of 520
    # tasks declaring a budget, arriving now from the policy documents rather
    # than from the tasks. Declaring those tools harmless to make the build pass
    # would be answering the linter instead of reporting it.
    rendered = rendered.replace("profile: supervised", "profile: benchmark")
    return load_policy_text(rendered), draft


def entity_facts(domain: str) -> dict[str, dict[str, str]]:
    """Their own database, keyed by entity id, as the facts a read would return.

    A state-conditional rule reads a fact, and in a live deployment that fact
    arrives in the result of the read the ordering rule already insists on: the
    agent calls `get_order`, sees `status: pending`, and the withdrawal lifts.
    A replay has no results, so without this the conditional tier is tested with
    no input at all, which tests nothing and refuses everything.

    The values come from `domains/<d>/db.json`, which is tau2's, not ours.
    """
    path = _root() / domain / "db.json"
    if not path.exists():
        return {}
    try:
        db = json.loads(path.read_text())
    except ValueError:
        return {}
    out: dict[str, dict[str, str]] = {}
    for collection in db.values():
        if not isinstance(collection, dict):
            continue
        for key, row in collection.items():
            if isinstance(row, dict) and "status" in row:
                out[str(key)] = {"status": str(row["status"])}
    return out


def _observed(args: dict, facts: dict[str, dict[str, str]]) -> dict[str, str]:
    """Facts for whatever entity this call names, from their database."""
    for value in args.values():
        if isinstance(value, str) and value in facts:
            return facts[value]
    return {}


def replay(domain: str, limit: int | None = None) -> dict:
    """Every ground-truth action, through a gateway enforcing their rules."""
    compiled = compile_policy(domain, catalogue(domain))
    if compiled is None:
        return {"skipped": "no policy document"}
    policy, draft = compiled
    tasks = json.loads((_root() / domain / "tasks.json").read_text())
    if limit:
        tasks = tasks[:limit]

    facts = entity_facts(domain)
    blocked: Counter[str] = Counter()
    reasons: Counter[str] = Counter()
    total = 0
    for task in tasks:
        actions = (task.get("evaluation_criteria") or {}).get("actions") or []
        if not actions:
            continue
        stack = policy.build()
        for step, entry in enumerate(actions, start=1):
            tool = str(entry.get("name") or "")
            if not tool:
                continue
            args = entry.get("arguments")
            args = dict(args) if isinstance(args, dict) else {}
            observed = _observed(args, facts)
            if observed and stack.broker.conditional_tools is not None:
                stack.broker.conditional_tools.observe_facts(observed)
            total += 1
            decision = stack.authorize(Action(
                step=step, tool=tool, resource=f"tool:{tool}",
                verb=policy.verb_for(tool), args=args, meta={}))
            if not decision.allowed:
                blocked[tool] += 1
                reasons[(decision.reasons or ("(none)",))[0][:70]] += 1
    rules = [r for r in draft.rules if r.kind in ("ordering", "conditional")]
    return {"tasks": len(tasks), "actions": total, "blocked": sum(blocked.values()),
            "rules": len(rules), "by_tool": blocked, "reasons": reasons,
            "entities": len(facts)}


#: A task whose ground truth contains no write is one tau2 says should end in a
#: refusal. Its `nl_assertions` say so in words; the empty write set says it in
#: data, and the data is what this reads.
def refusal_tasks(domain: str, reads: set[str]) -> list[dict]:
    tasks = json.loads((_root() / domain / "tasks.json").read_text())
    out = []
    for task in tasks:
        actions = (task.get("evaluation_criteria") or {}).get("actions") or []
        names = [str(a.get("name") or "") for a in actions]
        if names and not any(n and n not in reads for n in names):
            out.append(task)
    return out


def containment(domain: str) -> dict:
    """Would the gateway stop a write on a task where tau2 says none belongs?

    The construction avoids choosing an attack, which is the objection this file
    exists to answer. For each task whose ground truth contains **no write at
    all**, the reads are replayed to establish state from their database, and
    then EVERY write tool in their catalogue is attempted on the entity those
    reads touched. Nothing is selected: the set is exhaustive over their own
    catalogue, and their own ground truth is what says no write belongs.

    What it measures is precisely the question tau2 cannot ask of itself. That
    benchmark scores whether the AGENT refuses; this scores whether the gateway
    would stop the call if the agent did not.
    """
    compiled = compile_policy(domain, catalogue(domain))
    if compiled is None:
        return {"skipped": "no policy document"}
    policy, _draft = compiled
    tools = catalogue(domain)
    reads = {t for t in tools if policy.verb_for(t) == "read"}
    writes = [t for t in tools if t not in reads]
    facts = entity_facts(domain)

    tasks = refusal_tasks(domain, reads)
    attempted = refused = 0
    by_reason: Counter[str] = Counter()
    for task in tasks:
        actions = (task.get("evaluation_criteria") or {}).get("actions") or []
        entity_args: dict[str, str] = {}
        stack = policy.build()
        step = 0
        for entry in actions:                       # their reads, in order
            step += 1
            args = entry.get("arguments")
            args = dict(args) if isinstance(args, dict) else {}
            entity_args.update({k: v for k, v in args.items()
                                if isinstance(v, str)})
            observed = _observed(args, facts)
            if observed and stack.broker.conditional_tools is not None:
                stack.broker.conditional_tools.observe_facts(observed)
            stack.authorize(Action(step=step, tool=str(entry.get("name")),
                                   resource="t",
                                   verb=policy.verb_for(str(entry.get("name"))),
                                   args=args, meta={}))
        for tool in writes:                         # every write, none chosen
            step += 1
            decision = stack.authorize(Action(
                step=step, tool=tool, resource=f"tool:{tool}",
                verb=policy.verb_for(tool), args=dict(entity_args), meta={}))
            attempted += 1
            if not decision.allowed:
                refused += 1
                by_reason[(decision.reasons or ("(none)",))[0][:64]] += 1
    return {"tasks": len(tasks), "writes": len(writes), "attempted": attempted,
            "refused": refused, "reasons": by_reason}


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--domains", default=",".join(DOMAINS))
    p.add_argument("--limit", type=int, default=None)
    args = p.parse_args(argv if argv is not None else sys.argv[1:])

    if not _root().exists():
        print(f"tau2 corpus not found at {_root()}", file=sys.stderr)
        return 2

    print("# Their rules, their traffic, our gateway\n")
    print("STATUS: current\n")
    print("```bash\npython -m benchmarks.tau2_policy_enforcement\n```\n")
    print("Rules compiled from each domain's own `policy.md`. Traffic is that")
    print("domain's `evaluation_criteria.actions`, which is tau2's ground truth")
    print("for what a correct agent does, so **every block is a false block**.\n")
    print("| domain | rules compiled | entities with state | tasks | "
          "ground-truth actions | blocked |")
    print("| --- | --: | --: | --: | --: | --: |")
    everything: dict[str, dict] = {}
    for domain in [d.strip() for d in args.domains.split(",") if d.strip()]:
        result = replay(domain, args.limit)
        everything[domain] = result
        if "skipped" in result:
            print(f"| {domain} | _skipped: {result['skipped']}_ | | | | |")
            continue
        print(f"| {domain} | {result['rules']} | {result['entities']} | "
              f"{result['tasks']} | {result['actions']} | "
              f"**{result['blocked']}** |")
    total_actions = sum(r.get("actions", 0) for r in everything.values())
    total_blocked = sum(r.get("blocked", 0) for r in everything.values())
    if total_actions:
        # `0.0%` would read as none at all when the rate is 0.007%, which is
        # exactly the rounded-to-zero the claims ratchet exists to catch. The
        # fraction is the honest rendering and it carries its own denominator.
        print(f"| **total** | | | | **{total_actions}** | "
              f"**{total_blocked} of {total_actions}** "
              f"({total_blocked / total_actions:.3%}) |")
    print("\n## Containment: a write where their ground truth has none\n")
    print("| domain | refusal tasks | write tools | attempts | refused |")
    print("| --- | --: | --: | --: | --: |")
    for domain in [d.strip() for d in args.domains.split(",") if d.strip()]:
        held = containment(domain)
        if "skipped" in held or not held.get("attempted"):
            print(f"| {domain} | _no refusal tasks_ | | | |")
            continue
        print(f"| {domain} | {held['tasks']} | {held['writes']} | "
              f"{held['attempted']} | **{held['refused']} of "
              f"{held['attempted']}** "
              f"({held['refused'] / held['attempted']:.1%}) |")
        for reason, count in held["reasons"].most_common(4):
            print(f"    - {count}x `{reason}`")

    for domain, result in everything.items():
        if result.get("blocked"):
            print(f"\n## What {domain} refused that it should not have\n")
            for reason, count in result["reasons"].most_common(6):
                print(f"- {count}x `{reason}`")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
