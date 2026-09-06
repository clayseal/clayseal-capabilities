"""How sure the compiler has to be before a tool is allowed.

    python examples/06_how_sure.py

You can ask the compiler several times. A tool that only shows up in some
of the answers is probably a guess. `k` is the cutoff: the fraction of
answers that have to name a tool before this session may use it.

    k ≈ 0.0001   appeared at least once (the published default)
    k = 0.5      showed up in at least half the answers
    k_for        a higher cutoff for one sensitive tool

No API key. The five answers below are canned, so you can see the knob
move. In a deployment you pass a real `ask` callable instead.
"""
from __future__ import annotations

import json

from clayseal.capabilities import Guardrail, Refused, compile_rules

CATALOGUE = [
    {"function": {"name": "checklist_item",
                  "description": "Tick a checklist box",
                  "parameters": {"properties": {}}}},
    {"function": {"name": "pay_vendor",
                  "description": "Pay a vendor",
                  "parameters": {"properties": {"vendor": {}, "amount": {}}}}},
    {"function": {"name": "wire_funds",
                  "description": "Wire to the ops float",
                  "parameters": {"properties": {"amount": {}}}}},
]

POLICY = {
    "version": 1,
    "goal": {"id": "pay-acme",
             "summary": "Pay Acme after the checklist, keep the total under 1000."},
    "profile": "supervised",
    "expires_at": "2030-01-01T00:00:00Z",
    "tools": {
        "allow": ["checklist_item", "pay_vendor", "wire_funds"],
        "harmless": ["checklist_item"],
        "effects": {"checklist_item": "read", "pay_vendor": "write",
                    "wire_funds": "write"},
    },
    "paths": {"pathless": ["checklist_item", "pay_vendor", "wire_funds"]},
    "budgets": {"value": {
        "ceilings": {"payments": "1000.00"},
        "tracked": {"pay_vendor": {"arg": "amount", "budget": "payments"},
                    "wire_funds": {"arg": "amount", "budget": "payments"}},
    }},
}


def _answer(include_wire: bool) -> str:
    prec = [{"before": "checklist_item", "after": "pay_vendor"}]
    if include_wire:
        prec.append({"before": "checklist_item", "after": "wire_funds"})
    return json.dumps({
        "precedence": prec,
        "invalidations": [],
        "entities": [{"key": "vendor", "allowed": ["Acme"]}],
        "distinct_subjects": False,
        "idempotency": False,
    })


# Four ordinary answers, then one that also names wire_funds.
ANSWERS = [_answer(False)] * 4 + [_answer(True)]


def _ask_from(answers):
    n = {"i": 0}

    def ask(_system, _payload):
        raw = answers[n["i"] % len(answers)]
        n["i"] += 1
        return raw

    return ask


def _try(label, k):
    print(f"\n{label}  (k={k:g}, 5 draws)")
    compiled = compile_rules(
        CATALOGUE, POLICY["goal"]["summary"],
        ask=_ask_from(ANSWERS), draws=5, k=k,
    )
    kept = sorted((compiled or {}).get("tool_freq") or {})
    print("  compiler kept:", ", ".join(kept) or "(nothing)")
    guard = Guardrail.from_dict(
        {**POLICY, "compile": {"draws": 5, "k": k}},
        ask=_ask_from(ANSWERS),
        tool_schemas=CATALOGUE,
        entailment_judge=None,
    )
    tools = guard.wrap_all({
        "checklist_item": lambda: "ticked",
        "pay_vendor": lambda vendor, amount: f"paid {vendor} ${amount}",
        "wire_funds": lambda amount: f"wired ${amount}",
    })
    tools["checklist_item"]()
    print("  pay_vendor:", tools["pay_vendor"](vendor="Acme", amount=400))
    try:
        print("  wire_funds:", tools["wire_funds"](amount=50))
    except Refused as exc:
        print("  wire_funds: refused —", exc.reasons[0])


if __name__ == "__main__":
    print("wire_funds showed up in 1 of 5 compiler answers.")
    _try("loose  — appeared at least once", 1e-4)
    _try("tight  — has to show up in half the answers", 0.5)
    print()
    print("Raise k when you want the compiler to be more sure. That is the")
    print("same tradeoff as relative_loss, which is how many of your own")
    print("good actions you will let inferred rules refuse.")
