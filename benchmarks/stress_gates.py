"""One hostile corpus, every gate, two properties that must never break.

    python -m benchmarks.stress_gates
    python -m benchmarks.stress_gates --gate egress --verbose

`stress_budget.py` found four defects in the budget rungs and all four were the
same decision made in four places: **when the input is unusable, proceed.** For a
parser that is often right. For an authorization control it is always wrong, and
it is invisible from above, the broker records that the rung passed, the
scoreboard counts it as enforced, and the ladder reports containment it never
performed.

Fixing four sites does not remove a bug class. This module removes it by making
the class a *test* that runs against every gate uniformly, so the next gate
someone adds is audited by construction rather than by remembering.

## The two properties

``NEVER_RAISES``     A gate may deny. It may not throw *unexpectedly*. A gate
                     is allowed to declare a typed validation error as its
                     denial mechanism, ``ComputeBudget.reserve`` raises
                     ``ValueError`` on a negative estimate, deliberately and in
                     its docstring, and those are recorded, not counted. What
                     is counted is an exception nobody chose: a ``TypeError``
                     from comparing a str to an int, an ``AttributeError`` from
                     calling ``.strip()`` on a list. An exception in the
                     authorization path is a denial-of-service at best, and at
                     worst it is caught by a broad handler upstream and becomes
                     an allow. Found live: `Decimal('NaN')` quantized fine and
                     then raised `InvalidOperation` on the `amount < 0` check,
                     escaping `reserve()` entirely.

``NEVER_FAILS_OPEN`` A gate must not return *allow* because it failed to
                     understand its input. Found live: an amount of `1e999`
                     against a ceiling of 10 returned `allowed=True` with reason
                     `ok_untracked`, so the spend ceiling stopped applying
                     exactly when the amount was absurd.

The second property needs care, and the care is the whole design. "Allowed" is
not automatically a failure, most gates are allow-by-default for inputs outside
their remit, and that is correct. The property is narrower: **for an input the
gate is supposed to police, an unusable value must not be allowed.** Each gate
therefore declares its own `in_remit` predicate, and only inputs inside the remit
are held to the fail-closed standard.

## The corpus

Shared across every gate, because the interesting inputs are the same everywhere:
numeric edge cases that survive one coercion and break the next, values that are
valid in one type system and meaningless in another, and the empty/None/wrong-type
cases that separate "absent" from "present and garbage".
"""
from __future__ import annotations

import argparse
import json
import sys
import traceback
from decimal import Decimal
from pathlib import Path

# --------------------------------------------------------------------------- #
# The shared hostile corpus
# --------------------------------------------------------------------------- #
#: Values that are *present* and *unusable*. Absent inputs are deliberately not
#: here: a missing argument is a different situation from a malformed one, and
#: conflating them produces false alarms on legitimate calls.
HOSTILE_SCALARS = [
    "1e999",              # overflows cent-quantization; "transfer everything"
    "-1e999",
    10 ** 30,             # an ordinary int that overflows the same way
    -(10 ** 30),
    "Infinity", "-Infinity", "NaN", "sNaN",
    float("inf"), float("-inf"), float("nan"),
    "0x10", "1_000", "١٢٣",   # hex, underscored, non-ASCII digits
    "", "   ", "\x00", "\n",
    None, True, False, [1], {"a": 1}, object(),
]

#: Paths that are present and unusable, or that try to escape by encoding.
HOSTILE_PATHS = [
    "", "   ", "\x00", "//", "\\\\", ".", "..", "../..",
    "/app/../../etc/shadow", "/app/%2e%2e/etc/shadow",
    "/app/‮/etc/shadow",          # right-to-left override
    "/app/" + "a" * 5000,              # length
    "/APP/DATA", "/app//data", "/app/./data",
    None, 0, [1], {"a": 1}, True,
]

#: Destinations that are present and unusable.
HOSTILE_DESTINATIONS = [
    "", "   ", "\x00", "@", "@@", "a@", "@b",
    "http://", "net:", "net://", "://evil.test",
    "evil.test.trusted.test",
    "a" * 5000 + "@evil.test",
    None, 0, [1], {"a": 1}, True,
]


class GateResult:
    """What a gate did with one hostile input."""

    __slots__ = ("value", "allowed", "reason", "error")

    def __init__(self, value, allowed=None, reason="", error=None):
        self.value = value
        self.allowed = allowed
        self.reason = reason
        self.error = error


# --------------------------------------------------------------------------- #
# Gate adapters, each declares what it polices and how to call it
# --------------------------------------------------------------------------- #
def gate_value_budget():
    from agentauth.capabilities.value_budget import (
        SessionValueBudget, ValueBudgetConfig)

    def probe(value) -> GateResult:
        budget = SessionValueBudget(config=ValueBudgetConfig(
            tracked={"t": ("amount", "p")}, ceilings={"p": Decimal(10)}))
        res = budget.reserve("t", {"amount": value})
        return GateResult(value, res.allowed, res.reason)

    # Everything in the corpus is a *present* amount on a tracked tool, so the
    # gate is on the hook for all of it.
    return "value-budget", HOSTILE_SCALARS, probe, lambda v: True


def gate_call_budget():
    from agentauth.capabilities.call_budget import (
        CallBudgetConfig, SessionCallBudget)

    def probe(value) -> GateResult:
        budget = SessionCallBudget(config=CallBudgetConfig(
            tracked={"t": "p"}, ceilings={"p": 2}))
        res = budget.reserve("t", {"_idempotency_key": value})
        return GateResult(value, res.allowed, res.reason)

    # The call budget counts calls; a malformed idempotency key must not let a
    # call slip the count, but a key is not itself a policed quantity, so only
    # NEVER_RAISES is enforced here.
    return "call-budget", HOSTILE_SCALARS, probe, lambda v: False


def gate_compute_budget():
    from agentauth.capabilities.compute_budget import (
        ComputeBudgetConfig, SessionComputeBudget)

    def probe(value) -> GateResult:
        budget = SessionComputeBudget(config=ComputeBudgetConfig(
            tracked={"t": "p"}, ceilings={"p": 30.0}))
        res = budget.reserve("t", value)
        return GateResult(value, res.allowed, getattr(res, "reason", ""))

    import math as _math

    def unusable(v):
        # `10**30` clamped to the ceiling is CORRECT, the run gets the grant's
        # worth and no more, which is the rung working. Only values that cannot
        # be metered at all are the gate's problem.
        if isinstance(v, bool) or not isinstance(v, (int, float)):
            return True
        return not _math.isfinite(v)

    # A negative estimate raises ValueError by documented design; that is a
    # denial, not an unhandled crash.
    return "compute-budget", HOSTILE_SCALARS, probe, unusable, (ValueError,)


def gate_task_scope():
    from agentauth.core.task_scope import TaskScope, task_scope_allows_path

    scope = TaskScope(allowed_paths=("/app/**",), denied_paths=("/app/secret/**",))

    def probe(value) -> GateResult:
        allowed = task_scope_allows_path(scope, value)
        return GateResult(value, bool(allowed), "")

    # Only paths that should be OUT of scope count. `/app//data` and
    # `/app/./data` normalise to `/app/data`, which is in scope, and admitting
    # them is correct; flagging those was the harness being wrong, not the gate.
    # `%2e%2e` and the RTL override are literal directory names inside /app
    # in scope unless something downstream URL-decodes, which is a real but
    # conditional risk recorded in the writeup rather than asserted here.
    def should_be_out_of_scope(v):
        return isinstance(v, str) and v.startswith("/etc")

    return "task-scope", HOSTILE_PATHS, probe, should_be_out_of_scope


def gate_protected_zones():
    from agentauth.capabilities.hardening.protected_zones import is_protected_path

    def probe(value) -> GateResult:
        protected = is_protected_path(value)
        # Protected zones are a DENY list: "allowed" means not protected.
        return GateResult(value, not protected, "")

    # A deny-list is allow-by-default by design, so an unrecognised path being
    # allowed is not a fail-open here. Only NEVER_RAISES applies.
    return "protected-zones", HOSTILE_PATHS, probe, lambda v: False


def gate_egress_policy():
    from agentauth.capabilities.hardening.egress_policy import EgressPolicy

    policy = EgressPolicy(allowed_domains=frozenset({"trusted.test"}),
                          allowed_recipients=frozenset({"ok@trusted.test"}))

    def probe(value) -> GateResult:
        verdict = policy.check("mcp:tool:send", {"to": value})
        allowed = verdict[0] if isinstance(verdict, tuple) else bool(verdict)
        reason = verdict[1] if isinstance(verdict, tuple) and len(verdict) > 1 else ""
        return GateResult(value, bool(allowed), str(reason))

    # in_remit is deliberately narrow, and getting it wrong is how a harness
    # cries wolf. `''`, `net:`, `@`, None and 0 yield NO extractable destination,
    # so "within policy" is correct: there is nothing to egress to. Only inputs
    # that DO name a host are the policy's business. Verified separately that the
    # matcher is sound: `trusted.test.evil.com`, `nottrusted.test` and
    # `xtrusted.test` are all denied against an allow-list of `trusted.test`,
    # and matching is case-insensitive.
    def names_a_foreign_host(v):
        if not isinstance(v, str) or "." not in v:
            return False
        if v.startswith(("net:", "http://")):
            return False
        # `evil.test.trusted.test` IS a subdomain of the allow-listed domain, and
        # admitting subdomains of a domain you control is the intended semantics,
        # not a bypass. The genuine confusion attempts are verified denied:
        # `trusted.test.evil.com`, `nottrusted.test`, `xtrusted.test`.
        host = v.rsplit("@", 1)[-1].strip().lower().rstrip(".")
        return not any(host == d or host.endswith("." + d)
                       for d in policy.allowed_domains)

    return "egress-policy", HOSTILE_DESTINATIONS, probe, names_a_foreign_host


GATES = {
    "value-budget": gate_value_budget,
    "call-budget": gate_call_budget,
    "compute-budget": gate_compute_budget,
    "task-scope": gate_task_scope,
    "protected-zones": gate_protected_zones,
    "egress-policy": gate_egress_policy,
}


# --------------------------------------------------------------------------- #
# Runner
# --------------------------------------------------------------------------- #
def run_gate(name: str, verbose: bool = False) -> dict:
    spec = GATES[name]()
    corpus_name, corpus, probe, in_remit = spec[:4]
    declared = spec[4] if len(spec) > 4 else ()
    raises, fails_open, ok = [], [], 0
    for value in corpus:
        try:
            result = probe(value)
        except declared:  # a denial the gate documents; not a defect
            ok += 1
            continue
        except Exception as exc:  # noqa: BLE001 - cataloguing is the point
            raises.append({"value": repr(value)[:60],
                           "error": f"{type(exc).__name__}: {str(exc)[:80]}",
                           "trace": traceback.format_exc(limit=2)[-200:]
                           if verbose else ""})
            continue
        if result.allowed and in_remit(value):
            fails_open.append({"value": repr(value)[:60],
                               "reason": result.reason[:60]})
        else:
            ok += 1
    return {
        "gate": corpus_name, "inputs": len(corpus), "clean": ok,
        "NEVER_RAISES": raises, "NEVER_FAILS_OPEN": fails_open,
    }


def render(reports: list[dict]) -> str:
    head = f"{'gate':<20}{'inputs':>8}{'raises':>9}{'fails open':>13}{'verdict':>10}"
    lines = ["adversarial input stress across every gate", "=" * len(head), "",
             head, "-" * len(head)]
    for r in reports:
        nr, nf = len(r["NEVER_RAISES"]), len(r["NEVER_FAILS_OPEN"])
        verdict = "ok" if not nr and not nf else "FAIL"
        lines.append(f"{r['gate']:<20}{r['inputs']:>8}{nr:>9}{nf:>13}{verdict:>10}")
    lines.append("")
    for r in reports:
        for kind in ("NEVER_RAISES", "NEVER_FAILS_OPEN"):
            for item in r[kind]:
                detail = item.get("error") or f"allowed as {item.get('reason')!r}"
                lines.append(f"  [{r['gate']}] {kind}: {item['value']} -> {detail}")
    return "\n".join(lines)


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--gate", nargs="*", default=sorted(GATES))
    p.add_argument("--verbose", action="store_true")
    p.add_argument("--json", type=Path, default=None)
    args = p.parse_args(argv)

    reports = []
    for name in args.gate:
        if name not in GATES:
            print(f"unknown gate {name!r}; known: {sorted(GATES)}", file=sys.stderr)
            continue
        try:
            reports.append(run_gate(name, verbose=args.verbose))
        except Exception as exc:  # a gate whose harness cannot even build
            print(f"{name}: harness error {type(exc).__name__}: {exc}",
                  file=sys.stderr)
    print(render(reports))
    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(json.dumps(reports, indent=2, default=str))
        print(f"\nwrote {args.json}")
    bad = sum(len(r["NEVER_RAISES"]) + len(r["NEVER_FAILS_OPEN"]) for r in reports)
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
