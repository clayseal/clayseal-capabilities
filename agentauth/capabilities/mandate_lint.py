"""Coverage checks on a mandate, because the ledger is not what fails.

`benchmarks/stress_aggregation.py` attacks the aggregation key rather than the
ceiling, which is what an attacker who knows a cumulative control exists actually
does. Of eleven axes, the ones that escaped were:

    session restart            a fresh session is a fresh ledger
    key splitting              two tools, two budget ids, one effect
    untracked sibling tool     a money tool outside `tracked` has no ceiling
    batch amortization         one call, N effects, one debit  (closed by EffectSpec)
    unit confusion             cents debited against a dollar ceiling  (same)

The last two were closed in the ledger by declaring multiplicity and scale. The
first three cannot be: they are not defects in the ledger, they are the mandate
failing to say what the ledger should count. `SessionValueBudget` debits exactly
what it was told to debit, correctly, on every one of those axes.

That makes them a *configuration* failure mode, and configuration failure modes
do not get fixed by being written up. They get fixed by something that reads the
configuration and says which effects are uncounted, in the same way
`hardening/object_class.py` compiles in its patterns rather than inferring them.
Everything here is static and offline: no model, no traffic, no learning. A
linter that guesses is a linter that gets muted.

The findings are advisory by default. `require_clean()` is the strict form, for a
deployment that wants an uncovered money tool to be a startup failure rather than
a log line.
"""
from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any

__all__ = ["EFFECT_FAMILIES", "Finding", "lint_mandate", "require_clean"]


#: Tool-name fragments that denote a *consequential, quantified* effect: an
#: action that moves value, grants standing authority, or destroys state. Keyed
#: by family, because two tools in the same family debiting different budget ids
#: is the key-splitting escape, and family membership is how that is detected.
#:
#: Deliberately narrow. A pattern that matches `get_balance` produces a finding
#: on a read, and an operator who sees one false finding stops reading the rest.
EFFECT_FAMILIES: dict[str, tuple[str, ...]] = {
    "value": ("transfer", "payout", "payment", "pay_", "wire", "remit",
              "disburse", "refund", "charge", "invoice", "withdraw", "purchase"),
    "authority": ("grant", "add_member", "add_user", "assign_role",
                  "share", "invite", "authorize_"),
    "destruction": ("delete", "destroy", "purge", "drop_", "revoke",
                    "terminate", "wipe"),
}

#: Names that denote multiplicity in one call. A tool matching one of these,
#: tracked without a declared count argument, debits once for N effects.
BATCH_MARKERS = ("batch", "bulk", "_all", "multi", "many", "_each")

#: Argument or tool names implying a minor unit. A ceiling is written in the
#: unit a human thinks in, and a tool quoting the other one is a 100x error in
#: the attacker's favour that looks like ordinary traffic.
MINOR_UNIT_MARKERS = ("cents", "minor", "pence", "satoshi", "wei", "millis")

_WORD = re.compile(r"[^a-z0-9]+")


def _norm(name: str) -> str:
    return _WORD.sub("_", str(name).lower())


def _family_of(tool: str) -> str | None:
    low = _norm(tool)
    for family, markers in EFFECT_FAMILIES.items():
        if any(m in low for m in markers):
            return family
    return None


@dataclass(frozen=True)
class Finding:
    """One uncounted or miscounted effect, with the escape it enables."""

    code: str
    severity: str          # "error" | "warning"
    subject: str           # the tool or budget id at fault
    detail: str
    escape: str            # the stress_aggregation axis this corresponds to

    def __str__(self) -> str:
        return f"[{self.severity}] {self.code}: {self.subject} — {self.detail}"


def _tracked_pairs(tracked: Mapping[str, Any]) -> list[tuple[str, str, Any]]:
    """(tool, budget_id, spec) for both the legacy tuple and `EffectSpec`."""
    out: list[tuple[str, str, Any]] = []
    for tool, spec in (tracked or {}).items():
        budget_id = getattr(spec, "budget_id", None)
        if budget_id is None and isinstance(spec, (tuple, list)) and len(spec) >= 2:
            budget_id = spec[1]
        elif budget_id is None and isinstance(spec, str):
            budget_id = spec           # call/compute budgets map tool -> id
        out.append((str(tool), str(budget_id or ""), spec))
    return out


def lint_mandate(
    *,
    catalog: Iterable[str] = (),
    declared_harmless: Iterable[str] = (),
    value_tracked: Mapping[str, Any] | None = None,
    call_tracked: Mapping[str, Any] | None = None,
    ceilings: Mapping[str, Any] | None = None,
    principal_scoped: bool = False,
    stateless: bool = False,
) -> list[Finding]:
    """Report every effect the mandate leaves uncounted.

    `catalog` is the tool set the agent can actually reach. Without it the
    untracked-sibling check cannot run at all, which is the honest outcome: you
    cannot tell that a money tool is missing from a ledger by reading the ledger.
    """
    declared_harmless = {str(t) for t in declared_harmless or ()}
    value_tracked = dict(value_tracked or {})
    call_tracked = dict(call_tracked or {})
    ceilings = dict(ceilings or {})
    catalog = [str(t) for t in catalog]
    findings: list[Finding] = []

    covered = set(value_tracked) | set(call_tracked)
    pairs = _tracked_pairs(value_tracked)

    # 1. Untracked sibling tool. The most likely real misconfiguration: a
    #    mandate enumerates the money tools it knows about, and the catalog grows.
    #
    #    Two rules, and the second is the one that matters. Name matching finds
    #    `payments.wire`; it cannot find `process_item_47`, and
    #    `benchmarks/mandate_search.py` measures what that costs — over 4,000
    #    sampled mandates, **211 escaped while this linter called them clean**,
    #    every one of them through an opaquely-named tool.
    #
    #    So a name is evidence, not a gate. Any reachable tool that neither
    #    debits a budget nor is explicitly declared harmless is unaccounted for,
    #    and unaccounted-for is the honest verdict: the linter does not know what
    #    it does, and neither does the ceiling.
    for tool in catalog:
        if tool in covered or tool in declared_harmless:
            continue
        family = _family_of(tool)
        if family:
            findings.append(Finding(
                code="untracked-effectful-tool", severity="error", subject=tool,
                detail=(f"reachable and in the {family!r} family but debits no "
                        f"budget, so no ceiling applies to it at all"),
                escape="untracked sibling tool"))
        else:
            findings.append(Finding(
                code="unaccounted-tool", severity="warning", subject=tool,
                detail=("reachable, debits no budget, and not declared "
                        "harmless; nothing here can tell whether it has an "
                        "effect. Track it or list it in declared_harmless"),
                escape="untracked sibling tool"))

    # 2. Key splitting. Two tools in one family against two budget ids means the
    #    ceiling is per-name rather than per-effect, and the attacker picks names.
    by_family: dict[str, dict[str, list[str]]] = {}
    for tool, budget_id, _spec in pairs:
        family = _family_of(tool)
        if family and budget_id:
            by_family.setdefault(family, {}).setdefault(budget_id, []).append(tool)
    for family, buckets in by_family.items():
        if len(buckets) > 1:
            rendered = "; ".join(f"{bid}<-{','.join(sorted(ts))}"
                                 for bid, ts in sorted(buckets.items()))
            findings.append(Finding(
                code="split-aggregation-key", severity="error", subject=family,
                detail=(f"one effect family across {len(buckets)} budget ids "
                        f"({rendered}); the aggregate ceiling is the sum, not "
                        f"the smallest. If the document says one total with a "
                        f"sub-limit inside it, this engine holds one ceiling "
                        f"per tool and cannot hold both: put every tool on the "
                        f"OUTER limit so the total is right, and know that the "
                        f"inner one is then unenforced"),
                escape="key splitting"))

    # 3. A tracked tool whose budget has no ceiling is tracked in name only.
    for tool, budget_id, _spec in pairs:
        if budget_id and ceilings.get(budget_id) is None:
            findings.append(Finding(
                code="uncapped-budget", severity="error", subject=budget_id,
                detail=f"{tool} debits it but it carries no ceiling",
                escape="untracked sibling tool"))

    # 4. Undeclared multiplicity. Closed in the ledger by `EffectSpec.count_arg`,
    #    so this fires only where the mandate did not use it.
    for tool, _budget_id, spec in pairs:
        low = _norm(tool)
        if any(m in low for m in BATCH_MARKERS) and not getattr(spec, "count_arg", ""):
            findings.append(Finding(
                code="undeclared-multiplicity", severity="error", subject=tool,
                detail=("named as a batch tool but declares no count argument, "
                        "so one reservation covers N effects"),
                escape="batch amortization"))

    # 5. Undeclared unit, in the two shapes that matter: a tool that announces a
    #    minor unit without a scale, and one budget fed by both scaled and
    #    unscaled tools.
    scales_per_budget: dict[str, set[str]] = {}
    for tool, budget_id, spec in pairs:
        scale = str(getattr(spec, "scale", 1) or 1)
        scales_per_budget.setdefault(budget_id, set()).add(scale)
        text = _norm(tool) + "_" + _norm(getattr(spec, "amount_arg", "") or "")
        if any(m in text for m in MINOR_UNIT_MARKERS) and scale == "1":
            findings.append(Finding(
                code="undeclared-unit", severity="error", subject=tool,
                detail=("names a minor unit but declares no scale; the ledger "
                        "debits the number as written"),
                escape="unit confusion"))
    for budget_id, scales in scales_per_budget.items():
        if len(scales) > 1:
            findings.append(Finding(
                code="mixed-unit-budget", severity="warning", subject=budget_id,
                detail=(f"fed by tools declaring {len(scales)} different scales "
                        f"({', '.join(sorted(scales))}); check they agree"),
                escape="unit confusion"))

    # 6. Session restart. Not a defect in anything, and the fix already exists —
    #    `principal_ledger.py` keys the ledger to the mandate rather than the
    #    session. So this reports whether that fix is in use, and it is a warning
    #    rather than an error because a genuinely per-session ceiling is a
    #    coherent thing to want.
    if ceilings and not principal_scoped:
        # A warning where a session exists, an ERROR where one cannot.
        #
        # MCP 2026-07-28 removes the `initialize` handshake and the
        # `Mcp-Session-Id` header, and states the reason plainly: any server
        # instance must be able to serve any request so deployments can scale
        # horizontally without sticky routing. A Streamable HTTP deployment
        # behind a load balancer therefore has NO session for a ceiling to be
        # counted over, and a session-scoped ceiling there is not a weak control
        # that an attacker has to work to reset. It resets on its own, per
        # request, and the aggregate rung this library exists for is inert.
        #
        # So a document that declares `deployment: {stateless: true}` and still
        # asks for a session-scoped ceiling is asking for something that cannot
        # be built, and refusing is the same discipline the rest of this
        # compiler follows: a gateway that enforces the wrong thing is worse
        # than one that will not start.
        findings.append(Finding(
            code="session-scoped-ceiling",
            severity="error" if stateless else "warning",
            subject=", ".join(sorted(ceilings)) or "(all)",
            detail=(
                ("this deployment declares itself stateless, where no session "
                 "survives a request, so a per-session ceiling is counted over "
                 "nothing and resets on every call. Bind it to a principal "
                 "ledger, which is the only anchor that outlives a request "
                 "once sessions are gone")
                if stateless else
                ("counted per session, so a second session gets a second "
                 "ceiling; bind to a principal ledger if the limit is meant "
                 "to be an authority limit")),
            escape="session restart"))

    return findings


def require_clean(findings: Iterable[Finding], *, strict: bool = False) -> None:
    """Raise on findings. For a fail-closed deployment.

    Default raises on errors only, which is the usable setting: a warning like
    `unaccounted-tool` fires on every read tool a mandate has not enumerated,
    and a mode nobody can satisfy is a mode nobody turns on.

    `strict=True` raises on warnings too, and it is what the closure property
    actually requires. Measured over 4,000 sampled mandates in
    `benchmarks/mandate_search.py`: 1,870 escaped, and **466 of them carried no
    error-level finding** — every one through a tool the mandate never accounted
    for. So a deployment that wants "if the linter is happy, the ceiling holds"
    has to pay for it by declaring its catalog, and one that does not should know
    it is relying on tool names being honest.
    """
    threshold = ("error", "warning") if strict else ("error",)
    blocking = [f for f in findings if f.severity in threshold]
    if blocking:
        raise ValueError(
            "mandate leaves effects uncounted:\n  "
            + "\n  ".join(str(f) for f in blocking))
