"""Mutation stress of the commit-token verifier — the cryptographic root.

    python -m benchmarks.stress_commit
    python -m benchmarks.stress_commit --verbose

Every other control in this repo sits above the commit token. Scope, budgets,
egress and the behavioural layer all presuppose that a verified token means what
it says: this authority, this tool, this resource, these exact arguments, this
query, not yet expired, not already spent. If the verifier can be made to say
yes when any one of those is false, nothing above it matters.

So the property here is not a list of scenarios, it is total:

``NO_MUTATION_VERIFIES``  Take a genuinely valid (token, context) pair. Change
                          ANY single field of the token, or ANY single field of
                          the context, to ANY value. Verification must fail.
                          There is exactly one input that verifies, and it is
                          the untouched one.

``NEVER_RAISES``          The verifier returns ``(False, reason)``. It does not
                          throw. A crash in the cryptographic root is a denial
                          of service, and upstream of a broad ``except`` it is
                          an allow.

``REPLAY_IS_REFUSED``     With a used-token store, the second presentation of a
                          token fails. A token is a one-shot authorization for
                          one side effect; if it is not, a captured token is a
                          standing grant until expiry.

The mutation corpus is deliberately not "plausible attacker values". It is the
same hostile set the other gates get — empty strings, wrong types, non-finite
numbers, near-miss strings — because the interesting failures are where a field
is compared with ``int()`` or ``==`` after passing through a coercion that
silently succeeds on nonsense.
"""
from __future__ import annotations

import argparse
import json
import sys
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path

from agentauth.capabilities.commit import (
    InMemoryUsedTokenStore,
    issue_commit_token,
    verify_commit_token,
)
from agentauth.core.runtime import (
    ActionDescriptor,
    AuthorityContext,
    ExecutionContext,
)
from agentauth.core.signing import generate_keypair

#: Values a mutated field may take. Includes near-misses, because an equality
#: check that is really a prefix or substring check fails exactly here.
MUTATIONS = [
    "", "   ", "0", "-1", "1", "99999999999999999999",
    "x", "X", None, 0, 1, True, False, [1], {"a": 1},
    "1e999", "Infinity", "NaN", float("nan"), float("inf"),
    "mcp.tools/call/issue_payroll_bonus",   # a real-looking action name
    "rippling-hr:issue_payroll_bonus",      # a real-looking resource
]

TOKEN_FIELDS = ["token_id", "issued_at", "expires_at", "query_id",
                "authority_id", "authority_version", "permit_epoch",
                "tool_name", "resource_ref", "arguments_hash"]


def _pair(ttl: int = 300):
    """A genuinely valid (signed token, context, trusted key) triple."""
    key = generate_keypair()
    ctx = ExecutionContext(
        action=ActionDescriptor(
            action_name="mcp.tools/call/issue_payroll_bonus",
            resource_ref="rippling-hr:issue_payroll_bonus"),
        input={"employee_id": "emp_001", "bonus_amount": 100},
        authority=AuthorityContext(authority_id="rippling-action-agent",
                                   tenant_id="ten_demo"),
        query_id="q-demo",
    )
    signed = issue_commit_token(ctx, key=key, ttl_seconds=ttl)
    trusted = [signed.signature.get("public_key", "")]
    return signed, ctx, trusted


def _verify(signed, ctx, trusted, **kw):
    """Verify the way a deployment has to: minter pinned, replay store present.

    The store used to be optional here, because it was optional anywhere the
    deployment environment was unset. It is required now, and this harness spent
    one run reporting BASELINE=1 — "a valid token did not verify" — which is the
    guard working and the harness not having caught up. Each call gets a FRESH
    store unless the caller passes one, so a mutation check is not accidentally
    measuring replay defense.
    """
    kw.setdefault("used_token_store", InMemoryUsedTokenStore())
    return verify_commit_token(signed, ctx=ctx, trusted_minting_keys=trusted, **kw)


def run() -> dict:
    findings: dict[str, list] = {
        "NO_MUTATION_VERIFIES": [], "NEVER_RAISES": [],
        "REPLAY_IS_REFUSED": [], "BASELINE": [],
    }
    checks = 0

    # 0. The untouched pair must verify, or every negative below is vacuous.
    signed, ctx, trusted = _pair()
    ok, reason = _verify(signed, ctx, trusted)
    if not ok:
        findings["BASELINE"].append({"detail": f"a valid token did not verify: {reason}"})
        return {"checks": 0, **findings}

    # 1. Mutate every token field with every hostile value.
    for field in TOKEN_FIELDS:
        for value in MUTATIONS:
            signed, ctx, trusted = _pair()
            current = getattr(signed.token, field)
            if current == value:
                continue  # not a mutation
            # `authority_version` and `permit_epoch` are compared with `int()`
            # on BOTH sides, deliberately, so '1' and 1 are the same value. A
            # textual difference there is not a semantic one, and counting it
            # reported two "verifications" that were the verifier working.
            if field in ("authority_version", "permit_epoch"):
                try:
                    if int(current) == int(value):
                        continue
                except (TypeError, ValueError, OverflowError):
                    pass  # not int-comparable, so it IS a mutation
            try:
                mutated = replace(signed, token=replace(signed.token, **{field: value}))
                ok, _ = _verify(mutated, ctx, trusted)
                checks += 1
            except ValueError:
                # `CommitToken.__post_init__` refuses to build an unserializable
                # token. Construction refused IS a denial — the invalid state
                # cannot exist, so there is nothing for the verifier to mishandle.
                checks += 1
                continue
            except Exception as exc:  # noqa: BLE001
                findings["NEVER_RAISES"].append(
                    {"where": f"token.{field}", "value": repr(value)[:40],
                     "error": f"{type(exc).__name__}: {str(exc)[:70]}"})
                continue
            if ok:
                findings["NO_MUTATION_VERIFIES"].append(
                    {"where": f"token.{field}", "value": repr(value)[:40]})

    # 2. Mutate the context, which is caller-supplied and unsigned.
    ctx_mutations = {
        "action_name": lambda c, v: replace(c, action=replace(c.action, action_name=v)),
        "resource_ref": lambda c, v: replace(c, action=replace(c.action, resource_ref=v)),
        "query_id": lambda c, v: replace(c, query_id=v),
        "authority_id": lambda c, v: replace(c, authority=replace(c.authority, authority_id=v)),
        "input": lambda c, v: replace(c, input={"employee_id": "emp_001", "bonus_amount": v}),
    }
    for name, apply in ctx_mutations.items():
        for value in MUTATIONS:
            signed, ctx, trusted = _pair()
            # Re-setting a context field to the value it already holds is not a
            # mutation. Skipping this for token fields but not context fields
            # produced two more false positives on the first run.
            if name == "action_name" and value == ctx.action.action_name:
                continue
            if name == "resource_ref" and value == ctx.action.resource_ref:
                continue
            if name == "query_id" and value == ctx.query_id:
                continue
            if name == "authority_id" and value == ctx.authority.authority_id:
                continue
            try:
                mutated_ctx = apply(ctx, value)
            except Exception:
                continue  # the context itself refused to be built that way
            try:
                ok, _ = _verify(signed, mutated_ctx, trusted)
                checks += 1
            except Exception as exc:  # noqa: BLE001
                findings["NEVER_RAISES"].append(
                    {"where": f"ctx.{name}", "value": repr(value)[:40],
                     "error": f"{type(exc).__name__}: {str(exc)[:70]}"})
                continue
            # An "input" mutation that happens to reproduce the original value
            # is not a mutation.
            if name == "input" and value == 100:
                continue
            if ok:
                findings["NO_MUTATION_VERIFIES"].append(
                    {"where": f"ctx.{name}", "value": repr(value)[:40]})

    # 3. A different signer must not be accepted, even with a perfect token.
    signed, ctx, trusted = _pair()
    other = generate_keypair()
    forged = issue_commit_token(ctx, key=other, ttl_seconds=300)
    ok, _ = _verify(forged, ctx, trusted)
    checks += 1
    if ok:
        findings["NO_MUTATION_VERIFIES"].append(
            {"where": "signer", "value": "a different, valid keypair"})

    # 4. Expiry.
    signed, ctx, trusted = _pair(ttl=1)
    future = datetime.now(timezone.utc) + timedelta(hours=1)
    ok, _ = _verify(signed, ctx, trusted, at=future)
    checks += 1
    if ok:
        findings["NO_MUTATION_VERIFIES"].append(
            {"where": "expiry", "value": "verified an hour after expiry"})

    # 5. Replay: the second presentation must fail.
    signed, ctx, trusted = _pair()
    store = InMemoryUsedTokenStore()
    first, _ = _verify(signed, ctx, trusted, used_token_store=store)
    second, reason = _verify(signed, ctx, trusted, used_token_store=store)
    checks += 2
    if not first:
        findings["BASELINE"].append({"detail": "first presentation failed"})
    if second:
        findings["REPLAY_IS_REFUSED"].append(
            {"detail": "the same token verified twice against a used-token store"})

    # 6. A rejected token must not burn its slot: reject first, then present the
    #    genuine one and it must still work.
    signed, ctx, trusted = _pair()
    store = InMemoryUsedTokenStore()
    bad = replace(signed, token=replace(signed.token, query_id="wrong"))
    _verify(bad, ctx, trusted, used_token_store=store)
    ok, reason = _verify(signed, ctx, trusted, used_token_store=store)
    checks += 1
    if not ok:
        findings["BASELINE"].append(
            {"detail": f"a rejected token burned the token_id slot: {reason}"})

    # 7. The wire boundary must be total: hostile JSON yields a verdict, never
    #    an exception. `from_dict` raises ValueError/TypeError/KeyError by
    #    design (it constructs from trusted data); `parse_signed_commit_token`
    #    is the boundary callers should use.
    from agentauth.capabilities.commit import parse_signed_commit_token

    wire = signed.to_dict()
    for mutate in (
        lambda r: r["token"].__setitem__("authority_version", "PWNED"),
        lambda r: r["token"].__setitem__("authority_version", [1]),
        lambda r: r["token"].__setitem__("permit_epoch", "NaN"),
        lambda r: r["token"].pop("token_id", None),
        lambda r: r.pop("signature", None),
        lambda r: r.__setitem__("token", "not-a-dict"),
    ):
        import copy as _copy

        raw = _copy.deepcopy(wire)
        mutate(raw)
        try:
            token, reason = parse_signed_commit_token(raw)
            checks += 1
        except Exception as exc:  # noqa: BLE001
            findings["NEVER_RAISES"].append(
                {"where": "parse_signed_commit_token", "value": "hostile wire JSON",
                 "error": f"{type(exc).__name__}: {str(exc)[:70]}"})
            continue
        if token is not None or not reason:
            findings["NO_MUTATION_VERIFIES"].append(
                {"where": "parse_signed_commit_token", "value": "hostile wire JSON accepted"})
    for junk in (None, "nope", [1], 42):
        try:
            token, reason = parse_signed_commit_token(junk)
            checks += 1
        except Exception as exc:  # noqa: BLE001
            findings["NEVER_RAISES"].append(
                {"where": "parse_signed_commit_token", "value": repr(junk),
                 "error": f"{type(exc).__name__}: {str(exc)[:70]}"})
            continue
        if token is not None:
            findings["NO_MUTATION_VERIFIES"].append(
                {"where": "parse_signed_commit_token", "value": repr(junk)})

    return {"checks": checks, **findings}


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--json", type=Path, default=None)
    p.add_argument("--verbose", action="store_true")
    args = p.parse_args(argv)

    report = run()
    props = ["NO_MUTATION_VERIFIES", "NEVER_RAISES", "REPLAY_IS_REFUSED", "BASELINE"]
    print(f"commit-token mutation stress: {report['checks']} verifications\n")
    head = f"{'property':<26}{'violations':>12}"
    print(head)
    print("-" * len(head))
    for prop in props:
        print(f"{prop:<26}{len(report[prop]):>12}")
    bad = sum(len(report[p]) for p in props)
    if not bad:
        print("\nno mutation of any token or context field produced a verification")
    else:
        print()
        for prop in props:
            for item in report[prop][: (None if args.verbose else 12)]:
                detail = item.get("error") or item.get("detail") or ""
                where = item.get("where", "")
                print(f"  [{prop}] {where} {item.get('value','')} {detail}".rstrip())
    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(json.dumps(report, indent=2, default=str))
        print(f"\nwrote {args.json}")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
