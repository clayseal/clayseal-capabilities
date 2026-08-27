"""Fuzzing the identity adapters, which are the last unfuzzed wire boundary.

    python -m benchmarks.stress_identity

Every other input boundary in this library has been fuzzed and each one gave up a
fail-open: `1e999` as a transfer amount returned `allowed=True`, a `NaN` compute
ceiling granted 1,000,000 seconds as `ok`, `is_protected_path` raised on a list.
The adapters in `agentauth/capabilities/identity_adapters/` take an attacker- or
third-party-shaped claims dict and turn it into an `AuthorityBinding`, and nothing
had ever handed them a malformed one.

Three questions, in increasing order of how much they matter.

**Totality.** An adapter that raises on a malformed claim takes the authorization
call with it. Same shape as the `NaN` defect in `value_budget`.

**Authority inflation.** `evidence_verified` defaults to `False` on every adapter
but `agentauth`'s. A claims dict that can flip it, or that arrives carrying
capabilities it was never granted, is authority manufactured at the boundary.

**Principal identity, which is the one that actually matters now.**
`AuthorityBinding.subject_id` is what `principal_ledger.py` keys its ledger to,
and that ledger is the *fix* for the session-restart escape in
`stress_aggregation.py`. So subject_id has two obligations that pull in opposite
directions, and both are ledger-critical:

    collision   two different principals must never share a subject_id, or one
                spends against the other's ceiling
    stability   one principal must never produce two subject_ids, or the ledger
                splits and the session-restart escape is back at the identity
                layer instead of the session layer

A cross-issuer collision is the sharper of the two: `sub` is only unique within
an issuer, and any deployment accepting more than one issuer where subject_id
ignores `iss` has a budget an attacker can target by minting their own token.

Deterministic and offline. No network, no model.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from agentauth.capabilities.identity_adapters import (
    auth0,
    aws_sts,
    azure_ad,
    gcp,
    oidc,
)
from agentauth.capabilities.principal_ledger import principal_key

ADAPTERS = {
    "oidc": oidc.provider,
    "auth0": auth0.provider,
    "azure_ad": azure_ad.provider,
    "aws_sts": aws_sts.provider,
    "gcp": gcp.provider,
}

#: Claims dicts an adapter should survive. Each is a shape a real boundary sees:
#: a truncated token, a type-confused field, an oversized field, a field carrying
#: the separator the id format uses.
MALFORMED: list[tuple[str, dict]] = [
    ("empty", {}),
    ("sub is None", {"sub": None, "iss": "https://a.example"}),
    ("sub is a list", {"sub": ["a", "b"], "iss": "https://a.example"}),
    ("sub is a dict", {"sub": {"nested": 1}, "iss": "https://a.example"}),
    ("sub is an int", {"sub": 12345, "iss": "https://a.example"}),
    ("iss is None", {"sub": "alice", "iss": None}),
    ("iss is a list", {"sub": "alice", "iss": ["https://a.example"]}),
    ("scope is a dict", {"sub": "a", "iss": "i", "scope": {"x": 1}}),
    ("scope is an int", {"sub": "a", "iss": "i", "scope": 7}),
    ("scopes is a string", {"sub": "a", "iss": "i", "scopes": "not-a-list"}),
    ("exp is a string", {"sub": "a", "iss": "i", "exp": "tomorrow"}),
    ("exp is NaN", {"sub": "a", "iss": "i", "exp": float("nan")}),
    ("exp is inf", {"sub": "a", "iss": "i", "exp": float("inf")}),
    ("huge sub", {"sub": "x" * 100_000, "iss": "i"}),
    ("null byte in sub", {"sub": "ali\x00ce", "iss": "i"}),
    ("newline in sub", {"sub": "alice\niss=evil", "iss": "i"}),
    ("separator in sub", {"sub": "alice|https://evil.example", "iss": "i"}),
    ("unicode rtl in sub", {"sub": "ali\u202ece", "iss": "i"}),
    ("deeply nested", {"sub": "a", "iss": "i", "x": {"y": {"z": [{"w": 1}]}}}),
    ("capabilities injected", {"sub": "a", "iss": "i",
                               "capabilities": ["payments.transfer:*"]}),
    ("evidence_verified injected", {"sub": "a", "iss": "i",
                                    "evidence_verified": True}),
    ("trust_tier injected", {"sub": "a", "iss": "i", "trust_tier": "hardware"}),
    ("has_capability_grant injected", {"sub": "a", "iss": "i",
                                       "has_capability_grant": True}),
]


def _binding(provider, raw):
    return provider.to_binding(raw)


# --------------------------------------------------------------------------- #
def probe_totality() -> list[dict]:
    """No adapter may raise. A raise here takes the authorization call with it."""
    rows = []
    for name, provider in ADAPTERS.items():
        for label, raw in MALFORMED:
            try:
                _binding(provider, raw)
                rows.append({"adapter": name, "input": label, "outcome": "ok"})
            except Exception as exc:  # noqa: BLE001 - the point is to catch all
                rows.append({"adapter": name, "input": label,
                             "outcome": "RAISED",
                             "detail": f"{type(exc).__name__}: {exc}"[:120]})
    return rows


def probe_authority_inflation() -> list[dict]:
    """Claims must not be able to assert their own verification or trust.

    Differential, and it has to be. The first version of this probe flagged any
    non-empty value as inflation and reported `trust_tier -> workload_attested`
    on all five adapters, which is simply the default those adapters set; the
    claim had nothing to do with it. A probe that cannot tell a default from an
    injection reports five findings where the real count is different, and a
    fuzzer with a false-positive rate is one whose true positives get waved off.

    So each field is built twice, with and without the injected claim, and only a
    DIFFERENCE counts.
    """
    rows = []
    base = {"sub": "a", "iss": "i"}
    inflating = [
        ("evidence_verified", True),
        ("has_capability_grant", True),
        ("trust_tier", "hardware"),
        ("capabilities", ["payments.transfer:*"]),
    ]
    for name, provider in ADAPTERS.items():
        try:
            clean = _binding(provider, dict(base))
        except Exception as exc:  # noqa: BLE001
            rows.append({"adapter": name, "field": "(baseline)",
                         "inflated": None, "note": type(exc).__name__})
            continue
        for field, value in inflating:
            try:
                dirty = _binding(provider, {**base, field: value})
            except Exception as exc:  # noqa: BLE001
                rows.append({"adapter": name, "field": field,
                             "inflated": None, "note": type(exc).__name__})
                continue
            before, after = getattr(clean, field, None), getattr(dirty, field, None)
            rows.append({"adapter": name, "field": field,
                         "inflated": before != after,
                         "value": f"{before!s:.24} -> {after!s:.24}"})
    return rows


def probe_principal_identity() -> list[dict]:
    """subject_id: never collide across principals, never split within one."""
    rows = []
    for name, provider in ADAPTERS.items():
        def sid(raw, provider=provider):
            try:
                return getattr(_binding(provider, raw), "subject_id", None)
            except Exception:  # noqa: BLE001
                return "<raised>"

        # Collision: one `sub`, two issuers. `sub` is unique only within an
        # issuer, so any deployment trusting two issuers where subject_id drops
        # `iss` lets either issuer mint the other's principal.
        a = sid({"sub": "alice", "iss": "https://good.example"})
        b = sid({"sub": "alice", "iss": "https://evil.example"})
        rows.append({"adapter": name, "check": "subject_id cross-issuer",
                     "bad": a == b and a not in (None, "<raised>"),
                     # Known and faithful: `subject_id` IS the raw `sub` claim,
                     # and reporting it unqualified is correct behaviour for an
                     # adapter. The defect would be a LEDGER keyed on it, which
                     # is what the next row checks.
                     "known": True,
                     "detail": f"{a!s:.30} vs {b!s:.30}"})

        # The same pair through `principal_ledger.principal_key`, which is what
        # a ledger must actually be keyed on. The row above is expected to fail
        # on every adapter, `sub` is unique only within an issuer and the
        # adapters report it faithfully, so this row is the one that matters.
        def pk(raw, provider=provider):
            try:
                return principal_key(_binding(provider, raw))
            except Exception:  # noqa: BLE001
                return "<raised>"

        ka = pk({"sub": "alice", "iss": "https://good.example"})
        kb = pk({"sub": "alice", "iss": "https://evil.example"})
        rows.append({"adapter": name, "check": "principal_key cross-issuer",
                     "bad": ka == kb and ka != "<raised>",
                     "detail": f"{ka!s:.30} vs {kb!s:.30}"})

        # Forgery: a `sub` carrying the separator a composite id would use. If
        # subject_id is built by joining, this is how one principal spells
        # another.
        c = sid({"sub": "https://evil.example|alice", "iss": "https://x.example"})
        rows.append({"adapter": name, "check": "separator in sub",
                     "bad": c not in (None, "<raised>") and "|" in str(c)
                            and str(c).count("|") > 1,
                     "detail": f"{c!s:.60}"})

        # Stability: the same principal presenting twice must key the same. A
        # split here reintroduces the session-restart escape at the identity
        # layer, where the principal ledger cannot see it.
        base = {"sub": "alice", "iss": "https://good.example"}
        d = sid(base)
        e = sid({**base, "scope": "read write", "exp": 999})
        rows.append({"adapter": name, "check": "stability under extra claims",
                     "bad": d != e,
                     "detail": f"{d!s:.40} vs {e!s:.40}"})
    return rows


# --------------------------------------------------------------------------- #
def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--json", type=Path, default=None)
    args = p.parse_args(argv)

    tot = probe_totality()
    inf = probe_authority_inflation()
    ident = probe_principal_identity()

    raised = [r for r in tot if r["outcome"] == "RAISED"]
    print(f"totality           {len(tot) - len(raised)}/{len(tot)} survived")
    for r in raised[:12]:
        print(f"  RAISED  {r['adapter']:<9} {r['input']:<28} {r['detail']}")
    if len(raised) > 12:
        print(f"  ... and {len(raised) - 12} more")

    inflated = [r for r in inf if r.get("inflated")]
    print(f"\nauthority inflation {len(inflated)} of {len(inf)} probes inflated")
    for r in inflated:
        print(f"  INFLATED {r['adapter']:<9} {r['field']:<22} -> {r['value']}")

    bad = [r for r in ident if r["bad"] and not r.get("known")]
    known = [r for r in ident if r["bad"] and r.get("known")]
    print(f"\nprincipal identity  {len(bad)} open, {len(known)} known-and-mitigated"
          f", of {len(ident)} checks")
    for r in ident:
        mark = ("FAIL" if not r.get("known") else "known") if r["bad"] else "ok"
        print(f"  {mark:<6}{r['adapter']:<9} {r['check']:<28} {r['detail']}")

    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(json.dumps(
            {"totality": tot, "inflation": inf, "identity": ident}, indent=2))

    print(f"\n{len(raised)} raises, {len(inflated)} inflations, "
          f"{len(bad)} open identity failures "
          f"({len(known)} known, mitigated by principal_key)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
