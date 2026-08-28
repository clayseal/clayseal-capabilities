"""Authority fields may never be sourced from an untrusted claims dict.

Every adapter here normalizes provider-shaped claims into the internal record
`AuthorityBinding.from_verified_credential` expects. Three of them do it
*conditionally*, and fall back to passing the caller's dict through untouched:

    oidc.py:30        claims_from_oidc(raw)   if "sub" in raw and "iss" in raw   else raw
    auth0.py:33       claims_from_auth0(raw)  if "auth0.com" in iss              else raw
    spiffe_jwt.py:34  claims_from_spiffe(raw) if "sub" in raw                    else raw

The fallback is there for input that is already in internal form. It cannot tell
already-normalized from attacker-authored, and the difference matters because the
internal form has fields the claims form does not. Measured by
`benchmarks/stress_identity.py`:

    {"subject_id": "alice", "capabilities": ["payments.transfer:*"],
     "has_capability_grant": true}

presented to the oidc or auth0 adapter yields a binding carrying exactly that
capability. No signature is involved; the claims dict asserts its own authority
and the adapter agrees.

This is the sixth instance of one shape in this library: a control that stops
applying when its input does not match what it expected, and reports success. The
others were `1e999` against a value ceiling, a `NaN` compute ceiling, a list
handed to `is_protected_path`, the planner's three fail-open paths, and the
replay store's outage branch.

The fix is not to delete the fallback, some callers legitimately hold an already
normalized record, but to make the fallback unable to carry authority. Identity
claims describe *who*; authority comes from the mandate and the capability
authorizer. A claims dict that mentions capabilities is either confused or
hostile, and it costs nothing to treat both the same way.
"""
from __future__ import annotations

from collections.abc import Mapping
from typing import Any

__all__ = ["AUTHORITY_FIELDS", "strip_authority_fields"]

#: Fields on `AuthorityBinding` that confer authority or assert its provenance.
#: None of these may originate in a claims dict. `evidence_verified` is included
#: even though the constructor keyword already wins, because relying on argument
#: precedence to defeat an injected field is a property of the current call site
#: rather than of the data.
AUTHORITY_FIELDS = frozenset({
    "capabilities",
    "capability_rules",
    "has_capability_grant",
    "evidence_verified",
    "trust_tier",
    "delegation_chain",
    "selectors",
    "proof_of_possession",
    "presenter_key_hash",
    "authority_id",
})


def strip_authority_fields(raw: Mapping[str, Any]) -> dict[str, Any]:
    """Return `raw` without any field that would confer authority.

    Silent by design. A raise would turn a merely confused token into an outage,
    and the dropped fields carried no authority the caller was entitled to, so
    there is nothing for the caller to do differently. The adapters that call
    this are on the authorization path.
    """
    if not isinstance(raw, Mapping):
        return {}
    return {k: v for k, v in raw.items() if k not in AUTHORITY_FIELDS}
