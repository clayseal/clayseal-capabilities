"""DP-30: Step-up protocol — structured request/approval/patch for scope expansion.

When the governor returns STEP_UP, the broker needs a structured way to:
1. Tell the control plane exactly what is being requested.
2. Receive a signed/trusted approval scoped to specific resources.
3. Apply the approved scope patch to the authority and lease.

This module defines the protocol types and the ``apply_step_up`` function.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

from agentauth.core.hash_util import hash_canonical_json
from agentauth.core.runtime import AuthorityContext
from agentauth.core.signing import SigningKey, signature_key_id_matches, verify

# Escape hatch for the legacy/unsigned path (tests, trusted-local contexts).
ALLOW_UNSIGNED_ENV = "AGENTAUTH_STEP_UP_ALLOW_UNSIGNED"


def _env_allows_unsigned() -> bool:
    return os.getenv(ALLOW_UNSIGNED_ENV, "").strip().lower() in {"1", "true", "yes"}


def apply_authority_patch(authority: AuthorityContext, patch: dict[str, object] | None) -> None:
    if not patch:
        return
    for key, value in patch.items():
        if not hasattr(authority, key):
            continue
        setattr(authority, key, value)  # type: ignore[arg-type]



@dataclass(frozen=True)
class StepUpRequest:
    """Structured request emitted when the governor returns STEP_UP.

    The control plane shows this to the human approver.  The approver
    can approve, deny, or narrow the request.
    """

    request_id: str
    query_id: str | None
    resource_ref: str
    operation: str
    reason: str
    violations: list[str] = field(default_factory=list)
    suggested_approval: dict[str, Any] = field(default_factory=dict)
    # --- action binding -----------------------------------------------------
    # `resource_ref` and `operation` are `mcp:tool:<name>` and a verb in the live
    # path, so two different `send_money` calls to two different recipients
    # differ only by the uuid in `request_id`. An approval therefore committed to
    # "a send_money happened", not to the send the human was shown. These fields
    # put the concrete action inside the commitment.
    tool: str = ""
    arguments_hash: str = ""
    layer: str = ""
    expires_at: str = ""
    #: Machine-readable rule ids, one per entry in `violations`. The prose in
    #: `violations` is for humans and partly attacker-authored (see
    #: `render_card`); the codes are what a grant may waive.
    codes: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": "agent-receipts.step-up-request.v1",
            "request_id": self.request_id,
            "query_id": self.query_id,
            "resource_ref": self.resource_ref,
            "operation": self.operation,
            "reason": self.reason,
            "violations": list(self.violations),
            "suggested_approval": dict(self.suggested_approval),
            "tool": self.tool,
            "arguments_hash": self.arguments_hash,
            "layer": self.layer,
            "expires_at": self.expires_at,
            "codes": list(self.codes),
        }

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> StepUpRequest:
        """Rebuild a request from `to_dict`, commitment-preserving.

        Needed to persist outstanding step-ups across a process boundary: the
        worker that receives a human's approval is usually not the worker that
        asked for it, and `SessionBroker.resolve_step_up` refuses any approval
        whose commitment this session never issued. Without a round trip the
        step-up protocol simply does not complete on a multi-worker deployment.

        Every field `to_dict` writes is read back, and `test_session_state.py`
        asserts `from_dict(to_dict(r)).commitment() == r.commitment()` — a field
        added to one and forgotten in the other would silently change the
        commitment and invalidate every approval in flight.
        """
        return cls(
            request_id=str(raw["request_id"]),
            query_id=raw.get("query_id"),
            resource_ref=str(raw["resource_ref"]),
            operation=str(raw["operation"]),
            reason=str(raw.get("reason", "")),
            violations=list(raw.get("violations") or []),
            suggested_approval=dict(raw.get("suggested_approval") or {}),
            tool=str(raw.get("tool", "")),
            arguments_hash=str(raw.get("arguments_hash", "")),
            layer=str(raw.get("layer", "")),
            expires_at=str(raw.get("expires_at", "")),
            codes=tuple(raw.get("codes") or ()),
        )

    def commitment(self) -> str:
        return f"sha256:{hash_canonical_json(self.to_dict())}"


@dataclass(frozen=True)
class StepUpApproval:
    """Trusted approval from the control plane scoped to specific resources.

    ``allow_resources`` are the concrete resource refs the human approved.
    ``ttl_seconds`` bounds how long the approval is valid.
    ``request_commitment`` binds this approval to the original request.
    """

    approval_id: str
    request_commitment: str
    allow_resources: list[str]
    allow_write: bool = False
    ttl_seconds: int = 600
    extra_budget: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": "agent-receipts.step-up-approval.v1",
            "approval_id": self.approval_id,
            "request_commitment": self.request_commitment,
            "allow_resources": list(self.allow_resources),
            "allow_write": self.allow_write,
            "ttl_seconds": self.ttl_seconds,
            "extra_budget": self.extra_budget,
        }

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> StepUpApproval:
        return cls(
            approval_id=str(raw["approval_id"]),
            request_commitment=str(raw["request_commitment"]),
            allow_resources=[str(item) for item in raw.get("allow_resources", [])],
            allow_write=bool(raw.get("allow_write", False)),
            ttl_seconds=int(raw.get("ttl_seconds", 600)),
            extra_budget=raw.get("extra_budget"),
        )


@dataclass(frozen=True)
class SignedStepUpApproval:
    """A :class:`StepUpApproval` signed by the control plane (mirrors
    :class:`agentauth.capabilities.commit.SignedCommitToken`).

    An unsigned ``StepUpApproval`` is just data an untrusted party can forge to
    widen its own scope/TTL/budget; the signed form lets the broker prove the
    approval came from the control plane before ``apply_step_up`` mutates the
    authority.
    """

    approval: StepUpApproval
    signature: dict[str, str]

    def to_dict(self) -> dict[str, Any]:
        return {"approval": self.approval.to_dict(), "signature": dict(self.signature)}

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> SignedStepUpApproval:
        return cls(
            approval=StepUpApproval.from_dict(dict(raw["approval"])),
            signature=dict(raw["signature"]),
        )


def sign_step_up_approval(
    approval: StepUpApproval, *, key: SigningKey
) -> SignedStepUpApproval:
    """Sign an approval with the control plane's key."""
    return SignedStepUpApproval(approval=approval, signature=key.sign(approval.to_dict()))


def verify_step_up_approval(
    signed: SignedStepUpApproval, *, request_commitment: str | None
) -> tuple[bool, str | None]:
    """Verify an approval's signature and its binding to the originating request.

    ``request_commitment`` MUST be the ``StepUpRequest.commitment()`` of the
    request this approval answers — binding the approval to one specific request
    stops a signed approval being replayed against a different one.
    """
    if not signature_key_id_matches(signed.signature):
        return False, "step-up approval signature key_id does not match public_key"
    if not verify(signed.approval.to_dict(), signed.signature):
        return False, "step-up approval signature invalid"
    if not request_commitment:
        return False, "step-up approval requires a request_commitment to bind against"
    if signed.approval.request_commitment != request_commitment:
        return False, "step-up approval request_commitment mismatch"
    return True, None


def _authenticate_approval(
    approval: StepUpApproval | SignedStepUpApproval,
    *,
    request_commitment: str | None,
    allow_unsigned: bool,
) -> StepUpApproval:
    if isinstance(approval, SignedStepUpApproval):
        ok, reason = verify_step_up_approval(approval, request_commitment=request_commitment)
        if not ok:
            raise ValueError(f"step-up approval rejected: {reason}")
        return approval.approval
    if not (allow_unsigned or _env_allows_unsigned()):
        raise ValueError(
            "apply_step_up requires a SignedStepUpApproval: sign the approval with "
            "sign_step_up_approval(approval, key=...) and pass the originating "
            "request_commitment=StepUpRequest.commitment(). Pass allow_unsigned=True "
            f"(or set {ALLOW_UNSIGNED_ENV}=1) ONLY in tests/trusted-local contexts."
        )
    # The escape above turns off approval AUTHENTICATION, and an approval widens
    # authority — it is the one object in this protocol whose whole job is to
    # grant something the floor refused. A deployment that reaches this branch is
    # applying a grant nobody signed.
    #
    # Its siblings were already blocked in production (`AGENT_RECEIPTS_ALLOW_STUB`,
    # `AGENTAUTH_DEV_ATTESTOR` and the rest are in `production._RECEIPTS_PRODUCTION_DENY`);
    # this one was not, so setting one environment variable disabled the check
    # and the system reported success. That is the shape this repository has
    # already shipped six times and names in `principal_ledger`: "a control that
    # stopped applying when its input was unusual, and reported success."
    from agentauth.core.production import fail_closed

    if fail_closed():
        raise ValueError(
            "unsigned step-up approvals are refused: an approval grants "
            "authority the floor refused, so it must be signed. Unset "
            f"{ALLOW_UNSIGNED_ENV} and pass a SignedStepUpApproval, or set "
            "AGENTAUTH_ENV=development to relax this while developing."
        )
    return approval




#: Violation prose the broker emits, mapped to a stable rule id. A grant waives
#: CODES, never prose: the prose contains attacker-controlled substrings and
#: changes whenever a message is reworded.
_CODE_PREFIXES: tuple[tuple[str, str], ...] = (
    ("egress", "egress.destination"),
    ("recipient", "egress.destination"),
    ("resource out of scope", "scope.resource"),
    ("path outside", "scope.path"),
    ("protected", "scope.protected"),
    ("verb class", "scope.verb"),
    ("off-plan", "envelope.off_plan"),
    ("off slot", "envelope.off_slot"),
    ("sealed-plan", "sealed_plan.drift"),
    ("declaration", "declaration"),
    ("session-taint", "session.taint"),
    ("session-bind", "session.bind"),
    ("entailment", "content.entailment"),
    ("budget", "budget"),
    ("target density", "density.target"),
    ("in-scope staging", "staging"),
    ("flow:", "flow.derivation"),
)


def violation_code(violation: str) -> str:
    """Stable rule id for a violation string.

    Deliberately a prefix table rather than parsing: the prose is written for a
    human and is not a protocol surface. An unrecognised violation maps to
    `unclassified`, which no grant can waive, so a new rule fails closed until
    somebody classifies it.
    """
    low = (violation or "").strip().lower()
    for needle, code in _CODE_PREFIXES:
        if needle in low:
            return code
    return "unclassified"


def bind_to_action(
    request: StepUpRequest,
    *,
    tool: str,
    arguments_hash: str,
    layer: str,
    ttl_seconds: int = 600,
    now: datetime | None = None,
) -> StepUpRequest:
    """Attach the concrete action to a request, and stamp its expiry.

    Called once at the broker's single step-up convergence point rather than at
    each of the nine construction sites, so a new step-up path cannot forget it.
    """
    from dataclasses import replace as _replace

    current = now or datetime.now(timezone.utc)
    return _replace(
        request,
        tool=tool,
        arguments_hash=arguments_hash,
        layer=layer,
        expires_at=(current + timedelta(seconds=ttl_seconds)).isoformat(),
        codes=tuple(violation_code(v) for v in request.violations),
    )


def render_card(request: StepUpRequest) -> dict[str, Any]:
    """What a human may safely be shown.

    `build_step_up_request` sets `reason = "; ".join(violations[:3])`, and the
    violations routinely embed attacker-controlled strings: the egress reason
    interpolates the destination, provenance reasons carry the token, and
    content-entailment reasons are drawn from the write body. So the text on the
    approval card is partly authored by the attacker, and the approval card is
    the one surface whose entire purpose is to persuade a human.

    This returns typed trusted fields only. Anything attacker-influenced goes in
    `untrusted_values`, which a UI must render inert (no links, no markup, no
    autofill) and which is deliberately NOT part of `summary`.
    """
    return {
        "summary": {
            "tool": request.tool,
            "operation": request.operation,
            "resource": request.resource_ref,
            "layer": request.layer,
            "arguments_hash": request.arguments_hash,
            "expires_at": request.expires_at,
            "rules": list(request.codes),
        },
        "untrusted_values": list(request.violations),
        "commitment": request.commitment(),
    }


def build_step_up_request(
    *,
    request_id: str,
    query_id: str | None,
    resource_ref: str,
    operation: str,
    violations: list[str],
) -> StepUpRequest:
    reason = "; ".join(violations[:3]) if violations else "step-up required"
    return StepUpRequest(
        request_id=request_id,
        query_id=query_id,
        resource_ref=resource_ref,
        operation=operation,
        reason=reason,
        violations=list(violations),
        suggested_approval={
            "allow_resources": [resource_ref],
            "allow_write": operation != "read",
        },
    )


def apply_step_up(
    authority: AuthorityContext,
    approval: StepUpApproval | SignedStepUpApproval,
    *,
    request_commitment: str | None = None,
    allow_unsigned: bool = False,
) -> dict[str, object]:
    """Apply an approved step-up to the authority context.

    Adds the approved resources to ``approval_refs`` and ``resource_scope``,
    optionally extends the lease TTL and budget.

    SECURITY: pass a :class:`SignedStepUpApproval` plus the originating
    ``request_commitment``; the signature and binding are verified BEFORE any
    mutation. An unsigned :class:`StepUpApproval` is refused unless
    ``allow_unsigned=True`` (or ``AGENTAUTH_STEP_UP_ALLOW_UNSIGNED=1``), an
    explicit escape hatch intended for tests/trusted-local use only.

    Returns the authority patch that was applied.
    """
    approval = _authenticate_approval(
        approval, request_commitment=request_commitment, allow_unsigned=allow_unsigned
    )

    patch: dict[str, object] = {}

    new_refs = list(authority.approval_refs)
    for resource in approval.allow_resources:
        if resource not in new_refs:
            new_refs.append(resource)
    patch["approval_refs"] = new_refs

    new_scope = list(authority.resource_scope)
    for resource in approval.allow_resources:
        if resource not in new_scope:
            new_scope.append(resource)
    patch["resource_scope"] = new_scope

    if approval.ttl_seconds > 0:
        expires = datetime.now(timezone.utc) + timedelta(seconds=approval.ttl_seconds)
        patch["expires_at"] = expires.isoformat()

    if approval.extra_budget is not None:
        current = authority.lease_remaining_calls or 0
        patch["lease_remaining_calls"] = current + approval.extra_budget

    patch["authority_version"] = authority.authority_version + 1

    apply_authority_patch(authority, patch)
    return patch
