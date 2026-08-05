"""Turn a sandboxed run into attestation evidence.

The payload answers, for one run: which policy governed it, which binary
enforced that policy, what the enforcer observed, and how it ended. It lands in
``ExecutionContext.sandboxing`` — a field that has existed in the core schema
with no producer — so the evidence rides along with the commit token and into
receipts without any schema change.

FAIL CLOSED ON DEGRADED EVIDENCE. If iVisor could not use the trace fd it warns
and reroutes verdicts to stderr, which the guest can write. A run in that state
has produced *no* trustworthy observations, and the difference between "nothing
was denied" and "we could not see what happened" is the whole value of the
attestation. `evidence_ok: false` says so explicitly, and the verdict counts are
zeroed rather than reported from a forgeable stream.

Layering: records leave as plain dicts through a sink callback, exactly as
``decision_log`` does, so this module never imports L3.
"""
from __future__ import annotations

import hashlib
from collections.abc import Callable
from functools import lru_cache
from pathlib import Path
from typing import Any

from agentauth.core.hash_util import hash_canonical_json

from agentauth.capabilities.sandbox.driver import IVisorResult

SANDBOX_SCHEMA = "agentauth.capabilities.sandbox.attestation.v1"


@lru_cache(maxsize=32)
def ivisor_binary_identity(path: str) -> dict[str, Any]:
    """Identify the enforcing binary by content hash.

    Deliberately not a codesign query: the entitlement matters to macOS, but for
    attestation the question is "which build ran", and a hash answers that
    without shelling out. Cached — the binary does not change mid-session.
    """
    target = Path(path)
    try:
        raw = target.read_bytes()
    except OSError:
        return {"path": str(target), "sha256": None, "size": None,
                "error": "unreadable"}
    return {"path": str(target),
            "sha256": hashlib.sha256(raw).hexdigest(),
            "size": len(raw)}


def sandboxing_context(*, result: IVisorResult, lowered, staged=None,
                       run_id: str, ivisor_bin: str,
                       config_path: str | Path | None = None,
                       workspace_delta: dict | None = None) -> dict[str, Any]:
    """Build the ``ExecutionContext.sandboxing`` payload for one run."""
    evidence_ok = result.evidence_ok
    payload: dict[str, Any] = {
        "schema": SANDBOX_SCHEMA,
        "sandbox": "ivisor",
        "run_id": run_id,
        "policy_digest": lowered.config.digest(),
        "config_path": str(config_path) if config_path else None,
        "binary": ivisor_binary_identity(str(ivisor_bin)),
        "evidence_ok": evidence_ok,
        "trace_degraded": result.trace_degraded,
        "verdicts": result.summary() if evidence_ok else {
            "allow": 0, "deny": 0, "miss": 0,
            "unverified_claims": len(result.unverified_claims)},
        "denied": ([event.summary() for event in result.denials()]
                   if evidence_ok else []),
        "exit": {"kind": result.exit_kind.value, "code": result.exit_code,
                 "signal": result.signal},
        "wall_seconds": round(result.wall_seconds, 6),
        "cpu_seconds": (None if result.cpu_seconds is None
                        else round(result.cpu_seconds, 6)),
        "lowering": lowered.report.to_dict(),
    }
    if staged is not None:
        payload["workspace_manifest_digest"] = hash_canonical_json(
            dict(sorted(staged.manifest.items())))
    if workspace_delta is not None:
        payload["workspace_delta"] = workspace_delta
    return payload


def attach_sandboxing(ctx, payload: dict[str, Any]) -> None:
    """Attach the payload to an ExecutionContext.

    ``ExecutionContext.sandboxing`` is already part of the core schema and is
    serialized by ``to_dict``, so nothing upstream needs to change.
    """
    ctx.sandboxing = payload


def sandbox_outcome_label(payload: dict[str, Any]) -> str:
    """allow / deny / indeterminate for one run.

    A degraded run is `indeterminate`, never `allow`: absence of observed
    denials is not evidence of absence when the channel was untrusted.
    """
    if not payload.get("evidence_ok", False):
        return "indeterminate"
    return "deny" if payload.get("verdicts", {}).get("deny", 0) else "allow"


def log_sandbox_run(payload: dict[str, Any], *, decision_log=None,
                    query_id: str | None = None,
                    receipt_sink: Callable[[dict], None] | None = None,
                    tool: str = "sandbox.ivisor") -> dict[str, Any]:
    """Append the run to the hash-chained decision log and emit a receipt.

    The run is recorded at ``layer="substrate"`` to distinguish syscall-level
    evidence from the broker's own tool-call decisions in the same chain.
    """
    outcome = sandbox_outcome_label(payload)
    reasons: list[str] = []
    if payload.get("trace_degraded"):
        reasons.append("trace_degraded: verdicts fell back to a forgeable stream")
    reasons.extend(payload.get("denied", [])[:8])
    if payload.get("unverified_claims") or payload.get("verdicts", {}).get(
            "unverified_claims"):
        reasons.append("guest emitted policy-shaped lines on stdout/stderr")

    record = None
    if decision_log is not None:
        record = decision_log.append(
            query_id=query_id,
            tool=tool,
            resource=f"sandbox:run/{payload.get('run_id')}",
            action_verb="execute",
            arguments_hash=payload.get("policy_digest", ""),
            outcome=outcome,
            layer="substrate",
            reasons=tuple(reasons),
        )
    emitted = {"schema": SANDBOX_SCHEMA, "outcome": outcome,
               "sandboxing": payload,
               "decision_record": record.to_dict() if record is not None else None}
    if receipt_sink is not None:
        receipt_sink(emitted)
    return emitted
