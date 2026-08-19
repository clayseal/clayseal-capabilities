"""Serialising a live session, so a gateway can be more than one process.

Every control in `SessionBroker` lived in Python object memory and nowhere else:
the trajectory, the outstanding step-up requests, the approvals already spent,
the audit budget consumed, the grants a human issued, the session taints. A
restart dropped all of it, and a second worker never had it.

That is not a durability nicety. Three of those fields ARE controls, and losing
them fails open:

**Outstanding step-ups.** `resolve_step_up` refuses any approval whose
commitment "this session never issued" — correct, and fatal behind a load
balancer, because the worker that receives the human's approval is usually not
the worker that asked. The step-up protocol simply does not complete on a
multi-worker deployment. This is the single most consequential one.

**Spent approvals.** `_consumed` is the single-use ledger. Restart it and every
approval is fresh again, which is the replay defence `used_token_store` already
solved one layer down for commit tokens.

**Audit spend.** `audits_spent` bounds how often the session may interrupt a
human, and a step-up policy is attackable by exhaustion. A ceiling that resets on
restart is not a ceiling.

WHAT THIS IS AND IS NOT
-----------------------
This is the SERIALISATION, not a distributed store. `snapshot()` returns plain
JSON-able data and `restore()` puts it back, so a deployment can put it in
whatever it already runs — Redis, Postgres, a session row. `RedisUsedTokenStore`
is the existing precedent for that shape and this deliberately mirrors it: the
seam ships, the backend is the integrator's.

It also does not make concurrent access across processes safe on its own. The
`SessionBroker` lock is process-local, exactly as `PrincipalLedger`'s was before
`SharedPrincipalLedger`; a cross-process deployment needs the same treatment
here, and `benchmarks/results/production_readiness.md` documents what that took.
Read-modify-write around `snapshot`/`restore` needs the store's own compare-and-set.

WHAT IS DELIBERATELY NOT CARRIED
--------------------------------
The goal, the scope, the egress policy, the intent envelope and the budgets are
CONFIGURATION: they are rebuilt from the mandate when the session is rehydrated,
and a snapshot that carried them would let a restore silently widen authority.
Only the state a session ACCUMULATES is here.
"""
from __future__ import annotations

from typing import Any

from agentauth.capabilities.monitor.action import Action, ContextItem, TrustLevel

SESSION_STATE_SCHEMA = "agent-receipts.session-state.v1"


def _action_to_dict(action: Action) -> dict[str, Any]:
    return {
        "step": action.step,
        "tool": action.tool,
        "resource": action.resource,
        "verb": action.verb,
        "args": dict(action.args or {}),
        "derived_from": list(action.derived_from or ()),
        "outcome": action.outcome,
        "meta": dict(action.meta or {}),
    }


def _action_from_dict(raw: dict[str, Any]) -> Action:
    return Action(
        step=int(raw["step"]),
        tool=str(raw["tool"]),
        resource=str(raw["resource"]),
        verb=str(raw["verb"]),
        args=dict(raw.get("args") or {}),
        derived_from=tuple(raw.get("derived_from") or ()),
        outcome=raw.get("outcome"),
        meta=dict(raw.get("meta") or {}),
    )


def _context_to_dict(item: ContextItem) -> dict[str, Any]:
    return {
        "item_id": item.item_id,
        "trust": item.trust.value,
        "introduced_at_step": item.introduced_at_step,
        "summary": item.summary,
    }


def _context_from_dict(raw: dict[str, Any]) -> ContextItem:
    return ContextItem(
        item_id=str(raw["item_id"]),
        trust=TrustLevel(raw.get("trust", "untrusted")),
        introduced_at_step=int(raw.get("introduced_at_step", 0)),
        summary=str(raw.get("summary", "")),
    )


def snapshot(broker: Any) -> dict[str, Any]:
    """Everything a session accumulated, as JSON-able data.

    Taken under the session lock, so the snapshot is a consistent moment rather
    than a torn read of a session that is still deciding.
    """
    with broker._lock:
        return {
            "schema": SESSION_STATE_SCHEMA,
            "query_id": broker.goal.query_id,
            "trajectory": {
                "actions": [_action_to_dict(a) for a in broker._trajectory.actions],
                "context": [_context_to_dict(c) for c in broker._trajectory.context],
            },
            # The controls. Losing any of these fails open — see the module docstring.
            "pending_step_ups": {
                commitment: request.to_dict()
                for commitment, request in broker._pending.items()
                if hasattr(request, "to_dict")
            },
            "consumed_approvals": sorted(broker._consumed),
            "audits_spent": broker.audits_spent,
            "grants": broker.grants.snapshot()
            if hasattr(broker.grants, "snapshot") else None,
            # Session memory and replan extensions.
            "session_memory": {
                "symlink_taints": [list(t) for t in broker.session.symlink_taints],
                "csv_columns": {k: list(v) for k, v in broker.session.csv_columns.items()},
                "file_text": dict(broker.session.file_text),
                "file_line_shift": dict(broker.session.file_line_shift),
                "sealed_violation": bool(broker.session.sealed_violation),
            },
            "scope_extensions": [list(pair) for pair in broker._extended],
            "declaration_denials": list(broker._declaration_denials),
            "declaration_advisories": list(broker._declaration_advisories),
            # The audit chain, so a rehydrated session appends to it rather than
            # starting a second one that no verifier can join to the first.
            "decision_log": {
                "session_id": broker.decision_log.session_id,
                "records": broker.decision_log.records(),
            },
        }


def restore(broker: Any, state: dict[str, Any]) -> None:
    """Put a snapshot back onto a broker built from the same mandate.

    The caller rebuilds the broker from configuration first — goal, scope,
    egress, budgets — and then restores what the session accumulated. Splitting
    it that way is what stops a snapshot from being a channel for widening
    authority: nothing here can grant a permission the fresh broker did not
    already have.
    """
    if not isinstance(state, dict):
        raise TypeError(f"session state must be an object, got {type(state).__name__}")
    schema = state.get("schema")
    if schema != SESSION_STATE_SCHEMA:
        raise ValueError(
            f"session state schema {schema!r} is not {SESSION_STATE_SCHEMA!r}"
        )
    if state.get("query_id") != broker.goal.query_id:
        raise ValueError(
            f"session state is for query {state.get('query_id')!r}, "
            f"this broker is {broker.goal.query_id!r}"
        )

    from agentauth.capabilities.step_up import StepUpRequest

    with broker._lock:
        traj = state.get("trajectory") or {}
        broker._trajectory.actions = [
            _action_from_dict(a) for a in traj.get("actions") or ()
        ]
        broker._trajectory.context = [
            _context_from_dict(c) for c in traj.get("context") or ()
        ]

        broker._pending = {
            commitment: StepUpRequest.from_dict(raw)
            for commitment, raw in (state.get("pending_step_ups") or {}).items()
        }
        broker._consumed = set(state.get("consumed_approvals") or ())
        broker.audits_spent = int(state.get("audits_spent") or 0)
        grants = state.get("grants")
        if grants is not None and hasattr(broker.grants, "load"):
            broker.grants.load(grants)

        memory = state.get("session_memory") or {}
        broker.session.symlink_taints = {
            tuple(pair) for pair in memory.get("symlink_taints") or ()
        }
        broker.session.csv_columns = {
            k: list(v) for k, v in (memory.get("csv_columns") or {}).items()
        }
        broker.session.file_text = dict(memory.get("file_text") or {})
        broker.session.file_line_shift = dict(memory.get("file_line_shift") or {})
        broker.session.sealed_violation = bool(memory.get("sealed_violation"))

        broker._extended_pairs = {
            tuple(pair) for pair in state.get("scope_extensions") or ()
        }
        broker._declaration_denials = tuple(state.get("declaration_denials") or ())
        broker._declaration_advisories = tuple(
            state.get("declaration_advisories") or ()
        )

        log = state.get("decision_log") or {}
        if log.get("session_id"):
            broker.decision_log.session_id = log["session_id"]
        records = log.get("records") or []
        if records:
            _restore_chain(broker.decision_log, records)


def _restore_chain(decision_log: Any, records: list[dict[str, Any]]) -> None:
    """Rebuild the hash chain and REFUSE a snapshot whose chain does not verify.

    A tamper-evident log that a restore can quietly rewrite is not
    tamper-evident. The records go back exactly as they were and the chain is
    re-verified against them, so a snapshot edited in the store fails here rather
    than becoming the new truth.
    """
    from agentauth.capabilities.decision_log import DecisionRecord

    rebuilt = [
        DecisionRecord(
            seq=int(r["seq"]),
            receipt_id=str(r["receipt_id"]),
            created_at=str(r["created_at"]),
            query_id=r.get("query_id"),
            tool=str(r["action"]["tool"]),
            resource=str(r["action"]["resource"]),
            action_verb=str(r["action"]["verb"]),
            arguments_hash=str(r["action"]["arguments_hash"]),
            outcome=str(r["decision"]["outcome"]),
            layer=str(r["decision"]["layer"]),
            reasons=tuple(r["decision"].get("reasons") or ()),
            anomaly_score=r["decision"].get("anomaly_score"),
            prev_hash=str(r["prev_hash"]),
            receipt_hash=str(r.get("receipt_hash", "")),
        )
        for r in records
    ]
    decision_log._records = rebuilt
    ok, reason = decision_log.verify()
    if not ok:
        decision_log._records = []
        raise ValueError(f"session state decision chain does not verify: {reason}")


def rehydrate(broker: Any, state: dict[str, Any] | None) -> Any:
    """Convenience: restore when there is state, and return the broker either way."""
    if state:
        restore(broker, state)
    return broker
