"""Tamper-evident decision log — the L2 side of the receipts loop.

The broker decides; the receipts layer (L3) makes those decisions verifiable.
This is the seam between them. For every authorization the broker emits a
canonical ``DecisionRecord`` and chains it: each record's hash covers the prior
record's hash, so any edit, drop, or reorder of a past decision breaks the chain
and is detected by :meth:`DecisionLog.verify`. The record carries the action
binding (tool, resource, arguments hash) and the behavioral anomaly score, so an
auditor can recompute the decision, matching the receipts
``anomaly-score-proof`` contract.

Capabilities (L2) does not import receipts (L3): records are plain dicts pushed
through a sink callback, and L3 wraps them in signed / TEE-attested bundles. The
schema id mirrors the receipts namespace so L3 recognizes them.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from agentauth.core.hash_util import hash_canonical_json

DECISION_SCHEMA = "agent-receipts.broker-decision.v1"


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass(frozen=True)
class DecisionRecord:
    seq: int
    receipt_id: str
    created_at: str
    query_id: str | None
    tool: str
    resource: str
    action_verb: str
    arguments_hash: str
    outcome: str
    layer: str
    reasons: tuple[str, ...]
    anomaly_score: float | None
    prev_hash: str
    receipt_hash: str = ""

    def body(self) -> dict[str, Any]:
        """Canonical content the receipt_hash commits to (everything but itself)."""
        return {
            "schema": DECISION_SCHEMA,
            "seq": self.seq,
            "receipt_id": self.receipt_id,
            "created_at": self.created_at,
            "query_id": self.query_id,
            "action": {
                "tool": self.tool,
                "resource": self.resource,
                "verb": self.action_verb,
                "arguments_hash": self.arguments_hash,
            },
            "decision": {
                "outcome": self.outcome,
                "layer": self.layer,
                "reasons": list(self.reasons),
                "anomaly_score": self.anomaly_score,
            },
            "prev_hash": self.prev_hash,
        }

    def compute_hash(self) -> str:
        return f"sha256:{hash_canonical_json(self.body())}"

    def to_dict(self) -> dict[str, Any]:
        return {**self.body(), "receipt_hash": self.receipt_hash}


@dataclass
class DecisionLog:
    """Append-only, hash-chained log of broker decisions for one session."""

    session_id: str = field(default_factory=lambda: str(uuid4()))
    _records: list[DecisionRecord] = field(default_factory=list)

    @property
    def genesis(self) -> str:
        return f"sha256:{hash_canonical_json({'session_id': self.session_id, 'genesis': True})}"

    @property
    def head_hash(self) -> str:
        return self._records[-1].receipt_hash if self._records else self.genesis

    def append(
        self,
        *,
        query_id: str | None,
        tool: str,
        resource: str,
        action_verb: str,
        arguments_hash: str,
        outcome: str,
        layer: str,
        reasons: tuple[str, ...],
        anomaly_score: float | None = None,
    ) -> DecisionRecord:
        record = DecisionRecord(
            seq=len(self._records),
            receipt_id=str(uuid4()),
            created_at=_utc_now_iso(),
            query_id=query_id,
            tool=tool, resource=resource, action_verb=action_verb,
            arguments_hash=arguments_hash,
            outcome=outcome, layer=layer, reasons=tuple(reasons),
            anomaly_score=anomaly_score,
            prev_hash=self.head_hash,
        )
        record = DecisionRecord(**{**record.__dict__, "receipt_hash": record.compute_hash()})
        self._records.append(record)
        return record

    def records(self) -> list[dict[str, Any]]:
        return [r.to_dict() for r in self._records]

    def verify(self) -> tuple[bool, str | None]:
        """Recompute the chain; detect any tamper, drop, or reorder."""
        prev = self.genesis
        for i, record in enumerate(self._records):
            if record.seq != i:
                return False, f"record {i} has seq {record.seq}"
            if record.prev_hash != prev:
                return False, f"record {i} prev_hash breaks the chain"
            if record.receipt_hash != record.compute_hash():
                return False, f"record {i} content does not match its hash"
            prev = record.receipt_hash
        return True, None
