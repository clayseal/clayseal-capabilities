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


#: How many records one session keeps in memory before the oldest are dropped.
#:
#: A live session is unbounded — a coding agent runs for hours — and every
#: decision appended a record that was never released, so the log grew with the
#: session and was lost whole on exit. Two failures in one: a memory leak in a
#: long run, and no evidence at all unless the integrator wired a sink.
#:
#: The bound only affects what is held in MEMORY. `retained` records are still
#: enough to verify the recent chain, and `head_hash` still covers everything
#: ever appended, so an evicted record is not erased from the chain's history —
#: only from this process's copy of it. Durable retention is the sink's job.
DEFAULT_MAX_RECORDS = 10_000


@dataclass
class DecisionLog:
    """Append-only, hash-chained log of broker decisions for one session.

    Bounded in memory and unbounded in the chain: eviction drops old records but
    never rewrites `prev_hash`, so a verifier handed the retained window plus the
    evicted prefix (from the sink) reconstructs the whole chain.
    """

    session_id: str = field(default_factory=lambda: str(uuid4()))
    #: ``None`` disables eviction entirely, for a caller that keeps the whole
    #: session in memory on purpose (the benchmark harnesses do).
    max_records: int | None = DEFAULT_MAX_RECORDS
    #: Count of records evicted from memory. Non-zero means this log alone is no
    #: longer a complete chain, which a verifier has to know rather than infer.
    evicted: int = 0
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
            # Total appended, not the in-memory length: once eviction starts,
            # `len(_records)` stops being the sequence number and every later
            # record would reuse the same one.
            seq=self.evicted + len(self._records),
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
        if self.max_records is not None and len(self._records) > self.max_records:
            # Drop from the front. `seq` and `prev_hash` are untouched, so the
            # retained window still chains internally and still chains to the
            # evicted prefix wherever that prefix was durably kept.
            overflow = len(self._records) - self.max_records
            del self._records[:overflow]
            self.evicted += overflow
        return record

    def durability(self, sink: Any = None) -> dict[str, Any]:
        """What this log is holding, and what escaped it.

        `evicted > 0` with `dropped > 0` is the state that matters: records left
        memory and did not reach durable storage, so decisions were made that the
        evidence plane cannot account for. Both numbers exist to be alerted on.
        """
        return {
            "retained": len(self._records),
            "evicted": self.evicted,
            "max_records": self.max_records,
            "dropped_by_sink": int(getattr(sink, "dropped", 0)) if sink else None,
            "head_hash": self.head_hash,
        }

    def records(self) -> list[dict[str, Any]]:
        return [r.to_dict() for r in self._records]

    def verify(self) -> tuple[bool, str | None]:
        """Recompute the retained chain; detect any tamper, drop, or reorder.

        When records have been evicted this verifies the retained WINDOW: the
        first retained record's `prev_hash` points at an evicted record this log
        no longer holds, so the check starts from that record rather than from
        genesis. Eviction is bookkeeping and tampering is not, and conflating
        them would make a long session look compromised.
        """
        prev = self.genesis if self.evicted == 0 else None
        for i, record in enumerate(self._records):
            expected_seq = i + self.evicted
            if record.seq != expected_seq:
                return False, f"record {i} has seq {record.seq}"
            if prev is None:
                prev = record.prev_hash  # first retained record after eviction
            if record.prev_hash != prev:
                return False, f"record {i} prev_hash breaks the chain"
            if record.receipt_hash != record.compute_hash():
                return False, f"record {i} content does not match its hash"
            prev = record.receipt_hash
        return True, None
