"""Where decision records go when the process ends.

`DecisionLog` is correct, hash-chained, tamper-evident, verifiable offline, and
it lived entirely in memory behind an optional `receipt_sink` callback that
defaulted to `None`. For a layer whose pitch is "the decision can be verified
offline by a gateway or receipt verifier", the default was that nothing was
written anywhere.

Bounding the log fixed the leak and made the gap sharper: records are now evicted
from memory, so without a sink they are not merely lost at exit, they are lost
during the run. Eviction is only safe because the evicted prefix went somewhere.

WHY THERE IS STILL NO DEFAULT DESTINATION
-----------------------------------------
A sink writes an audit trail, and where an audit trail belongs is a deployment
decision with legal and retention consequences. Picking one here would mean
either writing to a path nobody asked for or silently doing nothing, and doing
nothing while appearing configured is the failure mode this module exists to
close. So the default is a sink that REFUSES to be silent: `NullSink` counts what
it drops and `DecisionLog` reports it, and a stack built without a sink says so
in its findings rather than looking configured.

The sinks here cover the shapes a deployment already has:

``JsonlFileSink``   append-only file, one record per line, fsync-optional.
``RotatingJsonlSink`` the same with a size cap and generation rollover.
``RedisStreamSink`` XADD to a stream another service consumes.
``CompositeSink``   several at once; one failing does not stop the others.
``NullSink``        explicit "nowhere", which counts.

EVERY SINK IS BEST-EFFORT AND NONE OF THEM CAN DENY
---------------------------------------------------
A sink runs after the decision is made. A sink that raised would turn a disk full
into a failed authorization, converting an evidence problem into an availability
problem, and a sink that could veto would be an undeclared authorization layer.
So failures are counted and exposed, never raised. `dropped` going non-zero is
what an operator alerts on: it means decisions were made that the evidence plane
did not record.
"""
from __future__ import annotations

import json
import os
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol, runtime_checkable

DECISION_SINK_PATH_ENV = "AGENTAUTH_DECISION_LOG_PATH"
DECISION_SINK_REDIS_URL_ENV = "AGENTAUTH_DECISION_LOG_REDIS_URL"
DECISION_SINK_REDIS_STREAM_ENV = "AGENTAUTH_DECISION_LOG_REDIS_STREAM"
DECISION_SINK_FSYNC_ENV = "AGENTAUTH_DECISION_LOG_FSYNC"


#: Audit evidence and ledger state are created private to the owning user.
#:
#: These files carry principal identity, resource paths, decision outcomes and
#: spend. Created through a plain `open("a")` they inherit the process umask,
#: which on a typical host is 0o644: every local user can read the whole
#: authorization trail of a security control. `os.open` applies the mode at
#: creation instead of leaving a window between create and chmod.
PRIVATE_FILE_MODE = 0o600
PRIVATE_DIR_MODE = 0o700


def open_private_append(path, *, encoding: str = "utf-8"):
    """Append-open `path`, creating it 0o600 rather than umask-default."""
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_APPEND,
                 PRIVATE_FILE_MODE)
    return os.fdopen(fd, "a", encoding=encoding)


def make_private_parent(path) -> None:
    """Create the containing directory 0o700 when this call is what makes it."""
    parent = Path(path).parent
    existed = parent.exists()
    parent.mkdir(parents=True, exist_ok=True)
    if not existed:
        try:
            parent.chmod(PRIVATE_DIR_MODE)
        except OSError:      # a filesystem that does not carry modes
            pass


@runtime_checkable
class DecisionSink(Protocol):
    """Somewhere a decision record durably lands."""

    #: Records this sink failed to write. Non-zero means decisions were made
    #: that the evidence plane did not record.
    dropped: int

    def __call__(self, record: dict[str, Any]) -> None:
        ...


@dataclass
class NullSink:
    """Explicitly nowhere, and it counts, which is the whole point.

    The previous default was `receipt_sink=None`, indistinguishable at runtime
    from a sink that was configured and working. This one makes "no durable
    evidence" a number an operator can see.
    """

    dropped: int = 0

    def __call__(self, record: dict[str, Any]) -> None:
        self.dropped += 1


@dataclass
class JsonlFileSink:
    """Append-only JSONL. The shape every log shipper already reads.

    Opened once and held, because opening per record costs a syscall pair on the
    hot path and buys nothing: an append to an already-open handle is what makes
    the ordering guarantee cheap.
    """

    path: Path
    #: `fsync` after every record. Off by default: it costs a disk round trip per
    #: authorization, and the chain already detects a lost tail (the next record's
    #: `prev_hash` will not match). On for a deployment that must not lose the
    #: last few decisions to a machine failure.
    fsync: bool = False
    dropped: int = 0
    _handle: Any = field(default=None, repr=False, init=False)
    _lock: Any = field(default_factory=threading.Lock, repr=False, init=False)

    def __post_init__(self) -> None:
        self.path = Path(self.path)
        make_private_parent(self.path)

    def __call__(self, record: dict[str, Any]) -> None:
        try:
            line = json.dumps(record, separators=(",", ":"), sort_keys=True)
        except (TypeError, ValueError):
            self.dropped += 1
            return
        with self._lock:
            try:
                if self._handle is None:
                    self._handle = open_private_append(self.path)
                self._handle.write(line + "\n")
                self._handle.flush()
                if self.fsync:
                    os.fsync(self._handle.fileno())
            except OSError:
                # A full disk must not fail an authorization that already
                # happened. Count it and keep going; `dropped` is the alert.
                self.dropped += 1
                self._close()

    def _close(self) -> None:
        try:
            if self._handle is not None:
                self._handle.close()
        except OSError:
            pass
        self._handle = None

    def close(self) -> None:
        with self._lock:
            self._close()


@dataclass
class RotatingJsonlSink(JsonlFileSink):
    """`JsonlFileSink` with a size cap, for a long-lived gateway.

    Rolls to ``<name>.1``, ``<name>.2``, … so the chain stays reconstructable in
    order. Rotation is not deletion: nothing is discarded here, because a
    retention policy belongs to the deployment and an audit trail that silently
    forgets is worse than one that grows.
    """

    max_bytes: int = 256 * 1024 * 1024
    _generation: int = field(default=0, init=False, repr=False)

    def __call__(self, record: dict[str, Any]) -> None:
        with self._lock:
            try:
                if self._handle is not None and self._handle.tell() >= self.max_bytes:
                    self._rotate()
            except OSError:
                self.dropped += 1
                self._close()
        super().__call__(record)

    def _rotate(self) -> None:
        self._close()
        self._generation += 1
        rolled = self.path.with_suffix(self.path.suffix + f".{self._generation}")
        try:
            self.path.rename(rolled)
        except OSError:
            self.dropped += 1


@dataclass
class RedisStreamSink:
    """`XADD` to a Redis stream another service consumes.

    The natural pairing for a deployment already running Redis for the replay
    store and the shared ledger, and the one that gets records off the box the
    agent runs on, which is where an audit trail should not live if the box is
    what you are auditing.
    """

    client: Any
    stream: str = "agentauth:decisions"
    #: Cap the stream so it cannot grow without bound. Approximate trimming is
    #: much cheaper and the bound is an operational one, not a correctness one.
    maxlen: int | None = 1_000_000
    dropped: int = 0

    def __call__(self, record: dict[str, Any]) -> None:
        try:
            payload = {"record": json.dumps(record, separators=(",", ":"), sort_keys=True)}
        except (TypeError, ValueError):
            self.dropped += 1
            return
        try:
            if self.maxlen is not None:
                self.client.xadd(self.stream, payload, maxlen=self.maxlen, approximate=True)
            else:
                self.client.xadd(self.stream, payload)
        except Exception:  # noqa: BLE001 - a sink may never fail an authorization
            self.dropped += 1


@dataclass
class CompositeSink:
    """Several sinks; one failing does not stop the others.

    A deployment usually wants both a local file (survives a network partition)
    and a remote stream (survives the machine). Fanning out here rather than
    chaining means a Redis outage does not cost the local copy.
    """

    sinks: tuple[Any, ...] = ()

    @property
    def dropped(self) -> int:
        return sum(int(getattr(s, "dropped", 0)) for s in self.sinks)

    def __call__(self, record: dict[str, Any]) -> None:
        for sink in self.sinks:
            try:
                sink(record)
            except Exception:  # noqa: BLE001, S110 - one bad sink must not shadow the rest
                # Deliberately silent HERE and counted THERE: each sink owns its
                # own `dropped`, and `CompositeSink.dropped` sums them, so the
                # failure is visible without this loop needing to know how.
                pass


def sink_from_env() -> Any:
    """Build the configured sink, or a counting `NullSink` when none is set.

    Never returns ``None``: "nothing configured" and "configured and working" must
    not look the same at runtime.
    """
    sinks: list[Any] = []

    path = os.environ.get(DECISION_SINK_PATH_ENV, "").strip()
    if path:
        fsync = os.environ.get(DECISION_SINK_FSYNC_ENV, "").strip().lower() in {
            "1", "true", "yes", "on",
        }
        sinks.append(JsonlFileSink(path=Path(path), fsync=fsync))

    url = os.environ.get(DECISION_SINK_REDIS_URL_ENV, "").strip()
    if url:
        import redis  # optional extra, imported only when configured

        stream = (
            os.environ.get(DECISION_SINK_REDIS_STREAM_ENV, "").strip()
            or "agentauth:decisions"
        )
        sinks.append(RedisStreamSink(client=redis.Redis.from_url(url), stream=stream))

    if not sinks:
        return NullSink()
    if len(sinks) == 1:
        return sinks[0]
    return CompositeSink(sinks=tuple(sinks))


# --------------------------------------------------------------------------- #
# Where a security team already looks.
# --------------------------------------------------------------------------- #

#: OCSF class 6003, "API Activity", which is the class an authorization decision
#: about a tool call belongs to. Activity 1 is Create and 3 is Update; a gateway
#: decision is neither, so `Other` with the verb in the metadata is the honest
#: mapping rather than forcing it into a shape it does not have.
OCSF_API_ACTIVITY = 6003
OCSF_SEVERITY = {"allow": 1, "step_up": 3, "deny": 4}   # Informational/Medium/High
#: OCSF status: 1 Success, 2 Failure. A refusal is a SUCCESS of the control and
#: a FAILURE of the attempt, and the field describes the attempt.
OCSF_STATUS = {"allow": 1, "step_up": 2, "deny": 2}


def to_ocsf(record: dict[str, Any]) -> dict[str, Any]:
    """A decision record in the shape a SIEM already parses.

    The original release audit closed with "decisions do not reach the systems
    that watch for incidents", and shipping JSONL did not fix that: a security
    team does not write a bespoke parser for one vendor's log. OCSF is the shape
    they already ingest, so this maps rather than invents.

    Nothing is added that the record did not already carry. Arguments stay
    hashed, the receipt hash and the previous hash travel so the chain is
    verifiable from the SIEM's copy, and the trace id travels so the event joins
    to the caller's trace. A SIEM event that cannot be tied back to the receipt
    it came from is a rumour.
    """
    decision = record.get("decision") or {}
    action = record.get("action") or {}
    outcome = str(decision.get("outcome", "")).lower()
    trace = record.get("trace") or {}
    return {
        "class_uid": OCSF_API_ACTIVITY,
        "class_name": "API Activity",
        "category_uid": 6,
        "activity_id": 0,
        "activity_name": "Other",
        "type_uid": OCSF_API_ACTIVITY * 100,
        "severity_id": OCSF_SEVERITY.get(outcome, 0),
        "status_id": OCSF_STATUS.get(outcome, 0),
        "status_detail": "; ".join(decision.get("reasons") or ()) or None,
        "time": record.get("created_at"),
        "api": {
            "operation": action.get("verb"),
            "service": {"name": action.get("tool")},
            "request": {"uid": record.get("receipt_id")},
        },
        "resources": [{"uid": action.get("resource")}]
        if action.get("resource") else [],
        "actor": {"session": {"uid": record.get("query_id")}},
        "metadata": {
            "product": {"name": "clayseal", "vendor_name": "clayseal"},
            "version": "1.4.0",
            "log_name": record.get("schema"),
            "trace_uid": trace.get("trace_id"),
            "correlation_uid": trace.get("span_id"),
        },
        "unmapped": {
            "layer": decision.get("layer"),
            "anomaly_score": decision.get("anomaly_score"),
            "arguments_hash": action.get("arguments_hash"),
            "receipt_hash": record.get("receipt_hash"),
            "prev_hash": record.get("prev_hash"),
            "seq": record.get("seq"),
        },
    }


@dataclass
class OcsfSink:
    """Re-shape each record and hand it on. Composes with any other sink."""

    inner: Any
    dropped: int = 0

    def __call__(self, record: dict[str, Any]) -> None:
        try:
            event = to_ocsf(record)
        except Exception:  # noqa: BLE001 - a mapping failure is not a lost decision
            self.dropped += 1
            return
        self.inner(event)


@dataclass
class OtelSpanSink:
    """One span per decision, when an OpenTelemetry SDK is installed.

    Optional by construction. This library has two runtime dependencies and
    that is a large part of why it installs at all, so the SDK is imported
    lazily and its absence makes this a counter rather than an error: a
    deployment without OTel gets `unavailable` incrementing, which is visible,
    instead of a crash at the first decision.

    The span is created with the decision's own trace id as its parent when one
    is present, which is the whole point: the span lands inside the caller's
    trace rather than beside it.
    """

    tracer_name: str = "clayseal"
    dropped: int = 0
    unavailable: int = 0
    _tracer: Any = None
    _looked: bool = False

    def _tracer_or_none(self) -> Any:
        if not self._looked:
            self._looked = True
            try:
                from opentelemetry import trace as otel

                self._tracer = otel.get_tracer(self.tracer_name)
            except Exception:  # noqa: BLE001 - absence is the ordinary case
                self._tracer = None
        return self._tracer

    def __call__(self, record: dict[str, Any]) -> None:
        tracer = self._tracer_or_none()
        if tracer is None:
            self.unavailable += 1
            return
        decision = record.get("decision") or {}
        action = record.get("action") or {}
        try:
            with tracer.start_as_current_span(
                f"clayseal.authorize {action.get('tool', '')}".strip()
            ) as span:
                span.set_attribute("clayseal.outcome",
                                   str(decision.get("outcome", "")))
                span.set_attribute("clayseal.layer",
                                   str(decision.get("layer", "")))
                span.set_attribute("clayseal.tool", str(action.get("tool", "")))
                span.set_attribute("clayseal.verb", str(action.get("verb", "")))
                span.set_attribute("clayseal.receipt_hash",
                                   str(record.get("receipt_hash", "")))
                reasons = decision.get("reasons") or ()
                if reasons:
                    span.set_attribute("clayseal.reasons", "; ".join(reasons))
        except Exception:  # noqa: BLE001 - telemetry is never load-bearing
            self.dropped += 1
