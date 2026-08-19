from __future__ import annotations

import heapq
import os
import threading
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Protocol, runtime_checkable
from uuid import uuid4

from agentauth.core.hash_util import hash_canonical_json
from agentauth.core.runtime import ExecutionContext
from agentauth.core.signing import SigningKey, signature_key_id_matches, verify

COMMIT_TOKEN_SCHEMA = "agent-receipts.commit-token.v1"
COMMIT_TOKEN_TRUSTED_KEYS_ENV = "AGENTAUTH_COMMIT_TOKEN_TRUSTED_KEYS"


def trusted_minting_keys_from_env() -> set[str]:
    """Pinned commit-token minting keys from the environment.

    Comma-separated entries; each is either a hex Ed25519 public key (an
    optional ``ed25519:`` prefix is stripped) or a signature ``key_id``.
    """
    raw = os.environ.get(COMMIT_TOKEN_TRUSTED_KEYS_ENV, "")
    keys: set[str] = set()
    for item in raw.split(","):
        normalized = item.strip().removeprefix("ed25519:")
        if normalized:
            keys.add(normalized)
    return keys


@runtime_checkable
class UsedTokenStore(Protocol):
    """Swappable single-use ledger for commit tokens (replay defense).

    A commit token authorizes exactly ONE irreversible side effect. Without a
    store, a captured/valid token can be replayed until it expires. Implement
    this seam over whatever your deployment already runs:

    - single-instance / dev: :class:`InMemoryUsedTokenStore` (the default);
    - multi-instance AWS: a shared/distributed store (e.g. Redis ``SET NX PX``
      or a DynamoDB conditional put with a TTL attribute) so a token consumed
      on one instance is rejected on every other.
    """

    def mark_used(self, token_id: str, expires_at: datetime) -> bool:
        """Atomically record ``token_id`` as consumed until ``expires_at``.

        Returns ``True`` when this is the first time the token is seen (the
        caller may proceed), or ``False`` when the token was already recorded
        and has not yet expired (a replay — the caller MUST reject).
        """
        ...


class InMemoryUsedTokenStore:
    """Process-local, thread-safe :class:`UsedTokenStore` with TTL eviction.

    WARNING: this only defends against replay WITHIN a single process. On a
    multi-instance deployment (e.g. several AWS tasks behind a load balancer) a
    token consumed on one instance is NOT visible to the others — back
    :func:`verify_commit_token` with a shared/distributed store instead.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._seen: dict[str, datetime] = {}
        #: (expires_at, token_id) min-heap so eviction touches only expired
        #: entries instead of walking the whole ledger on every call.
        self._expiry: list[tuple[datetime, str]] = []

    def mark_used(self, token_id: str, expires_at: datetime) -> bool:
        token_id = str(token_id)
        now = _utc_now()
        with self._lock:
            self._evict(now)
            existing = self._seen.get(token_id)
            if existing is not None and existing > now:
                return False
            self._seen[token_id] = expires_at
            heapq.heappush(self._expiry, (expires_at, token_id))
            return True

    def _evict(self, now: datetime) -> None:
        """Drop only what has actually expired, not the whole ledger.

        The previous implementation rebuilt a list over EVERY entry on every
        call, so marking N tokens cost O(N^2) and the per-call price grew with
        the live set: measured 32.5us at token 2,000 and 402.8us at token 20,000,
        a 12.4x rise on traffic that should be flat. A gateway under load pays
        that quadratic, and an attacker can inflate the live set on purpose by
        issuing tokens, which turns replay defense into the slowest thing in the
        request path. The confidentiality accumulator has the identical defect
        and is currently red in `test_flow_invariants.py`; this is the same bug
        wearing a different hat.

        A heap keyed on expiry touches only the entries that have genuinely
        expired, so eviction is amortised O(log N) and idle traffic costs
        nothing. The staleness guard matters: a token re-marked after its first
        entry expired leaves the old heap entry behind, and popping it must not
        delete the live record.
        """
        while self._expiry and self._expiry[0][0] <= now:
            expires_at, token_id = heapq.heappop(self._expiry)
            if self._seen.get(token_id) == expires_at:
                del self._seen[token_id]


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _parse_dt(value: str) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


@dataclass(frozen=True)
class CommitToken:
    """
    Signed, single-purpose authorization to perform an irreversible "commit" tool call.

    A commit token is meant to be minted by a hardened control plane (governor/committer),
    then verified at the tool proxy boundary before allowing the real side effect.
    """

    token_id: str
    issued_at: str
    expires_at: str
    query_id: str | None
    authority_id: str
    authority_version: int
    permit_epoch: int
    tool_name: str
    resource_ref: str | None
    arguments_hash: str

    def __post_init__(self) -> None:
        """Reject a token that cannot be serialized, at construction.

        ``to_dict`` coerces the two integer fields with ``int()``, and it is the
        FIRST thing ``verify_commit_token`` calls — before the signature check.
        So a ``CommitToken`` holding ``authority_version='x'`` does not fail
        verification, it raises ``ValueError`` from inside the verifier, ahead of
        every check that would have rejected it.

        No shipped path produces such a token: ``from_dict`` coerces with
        ``int()`` and ``issue_commit_token`` reads integers off the context. But
        the dataclass permitted the state, and a type that permits a state whose
        only expression is an exception deep inside the verifier is the wrong
        shape. Validate here and the invalid token simply cannot exist, which is
        strictly better than every consumer remembering to guard.

        Found by ``benchmarks/stress_commit.py``, which mutates every field of a
        valid token and asserts that exactly one input verifies. It found no
        mutation that verified — the binding is sound — and 37 that raised.
        """
        for name in ("authority_version", "permit_epoch"):
            raw = getattr(self, name)
            try:
                int(raw)
            except (TypeError, ValueError, OverflowError) as exc:
                raise ValueError(
                    f"commit token {name} must be an integer, got {raw!r}") from exc

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": COMMIT_TOKEN_SCHEMA,
            "token_id": self.token_id,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "query_id": self.query_id,
            "authority_id": self.authority_id,
            "authority_version": int(self.authority_version),
            "permit_epoch": int(self.permit_epoch),
            "tool_name": self.tool_name,
            "resource_ref": self.resource_ref,
            "arguments_hash": self.arguments_hash,
        }

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> CommitToken:
        return cls(
            token_id=str(raw["token_id"]),
            issued_at=str(raw["issued_at"]),
            expires_at=str(raw["expires_at"]),
            query_id=raw.get("query_id"),
            authority_id=str(raw["authority_id"]),
            authority_version=int(raw.get("authority_version", 1)),
            permit_epoch=int(raw.get("permit_epoch", 0)),
            tool_name=str(raw["tool_name"]),
            resource_ref=raw.get("resource_ref"),
            arguments_hash=str(raw["arguments_hash"]),
        )


@dataclass(frozen=True)
class SignedCommitToken:
    token: CommitToken
    signature: dict[str, str]

    def to_dict(self) -> dict[str, Any]:
        return {"token": self.token.to_dict(), "signature": dict(self.signature)}

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> SignedCommitToken:
        """Construct from TRUSTED data. Raises on anything malformed.

        For bytes off the wire use :func:`parse_signed_commit_token`, which
        returns a verdict instead of an exception.
        """
        return cls(
            token=CommitToken.from_dict(dict(raw["token"])),
            signature=dict(raw["signature"]),
        )


def parse_signed_commit_token(
    raw: Any,
) -> tuple[SignedCommitToken | None, str | None]:
    """Total parse of an untrusted, wire-format commit token.

    ``SignedCommitToken.from_dict`` is a *constructor for trusted data*: it
    indexes required keys and coerces with ``int()``/``str()``, so hostile JSON
    produces a raw exception rather than a decision. Measured across six
    single-field mutations of an otherwise well-formed token, it raises
    ``ValueError``, ``TypeError`` and ``KeyError`` — three different types, none
    of them a verdict:

        authority_version='PWNED'  -> ValueError
        authority_version=[1]      -> TypeError
        permit_epoch='NaN'         -> ValueError
        token_id absent            -> KeyError
        token not a mapping        -> ValueError
        signature absent           -> KeyError

    That is not a fail-open — no malformed token verifies, and the mutation
    stress in ``benchmarks/stress_commit.py`` confirms every field of the token
    and of the context is genuinely bound. It is worse-shaped than that: an
    unhandled exception at the exact boundary where attacker-controlled bytes
    enter the system. Every caller must wrap it, and the first caller that wraps
    it in a broad ``except Exception`` turns a parse failure into whatever the
    surrounding code does next.

    So the boundary gets its own total entry point. This function returns
    ``(token, None)`` or ``(None, reason)`` and raises nothing, for any input at
    all — including ``None``, a list, or a string. ``from_dict`` keeps its
    existing behaviour and is documented as the trusted-data constructor.
    """
    if not isinstance(raw, dict):
        return None, f"commit token payload must be an object, got {type(raw).__name__}"
    try:
        return SignedCommitToken.from_dict(raw), None
    except KeyError as exc:
        return None, f"commit token missing required field {exc.args[0]!r}"
    except (TypeError, ValueError) as exc:
        return None, f"commit token field is malformed: {exc}"
    except Exception as exc:  # noqa: BLE001 - the boundary must be total
        return None, f"commit token could not be parsed: {type(exc).__name__}"


def issue_commit_token(
    ctx: ExecutionContext,
    *,
    key: SigningKey,
    ttl_seconds: int,
) -> SignedCommitToken:
    if ttl_seconds <= 0:
        raise ValueError("ttl_seconds must be > 0")
    # The context is caller-supplied and unsigned, so it is untrusted input in
    # exactly the way the signed token is not. ``ActionDescriptor`` performs no
    # validation and lives in the sibling core package, so the guard belongs
    # here: a non-string ``action_name`` raised ``AttributeError`` from
    # ``.rsplit`` — nine variants, found by benchmarks/stress_commit.py.
    #
    # RAISES, and does not return a verdict. The verifier's matching guard
    # returns ``(False, reason)`` because verification is total by contract: it
    # answers a question about attacker-supplied bytes and must never throw.
    # Minting is the opposite — there is no "no" to return, only a token or
    # nothing — and this guard was copy-pasted from the verifier, so it returned
    # a ``tuple`` from a function annotated ``-> SignedCommitToken``. The caller
    # then failed with an ``AttributeError`` one frame further out, which is the
    # exact failure shape the guard exists to prevent. ``ValueError`` matches the
    # ``ttl_seconds`` guard directly above it.
    if not isinstance(ctx.action.action_name, str):
        # ValueError, not TypeError, and deliberately: this mirrors the
        # `ttl_seconds` guard directly above, so a caller wrapping the mint call
        # catches one exception type for "the context you handed me is not
        # mintable" rather than two.
        raise ValueError(  # noqa: TRY004
            "execution context action_name must be a string, got "
            f"{type(ctx.action.action_name).__name__}"
        )
    tool_name = ctx.action.action_name.rsplit("/", 1)[-1]
    now = _utc_now()
    token = CommitToken(
        token_id=str(uuid4()),
        issued_at=now.isoformat(),
        expires_at=(now + timedelta(seconds=ttl_seconds)).isoformat(),
        query_id=ctx.query_id,
        authority_id=ctx.authority.authority_id,
        authority_version=int(ctx.authority.authority_version),
        permit_epoch=int(ctx.authority.permit_epoch),
        tool_name=tool_name,
        resource_ref=ctx.action.resource_ref,
        arguments_hash=hash_canonical_json(ctx.input),
    )
    token_dict = token.to_dict()
    signature = key.sign(token_dict)
    return SignedCommitToken(token=token, signature=signature)


def verify_commit_token(
    signed: SignedCommitToken,
    *,
    ctx: ExecutionContext,
    at: datetime | None = None,
    used_token_store: UsedTokenStore | None = None,
    trusted_minting_keys: Iterable[str] | None = None,
) -> tuple[bool, str | None]:
    """Verify a signed commit token against ``ctx``.

    The signature proves integrity, not authority: any keyholder can produce an
    internally consistent token. ``trusted_minting_keys`` (or the
    ``AGENTAUTH_COMMIT_TOKEN_TRUSTED_KEYS`` env var) pins which signer(s) —
    hex public keys or key_ids — are the governor/committer allowed to mint.
    In production a pin is REQUIRED; without one verification fails closed.

    Single-use enforcement is a swappable seam: pass ``used_token_store`` and a
    ``token_id`` that has already been consumed (before its expiry) is rejected
    as a replay. PRODUCTION CALLERS MUST PASS A STORE — without one a captured,
    still-valid token can be replayed until it expires. Use
    :class:`InMemoryUsedTokenStore` for a single instance, or a shared /
    distributed :class:`UsedTokenStore` for a multi-instance AWS deployment.
    The store is consulted only after every other check passes, so a rejected
    token never burns a ``token_id`` slot. If the store raises — a partition, a
    timeout — verification DENIES with a reason rather than propagating the
    exception; see the handler for why that is not configurable.
    """
    at = at or _utc_now()
    token_dict = signed.token.to_dict()
    if not signature_key_id_matches(signed.signature):
        return False, "commit token signature key_id does not match public_key"
    if not verify(token_dict, signed.signature):
        return False, "commit token signature invalid"

    minting_keys = (
        set(trusted_minting_keys)
        if trusted_minting_keys is not None
        else trusted_minting_keys_from_env()
    )
    if minting_keys:
        signer_public_key = signed.signature.get("public_key", "")
        signer_key_id = signed.signature.get("key_id", "")
        if (
            signer_public_key not in minting_keys
            and signer_key_id not in minting_keys
        ):
            return False, "commit token signer is not a trusted minting key"
    else:
        from agentauth.core.production import is_production

        if is_production():
            return (
                False,
                "commit token trusted minting keys required in production "
                f"(set {COMMIT_TOKEN_TRUSTED_KEYS_ENV} or pass trusted_minting_keys)",
            )
    expires_at = _parse_dt(signed.token.expires_at)
    if expires_at is None:
        return False, "commit token expires_at invalid"
    if expires_at <= at.astimezone(timezone.utc):
        return False, "commit token expired"

    # The context is caller-supplied and unsigned, so it is untrusted input in
    # exactly the way the signed token is not. ``ActionDescriptor`` performs no
    # validation and lives in the sibling core package, so the guard belongs
    # here: a non-string ``action_name`` raised ``AttributeError`` from
    # ``.rsplit`` — nine variants, found by benchmarks/stress_commit.py — instead
    # of returning a verdict. A verifier that crashes on a malformed context is a
    # denial of service, and behind a broad ``except`` it is an allow.
    if not isinstance(ctx.action.action_name, str):
        return False, "execution context action_name must be a string"
    tool_name = ctx.action.action_name.rsplit("/", 1)[-1]
    if signed.token.tool_name != tool_name:
        return False, "commit token tool_name mismatch"
    if signed.token.resource_ref != ctx.action.resource_ref:
        return False, "commit token resource_ref mismatch"
    if signed.token.arguments_hash != hash_canonical_json(ctx.input):
        return False, "commit token arguments_hash mismatch"
    if signed.token.authority_id != ctx.authority.authority_id:
        return False, "commit token authority_id mismatch"
    if int(signed.token.authority_version) != int(ctx.authority.authority_version):
        return False, "commit token authority_version mismatch"
    if int(signed.token.permit_epoch) != int(ctx.authority.permit_epoch):
        return False, "commit token epoch mismatch"
    if signed.token.query_id != ctx.query_id:
        return False, "commit token query_id mismatch"

    # Single-use enforcement (replay defense). Reached only once the token is
    # otherwise valid, so a rejected token never consumes a token_id slot.
    if used_token_store is None:
        try:
            from agentauth.capabilities.used_token_store import default_used_token_store

            used_token_store = default_used_token_store()
        except ImportError:
            used_token_store = None
    if used_token_store is None:
        from agentauth.core.production import is_production

        if is_production():
            return (
                False,
                "commit token replay store required in production "
                "(configure AGENTAUTH_COMMIT_TOKEN_REDIS_URL or pass used_token_store)",
            )
    if used_token_store is not None:
        try:
            first_use = used_token_store.mark_used(signed.token.token_id, expires_at)
        except Exception as exc:  # noqa: BLE001 - see below
            # A replay store that cannot be reached must DENY, and it must deny
            # by returning a verdict rather than by propagating the backend's
            # exception.
            #
            # `RedisUsedTokenStore.mark_used` is a bare `client.set(...)` and
            # `DynamoDBUsedTokenStore` re-raises any non-conditional
            # `ClientError`, so before this a partition sent `ConnectionError` /
            # `TimeoutError` straight out of the verifier. That is technically
            # fail-closed, and it is still the wrong shape for two reasons: it
            # forces every integrator to implement the deny themselves, and the
            # first one who wraps this call in a broad `except` converts a
            # partition into whatever their fallback does. Single-use is the one
            # property with no second line of defence — nothing above the token
            # re-checks it — so the decision belongs here, once.
            #
            # Deliberately NOT offered as a fail-open option. A caller who wants
            # to trade replay exposure for availability already has a supported
            # way to say so: pass no store, and accept the documented exposure
            # explicitly rather than inheriting it from an outage.
            return False, f"commit token replay store unavailable: {type(exc).__name__}"
        if not first_use:
            return False, "commit token already used (replay)"

    return True, None
