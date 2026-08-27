"""Distributed and in-process commit-token replay stores."""

from __future__ import annotations

import threading
from datetime import datetime, timezone
from urllib.parse import urlparse

from clayseal.capabilities.commit import InMemoryUsedTokenStore, UsedTokenStore
from clayseal.core import env

COMMIT_TOKEN_STORE_ENV = "CLAYSEAL_COMMIT_TOKEN_STORE"
COMMIT_TOKEN_REDIS_URL_ENV = "CLAYSEAL_COMMIT_TOKEN_REDIS_URL"
COMMIT_TOKEN_DYNAMODB_TABLE_ENV = "CLAYSEAL_COMMIT_TOKEN_DYNAMODB_TABLE"
COMMIT_TOKEN_DYNAMODB_REGION_ENV = "CLAYSEAL_COMMIT_TOKEN_DYNAMODB_REGION"


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _ttl_ms(expires_at: datetime, *, now: datetime | None = None) -> int:
    current = now or _utc_now()
    remaining = int((expires_at - current).total_seconds() * 1000)
    return max(1, remaining)


class RedisUsedTokenStore:
    """Redis-backed :class:`UsedTokenStore` for multi-instance replay defense.

    Uses ``SET key NX PX ttl`` so a token consumed on one instance is rejected
    everywhere. Requires the optional ``redis`` package::

        pip install 'clayseal[redis]'
    """

    def __init__(self, redis_url: str, *, key_prefix: str = "agentauth:commit:") -> None:
        try:
            import redis
        except ImportError as exc:  # pragma: no cover
            raise ImportError(
                "RedisUsedTokenStore requires the redis package. "
                "Install with: pip install 'clayseal[redis]'"
            ) from exc
        self._client = redis.Redis.from_url(redis_url, decode_responses=True)
        self._prefix = key_prefix

    def _key(self, token_id: str) -> str:
        return f"{self._prefix}{token_id}"

    def mark_used(self, token_id: str, expires_at: datetime) -> bool:
        ttl = _ttl_ms(expires_at)
        return bool(self._client.set(self._key(token_id), "1", nx=True, px=ttl))


class DynamoDBUsedTokenStore:
    """DynamoDB-backed :class:`UsedTokenStore` for multi-instance replay defense.

    Requires ``boto3``::

        pip install 'clayseal[dynamodb]'
    """

    def __init__(
        self,
        table_name: str,
        *,
        region_name: str | None = None,
        key_attr: str = "token_id",
        ttl_attr: str = "expires_at",
    ) -> None:
        try:
            import boto3
            from botocore.exceptions import ClientError
        except ImportError as exc:  # pragma: no cover
            raise ImportError(
                "DynamoDBUsedTokenStore requires boto3. "
                "Install with: pip install 'clayseal[dynamodb]'"
            ) from exc
        self._client_error = ClientError
        session = boto3.session.Session(region_name=region_name)
        self._table = session.resource("dynamodb").Table(table_name)
        self._key_attr = key_attr
        self._ttl_attr = ttl_attr

    def mark_used(self, token_id: str, expires_at: datetime) -> bool:
        expires_epoch = int(expires_at.timestamp())
        try:
            self._table.put_item(
                Item={
                    self._key_attr: token_id,
                    self._ttl_attr: expires_epoch,
                },
                ConditionExpression=f"attribute_not_exists({self._key_attr})",
            )
            return True
        except self._client_error as exc:
            if exc.response.get("Error", {}).get("Code") == "ConditionalCheckFailedException":
                return False
            raise


def load_used_token_store_from_env() -> UsedTokenStore | None:
    """Resolve a replay store from environment variables.

    Resolution order:

    1. ``CLAYSEAL_COMMIT_TOKEN_STORE=memory`` -> in-process store (single instance)
    2. ``CLAYSEAL_COMMIT_TOKEN_REDIS_URL`` or ``redis://`` value in
       ``CLAYSEAL_COMMIT_TOKEN_STORE``
    3. ``CLAYSEAL_COMMIT_TOKEN_DYNAMODB_TABLE`` or ``dynamodb://table`` value in
       ``CLAYSEAL_COMMIT_TOKEN_STORE``
    """
    raw = env.get(COMMIT_TOKEN_STORE_ENV, "").strip().lower()
    redis_url = env.get(COMMIT_TOKEN_REDIS_URL_ENV, "").strip()
    dynamo_table = env.get(COMMIT_TOKEN_DYNAMODB_TABLE_ENV, "").strip()
    dynamo_region = env.get(COMMIT_TOKEN_DYNAMODB_REGION_ENV, "").strip() or None

    if raw in {"", "none", "off"} and not redis_url and not dynamo_table:
        return None
    if raw == "memory" or raw == "inmemory":
        return InMemoryUsedTokenStore()
    if raw.startswith("redis://") or raw.startswith("rediss://"):
        redis_url = raw
    if redis_url:
        return RedisUsedTokenStore(redis_url)
    if raw.startswith("dynamodb://"):
        parsed = urlparse(raw)
        dynamo_table = parsed.netloc or parsed.path.lstrip("/")
    if dynamo_table:
        return DynamoDBUsedTokenStore(dynamo_table, region_name=dynamo_region)
    if raw:
        raise ValueError(
            f"unsupported {COMMIT_TOKEN_STORE_ENV}={raw!r}; "
            "use memory, a redis:// URL, or dynamodb://<table>"
        )
    return None


# Process-wide default for gateways that do not inject a store explicitly.
_UNSET = object()
_DEFAULT_STORE: UsedTokenStore | object | None = _UNSET
_DEFAULT_LOCK = threading.Lock()


def default_used_token_store() -> UsedTokenStore | None:
    global _DEFAULT_STORE
    if _DEFAULT_STORE is _UNSET:
        with _DEFAULT_LOCK:
            if _DEFAULT_STORE is _UNSET:
                _DEFAULT_STORE = load_used_token_store_from_env()
    return _DEFAULT_STORE  # type: ignore[return-value]


def set_default_used_token_store(store: UsedTokenStore | None) -> None:
    global _DEFAULT_STORE
    with _DEFAULT_LOCK:
        _DEFAULT_STORE = store
