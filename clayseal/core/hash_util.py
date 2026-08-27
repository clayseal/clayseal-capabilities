from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from typing import Any


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical_json_bytes(value: Any, *, default: Callable[[Any], Any] | None = None) -> bytes:
    """Canonical JSON encoding (sorted keys, tight separators) as UTF-8 bytes.

    The single canonicalization used across layers for hashing, signing, and audit
    linkage. ``default`` is forwarded to ``json.dumps`` for non-JSON-native values
    (e.g. ``default=str`` to stringify datetimes)."""
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), default=default
    ).encode("utf-8")


def hash_canonical_json(value: Any) -> str:
    """Stable JSON hash (sorted keys) for commitments and audit linkage."""
    return sha256_hex(canonical_json_bytes(value))
