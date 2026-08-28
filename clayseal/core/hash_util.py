"""Canonical hashing, so two encodings of the same object are one hash.

`hash_canonical_json` is what binds a decision to the arguments it was made
about. The commit token carries an `arguments_hash`, and the whole point of that
binding is that re-ordering a dict or re-spelling a float must not produce a
different hash: an attacker who could change the encoding without changing the
hash input would have a mutation the binding cannot see.

So the JSON is emitted with sorted keys and no incidental whitespace, and the
digest is taken over the bytes rather than over a `str`, which would make the
answer depend on the platform's default encoding.
"""
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
