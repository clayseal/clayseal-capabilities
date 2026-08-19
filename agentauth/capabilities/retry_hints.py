"""Benign destination hints and a re-audited retry.

When the floor denies an egress destination, the provenance graph and allow-list
already know which values *would* have cleared. Handing those back is ARGUS's
utility win: the agent (or harness) retries with a grounded recipient, and the
retry goes through the full authorize path — nothing is bypassed.

This module only rewrites destination-shaped arguments. Content fields
(``body``, ``subject``, …) are left untouched so a hint cannot launder an
injected payload into a trusted send.
"""
from __future__ import annotations

from collections.abc import Callable
from typing import Any

from agentauth.capabilities.hardening.egress_policy import is_destination_key


def rewrite_destination_args(args: dict[str, Any], candidate: str) -> dict[str, Any] | None:
    """Return a copy of ``args`` with destination fields set to ``candidate``.

    Returns ``None`` when no destination-shaped key is present (nothing to
    retry) or when the rewrite would be a no-op (already using ``candidate``).
    """
    if not candidate or not isinstance(args, dict):
        return None
    keys = [k for k in args if is_destination_key(k)]
    if not keys:
        return None
    out = dict(args)
    changed = False
    for key in keys:
        cur = out.get(key)
        if isinstance(cur, str):
            if cur.strip() != candidate:
                out[key] = candidate
                changed = True
        elif isinstance(cur, (list, tuple)):
            # Replace the whole recipient list with the single grounded value.
            new = [candidate]
            if list(cur) != new:
                out[key] = new
                changed = True
        else:
            out[key] = candidate
            changed = True
    return out if changed else None


def reaudited_retry(
    gate: Callable[[str, dict[str, Any]], tuple[bool, str]],
    tool: str,
    args: dict[str, Any],
    candidates: list[str] | tuple[str, ...],
    *,
    max_attempts: int = 3,
) -> tuple[bool, str, dict[str, Any], str | None]:
    """Try up to ``max_attempts`` candidates through ``gate`` (full authorize).

    Returns ``(allowed, reason, args_used, candidate_or_None)``. On failure
    returns the original args and no candidate — caller should keep the first
    denial reason.
    """
    for cand in list(candidates)[:max_attempts]:
        rewritten = rewrite_destination_args(args, cand)
        if rewritten is None:
            continue
        ok, reason = gate(tool, rewritten)
        if ok:
            return True, reason, rewritten, cand
    return False, "", args, None
