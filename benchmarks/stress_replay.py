"""Attacks on the replay-defense seam.

    python -m benchmarks.stress_replay
    python -m benchmarks.stress_replay --threads 64 --tokens 20000

A commit token authorizes exactly ONE irreversible side effect. The verifier
enforces that by asking a `UsedTokenStore` whether it has seen the token before,
so **the store is the single point where single-use actually lives**. Everything
proved about the verifier in `commit_totality.md` is conditional on it: a store
that says "new" twice turns a one-shot authorization into a standing grant until
expiry, and no correctness above it helps.

The store is also the component most likely to be wrong, because it is the only
one that is concurrent, distributed, and dependent on a network.

## The attacks

``RACE``            N threads present the SAME token simultaneously. Exactly one
                    must win. This is the double-spend: two instances behind a
                    load balancer both calling `verify_commit_token` at the same
                    moment is not an edge case, it is Tuesday.

``OUTAGE``          The backend is unavailable. A replay store that fails OPEN
                    under partition silently disables single-use for the whole
                    fleet, and the ladder above reports containment it is not
                    performing. Failing closed is correct; failing closed *by
                    raising an unhandled exception out of the verifier* is the
                    third-best outcome and is what the other gates all did.

``HOSTILE_INPUT``   token_id and expires_at come from a parsed token. They must
                    not crash the store or collide two distinct tokens onto one
                    key.

``SCALING``         `InMemoryUsedTokenStore._evict` walks the entire dict on
                    every call, so marking N tokens is O(N^2). The confidentiality
                    accumulator has the identical defect and it is currently red
                    in `test_flow_invariants.py`; this checks whether replay
                    defense shares it.
"""
from __future__ import annotations

import argparse
import json
import sys
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

from agentauth.capabilities.commit import InMemoryUsedTokenStore

FUTURE = datetime.now(timezone.utc) + timedelta(hours=1)


class FlakyStore:
    """A store whose backend is down — the outage case, without a live Redis.

    Mirrors what `RedisUsedTokenStore.mark_used` does when `redis` cannot reach
    the server: `self._client.set(...)` raises `ConnectionError`, which is not
    caught anywhere in `mark_used`, `verify_commit_token`, or the broker.
    """

    def __init__(self, exc: Exception) -> None:
        self._exc = exc

    def mark_used(self, token_id: str, expires_at: datetime) -> bool:
        raise self._exc


def attack_race(threads: int) -> dict:
    """Exactly one presenter of a token may win."""
    store = InMemoryUsedTokenStore()
    wins: list[bool] = []
    lock = threading.Lock()
    barrier = threading.Barrier(threads)

    def present() -> None:
        barrier.wait()  # maximise the overlap
        got = store.mark_used("tok-contested", FUTURE)
        with lock:
            wins.append(got)

    workers = [threading.Thread(target=present) for _ in range(threads)]
    for w in workers:
        w.start()
    for w in workers:
        w.join()
    won = sum(1 for w in wins if w)
    return {"attack": "RACE", "threads": threads, "winners": won,
            "violation": None if won == 1 else
            f"{won} of {threads} concurrent presentations succeeded"}


def attack_outage() -> dict:
    """What the verifier does when the replay store cannot be reached."""
    from agentauth.capabilities.commit import verify_commit_token
    from benchmarks.stress_commit import _pair

    signed, ctx, trusted = _pair()
    findings = []
    for exc in (ConnectionError("redis down"), TimeoutError("dynamo timeout")):
        store = FlakyStore(exc)
        try:
            ok, reason = verify_commit_token(
                signed, ctx=ctx, trusted_minting_keys=trusted,
                used_token_store=store)
            outcome = "ALLOWED" if ok else f"denied ({reason})"
        except Exception as raised:  # noqa: BLE001
            outcome = f"raised {type(raised).__name__}"
        findings.append({"backend_error": type(exc).__name__, "verifier": outcome})
    # Fail-open is catastrophic; raising is merely wrong-shaped.
    opened = [f for f in findings if f["verifier"] == "ALLOWED"]
    raised = [f for f in findings if f["verifier"].startswith("raised")]
    return {"attack": "OUTAGE", "detail": findings,
            "violation": ("replay store outage FAILS OPEN" if opened
                          else f"verifier raises on backend outage: "
                               f"{[f['verifier'] for f in raised]}" if raised
                          else None)}


def attack_hostile_input() -> dict:
    """token_id and expires_at reach the store from a parsed token."""
    store = InMemoryUsedTokenStore()
    problems = []
    hostile_ids = ["", "   ", "a" * 100_000, "tok\nid", "tok:id", None, 0, [1], True]
    for tid in hostile_ids:
        try:
            store.mark_used(tid, FUTURE)
        except Exception as exc:  # noqa: BLE001
            problems.append({"token_id": repr(tid)[:40],
                             "error": f"{type(exc).__name__}: {str(exc)[:60]}"})
    past = datetime.now(timezone.utc) - timedelta(hours=1)
    for label, exp in (("already expired", past), ("year 9999",
                       datetime(9999, 1, 1, tzinfo=timezone.utc))):
        try:
            store.mark_used(f"tok-{label}", exp)
        except Exception as exc:  # noqa: BLE001
            problems.append({"expires_at": label,
                             "error": f"{type(exc).__name__}: {str(exc)[:60]}"})

    # Distinct tokens must not collide onto one slot.
    collided = None
    if store.mark_used("tok-A", FUTURE) and not store.mark_used("tok-B", FUTURE):
        collided = "two distinct token_ids shared a slot"
    return {"attack": "HOSTILE_INPUT", "problems": problems,
            "violation": collided or (f"{len(problems)} inputs raised"
                                      if problems else None)}


def attack_scaling(tokens: int) -> dict:
    """Is marking N tokens linear, or does eviction make it quadratic?"""
    store = InMemoryUsedTokenStore()
    marks: dict[int, float] = {}
    checkpoints = {tokens // 10, tokens // 2, tokens - 1}
    for i in range(tokens):
        start = time.perf_counter()
        store.mark_used(f"tok-{i}", FUTURE)
        if i in checkpoints:
            marks[i] = time.perf_counter() - start
    early = marks.get(tokens // 10, 0.0)
    late = marks.get(tokens - 1, 0.0)
    ratio = (late / early) if early > 0 else 0.0
    # Asserted on the RATIO of per-call cost, not wall clock, so it does not
    # flake on a loaded machine. Linear eviction shows up as a ratio tracking
    # the token count; O(1) shows up as a ratio near 1.
    return {"attack": "SCALING", "tokens": tokens,
            "per_call_us_early": round(early * 1e6, 2),
            "per_call_us_late": round(late * 1e6, 2),
            "ratio": round(ratio, 1),
            "violation": (f"per-call cost grew {ratio:.0f}x from token "
                          f"{tokens // 10} to {tokens}; eviction is linear in "
                          f"the live set, so marking N tokens is O(N^2)")
            if ratio > 10 else None}


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--threads", type=int, default=64)
    p.add_argument("--tokens", type=int, default=20000)
    p.add_argument("--json", type=Path, default=None)
    args = p.parse_args(argv)

    results = [
        attack_race(args.threads),
        attack_outage(),
        attack_hostile_input(),
        attack_scaling(args.tokens),
    ]
    print("replay-defense stress\n")
    head = f"{'attack':<16}{'verdict':<10}detail"
    print(head)
    print("-" * 76)
    for r in results:
        verdict = "FAIL" if r["violation"] else "ok"
        detail = r["violation"] or ""
        print(f"{r['attack']:<16}{verdict:<10}{detail}")
    for r in results:
        if r["attack"] == "OUTAGE":
            for d in r["detail"]:
                print(f"    {d['backend_error']:<18}-> verifier {d['verifier']}")
        if r["attack"] == "SCALING":
            print(f"    per-call {r['per_call_us_early']}us early, "
                  f"{r['per_call_us_late']}us late ({r['ratio']}x)")
        if r["attack"] == "HOSTILE_INPUT" and r["problems"]:
            for d in r["problems"][:8]:
                print(f"    {d}")
    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(json.dumps(results, indent=2, default=str))
        print(f"\nwrote {args.json}")
    return 1 if any(r["violation"] for r in results) else 0


if __name__ == "__main__":
    sys.exit(main())
