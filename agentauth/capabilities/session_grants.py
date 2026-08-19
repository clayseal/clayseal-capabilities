"""Authority a session acquired at runtime, and who granted it.

Three mechanisms currently widen a session's authority after it starts: a human
answering a STEP_UP, the plan extender admitting a new shape, and the floor's
resource-scope extension. Each kept its own bookkeeping (`PlanExtender._granted`,
`SessionBroker._extended_pairs`, and for the human, nothing at all), so the
question an operator actually asks — *how much authority did this session pick up
after it started, and from whom* — had no answer.

This is that ledger.

## Why an overlay rather than patching the mandate

`step_up.apply_step_up` mutates an `AuthorityContext`, and the obvious shortcut is
to point it at the broker's `TaskScope` or `EgressPolicy` instead. That is exactly
the bug `broker.py` already documents and fixed once for replanning: extensions
were appended to `self.scope.allowed_resources`, which is *the caller's* object,
so authority granted in one session outlived the broker and leaked into every
other session sharing that scope instance. An approval is a far more valuable
thing to leak than a replan.

So grants live here, keyed by session, and the mandate is never written to. The
broker consults this overlay; nothing mutates the grant it was given.

## Waivers are per reason code, not per action

A human approving one action is answering one question. If a step-up cited
`egress.destination` and the human said yes, the action may proceed *past that
objection* — it must not proceed past a budget ceiling or a protected-zone hit
that nobody was shown. `one_shot` grants therefore carry `waived_codes`, and
`waives()` is a set membership test rather than a boolean.

That is also what makes a second round-trip meaningful: an action re-authorized
after an approval can legitimately step up again for a *different* rule, and that
is a genuine second question rather than a loop.
"""
from __future__ import annotations

from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

__all__ = ["Grant", "GrantSource", "SessionGrants"]


class GrantSource(str):
    """Where a grant came from. Plain strings so it survives serialization."""

    MANDATE = "mandate"
    REPLAN = "replan"
    HUMAN = "human"


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


@dataclass(frozen=True)
class Grant:
    """One unit of runtime-acquired authority.

    ``kind`` is what the grant widens:

    ``one_shot``     a single action, keyed ``(tool, arguments_hash)``. Waives
                     only ``waived_codes`` and only ``uses`` times.
    ``resource``     a ``(resource, verb_class)`` pair, the floor's scope
                     extension.
    ``destination``  an egress target, so a human-confirmed novel payee is not
                     re-asked every call in the same session.
    ``shape``        a ``(tool, verb_class)`` the plan extender admitted.
    """

    kind: str
    key: tuple[str, ...]
    source: str
    waived_codes: frozenset[str] = frozenset()
    granted_at: datetime = field(default_factory=_utc_now)
    expires_at: datetime | None = None
    uses_remaining: int | None = None
    approval_id: str | None = None

    def live(self, *, now: datetime | None = None) -> bool:
        current = now or _utc_now()
        if self.expires_at is not None and self.expires_at <= current:
            return False
        return self.uses_remaining is None or self.uses_remaining > 0


@dataclass
class SessionGrants:
    """Session-local overlay. Never mutates the mandate it sits above."""

    _grants: list[Grant] = field(default_factory=list)

    # -- persistence ------------------------------------------------------ #
    def snapshot(self) -> list[dict]:
        """Grants as JSON-able data, for `session_state.snapshot`.

        A human-issued grant is authority. If it does not survive a restart or
        reach the next worker, either the human is asked the same question again
        (friction) or a one-shot they already spent comes back (a replay of an
        approval). Both are wrong in a way the session cannot detect.
        """
        return [
            {
                "kind": g.kind,
                "key": list(g.key),
                "source": str(g.source),
                "waived_codes": sorted(g.waived_codes),
                "granted_at": g.granted_at.isoformat(),
                "expires_at": g.expires_at.isoformat() if g.expires_at else None,
                "uses_remaining": g.uses_remaining,
                "approval_id": g.approval_id,
            }
            for g in self._grants
        ]

    def load(self, raw: list[dict] | None) -> None:
        """Replace the overlay from `snapshot`. Expiry is preserved, not reset.

        An expired grant is restored expired: `live()` reads `expires_at`, so a
        round trip through a store cannot extend authority by restarting the
        clock, which is the failure mode a naive `granted_at = now` would have.
        """
        from datetime import datetime as _dt

        def _at(value):
            return _dt.fromisoformat(value) if value else None

        self._grants = [
            Grant(
                kind=str(g["kind"]),
                key=tuple(g["key"]),
                source=str(g.get("source", "")),
                waived_codes=frozenset(g.get("waived_codes") or ()),
                granted_at=_at(g.get("granted_at")) or _utc_now(),
                expires_at=_at(g.get("expires_at")),
                uses_remaining=g.get("uses_remaining"),
                approval_id=g.get("approval_id"),
            )
            for g in (raw or ())
        ]

    # -- granting --------------------------------------------------------- #
    def add(self, grant: Grant) -> Grant:
        self._grants.append(grant)
        return grant

    def grant_one_shot(self, *, tool: str, arguments_hash: str,
                       waived_codes: Iterable[str], source: str,
                       ttl_seconds: int = 600, uses: int = 1,
                       approval_id: str | None = None) -> Grant:
        return self.add(Grant(
            kind="one_shot", key=(tool, arguments_hash), source=source,
            waived_codes=frozenset(waived_codes),
            expires_at=_utc_now() + timedelta(seconds=ttl_seconds),
            uses_remaining=uses, approval_id=approval_id))

    def grant_resource(self, *, resource: str, verb_class: str, source: str,
                       ttl_seconds: int | None = None) -> Grant:
        return self.add(Grant(
            kind="resource", key=(resource, verb_class), source=source,
            expires_at=(_utc_now() + timedelta(seconds=ttl_seconds))
            if ttl_seconds else None))

    def grant_destination(self, *, destination: str, source: str,
                          ttl_seconds: int = 600) -> Grant:
        return self.add(Grant(
            kind="destination", key=(destination,), source=source,
            expires_at=_utc_now() + timedelta(seconds=ttl_seconds)))

    def grant_shape(self, *, tool: str, verb_class: str, source: str) -> Grant:
        return self.add(Grant(kind="shape", key=(tool, verb_class), source=source))

    # -- consulting ------------------------------------------------------- #
    def waives(self, *, tool: str, arguments_hash: str, code: str,
               now: datetime | None = None) -> bool:
        """Does a live one-shot grant waive THIS rule for THIS exact action?

        Both halves matter. Keyed on the argument hash, so an approval for one
        transfer does not clear the next one; and on the code, so an approval of
        a destination does not clear a budget ceiling nobody was shown.
        """
        for grant in self._grants:
            if grant.kind != "one_shot" or not grant.live(now=now):
                continue
            if grant.key != (tool, arguments_hash):
                continue
            if code in grant.waived_codes:
                return True
        return False

    def consume(self, *, tool: str, arguments_hash: str, code: str) -> None:
        """Spend one use of the grant that waived this action."""
        for i, grant in enumerate(self._grants):
            if (grant.kind == "one_shot" and grant.live()
                    and grant.key == (tool, arguments_hash)
                    and code in grant.waived_codes
                    and grant.uses_remaining is not None):
                self._grants[i] = Grant(
                    kind=grant.kind, key=grant.key, source=grant.source,
                    waived_codes=grant.waived_codes, granted_at=grant.granted_at,
                    expires_at=grant.expires_at,
                    uses_remaining=grant.uses_remaining - 1,
                    approval_id=grant.approval_id)
                return

    def allows_resource(self, resource: str, verb_class: str,
                        now: datetime | None = None) -> bool:
        return any(g.kind == "resource" and g.key == (resource, verb_class)
                   and g.live(now=now) for g in self._grants)

    def allows_destination(self, destination: str,
                           now: datetime | None = None) -> bool:
        return any(g.kind == "destination" and g.key == (destination,)
                   and g.live(now=now) for g in self._grants)

    def allows_shape(self, tool: str, verb_class: str,
                     now: datetime | None = None) -> bool:
        return any(g.kind == "shape" and g.key == (tool, verb_class)
                   and g.live(now=now) for g in self._grants)

    # -- reporting -------------------------------------------------------- #
    def acquired(self) -> dict[str, Any]:
        """Runtime-acquired authority, by source and kind.

        This is the number no configuration currently reports and the one that
        answers "is replanning converging on allow-all". A session that ends
        having granted itself forty shapes is not the same system as one that
        ended with two, whatever their ASR columns say.
        """
        by_source: Counter[str] = Counter()
        by_kind: Counter[str] = Counter()
        for grant in self._grants:
            by_source[grant.source] += 1
            by_kind[grant.kind] += 1
        return {
            "total": len(self._grants),
            "by_source": dict(by_source),
            "by_kind": dict(by_kind),
            "human": by_source.get(GrantSource.HUMAN, 0),
        }

    def __len__(self) -> int:
        return len(self._grants)
