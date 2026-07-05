from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any
from uuid import uuid4

from agentauth.core.runtime import ExecutionContext
from agentauth.core.hash_util import hash_canonical_json
from agentauth.core.signing import SigningKey, signature_key_id_matches, verify

COMMIT_TOKEN_SCHEMA = "agent-receipts.commit-token.v1"


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
        return cls(
            token=CommitToken.from_dict(dict(raw["token"])),
            signature=dict(raw["signature"]),
        )


def issue_commit_token(
    ctx: ExecutionContext,
    *,
    key: SigningKey,
    ttl_seconds: int,
) -> SignedCommitToken:
    if ttl_seconds <= 0:
        raise ValueError("ttl_seconds must be > 0")
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
) -> tuple[bool, str | None]:
    at = at or _utc_now()
    token_dict = signed.token.to_dict()
    if not signature_key_id_matches(signed.signature):
        return False, "commit token signature key_id does not match public_key"
    if not verify(token_dict, signed.signature):
        return False, "commit token signature invalid"
    expires_at = _parse_dt(signed.token.expires_at)
    if expires_at is None:
        return False, "commit token expires_at invalid"
    if expires_at <= at.astimezone(timezone.utc):
        return False, "commit token expired"

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

    return True, None
