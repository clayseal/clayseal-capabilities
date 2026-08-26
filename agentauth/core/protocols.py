"""Protocol contracts for AgentAuth extension points."""
from __future__ import annotations

from typing import Any, Protocol, runtime_checkable


@runtime_checkable
class ReceiptExporter(Protocol):
    name: str

    def export(self, bundle: dict[str, Any], **kwargs: Any) -> dict[str, Any]:
        ...


@runtime_checkable
class AttestationVerifier(Protocol):
    name: str

    def verify(
        self,
        evidence: bytes | str | dict[str, Any],
        *,
        context: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        ...
