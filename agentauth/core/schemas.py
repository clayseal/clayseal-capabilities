"""Cross-layer data-shape validation.

Lightweight, dependency-free structural checks for the contracts that cross repo
boundaries. ``validate_binding`` is the canonical validator for a serialized
:class:`~agentauth.core.authority_binding.AuthorityBinding`: it returns a list of
human-readable problems, empty when the mapping is well-formed. Kept here (not in a
provider) so any layer can validate a binding it receives from another.
"""
from __future__ import annotations

from typing import Any

REQUIRED_BINDING_FIELDS = ("subject_id",)


def validate_binding(binding: dict[str, Any]) -> list[str]:
    """Return a list of problems with a serialized AuthorityBinding ( [] == valid )."""
    errors: list[str] = []

    if not isinstance(binding, dict):
        return [f"binding must be a mapping, got {type(binding).__name__}"]

    for field in REQUIRED_BINDING_FIELDS:
        value = binding.get(field)
        if not value or not isinstance(value, str):
            errors.append(f"{field!r} is required and must be a non-empty string")

    authority_id = binding.get("authority_id")
    if authority_id is not None and not isinstance(authority_id, str):
        errors.append("'authority_id' must be a string when present")

    caps = binding.get("capabilities", [])
    if not isinstance(caps, list) or not all(isinstance(c, str) for c in caps):
        errors.append("'capabilities' must be a list of strings")

    if "evidence_verified" in binding and not isinstance(binding["evidence_verified"], bool):
        errors.append("'evidence_verified' must be a boolean")

    return errors
