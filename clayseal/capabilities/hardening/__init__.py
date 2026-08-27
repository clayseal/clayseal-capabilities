"""Phase 3 enforcement-floor hardening: protected zones, egress policy, input
hardening. Closes the memo's weakly-substantiated attack claims (egress outside
policy, hidden-Unicode / poisoned descriptions, path exfiltration)."""
from __future__ import annotations

from clayseal.capabilities.hardening.egress_policy import EgressPolicy, extract_destinations
from clayseal.capabilities.hardening.input_hardening import HardeningReport, harden, sanitize, scan
from clayseal.capabilities.hardening.protected_zones import (
    DEFAULT_PROTECTED_PATTERNS,
    is_protected_path,
    protected_reason,
)

__all__ = [
    "DEFAULT_PROTECTED_PATTERNS",
    "EgressPolicy",
    "HardeningReport",
    "extract_destinations",
    "harden",
    "is_protected_path",
    "protected_reason",
    "sanitize",
    "scan",
]
