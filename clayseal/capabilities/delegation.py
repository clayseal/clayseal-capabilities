"""Delegation-token contract, canonical home: ``clayseal.core.delegation``.

Re-export so ``clayseal.capabilities.delegation`` remains a valid import path.
"""

from __future__ import annotations

from clayseal.core.delegation import (
    DELEGATION_SCHEMA,
    DelegationToken,
    delegation_from_envelope,
    issue_delegation,
    sign_delegation,
    verify_delegation_chain,
    verify_delegation_envelope,
    verify_delegation_signature,
)

__all__ = [
    "DELEGATION_SCHEMA",
    "DelegationToken",
    "delegation_from_envelope",
    "issue_delegation",
    "sign_delegation",
    "verify_delegation_chain",
    "verify_delegation_envelope",
    "verify_delegation_signature",
]
