"""Signed Mandate contract — canonical home: ``agentauth.core.mandate``.

The mandate schema and its validation rules ARE the cross-layer contract
(Seam C), so they live in the core package where receipts can verify mandate
sections without this layer installed. This module re-exports the full surface
so ``agentauth.capabilities.mandate`` remains a valid import path.
"""

from __future__ import annotations

from agentauth.core.mandate import (
    MANDATE_SCHEMA,
    REQUIRE_MANDATE_ACTIONS_ENV,
    REQUIRE_MANDATE_FOR_BUDGETS_ENV,
    Mandate,
    check_receipt_against_mandate,
    issue_mandate,
    mandate_bundle_section,
    mandate_reference,
    mandate_signer_matches_issuer,
    mandated_hpke_recipient_bytes,
    verify_bundle_mandate,
    verify_mandate_envelope,
    verify_mandate_signature,
)

__all__ = [
    "MANDATE_SCHEMA",
    "REQUIRE_MANDATE_ACTIONS_ENV",
    "REQUIRE_MANDATE_FOR_BUDGETS_ENV",
    "Mandate",
    "check_receipt_against_mandate",
    "issue_mandate",
    "mandate_bundle_section",
    "mandate_reference",
    "mandate_signer_matches_issuer",
    "mandated_hpke_recipient_bytes",
    "verify_bundle_mandate",
    "verify_mandate_envelope",
    "verify_mandate_signature",
]
