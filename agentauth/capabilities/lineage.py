"""Authority-lineage contract — canonical home: ``agentauth.core.lineage``.

Re-export so ``agentauth.capabilities.lineage`` remains a valid import path.
"""

from __future__ import annotations

from agentauth.core.lineage import (
    AuthorityLineage,
    AuthorityTransitionReason,
    AuthorityTransitionType,
)

__all__ = [
    "AuthorityLineage",
    "AuthorityTransitionReason",
    "AuthorityTransitionType",
]
