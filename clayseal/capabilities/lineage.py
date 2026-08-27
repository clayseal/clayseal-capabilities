"""Authority-lineage contract, canonical home: ``clayseal.core.lineage``.

Re-export so ``clayseal.capabilities.lineage`` remains a valid import path.
"""

from __future__ import annotations

from clayseal.core.lineage import (
    AuthorityLineage,
    AuthorityTransitionReason,
    AuthorityTransitionType,
)

__all__ = [
    "AuthorityLineage",
    "AuthorityTransitionReason",
    "AuthorityTransitionType",
]
