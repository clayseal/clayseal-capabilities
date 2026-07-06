"""Capability budget shapes — canonical home: ``agentauth.core.budget``.

Kept as a re-export so ``agentauth.capabilities.budget`` remains a valid import
path; the contract itself lives in the core package (receipts consumes it
without this layer installed).
"""

from __future__ import annotations

from agentauth.core.budget import BudgetType, CapabilityBudget

__all__ = ["BudgetType", "CapabilityBudget"]
