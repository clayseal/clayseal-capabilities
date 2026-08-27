"""CaMeL-style privileged planner, now a thin alias over the shipped one.

The implementation moved to ``clayseal.capabilities.monitor.planner``. It had
been living here, in the harness, while every live AgentDojo result in
``benchmarks/results/`` was produced by it, so the thing that built the primary
behavioural tier was the one piece a deployment could not install. A package
user got either a hand-authored ``structured_intent`` or no envelope at all, and
no envelope is a materially different posture from the one that was measured.

Nothing about the planner changed in the move; this module keeps the names the
benchmark and demo already import, so there is one implementation and the
measured path and the shipped path cannot drift apart.
"""
from __future__ import annotations

from clayseal.capabilities.monitor.planner import (
    LLMQueryPlanner,
    classify_verb,
    envelope_from_plan,
    read_tools,
    verb_class_order,
)

#: The benchmark's historical name for the LLM planner.
LLMPlanner = LLMQueryPlanner

#: Effect verbs, kept for callers that imported the module-level constant.
_EFFECT_VERBS = {"send", "transfer", "write"}

__all__ = [
    "LLMPlanner",
    "LLMQueryPlanner",
    "classify_verb",
    "envelope_from_plan",
    "read_tools",
    "verb_class_order",
]
