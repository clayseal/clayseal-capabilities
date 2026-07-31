"""Adversarial attack synthesis: turn benign corpora into labeled attack cases."""
from __future__ import annotations

from benchmarks.adversarial.attacks import (
    ATTACK_CLASSES,
    AttackVariant,
    synthesize,
)

__all__ = ["ATTACK_CLASSES", "AttackVariant", "synthesize"]
