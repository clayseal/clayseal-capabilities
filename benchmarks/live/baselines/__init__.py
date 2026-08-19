"""2026 baseline gates for BPL live H2H: AuthGraph + DRIFT mechanism reproductions.

These are *mechanism reproductions* at the same fidelity as the Progent / CaMeL
branches already in ``bpl_live.py``: they implement the published control
structure (what the paper says the monitor does), not a vendor of unreleased
upstream code.

- AuthGraph (arXiv:2605.26497): clean-context authorization graph + parameter
  provenance alignment. Upstream code was not open at integration time.
- DRIFT (arXiv:2506.12104): secure planner from the user query, injection
  isolator, dynamic validator for off-plan calls.

Neither mechanism tracks composite *session* value/call ceilings. On BPL
aggregate cases where the user prompt already names every violating step, a
faithful reproduction is expected to authorize those steps (same structural
gap as Progent on per-call schema). That is the point of the comparison.
"""
from __future__ import annotations

from .authgraph import AuthGraphGate
from .drift import DriftGate

__all__ = ["AuthGraphGate", "DriftGate"]
