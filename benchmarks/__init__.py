"""Clay Seal capability-enforcement benchmarks.

A dataset-agnostic harness that replays labeled agent tool-call traces (benign
vs attacker-induced) through Clay Seal's real enforcement decision path and
scores containment against user friction. Built to compare *architectural
approaches* to authorization on the same external data.

See ``benchmarks/README.md`` for the layout and the enforcement ladder.
"""

__all__ = ["core", "datasets"]
