"""Bounds on what a backtracking pattern is allowed to scan.

Python's `re` is a backtracking engine, so a pattern of the shape
`(?:group)+suffix` can explore exponentially many splits when the suffix never
matches. Measured on this codebase, one 16 KB tool argument took **3.5 seconds**
inside a single pattern. Every one of those patterns reads arguments an agent
controls, so that is a hang anybody can trigger with one call.

Two fixes are used here. Where the input has a grammar, the pattern is replaced
by a linear scan: see `_hosts_in` in `hardening/egress_policy.py`, which also
made a real bypass structurally impossible. Where a pattern is genuinely the
right tool, the input is bounded first, and the bound is chosen from what the
input actually IS rather than picked to make a benchmark pass:

`MAX_PATH`
    `PATH_MAX` on Linux. A longer string is not a path any kernel will open, so
    a pattern looking for a path in it has nothing to find.

`MAX_COMMAND`
    Longer than any command line these detectors were written against, and far
    below `ARG_MAX`.

`MAX_LINE`
    One line of a policy document.

Truncation is a real trade and it is bounded by the same reasoning: a match
hidden past the cap is missed. That is acceptable only because a value past
these caps is no longer the kind of thing the pattern is looking for. It is not
a general-purpose helper, and a detector whose input has no natural bound must
be rewritten as a linear scan instead of importing a number from here.
"""
from __future__ import annotations

MAX_PATH = 4096
MAX_COMMAND = 16_384
MAX_LINE = 4096
