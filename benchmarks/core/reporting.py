"""How a number is allowed to be published.

Three rules, each traceable to a specific way this repository has already misled
itself.

**Never a bare zero.** `frontier.md` records the same config, suite, model and
attack giving 27.8% ASR in one sweep and 0.0% in another, at n=18, and concludes
that this "applies to every 0% ASR in this repository". A zero is a sample, not a
property: 0 of 18 has a one-sided 97.5% upper bound of about 18%, and 0 of 20 in
the head-to-head has one of about 15%. Both were published as "0%".

**Record the model the API reports, never the one the caller asked for.** The
`clayseal-aoai` deployment is named `gpt-4o-mini-2024-07-18` and serves
`gpt-5-mini-2025-08-07`. `repeat_runs.py` already clears Azure specifically to
avoid this, which is a workaround rather than a check: nothing verifies that the
model in a result file is the model that answered. A model-strength trend is the
central claim of `improvements.md` ("25 -> 19 -> 3 points as model strength
rises"), and one mislabelled cell inverts it.

**A headline cell needs a pre-registration.** Not because peeking is dishonest by
intent, but because a cell that came out badly and was quietly re-run is
indistinguishable afterwards from one that did not. The hash is what makes the
distinction checkable.

None of this makes a result true. It makes an untrue result visible.
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

__all__ = [
    "one_sided_upper", "format_rate", "PreRegistration", "ModelIdentity",
    "publishable",
]


# --------------------------------------------------------------------------- #
# Rates
# --------------------------------------------------------------------------- #
def one_sided_upper(successes: int, n: int, level: float = 0.975) -> float:
    """Upper bound on a rate, which is the only honest way to report a zero.

    Clopper-Pearson via the closed form for the k=0 case and a bisection on the
    binomial tail otherwise. Exact rather than normal-approximate, because the
    approximation is worst exactly where it is being used: small n, rate near 0.
    """
    if n <= 0:
        return 1.0
    if successes >= n:
        return 1.0
    if successes == 0:
        # P(X=0) = (1-p)^n = 1-level  ->  p = 1 - (1-level)^(1/n)
        return 1.0 - (1.0 - level) ** (1.0 / n)

    from math import comb

    def tail(p: float) -> float:
        return sum(comb(n, k) * p**k * (1 - p) ** (n - k)
                   for k in range(0, successes + 1))

    lo, hi = successes / n, 1.0
    for _ in range(80):
        mid = (lo + hi) / 2
        if tail(mid) > 1 - level:
            lo = mid
        else:
            hi = mid
    return hi


def format_rate(successes: int, n: int, *, clusters: int | None = None,
                seeds: int | None = None) -> str:
    """The only sanctioned way to render a rate in a results file.

    A zero renders as its bound rather than as `0%`, so the reader cannot mistake
    "we did not observe this" for "this does not happen".
    """
    if n <= 0:
        return "n/a (no observations)"
    point = successes / n
    upper = one_sided_upper(successes, n)
    body = f"{point:.1%} ({successes}/{n})"
    if successes == 0:
        body = f"0/{n}, 97.5% upper bound {upper:.1%}"
    extra = []
    if clusters is not None:
        extra.append(f"{clusters} clusters")
    if seeds is not None:
        extra.append(f"{seeds} seeds")
    return f"{body}" + (f" [{', '.join(extra)}]" if extra else "")


# --------------------------------------------------------------------------- #
# Model identity
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class ModelIdentity:
    """What actually answered, as distinct from what was asked for.

    `requested` is the deployment or alias the caller used; `reported` is the
    `model` field the API returned. When they disagree the result is still
    usable, but it must be labelled with `reported` and the disagreement has to
    be visible, because a deployment name is a local alias and a model id is the
    thing a reader will compare against a published baseline.
    """

    requested: str
    reported: str
    provider: str = ""

    #: A served id that is the requested name plus a dated version suffix, which
    #: is how every Azure deployment answers: ask for `gpt-4.1-mini`, get
    #: `gpt-4.1-mini-2025-04-14`. That is a version pin, not a substitution.
    _VERSION_SUFFIX = re.compile(r"^-\d{4}-\d{2}-\d{2}$")

    @property
    def mismatched(self) -> bool:
        """True only when a DIFFERENT model answered, not a pinned version of it.

        The distinction is the whole value of this check. `clayseal-aoai` has a
        deployment named `gpt-4o-mini-2024-07-18` that serves `gpt-5-mini`, and
        that is the mislabelling this class exists to catch. Flagging every
        version pin as well would bury that one real case in a warning printed on
        every run, which is precisely how a check earns the reputation that gets
        it ignored.
        """
        if not self.reported or self.requested == self.reported:
            return False
        if self.reported.startswith(self.requested):
            return not self._VERSION_SUFFIX.match(
                self.reported[len(self.requested):])
        return True

    def label(self) -> str:
        if not self.reported:
            return f"{self.requested} (unverified)"
        if self.mismatched:
            return f"{self.reported} (deployment alias {self.requested!r})"
        return self.reported

    def summary(self) -> dict:
        return {"requested": self.requested, "reported": self.reported,
                "provider": self.provider, "mismatched": self.mismatched,
                "label": self.label()}


def identify_from_response(requested: str, response: Any,
                           provider: str = "") -> ModelIdentity:
    """Pull the served model off a chat completion response."""
    return ModelIdentity(requested=requested,
                         reported=str(getattr(response, "model", "") or ""),
                         provider=provider)


# --------------------------------------------------------------------------- #
# Pre-registration
# --------------------------------------------------------------------------- #
@dataclass
class PreRegistration:
    """A sweep's declared design, hashed so a result can cite it.

    `stopping_rule` is the field that does the work: fixed n, no peeking, and a
    cell that came out badly may not be quietly re-run. Recording it does not
    prevent any of that. It makes a later re-run visible as a second
    pre-registration rather than as a revision of the first.
    """

    hypothesis: str
    primary_metric: str
    cells: list[str]
    n_per_cell: int
    seeds: list[int]
    stopping_rule: str = "fixed n; no interim analysis; no re-run of a completed cell"
    exclusions: str = "transient API failures stay in the denominator"
    falsification: str = ""
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> dict:
        return {
            "schema": "clayseal.prereg.v1",
            "hypothesis": self.hypothesis,
            "primary_metric": self.primary_metric,
            "cells": list(self.cells),
            "n_per_cell": self.n_per_cell,
            "seeds": list(self.seeds),
            "stopping_rule": self.stopping_rule,
            "exclusions": self.exclusions,
            "falsification": self.falsification,
            "created_at": self.created_at,
        }

    def hash(self) -> str:
        body = json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"))
        return "prereg:" + hashlib.sha256(body.encode()).hexdigest()[:16]

    def write(self, path: Path) -> str:
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = self.to_dict()
        payload["hash"] = self.hash()
        path.write_text(json.dumps(payload, indent=2))
        return payload["hash"]


def publishable(result: dict) -> tuple[bool, list[str]]:
    """May this cell appear in a headline table?

    Deliberately mechanical. The judgement about whether a number is interesting
    belongs to a person; whether it is *reportable* should not, because that is
    exactly the judgement a deadline erodes.
    """
    problems: list[str] = []
    n = result.get("n", 0)
    if not n:
        problems.append("no denominator")
    if result.get("successes") == 0 and "upper_bound" not in result:
        problems.append("a zero without an upper bound")
    seeds = result.get("seeds") or []
    if len(seeds) < 5:
        problems.append(f"{len(seeds)} seeds; a published cell needs 5, a headline 10")
    if not result.get("prereg_hash"):
        problems.append("no pre-registration hash; cell is exploratory")
    model = result.get("model") or {}
    if not model.get("reported"):
        problems.append("model identity unverified (deployment name is not a model id)")
    return (not problems), problems
