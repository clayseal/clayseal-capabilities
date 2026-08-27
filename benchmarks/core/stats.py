"""Uncertainty for benchmark rates.

Every headline number in this repo is a proportion (containment, false-block)
and until now every one was reported as a bare point estimate. Our own
docs/methodology_audit.md records the same configuration producing 55.6%, then
11.1%, then 12.5% across identical runs, which means several published
comparisons sit inside their own noise band. A reader cannot tell which.

Two distinct sources of variance, deliberately kept separate because they
answer different questions:

**Sampling variance**, the corpus is a sample of the attacks that exist, so a
rate measured on it is an estimate. Events are *not* independent: RedCode's 60
`exfiltrate-file-over-network` cases share a template, and an engine that
handles one handles all 60. Treating them as 60 independent trials shrinks the
interval by roughly sqrt(60) and manufactures confidence we do not have. So the
resampling unit is the **task**, not the event (a cluster bootstrap), and the
interval it produces is honestly wide where the corpus is really a handful of
templates.

**Synthesis variance**, the adversarial leaderboard generates attack variants
from a seeded RNG, so a single seed reports one draw from the attack
distribution. Multi-seed runs report the spread across draws.

Wilson intervals are also provided for the event-level case. They are correct
only where events genuinely are independent trials, so `proportion_ci` is used
for reporting sub-counts, never for the headline rate on a templated corpus.
"""
from __future__ import annotations

import math
import random
import statistics
from dataclasses import dataclass

# Two-sided normal quantiles for the confidence levels we report.
_Z = {0.90: 1.6449, 0.95: 1.9600, 0.99: 2.5758}


@dataclass(frozen=True)
class Interval:
    """A point estimate with a confidence interval. ``n`` is the unit count."""

    point: float
    low: float
    high: float
    n: int
    level: float = 0.95
    method: str = ""

    @property
    def half_width(self) -> float:
        return (self.high - self.low) / 2.0

    def render(self, pct: bool = True) -> str:
        if pct:
            return f"{self.point:.1%} [{self.low:.1%}, {self.high:.1%}]"
        return f"{self.point:.4g} [{self.low:.4g}, {self.high:.4g}]"

    def summary(self) -> dict:
        return {
            "point": round(self.point, 4),
            "ci_low": round(self.low, 4),
            "ci_high": round(self.high, 4),
            "n": self.n,
            "level": self.level,
            "method": self.method,
        }

    def overlaps(self, other: Interval) -> bool:
        """True when two intervals overlap, i.e. the difference is not resolved.

        Non-overlap is a conservative test for a real difference; overlapping
        intervals can still differ significantly. It is the right direction of
        error for a claim we intend to defend in front of a buyer.
        """
        return not (self.high < other.low or other.high < self.low)


def proportion_ci(successes: int, n: int, level: float = 0.95) -> Interval:
    """Wilson score interval, for independent Bernoulli trials only.

    Preferred over the normal approximation because it stays inside [0, 1] and
    does not collapse to zero width at 0% or 100%, which is exactly where our
    containment numbers live. A 0-of-718 result is not "0% with certainty"; it
    is 0% with an upper bound near 0.5%.
    """
    if n <= 0:
        return Interval(0.0, 0.0, 1.0, 0, level, "wilson")
    z = _Z.get(level, _Z[0.95])
    p = successes / n
    denom = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / denom
    margin = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / denom
    return Interval(p, max(0.0, centre - margin), min(1.0, centre + margin), n, level, "wilson")


def cluster_bootstrap_ci(
    clusters: list[tuple[int, int]],
    *,
    level: float = 0.95,
    resamples: int = 2000,
    seed: int = 0,
) -> Interval:
    """Percentile bootstrap over clusters, each a ``(successes, trials)`` pair.

    Resampling whole tasks preserves the within-task correlation that makes the
    naive event-level interval too narrow. Returns the observed pooled rate as
    the point estimate with percentile bounds from the resample distribution.
    """
    clusters = [c for c in clusters if c[1] > 0]
    if not clusters:
        return Interval(0.0, 0.0, 1.0, 0, level, "cluster-bootstrap")

    total_s = sum(s for s, _ in clusters)
    total_n = sum(n for _, n in clusters)
    point = total_s / total_n
    if len(clusters) == 1:
        # One cluster carries no between-cluster information; fall back to the
        # event-level interval rather than reporting a zero-width fiction.
        return proportion_ci(total_s, total_n, level)

    rng = random.Random(seed)  # noqa: S311 - a bootstrap resampler, not a keystream
    k = len(clusters)
    rates = []
    for _ in range(resamples):
        s = n = 0
        for _ in range(k):
            cs, cn = clusters[rng.randrange(k)]
            s += cs
            n += cn
        if n:
            rates.append(s / n)
    rates.sort()
    alpha = (1 - level) / 2
    lo = rates[max(0, int(alpha * len(rates)))]
    hi = rates[min(len(rates) - 1, int((1 - alpha) * len(rates)))]

    # Boundary degeneracy. When every cluster scores identically (0/n or n/n)
    # every resample reproduces it and the interval collapses to zero width,
    # which reads as certainty we do not have: 0 of 718 is not "0%, definitely",
    # it is "0% observed, and the truth could be as high as ~0.4%". The rule of
    # three gives that bound at the cluster level, so a corpus of 20 templates
    # is correctly reported as far less conclusive than one of 700.
    if lo == hi:
        margin = min(1.0, 3.0 / k)
        if point <= 0.0:
            return Interval(0.0, 0.0, margin, k, level, "rule-of-three")
        if point >= 1.0:
            return Interval(1.0, 1.0 - margin, 1.0, k, level, "rule-of-three")
    return Interval(point, lo, hi, k, level, "cluster-bootstrap")


@dataclass(frozen=True)
class SeedSpread:
    """Distribution of one metric across synthesis seeds."""

    values: tuple[float, ...]
    label: str = ""

    @property
    def mean(self) -> float:
        return statistics.fmean(self.values) if self.values else 0.0

    @property
    def stdev(self) -> float:
        return statistics.stdev(self.values) if len(self.values) > 1 else 0.0

    @property
    def sem(self) -> float:
        return self.stdev / math.sqrt(len(self.values)) if len(self.values) > 1 else 0.0

    def interval(self, level: float = 0.95) -> Interval:
        """Normal interval on the mean across seeds.

        With the handful of seeds a run of this cost affords, this is a coarse
        instrument. It is reported to show the spread exists, not to support a
        fine-grained claim.
        """
        z = _Z.get(level, _Z[0.95])
        m, h = self.mean, z * self.sem
        return Interval(m, max(0.0, m - h), min(1.0, m + h), len(self.values), level, "seed-normal")

    def summary(self) -> dict:
        return {
            "label": self.label,
            "seeds": len(self.values),
            "mean": round(self.mean, 4),
            "stdev": round(self.stdev, 4),
            "min": round(min(self.values), 4) if self.values else 0.0,
            "max": round(max(self.values), 4) if self.values else 0.0,
            "values": [round(v, 4) for v in self.values],
        }


def is_resolved(a: Interval, b: Interval) -> bool:
    """Whether two rates are distinguishable at their confidence level."""
    return not a.overlaps(b)


def render_row(name: str, ci: Interval) -> str:
    return f"| {name} | {ci.point:.1%} | [{ci.low:.1%}, {ci.high:.1%}] | {ci.n} |"


# --------------------------------------------------------------------------- #
# Paired comparisons
# --------------------------------------------------------------------------- #
def mcnemar_exact(both: int, only_a: int, only_b: int, neither: int) -> float:
    """Two-sided exact McNemar p-value for two defenses on the SAME scenarios.

    The comparison this repository publishes is paired: every condition is
    replayed against the same 132 scenarios, so `clayseal` and `dataflow-taint`
    are not two independent samples and a Fisher or chi-square test on the
    marginals answers a question nobody asked. What matters is the DISCORDANT
    cells: the scenarios one contains and the other does not.

    Concordant scenarios carry no information about which is better, and
    including them in the denominator is what makes an unpaired test on paired
    data both wrong and, here, conservative in the wrong direction: the two
    mechanisms agree on only 21 of 132, so pooling drowns the signal.

    Exact rather than the chi-square approximation because the discordant count
    is small enough for it to matter, and because an exact binomial has no
    continuity-correction argument to have.
    """
    n = only_a + only_b
    if n == 0:
        return 1.0
    # Under H0 each discordant scenario is a fair coin.
    def _c(k: int) -> float:
        return math.exp(math.lgamma(n + 1) - math.lgamma(k + 1) - math.lgamma(n - k + 1))

    obs = min(only_a, only_b)
    tail = sum(_c(k) for k in range(0, obs + 1)) / (2 ** n)
    return min(1.0, 2 * tail)


def paired_difference_ci(
    pairs: list[tuple[bool, bool]], *, level: float = 0.95,
    resamples: int = 4000, seed: int = 0,
) -> Interval:
    """Bootstrap CI for `rate(a) - rate(b)` on paired binary outcomes.

    Resamples SCENARIOS, not outcomes, so the pairing is preserved in every
    resample. An unpaired interval on the same data is wider and centred in the
    same place, which reads as caution and is simply the wrong estimator: it
    discards the fact that the two conditions saw identical inputs.
    """
    if not pairs:
        return Interval(0.0, -1.0, 1.0, 0, level, "paired-bootstrap")
    point = (sum(a for a, _ in pairs) - sum(b for _, b in pairs)) / len(pairs)
    rng = random.Random(seed)  # noqa: S311 - a bootstrap resampler, not a keystream
    k = len(pairs)
    diffs = []
    for _ in range(resamples):
        s = 0
        for _ in range(k):
            a, b = pairs[rng.randrange(k)]
            s += int(a) - int(b)
        diffs.append(s / k)
    diffs.sort()
    alpha = (1 - level) / 2
    lo = diffs[max(0, int(alpha * len(diffs)))]
    hi = diffs[min(len(diffs) - 1, int((1 - alpha) * len(diffs)))]
    return Interval(point, lo, hi, k, level, "paired-bootstrap")


def holm_bonferroni(pvalues: dict[str, float], alpha: float = 0.05) -> dict[str, bool]:
    """Which of a family of tests survive at `alpha`, Holm-corrected.

    The sweep reports five conditions across three suites and three metrics. Any
    one of those cells can be quoted, so the family is what a reader would scan,
    and an uncorrected 0.05 over that many comparisons expects a false positive.
    Holm rather than Bonferroni because it is uniformly more powerful and needs
    no independence assumption, which these tests do not have.
    """
    ordered = sorted(pvalues.items(), key=lambda kv: kv[1])
    m = len(ordered)
    out: dict[str, bool] = {}
    rejected_so_far = True
    for i, (name, p) in enumerate(ordered):
        threshold = alpha / (m - i)
        rejected_so_far = rejected_so_far and p <= threshold
        out[name] = rejected_so_far
    return out
