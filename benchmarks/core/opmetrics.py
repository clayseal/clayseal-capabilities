"""Operating-point metrics: what a security buyer actually asks for.

Containment at an unconstrained false-block rate is a reward-hackable metric,
and this repo has the proof. ``test_sleight_detector_twin_corridor_beats_
population_floor`` records 100% containment produced by refusing 13 of 18 benign
trajectories, and nothing in the containment/false-block pair penalizes that. A
control that blocks everything scores a perfect containment.

UEBA and fraud detection settled this long ago, because they operate at base
rates where containment-style numbers carry no information. The fix is to stop
reporting a rate at whatever threshold the detector happened to choose, and start
reporting **detection at a false-alarm rate the operator chose**:

    detection @ fixed FPR   threshold pinned so benign block rate == 0.1% (1%),
                            then measure the fraction of attacks caught
    lift                    precision / prevalence at the shipping threshold
    steps-to-detect         how many attack actions execute before the block
    alert volume            step-ups + denials per 1,000 sessions
    partial AUC             area restricted to FPR <= 1%, the only region anyone
                            would deploy in

The structural property that makes this family unhackable: every metric here is
computed by *sweeping a threshold over a continuous score*. A detector whose
score does not separate the classes — including a deny-all, which assigns every
trajectory the same score — yields detection ≈ FPR at every operating point, so
it scores ~0 instead of 100%. That is asserted in
``benchmarks/tests/test_opmetrics.py`` rather than argued here.

Scores follow the repo's existing surprise convention: **larger is more
anomalous**. Callers pass benign and attack score arrays; nothing in this module
reads a label beyond which array a score arrived in.
"""
from __future__ import annotations

import math
from dataclasses import dataclass, field


# --------------------------------------------------------------------------- #
# ROC primitives
# --------------------------------------------------------------------------- #
def _roc_points(benign: list[float], attack: list[float]) -> list[tuple[float, float]]:
    """ROC as ``[(fpr, tpr), ...]`` ascending, tie-correct.

    Ties matter here more than usual: a degenerate scorer assigns every
    trajectory an identical score, and a naive implementation that steps one
    sample at a time draws a staircase through that tie group and reports
    spurious area under it. Grouping equal scores collapses the tie to a single
    chord, which is what makes a constant scorer score exactly chance.
    """
    if not benign or not attack:
        return [(0.0, 0.0), (1.0, 1.0)]
    scored = [(s, 0) for s in benign] + [(s, 1) for s in attack]
    scored.sort(key=lambda x: -x[0])
    n_b, n_a = len(benign), len(attack)
    points = [(0.0, 0.0)]
    tp = fp = 0
    i = 0
    while i < len(scored):
        threshold = scored[i][0]
        while i < len(scored) and scored[i][0] == threshold:
            if scored[i][1]:
                tp += 1
            else:
                fp += 1
            i += 1
        points.append((fp / n_b, tp / n_a))
    if points[-1] != (1.0, 1.0):
        points.append((1.0, 1.0))
    return points


def partial_auc(benign: list[float], attack: list[float],
                max_fpr: float = 0.01, *, standardized: bool = True) -> float:
    """Area under the ROC restricted to ``fpr <= max_fpr``.

    ``standardized`` rescales so 0.5 is chance and 1.0 is perfect *within the
    restricted region* (McClish). Without it every pAUC looks near zero and the
    number is unreadable.
    """
    points = _roc_points(benign, attack)
    area = 0.0
    prev_fpr, prev_tpr = 0.0, 0.0
    for fpr, tpr in points:
        if fpr > max_fpr:
            if prev_fpr < max_fpr:  # clip the crossing segment
                span = fpr - prev_fpr
                frac = (max_fpr - prev_fpr) / span if span else 0.0
                tpr_at = prev_tpr + frac * (tpr - prev_tpr)
                area += (max_fpr - prev_fpr) * (prev_tpr + tpr_at) / 2
            break
        area += (fpr - prev_fpr) * (prev_tpr + tpr) / 2
        prev_fpr, prev_tpr = fpr, tpr
    else:
        if prev_fpr < max_fpr:
            area += (max_fpr - prev_fpr) * prev_tpr
    if not standardized:
        return area
    chance = max_fpr * max_fpr / 2
    best = max_fpr
    return 0.5 * (1 + (area - chance) / (best - chance)) if best > chance else 0.5


def threshold_at_fpr(benign: list[float], fpr_target: float) -> float:
    """Smallest threshold whose benign block rate does not *exceed* ``fpr_target``.

    Blocking is ``score >= threshold``. The budget must hold as an upper bound,
    never approximately, and ties are what break a naive implementation: taking
    the k-th largest benign score as the threshold blocks every benign sharing
    that score, which can be all of them. A constant scorer is the extreme case —
    it has one tie group containing the whole corpus, so the k-th largest is also
    the smallest, and the "1% FPR" threshold blocks 100% of benign while catching
    100% of attacks. That is precisely the deny-all result this module exists to
    refuse to print.

    So candidates are evaluated rather than indexed: walk distinct scores
    downward and take the lowest threshold whose realized benign count still fits
    the budget. With ``n`` benign samples no threshold can realize an FPR finer
    than ``1/n``; the caller reads ``OperatingPoint.achieved_fpr`` and
    ``resolvable`` to know what the sample actually supported.
    """
    if not benign:
        return math.inf
    ordered = sorted(benign, reverse=True)
    n = len(ordered)
    budget = int(math.floor(fpr_target * n))
    if budget >= n:
        return -math.inf
    above = math.nextafter(ordered[0], math.inf)
    if budget <= 0:
        return above
    best = above
    count = 0
    i = 0
    while i < n:
        score = ordered[i]
        group = 0
        while i < n and ordered[i] == score:
            group += 1
            i += 1
        if count + group > budget:
            break
        count += group
        best = score
    return best


# --------------------------------------------------------------------------- #
# Operating point
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class OperatingPoint:
    """One threshold, and everything that follows from it."""

    fpr_target: float
    threshold: float
    achieved_fpr: float
    detection: float
    n_benign: int
    n_attack: int
    prevalence: float

    @property
    def resolvable(self) -> bool:
        """Can this sample realize the requested FPR at all?

        Below ``1/n`` the only threshold inside budget is one that blocks no
        benign, so detection collapses to whatever clears the highest benign
        score and the cell says more about the sample size than the detector.
        Reported rather than silently printed as a number.
        """
        return self.n_benign * self.fpr_target >= 1.0

    @property
    def precision(self) -> float:
        """Precision at the deployment prevalence, not the corpus's 50/50.

        A benchmark corpus is balanced by construction; production is not. Using
        the corpus ratio here is how a detector with no lift reads as precise.
        """
        tp = self.detection * self.prevalence
        fp = self.achieved_fpr * (1 - self.prevalence)
        return tp / (tp + fp) if (tp + fp) else 0.0

    @property
    def lift(self) -> float:
        """Precision over base rate. 1.0 means the alert told you nothing."""
        return self.precision / self.prevalence if self.prevalence else 0.0

    @property
    def alerts_per_1k(self) -> float:
        """Sessions escalated or denied per 1,000, at the deployment prevalence."""
        rate = (self.detection * self.prevalence
                + self.achieved_fpr * (1 - self.prevalence))
        return 1000 * rate

    def summary(self) -> dict:
        return {
            "fpr_target": self.fpr_target,
            "achieved_fpr": round(self.achieved_fpr, 5),
            "detection": round(self.detection, 4),
            "precision": round(self.precision, 4),
            "lift": round(self.lift, 2),
            "alerts_per_1k": round(self.alerts_per_1k, 1),
        }


@dataclass
class ScoreReport:
    """Everything measurable from one scorer on one corpus."""

    name: str
    corpus: str
    benign: list[float]
    attack: list[float]
    prevalence: float = 0.01
    steps_to_detect: list[int | None] = field(default_factory=list)
    n_attack_actions: list[int] = field(default_factory=list)

    def at(self, fpr_target: float) -> OperatingPoint:
        threshold = threshold_at_fpr(self.benign, fpr_target)
        blocked_b = sum(1 for s in self.benign if s >= threshold)
        blocked_a = sum(1 for s in self.attack if s >= threshold)
        return OperatingPoint(
            fpr_target=fpr_target,
            threshold=threshold,
            achieved_fpr=blocked_b / len(self.benign) if self.benign else 0.0,
            detection=blocked_a / len(self.attack) if self.attack else 0.0,
            n_benign=len(self.benign),
            n_attack=len(self.attack),
            prevalence=self.prevalence,
        )

    def pauc(self, max_fpr: float = 0.01) -> float:
        return partial_auc(self.benign, self.attack, max_fpr)

    def pauc_resolvable(self, max_fpr: float = 0.01) -> bool:
        """Does the ROC have any point inside the restricted region?

        With ``n`` benign the ROC steps in units of ``1/n``, so at n=18 the region
        FPR <= 1% contains no point and the restricted area is the trivial one:
        standardized pAUC is exactly 0.5 for *every* scorer, including a perfect
        one. That 0.5 is the absence of a measurement, not a finding of chance
        performance, and the distinction matters enormously when reading a small
        corpus like SLEIGHT.
        """
        return len(self.benign) * max_fpr >= 1.0

    def auc(self) -> float:
        """Full AUC — reported alongside pAUC so a corpus too small to resolve
        the deployment region still says something rather than nothing."""
        return partial_auc(self.benign, self.attack, 1.0, standardized=False)

    def median_steps_to_detect(self) -> float | None:
        """Median attack actions executed before the block, over caught attacks.

        Reported over caught attacks only, and paired with the catch rate, because
        averaging in the misses as "infinity" produces a number that improves when
        the detector gets worse.
        """
        caught = sorted(s for s in self.steps_to_detect if s is not None)
        if not caught:
            return None
        mid = len(caught) // 2
        return float(caught[mid]) if len(caught) % 2 else (caught[mid - 1] + caught[mid]) / 2

    def summary(self, fpr_targets: tuple[float, ...] = (0.001, 0.01, 0.05)) -> dict:
        return {
            "scorer": self.name,
            "corpus": self.corpus,
            "n_benign": len(self.benign),
            "n_attack": len(self.attack),
            "pauc@1%": round(self.pauc(0.01), 4),
            "median_steps_to_detect": self.median_steps_to_detect(),
            "operating_points": [self.at(f).summary() for f in fpr_targets],
        }


# --------------------------------------------------------------------------- #
# Reporting
# --------------------------------------------------------------------------- #
def render(reports: list[ScoreReport],
           fpr_targets: tuple[float, ...] = (0.001, 0.01, 0.05)) -> str:
    """A table whose columns are the questions an operator asks."""
    head = (f"{'corpus':<12}{'scorer':<14}{'n(b/a)':>10}{'AUC':>7}{'pAUC@1%':>9}"
            + "".join(f"{'det@' + _pct(f):>10}" for f in fpr_targets)
            + f"{'lift@1%':>9}{'steps':>7}")
    lines = [head, "-" * len(head)]
    for r in reports:
        pts = {f: r.at(f) for f in fpr_targets}
        steps = r.median_steps_to_detect()
        pauc = f"{r.pauc(0.01):>9.3f}" if r.pauc_resolvable(0.01) else f"{'n/r':>9}"
        cells = []
        for f in fpr_targets:
            pt = pts[f]
            # n/r, not 0.0%: an unresolvable cell is a missing measurement, and
            # printing a zero there reads as a detector that caught nothing.
            cells.append(f"{'n/r':>10}" if not pt.resolvable
                         else f"{100 * pt.detection:>9.1f}%")
        lift = pts[0.01].lift if pts[0.01].resolvable else None
        lines.append(
            f"{r.corpus:<12}{r.name:<14}"
            f"{f'{len(r.benign)}/{len(r.attack)}':>10}"
            f"{r.auc():>7.3f}" + pauc
            + "".join(cells)
            + (f"{lift:>9.2f}" if lift is not None else f"{'n/r':>9}")
            + (f"{steps:>7.0f}" if steps is not None else f"{'-':>7}")
        )
    return "\n".join(lines)


def _pct(f: float) -> str:
    return f"{f * 100:g}%"
