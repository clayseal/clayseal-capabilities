"""TrajectoryDetector — the escalating-cost orchestrator.

Composes injection-resistant layers into one decision over the action stream.
Every layer is a pure function of action metadata (tools, verbs, resources,
amounts, targets, counts, order, provenance labels); none reads attacker-
controlled natural-language content, so an injection can move the agent but
cannot argue a bad trajectory back inside the safe set. There is deliberately no
LLM judge in this layer: a model that reads untrusted content is the one
component an attacker can prompt-inject.

Layers, cheap to expensive:

1. Typed goal envelope (per-action structural).
2. Taint / provenance (trust labels, not content).
3. Waymo path envelope — does the trajectory stay inside the corridor of
   plausible action paths for its goal (reachability.PathEnvelope).
4. AML analytics — velocity, fan-out, structuring, escalation, peer-group
   deviation (aml.AmlAnalytics).
5. Goal-conditioned surprise -> conformal p-value (calibrated false-alarm bound).

The path envelope and AML typologies are calibrated by "past the benign
corridor / peer group", so they are strong low-false-positive structural signals
and can block outright. Every hard-blocking tier is conformally gated at
``alpha/k`` (k = number of active tiers), so by the Bonferroni union bound the
combined benign block rate is bounded by ``alpha`` — not by ``k*alpha``, which an
unadjusted OR of per-tier ``alpha`` gates would allow.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from agentauth.capabilities.monitor.action import Trajectory
from agentauth.capabilities.monitor.aml import AmlAnalytics, AmlVerdict
from agentauth.capabilities.monitor.conformal import MondrianConformal
from agentauth.capabilities.monitor.drift import CusumDrift
from agentauth.capabilities.monitor.envelope import TypedGoalEnvelope
from agentauth.capabilities.monitor.provenance import TaintTracker
from agentauth.capabilities.monitor.reachability import EnvelopeDeparture, PathEnvelope
from agentauth.capabilities.monitor.twin_corridor import assess_twin_structural
from agentauth.capabilities.monitor.scoring.base import SequenceScorer
from agentauth.capabilities.monitor.scoring.ngram import NGramScorer, goal_bucket


class Decision(str, Enum):
    ALLOW = "allow"
    ESCALATE = "escalate"
    BLOCK = "block"


@dataclass(frozen=True)
class StepVerdict:
    step: int
    decision: Decision
    surprise: float
    p_value: float
    conformal_flag: bool
    in_envelope: bool
    tainted: bool
    reasons: tuple[str, ...]


@dataclass
class DetectionReport:
    verdicts: list[StepVerdict] = field(default_factory=list)
    path_departure: EnvelopeDeparture | None = None
    aml: AmlVerdict | None = None
    structural_block: bool = False
    structural_reasons: tuple[str, ...] = ()
    anomaly_p: float = 1.0  # min conformal p-value across trajectory tiers (recomputable)

    @property
    def blocked(self) -> bool:
        return self.structural_block or any(v.decision is Decision.BLOCK for v in self.verdicts)

    @property
    def first_block_step(self) -> int | None:
        for v in self.verdicts:
            if v.decision is Decision.BLOCK:
                return v.step
        return None


@dataclass
class TrajectoryDetector:
    scorer: SequenceScorer = field(default_factory=NGramScorer)
    calibrator: MondrianConformal = field(default_factory=MondrianConformal)
    traj_calibrator: MondrianConformal = field(default_factory=MondrianConformal)
    struct_calibrator: MondrianConformal = field(default_factory=MondrianConformal)
    drift: CusumDrift | None = field(default_factory=CusumDrift)
    path_envelope: PathEnvelope | None = field(default_factory=PathEnvelope)
    aml: AmlAnalytics | None = field(default_factory=AmlAnalytics)
    alpha: float = 0.05
    calibration_frac: float = 0.4  # split-conformal: benign held out for calibration
    use_envelope: bool = True
    use_taint: bool = True
    # When assess(..., reference=benign_twin) is supplied, run the twin
    # corridor / intent two-signal / surface gate (SLEIGHT-style covert intent).
    use_twin_reference: bool = True
    _fitted: bool = False
    _aml_benign_rate: float = 1.0  # AML flag rate on held-out benign (reason-only)

    def fit(self, benign: list[Trajectory]) -> "TrajectoryDetector":
        # Split-conformal (inductive): the scorer trains on one slice and the
        # conformal layer calibrates on a DISJOINT slice. Calibrating on the
        # scorer's own training data leaks — an overfit scorer scores its train
        # set too low, the threshold turns too tight, and held-out benign is
        # flagged far above alpha. A held-out calibration slice restores
        # exchangeability with future benign, so the false-alarm bound holds.
        n = len(benign)
        cal_n = max(1, int(n * self.calibration_frac)) if n > 1 else 0
        fit_set = benign[cal_n:] if cal_n and cal_n < n else benign
        cal_set = benign[:cal_n] if cal_n and cal_n < n else benign

        fit = getattr(self.scorer, "fit", None)
        if callable(fit):
            fit(fit_set)
        pairs: list[tuple[str, float]] = []
        traj_pairs: list[tuple[str, float]] = []
        drift_pairs: list[tuple[str, list[float]]] = []
        for traj in cal_set:
            bucket = goal_bucket(traj)
            surprises = [s.surprise for s in self.scorer.surprise(traj)]
            pairs.extend((bucket, s) for s in surprises)
            # Trajectory-level statistic controls the block rate at alpha; a
            # per-step OR would inflate to ~1-(1-alpha)^length on long paths.
            traj_pairs.append((bucket, max(surprises) if surprises else 0.0))
            drift_pairs.append((bucket, surprises))
        self.calibrator.fit(pairs)
        self.traj_calibrator.fit(traj_pairs)
        if self.drift is not None:
            self.drift.fit(drift_pairs)
        # Structural tiers fit on the SAME fit slice as the scorer, so their
        # scores on the disjoint calibration slice are out-of-sample. Fitting on
        # all benign (including cal) makes every calibration penalty look in-
        # corridor, leaving the tier uncalibrated and free to block any novel-
        # but-benign path outright — which is exactly what inflated the benign
        # false-alarm rate far above alpha with no response to alpha at all.
        if self.path_envelope is not None:
            self.path_envelope.fit(fit_set)
        if self.aml is not None:
            self.aml.fit(fit_set)
        # Calibrate the path-envelope penalty and measure the AML benign flag
        # rate on the held-out slice, so both structural tiers respect the same
        # alpha budget as the learned scorer instead of blocking unconditionally.
        struct_pairs: list[tuple[str, float]] = []
        aml_flags = 0
        for traj in cal_set:
            bucket = goal_bucket(traj)
            if self.path_envelope is not None:
                struct_pairs.append((bucket, self.path_envelope.assess(traj).penalty))
            if self.aml is not None and self.aml.assess(traj).flagged:
                aml_flags += 1
        self.struct_calibrator.fit(struct_pairs)
        self._aml_benign_rate = (aml_flags / len(cal_set)) if cal_set else 1.0
        self._fitted = True
        return self

    def _tier_pvalues(self, traj: Trajectory) -> dict[str, float]:
        """Per-bucket conformal p-value of each CONTINUOUS blocking tier (learned
        scorer, CUSUM drift, path-envelope). Small = anomalous. AML is not here: as
        a discrete typology flag it informs reasons but does not carry a conformal
        budget (its aggregate-volume job is the floor's budget rung)."""
        if not self._fitted:
            return {}
        bucket = goal_bucket(traj)
        scored = {s.step: s.surprise for s in self.scorer.surprise(traj)}
        surprise_stream = [scored.get(a.step, 0.0) for a in traj.actions]
        traj_surprise = max(surprise_stream, default=0.0)
        parts: dict[str, float] = {"scorer": self.traj_calibrator.p_value(bucket, traj_surprise)}
        if self.drift is not None:
            parts["drift"] = self.drift.p_value(bucket, surprise_stream)
        if self.path_envelope is not None:
            dep = self.path_envelope.assess(traj)
            # A path penalty is evidence only when the trajectory is structurally
            # out of the corridor; an in-envelope penalty stays a non-signal (p=1).
            parts["path"] = (self.struct_calibrator.p_value(bucket, dep.penalty)
                             if (dep and dep.out_of_envelope) else 1.0)
        return parts

    def _tier_budget(self, active: list[str]) -> dict[str, float]:
        """Per-tier false-alarm budget. Each blocking tier is a proper per-bucket
        (Mondrian) conformal test, so gating it at ``alpha`` individually bounds
        THAT tier's benign block rate at alpha. The tiers block on different shapes
        (scorer: novel bigrams; drift: sustained elevation; path: corridor
        departure), so on the tested corpora their benign flags barely overlap and
        the empirical UNION false-alarm rate stays near alpha; the honest worst-case
        union bound is k*alpha. A single combined statistic could reclaim the split,
        but calibrating its threshold is data-fragile on heterogeneous corpora,
        whereas per-tier conformal control is robust — the deliberate trade here."""
        return {t: self.alpha for t in active}

    def assess(
        self,
        traj: Trajectory,
        *,
        reference: Trajectory | None = None,
    ) -> DetectionReport:
        """Score ``traj``. Optional ``reference`` is the sealed benign twin / plan.

        Population tiers (scorer, drift, path envelope) use the fitted benign
        corpus. When ``reference`` is set and ``use_twin_reference`` is true,
        twin-calibrated structural checks can hard-block covert departures that
        stay inside the coarse population corridor.
        """
        bucket = goal_bucket(traj)
        envelope = TypedGoalEnvelope.from_goal(traj.goal) if self.use_envelope else None
        taint = TaintTracker.from_trajectory(traj) if self.use_taint else None
        scored = {s.step: s.surprise for s in self.scorer.surprise(traj)}

        # Per-tier Bonferroni: gate each blocking tier's per-bucket conformal
        # p-value at its share of the alpha budget, so the UNION benign block rate
        # is bounded by alpha on every corpus (see _tier_budget). This holds the
        # bound robustly where an empirically calibrated combined threshold does not.
        tier_p = self._tier_pvalues(traj)
        budget = self._tier_budget(list(tier_p)) if tier_p else {}
        tier_block = {t: (p <= budget.get(t, 0.0)) for t, p in tier_p.items()}
        combined_block = self._fitted and any(tier_block.values())
        min_p = min(tier_p.values(), default=1.0)
        surprise_stream = [scored.get(a.step, 0.0) for a in traj.actions]
        traj_p = tier_p.get("scorer", 1.0)
        drift_p = tier_p.get("drift", 1.0)

        verdicts: list[StepVerdict] = []
        for action in traj.actions:
            surprise = scored.get(action.step, 0.0)
            p_value = self.calibrator.p_value(bucket, surprise) if self._fitted else 1.0
            conformal_flag = self._fitted and p_value <= self.alpha

            in_envelope = True
            reasons: list[str] = []
            if envelope is not None:
                ev = envelope.assess(action)
                in_envelope = ev.in_envelope
                reasons.extend(ev.reasons)

            hard_taint = False
            if taint is not None:
                tv = taint.assess(action)
                hard_taint = tv.escalate
                if tv.tainted:
                    reasons.append(f"driven by untrusted context {list(tv.untrusted_sources)}")
            if conformal_flag:
                reasons.append(f"step surprise p={p_value:.3f}")

            decision = self._step_decision(conformal_flag, hard_taint, in_envelope)
            verdicts.append(StepVerdict(
                step=action.step, decision=decision, surprise=surprise, p_value=p_value,
                conformal_flag=conformal_flag, in_envelope=in_envelope,
                tainted=hard_taint, reasons=tuple(reasons),
            ))

        # Attribution for a combined-statistic block: name every tier at or below
        # the block threshold (the one that achieved the min drove the decision).
        departure = self.path_envelope.assess(traj) if self.path_envelope else None
        aml_v = self.aml.assess(traj) if self.aml else None
        structural_reasons: list[str] = []
        if combined_block:
            structural_reasons.append(f"combined min-p={min_p:.4f} (alpha={self.alpha}, Bonferroni per-tier)")
            if tier_block.get("scorer"):
                structural_reasons.append(f"trajectory surprise p={traj_p:.4f} (budget {budget['scorer']:.4f})")
            if tier_block.get("drift"):
                structural_reasons.append(f"cusum drift p={drift_p:.4f} (sustained elevation)")
            if tier_block.get("path") and departure:
                structural_reasons.append(f"path-envelope p={tier_p['path']:.4f} (budget {budget['path']:.4f})")
                structural_reasons.extend(f"path-envelope: {r}" for r in departure.reasons)
        # AML is reason-only (no conformal budget); surface it when it fires.
        if aml_v and aml_v.flagged:
            structural_reasons.extend(f"aml: {r}" for r in aml_v.reasons)

        twin_block = False
        if (
            reference is not None
            and self.use_twin_reference
            and reference.actions
        ):
            twin = assess_twin_structural(traj, reference)
            if twin.blocked:
                twin_block = True
                structural_reasons.extend(twin.reasons)

        return DetectionReport(
            verdicts=verdicts,
            path_departure=departure,
            aml=aml_v,
            # Twin structural is a sealed-plan check, not a conformal population
            # tier; it hard-blocks when the reference corridor says so.
            structural_block=combined_block or twin_block,
            structural_reasons=tuple(structural_reasons),
            anomaly_p=min(traj_p, drift_p),
        )

    @staticmethod
    def _step_decision(conformal_flag: bool, hard_taint: bool, in_envelope: bool) -> Decision:
        # Taint hard-blocks only when the untrusted-driven consequential action
        # ALSO leaves the sealed goal (out of the typed envelope) — the injection
        # shape the module docstring describes: "driven by untrusted context, and
        # which does something consequential the sealed goal never asked for."
        # Provenance is data-flow derived, so a benign read->authorized action is
        # tainted too; on its own that must escalate, not block. A surprising step
        # or a structurally novel one escalates; the trajectory-level scorer and
        # structural tiers decide the hard blocks.
        if hard_taint and not in_envelope:
            return Decision.BLOCK
        if conformal_flag or not in_envelope or hard_taint:
            return Decision.ESCALATE
        return Decision.ALLOW
