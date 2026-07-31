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
and can block outright. The learned scorer's block rate is bounded by ``alpha``
through the conformal layer.
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
    calibration_frac: float = 0.3  # split-conformal: benign held out for calibration
    use_envelope: bool = True
    use_taint: bool = True
    _fitted: bool = False
    _aml_benign_rate: float = 1.0  # AML flag rate on held-out benign; gates blocking

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

    def assess(self, traj: Trajectory) -> DetectionReport:
        bucket = goal_bucket(traj)
        envelope = TypedGoalEnvelope.from_goal(traj.goal) if self.use_envelope else None
        taint = TaintTracker.from_trajectory(traj) if self.use_taint else None
        scored = {s.step: s.surprise for s in self.scorer.surprise(traj)}

        # Trajectory-level scorer decision (bounds block rate at alpha). Per-step
        # p-values are kept only for attribution / reasons, not for blocking.
        surprise_stream = [scored.get(a.step, 0.0) for a in traj.actions]
        traj_surprise = max(surprise_stream, default=0.0)
        traj_p = self.traj_calibrator.p_value(bucket, traj_surprise) if self._fitted else 1.0
        scorer_block = self._fitted and traj_p <= self.alpha
        # CUSUM drift: sustained small elevation a point check misses.
        drift_p = self.drift.p_value(bucket, surprise_stream) if (self.drift and self._fitted) else 1.0
        drift_block = self.drift is not None and self._fitted and drift_p <= self.alpha

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

        # Trajectory-level structural tiers (Waymo envelope + AML), each gated by
        # the alpha budget. The path-envelope penalty blocks only when it is
        # conformally extreme versus benign; AML blocks only if it was empirically
        # low-false-positive on held-out benign (rate <= alpha). Otherwise a tier
        # informs the reasons but does not hard-block, so the union benign
        # false-alarm rate stays near alpha instead of being unbounded.
        departure = self.path_envelope.assess(traj) if self.path_envelope else None
        aml_v = self.aml.assess(traj) if self.aml else None
        path_p = (self.struct_calibrator.p_value(bucket, departure.penalty)
                  if (departure and self._fitted) else 1.0)
        path_block = bool(departure and departure.out_of_envelope and path_p <= self.alpha)
        aml_block = bool(aml_v and aml_v.flagged and self._aml_benign_rate <= self.alpha)
        structural_reasons: list[str] = []
        if scorer_block:
            structural_reasons.append(f"trajectory surprise p={traj_p:.3f} (alpha={self.alpha})")
        if drift_block:
            structural_reasons.append(f"cusum drift p={drift_p:.3f} (sustained elevation)")
        if path_block:
            structural_reasons.append(f"path-envelope p={path_p:.3f} (alpha={self.alpha})")
            structural_reasons.extend(f"path-envelope: {r}" for r in departure.reasons)
        if aml_block:
            structural_reasons.append("aml: " + ", ".join(aml_v.typologies))
            structural_reasons.extend(f"aml: {r}" for r in aml_v.reasons)

        return DetectionReport(
            verdicts=verdicts,
            path_departure=departure,
            aml=aml_v,
            structural_block=bool(structural_reasons),
            structural_reasons=tuple(structural_reasons),
            anomaly_p=min(traj_p, drift_p),
        )

    @staticmethod
    def _step_decision(conformal_flag: bool, hard_taint: bool, in_envelope: bool) -> Decision:
        # Per-action blocking only for a hard taint signal (rare, not multiple-
        # comparisons inflated). A surprising step or a structurally novel one
        # escalates; the trajectory-level scorer/structural tiers decide blocks.
        if hard_taint:
            return Decision.BLOCK
        if conformal_flag or not in_envelope:
            return Decision.ESCALATE
        return Decision.ALLOW
