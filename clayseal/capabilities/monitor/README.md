# Goal-conditional trajectory security (behavioral layer)

The per-action layer (commit tokens, scoping, budgets) decides whether a single
action is permitted. This layer decides whether a *trajectory* stays faithful to
the sealed goal, catching sequences that are malicious even though every step is
individually allowed: slow subversion, complexity laundering, sub-threshold
splitting, delegated-trust laundering, and goal drift after reading poisoned
context.

The design asset is the **sealed goal**, captured by the control plane before
retrieved documents, memory, or tool output can contaminate it. Conditioning on
it turns population-level anomaly detection into intent-faithfulness detection.

## Injection-resistant by construction

Every layer is a pure function of **action metadata**, tools, verbs, resources,
amounts, targets, counts, order, and provenance labels. No layer reads the
natural-language content an attacker controls. That is the point: an injection
can move the agent, but it cannot write text that argues a bad trajectory back
inside the safe set the way it could talk an LLM judge out of a verdict. There is
deliberately **no LLM adjudicator** in this trust boundary, a model that reads
untrusted content is the one component an attacker can prompt-inject.

## Escalating-cost layers

Following the memo, the behavioral layer is "more like fraud detection or AML
than a normal sandbox," and asks, Waymo-style, whether the trajectory stays
inside a safe envelope of action paths.

| Layer | Module | Cost | Catches |
|-------|--------|------|---------|
| Typed goal envelope | `envelope.py` | free | actions structurally implausible for the goal |
| Taint / provenance | `provenance.py` | free | consequential actions driven by untrusted post-seal context |
| Waymo path envelope | `reachability.py` | cheap | trajectories that leave the corridor of plausible action paths (bursts, novel transitions, over-length) |
| AML analytics | `aml.py` | cheap | velocity, fan-out, structuring (many just-under-threshold value actions), post-read escalation, peer-group deviation, delegated-trust laundering |
| CUSUM drift | `drift.py` | cheap | slow subversion — a sustained small elevation in surprise that a single-point check misses (SPC / quality-control inspiration) |
| Conformal sequence scoring | `scoring/` + `conformal.py` | cheap | steps improbable under how this goal is normally pursued, at a bounded false-alarm rate |

All trajectory-level signals (max-surprise, CUSUM, path envelope, AML) are
calibrated per goal bucket by conformal, and the block decision is
**trajectory-level** so the false-alarm rate stays near `alpha`, a per-step OR
would inflate it to ~`1-(1-alpha)^length`. The conformal layer is **split**
(calibrated on a slice disjoint from the scorer's training) to avoid the
leakage that makes an overfit scorer's threshold too tight.

## One gateway: the SessionBroker

`clayseal/capabilities/broker.py` composes the per-action enforcement floor
(scope, protected zones, egress, budgets) and this behavioral detector into the
single online gateway the memo describes. Per action it runs the hard floor,
then, only for floor-allowed actions, the trajectory detector, and it speaks
the existing capability vocabulary: a soft escalation raises a
`step_up` request; every outcome updates a `ScopingMetrics` (prevented
violations, `scan`/`drift`/`novelty` triggers, broker overhead).

`detector.py` composes them. The path envelope and AML typologies are calibrated
by "past the benign corridor / peer group," so they are strong low-false-positive
structural signals and can block outright; the learned scorer's block rate is
bounded by `alpha` through conformal calibration. Structural tiers abstain on a
goal bucket with too few benign paths (`min_samples`) rather than over-flag.

## Result on long trajectories

Trained on a 4,000-trajectory synthetic corpus of multi-step workflows
(`training/synth_corpus.py`; avg length 8), the full detector contains every
in-scope attack shape the enforcement floor cannot see, at zero benign
false-block:

| Config | Benign FB | burst | structuring | fan-out | escalation |
|--------|-----------|-------|-------------|---------|-----------|
| structural + n-gram | 0.0% | 100% | 100% | 100% | 100% |
| structural + transformer | 7.2% | 100% | 100% | 100% | 100% |

The structural tiers (path envelope + AML) do the work; the sequence scorer is
secondary. These are the exact in-scope shapes AgentDojo / InjecAgent / ToolEmu
do not exercise and the per-action floor is blind to by construction.

## Why this is more than a threshold

The scorer emits an uncalibrated surprise. `conformal.py` converts it to a
p-value against held-out benign scores, so flagging at `p <= alpha` bounds the
benign false-block rate by `alpha` under exchangeability. The false-alarm rate is
a dial with a guarantee behind it, not a tuned constant. `MondrianConformal`
calibrates per goal bucket so a common task type cannot mask elevated false
alarms on a rare one. The n-gram and transformer scorers are interchangeable
behind this contract: swapping the scorer changes containment, never the
guarantee.

## Scorers

- `scoring/ngram.py`, deterministic goal-conditioned n-gram. No dependencies,
  runs anywhere, is the honest floor and the offline fallback.
- `scoring/transformer.py`, goal-conditioned decoder-only LM (torch, the
  `[monitor]` extra). Surprise is the model's negative log-probability of each
  action given the sealed goal and the prior actions. Trained on a GPU VM.

The detector is a **one-class** model: it trains on benign trajectories only and
flags departures, so it needs no labeled attacks to learn.

## Train and evaluate

```bash
# 1. Benign corpus from a dataset's user-task ground truth
python -m benchmarks.build_corpus --dataset agentdojo --limit 3000 --out benign.jsonl

# 2. Train the scorer (GPU VM)
python -m clayseal.capabilities.monitor.training.train \
    --corpus benign.jsonl --out models/traj-lm --epochs 20 --device cuda

# 3. Evaluate trajectory-level containment vs conformal false-block
python -m benchmarks.cli --dataset agentdojo --mode detector --scorer ngram
python -m benchmarks.cli --dataset agentdojo --mode detector \
    --scorer transformer --model-dir models/traj-lm --alpha 0.05
```

`benchmarks/azure/train_detector.sh` runs the whole sequence on a GPU VM and
compares the n-gram baseline against the trained transformer.

## Runtime use

```python
from clayseal.capabilities.monitor import TrajectoryDetector, NGramScorer

detector = TrajectoryDetector(scorer=NGramScorer(), alpha=0.02)
detector.fit(benign_trajectories)          # or load a trained transformer scorer
report = detector.assess(live_trajectory)  # per-step allow / escalate / block
if report.blocked:
    ...  # first_block_step, per-step reasons available on the report
```

`report.structural_reasons` explains any path-envelope or AML block, and each
`StepVerdict` carries its own reasons, so a block is always auditable in terms of
trajectory shape, never an opaque model verdict.

## Status

Built and tested offline: typed envelope, taint/provenance, Waymo path envelope,
AML analytics, n-gram + transformer scorers, conformal calibration, detector
orchestration, the long-trajectory corpus generator, and benchmark integration.
The conformal false-alarm guarantee is pinned by `python/tests/test_monitor.py`;
the structural tiers' in-scope containment is pinned there too. Next: a
delegated-trust-provenance typology for the main/sidekick laundering case, and an
n-gram/transformer scorer ensemble (they are complementary).
