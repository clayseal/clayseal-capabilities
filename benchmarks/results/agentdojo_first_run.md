# External evaluation — AgentDojo + InjecAgent (with Phase 3 hardening)

Deterministic replay of ground-truth tool calls through the real decision path;
no LLM. Run locally on Python 3.12 (agentdojo needs 3.10–3.12). Numbers reflect
the per-call argument-binding fix and Phase 3 protected zones.

## 1. AgentDojo enforcement ladder

77-task slice (1 injection/task) and 465-task scaled run (5 injections/task):

| Engine | Contain (77) | Contain (465) | False-block |
|--------|-------------|---------------|-------------|
| tool-allowlist | 77.9% | 77.8% | 0.0% |
| capability-token | 77.9% | 77.8% | 0.0% |
| task-scope | 77.9% | 77.8% | 0.0% |
| task-scope+binding | 100.0% | 95.6% | 0.0% |
| task-scope+binding+budget | 100.0% | 95.6% | 0.0% |

**Per-call binding fix.** Binding previously showed 18.1% false-block because a
single authorized arg-shape per tool rejected benign multi-call workflows.
Binding **per call** (the set of authorized argument-hashes, one per real call)
drops false-block to **0%** while keeping full argument-tampering containment —
the deployment lesson being that commit tokens bind a call, not a tool.

At scale the full stack contains **95.6% at 0% false-block**; the 4.4% that slip
through are injections that stay entirely within the authorized tool + args +
scope. Those are the behavioral detector's job (below), not the per-action layer.

## 2. AgentDojo adversarial leaderboard (per attack class, after Phase 3)

| Engine | Overall | FB | arg-tamper | path-exfil | unauth-tool | action-esc | connector-sub | goal-drift |
|--------|---------|----|-----------|-----------|-------------|------------|---------------|-----------|
| capability-token | 69% | 0% | 0% | 0% | 100% | 100% | 100% | 100% |
| task-scope | 88% | 0% | 0% | **100%** | 100% | 100% | 100% | 100% |
| task-scope+binding | 100% | 0% | 100% | 100% | 100% | 100% | 100% | 100% |

**Phase 3 protected zones** raised path-exfiltration from 77% to **100%**: a
global sensitive-path deny-list (keys, credential stores, env files, VCS
internals) applied before the goal's own path scope. The full stack now contains
every synthesized attack class at 0% false-block.

## 3. InjecAgent enforcement ladder

Full corpus, 2108 tasks / **3196 attack events**:

| Engine | Attack prevented | False-block |
|--------|------------------|-------------|
| tool-allowlist | 99.9% | 0.0% |
| capability-token | 100.0% | 0.0% |
| task-scope+ | 100.0% | 0.0% |

InjecAgent injections always invoke an out-of-scope tool, so capability
enforcement contains **100% at 0% false-block**. This is the easy end of the
spectrum; AgentDojo's in-scope injections are the hard end.

## 3b. InjecAgent and ToolEmu (three-corpus floor result)

| Corpus | Tasks | Attack events | Floor containment | False-block |
|--------|-------|---------------|-------------------|-------------|
| AgentDojo (465, ×5 inj) | 465 | 733 | 95.6% (event) / 100% (task) | 0% |
| InjecAgent | 2108 | 3196 | 100% | 0% |
| ToolEmu | 116 | 446 | 100% | 0% |

Across three external corpora the hardened enforcement floor contains attacks at
**0% benign false-block**. All three share one property: their attacks *leave*
the authorized surface (out-of-scope tool, escalated action, mutated payload,
protected path), which per-action enforcement is built to catch.

## 4. Defense in depth: the in-scope residual (what the floor cannot see)

The floor is blind by construction to attacks that stay entirely in scope. The
synthetic `in-scope-burst` class (repeat an authorized read 8× with its own
authorized args — an aggregate scanning/exfil-staging anomaly) makes this
measurable on AgentDojo:

| Layer | Containment of in-scope-burst | Benign false-block |
|-------|-------------------------------|--------------------|
| enforcement floor | **0.0%** | 0% |
| + detector (n-gram) | **71.4%** | 7.8% |
| + detector (transformer) | 41.6% | 7.8% |

The behavioral layer recovers 42–71% of what the floor structurally cannot,
at ~8% false-block. Scorer trade-off: the sharp n-gram is more sensitive to
repetition anomalies here; the transformer generalizes better on out-of-sample
benign (see §5). This is the layered thesis made concrete: floor for
surface-leaving attacks, detector for in-scope subversion.

## 5. Behavioral detector on AgentDojo injections, alpha = 0.05

| Scorer | Containment | False-block |
|--------|-------------|-------------|
| n-gram (baseline) | 100.0% | 83.9% |
| transformer (trained) | 100.0% | 0.0% |

The goal-conditioned transformer scores unseen tokens smoothly so the conformal
bound holds; the n-gram baseline breaks exchangeability on sparse trajectories
and is unusable. Validates the learned-scorer architecture. Small test sample
(31); direction is the headline.

## 6. Memo-faithful behavioral layer on long trajectories

The detector was re-grounded in the memo's two framings (AML analytics and the
Waymo safe-envelope) and the LLM adjudicator was removed — a content-reading
judge is the one prompt-injectable component. Every tier is now a pure function
of action metadata. Trained on a 4,000-trajectory synthetic corpus of multi-step
workflows (avg length 8):

| Detector config | Benign FB | burst | structuring | fan-out | escalation |
|-----------------|-----------|-------|-------------|---------|-----------|
| structural + n-gram | 0.0% | 100% | 100% | 100% | 100% |
| structural + transformer | 7.2% | 100% | 100% | 100% | 100% |

The Waymo path envelope (`reachability.py`) and AML analytics (`aml.py`) contain
every in-scope subversion shape the enforcement floor is blind to, at zero
false-block, without reading any attacker-controlled content. On the short real
corpora the sequence scorer led; on long trajectories the structural tiers do the
work and the scorer is secondary.

## 7. Real long trajectories (ATIF) + delegated-trust + ensemble

Wired the ATIF-v1.2 MCP agent-trajectory corpus already in the codebase
(`agentauth-receipts/benchmarks/corpus`): 38 real benign sessions, 282 tool-calls
(median 6, up to 32) — the longest real benign trajectories available.

Enforcement floor on real ATIF trajectories (attacks synthesized): full stack
**82% containment, 1% false-block**; `in-scope-burst` 3% (the detector's
residual). Behavioral detector trained/calibrated on the real ATIF benign
trajectories catches every in-scope shape:

| In-scope attack (real ATIF) | burst | structuring | fan-out | escalation | delegated-trust |
|-----------------------------|-------|-------------|---------|------------|-----------------|
| detector recall | 100% | 100% | 100% | 100% | 100% |

In-sample benign false-block is 10.5% — higher than on the synthetic corpus
because 38 heterogeneous real sessions lumped in one goal bucket give a noisier
corridor. The direct argument for more real per-goal data.

New capabilities:
- **delegated-trust-laundering typology** (`aml.py`) — a security-surface write
  justified by untrusted cross-boundary (main/sidekick) context, the Devin/Fusion
  threat, caught structurally (provenance labels + target surface, no content).
- **ensemble scorer** (`scoring/ensemble.py`) — z-standardized `max`/`mean` of
  n-gram + transformer, recovering both scorers' complementary strengths.

## 8. More real corpora (tau2, BFCL) + two conformal fixes

Wired two more corpora already in `agentauth-receipts/benchmarks/corpus`:
- **tau2-bench** (`tau2`): 2,545 real tasks, domain-bucketed (telecom 2,285,
  retail 112, banking 97, airline 43, mock 8); `evaluation_criteria.actions` give
  ground-truth trajectories, median 6 / max 33 calls.
- **Gorilla BFCL** (`bfcl`): 1,927 tasks incl. 200 multi-turn file-ops
  trajectories (a shared, well-sampled bucket).

Loaders set `meta["goal_kind"]` so the detector calibrates **per goal type**
(`tau2:telecom`, `bfcl:multi_turn_base`, `atif:<app>`).

tau2 enforcement leaderboard (400 tasks): full stack **95% / 0% false-block**.

Detector on real held-out trajectories exposed two statistical bugs, now fixed:
- **Calibration leakage** — calibrating the conformal on the scorer's own
  training data made the threshold too tight; fixed with **split-conformal** (a
  disjoint calibration slice).
- **Multiple comparisons** — blocking a trajectory when *any* step trips a
  per-step p ≤ α inflates trajectory false-block to ~1−(1−α)^length; fixed with a
  **trajectory-level conformal** on the max-surprise statistic.

Effect on real tau2 held-out benign false-block:

| | before | after |
|---|--------|-------|
| tau2:telecom | 29.4% | **8.0%** | 
| tau2 (all domains) | 30.6% | **7.9%** |

with 100% recall on the in-scope attacks retained. ATIF (1 session/app) now
degrades gracefully to **0% false-block** by abstaining where per-goal data is
too thin, still catching the absolute-threshold typologies (escalation,
delegated-trust) but not corridor-dependent ones — the concrete argument for
well-sampled per-goal corpora like tau2.

## 9. Cohesion pass: one gateway, CUSUM drift, capability reuse

Two subsystems (per-action floor, behavioral detector) were unified and the
system's own unused capabilities wired in:

- **SessionBroker** (`capabilities/broker.py`) — the single online gateway the
  memo describes: per action it runs the hard floor (scope, protected zones,
  egress, budgets) then, only for floor-allowed actions, the trajectory
  detector; a soft escalation raises a `step_up` request; every outcome updates
  `ScopingMetrics` (prevented violations, scan/drift/novelty triggers, overhead).
  End-to-end tests confirm floor-deny (out-of-scope, protected path), behavioral
  deny (in-scope burst the floor allows), and step-up plumbing.
- **CUSUM drift tier** (`monitor/drift.py`) — statistical-process-control
  inspiration for slow subversion: accumulates small per-step surprise
  deviations and fires on a sustained shift a point check misses ("refactor in
  one commit, weaken auth in the next"). Calibrated by conformal like every tier.
- **Two conformal correctness fixes** (from the real-data eval): split-conformal
  and trajectory-level aggregation (see §8).

138 tests pass.

## Phase 3 hardening modules (`agentauth/capabilities/hardening/`)

- **protected_zones** — global sensitive-path deny-list (wired; path-exfil 100%).
- **egress_policy** — destination allow-list for send/post tools (default-deny
  external egress); library + tests.
- **input_hardening** — detects/strips zero-width, bidi-override, unicode-tag,
  and homoglyph delivery tricks; feeds the monitor taint layer so poisoned
  content becomes untrusted context. Library + tests.

## Caveats
- AgentDojo ground-truth trajectories are short (1–3 actions); the detector's
  sequential signal is limited, so its contribution shows in false-block.
- Next: run the detector on the harder in-scope AgentDojo escapes, and add
  ToolEmu.
