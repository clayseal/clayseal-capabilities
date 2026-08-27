# Audit of `_results_table_draft.tex`


> The audited document is kept outside this repository. The findings below are
> checks of its claims against this code.

Measured against committed HEAD `9bd0ec0` in a detached worktree at
`audit-wt` (a local scratch script)
with `.benchmark-corpus` symlinked read-only from the main tree. The user's
working tree was not modified, stashed or reverted. Every number below is either
read from a file at HEAD, printed by a command run in that worktree, or produced
by a probe written for this audit; the source is named in each case.

---

## 1. Direct answer

**No.** The table is neither exhaustive nor accurate. It is closer to the
opposite of exhaustive: it publishes the axes we measured first and omits four of
the five axes measured most recently, including the two strongest results in the
repository, while carrying two rows that measure nothing.

Counts over the 14 body rows:

| status | rows |
| --- | --: |
| supported as written | **0** |
| survive with a corrected number or a corrected framing | **8** |
| unsupported, must be cut or re-run before any version is quotable | **6** |

Missing:

| status | count |
| --- | --: |
| strong results with no row at all | **5** |
| missing columns that the existing rows are not interpretable without | **2** |
| axis we are weak on with no row at all | **1** |

The five missing strong results are idempotence, delegation, observation
freshness, re-identification, and Mind2Web-SC. The two missing columns are
friction (false block) and attention (interruptions per task). The missing weak
axis is content-defined harm, where our number is 21.6%.

Zero of the 14 rows is publishable exactly as drafted. Eight of them describe a
real result that survives once the number, the denominator or the framing is
fixed.

The scoreboard disagreement flagged in the brief is the SLEIGHT row.
`benchmarks/results/scoreboard.md` at HEAD prints `sleight[detector] 27.8%
contained` and `sleight 4.7%` on the plain replay row. The table prints
approximately 98%. `benchmarks/results/scoreboard.json` at the same commit prints
5.6% for the same tier. I could not find 98 for SLEIGHT in any file under
`benchmarks/results/` at HEAD.

---

## 2. Rows that must change before publication, worst first

### 2.1 ULB / IBM AML

- **As written:** `ULB / IBM AML | peer deviation + fan-out | 0.86 AUC | 0.914; 15/15`
- **Should read:** cut the row.
- **Evidence:** `grep -rn '0\.86' docs/ benchmarks/results/*.md` at HEAD returns
  the draft `.tex` itself and one untracked file that already records "no
  source"; on the ours side, a diagonal Mahalanobis over the identical split and
  the identical training legits scores AUC 0.9619 at recall@1%FPR 0.6409 against
  the shipped sensor's 0.9140 and 0.3204, so the mechanism the row advertises
  loses to a label-free rung beneath it, and the 15/15 defines its positive set as
  laundering accounts whose fan-out already exceeds every legitimate account's
  fan-out on the same feature the z-score is built from
  (`benchmarks/aml_sequence_validation.py` line 87).

### 2.2 Business-process (live)

- **As written:** `Business-process (live) | authorized sequence, composite rule | approx 100% viol. (Progent / CaMeL) | 0% viol.`
- **Should read:** replace with Mind2Web-SC (same axis, public corpus). If the
  BPL scenarios are kept, they move to prose as "per-call privilege and dataflow
  gating, reproduced by us from their published mechanisms, violate on all four
  aggregate scenarios; neither system's own code was run."
- **Evidence:** both competitor figures come from branches we wrote inside
  `benchmarks/live/bpl_live.py` (line 133 `elif condition == "progent"`, line 146
  `elif condition == "camel"`), and in each scenario the ceiling handed to the
  budget config and the ceiling inside `violated()` are the same Python variable
  (lines 185/211/215, 293/318/322, 338/360/364, 380/402/406), so 0% is arithmetic.

### 2.3 SLEIGHT (twins)

- **As written:** `SLEIGHT (twins) | covert intent, same tools/paths | approx 6% (n-gram) | approx 98%`
- **Should read:** cut. If any SLEIGHT figure is published it is
  `best alternative: SLEIGHT-Bench's own Opus 4.6 monitor with extended thinking,
  32% at 1% FPR | ours: 5.6% with no reference at alpha 0.05`, with 97.7%
  labelled an oracle ceiling in the same sentence.
- **Evidence:** ablating the twin reference on the same fit and the same split
  takes containment from 17/18 to 1/18, shuffling the attack's own actions moves
  the corridor from 42/43 to 43/43 and shuffling the benign reference turns a 0%
  false block into 39/43, and `benchmarks/results/runtime_inputs.md` at HEAD
  states the corridor needs a paired clean run of the same task, which no
  deployment has.

### 2.4 IPI / ATB / AdvBench / MCP / ToolEmu

- **As written:** `IPI / ATB / AdvBench / MCP / ToolEmu | unauthorized recipient / poisoned tool | 0-40% below binding | 100%`
- **Should read:** delete, and publish only the ATB remnant as its own row:
  `AgentThreatBench data_exfil (UK AISI inspect_evals) | corpus-named attacker
  recipient vs corpus-named authorized list | 0/6 at the rungs below binding (our
  ablation) | 100% (6/6), 95% CI [50, 100]`.
- **Evidence:** ToolEmu contributes 0 attack events and 559 benign
  (`python -m benchmarks.cli --dataset toolemu` at HEAD, matching
  `scoreboard.json`), 1 of 35 non-benign IPI samples names a concrete target in
  the corpus while `benchmarks/datasets/ipi_coding.py` lines 58-83 synthesise the
  other 34 onto four hardcoded paths, and MCP and AdvBench are self-authored
  fixtures of 5 and 6 events (`benchmarks/fixtures/`).

### 2.5 Adaptive red-team

- **As written:** `Adaptive red-team | exfil / persist / destroy, mutating | 0% (RBAC / capability token) | 100%`
- **Should read:** cut, or restate as the narrow ablation that survives:
  `Path canonicalization under mutation search | 7 obfuscation families plus an
  oracle prefix escape, resolved not string-matched | n/a, no external system run
  | all variants resolved`.
- **Evidence:** adding `DenyAllEngine` as an extra arm over 100 redcode tasks and
  3 rounds gives containment 1.0000 on all four objectives at all three knowledge
  levels, identical to task-scope, and the tier has no benign arm, so nothing in
  it separates the mechanism from a policy that blocks everything.

### 2.6 AgentDojo (live)

- **As written:** `AgentDojo (live) | prompt-injection ASR | 5.6% built-in; Progent 11-17% | approx 0%`
- **Should read:** do not publish until re-run. If it holds:
  `Best alternative: CaMeL near 0% (arXiv:2503.18813, not run by us); Progent 4.2%
  (independent repro, arXiv:2606.26479); AgentDojo tool_filter 5.6-33.3% (our
  runs) | Ours: 1.4% [0.3, 7.5], 1 success in 72 distinct user x injection pairs,
  clean utility 54.2% against 83.3% undefended`.
- **Evidence:** the pooled run is commit `bb398fc` and
  `git log -S'_destinations_in(str(result))' -- benchmarks/live/broker_defense.py`
  returns `088e4fa` (added the free-text destination widening, 2026-08-02) and
  `721a8bb` (removed it, 2026-08-09), so the 216 runs sit between them and were
  produced by a rule HEAD's own docstring now describes as a 4.2% leak; separately
  `benchmarks/live/run_agentdojo.py` lines 313-314 truncate to the first 6 user
  and first 3 injection tasks, so the denominator is 72 distinct pairs repeated 3
  times, not 216 independent trials.

### 2.7 Utility cost

- **As written:** `Utility cost | clean-task cost (deployable) | ARGUS ~5; CaMeL ~7; Progent ~19 | 3 pts (grok)`
- **Should read:** `clean-task cost, paired, same arm the security rows report |
  ARGUS 5 pts (2605.03378, gpt-4o-mini); CaMeL 7 pts (2503.18813); Progent 12.5
  pts (our run of their code, gpt-4o-mini) | envelope-taint: 18.8 pts on
  grok-4-1-fast, 21.9 pts on gpt-4o-mini, 21.9 pts pooled over 96 paired clean
  tasks`.
- **Evidence:** recounting per-task success straight from
  `benchmarks/results/model-ladder/*-trace.json` gives grok-4-1-fast none 81.2%,
  envelope 78.1%, envelope-taint 62.5% at n=32, and envelope-taint is the arm
  every security row in the table reports (`pooled_asr.md` line 9), so the
  matched cost is 18.8 points and not 3.

### 2.8 Burst + flow + BFCL detector

- **As written:** `Burst + flow + BFCL detector | authorized bursts & chunked leaks | 0% (per-call ladder) | 100% / 0% FA`
- **Should read:** drop the detector from the row, drop "chunked leaks" from the
  class column, and quote the two enforcement mechanisms with their real
  friction: `100% contained (burst at burst>=10); false alarm 0.0% tau2 and 2.0%
  BFCL; flow blocks 200/200 single-write leak sessions at 0.00% false block on
  1,230 real benign writes, and does NOT block chunked leaks: 84/200 tau2 and
  122/171 BFCL walk the whole value out at 22 fragments`.
- **Re-measured 2026-08-09.** The false-block figure this entry recommended,
  0.2% (2/1,230), is superseded: the current run prints 0.00% (0/1,230) on tau2
  and 0.00% (0/691) on BFCL. The chunked half of the class column was never
  contained and is now measured. See `flow.md`.
- **Evidence:** `get_loader('bfcl').load(limit=1200)` returns tasks whose maximum
  benign session length is 1 call, and fitting the same detector on the same train
  split then handing it held-out benign sessions that legitimately repeat their
  own authorized read blocks 0/314 at length 1, 28/314 at length 2 and 314/314 at
  length 3, so the 0% false-alarm denominator excludes by construction every
  session shape the mechanism blocks.

### 2.9 Long-horizon

- **As written:** `Long-horizon | needle in session's own tool | 0-83% (lower rungs) | 100% / 0 FA`
- **Should read:** `Long-horizon position independence | one buried attack action
  per session, needle carrying the attack corpus's verb, target and args | 0%
  naive allowlist; 88-100% capability token (ours, seed-dependent) | 100% (40/40)
  at seeds 0, 1, 7, 12345, unchanged from 10 to 2,000 actions per session`. Drop
  "0 FA".
- **Evidence:** rebuilding the needle so it actually wears the session's own
  clothes, carrier tool and resource and action and authorized args with only the
  target changed, collapses detection to 0% at capability-token and 2% at every
  rung above, so the experiment the "What it isolates" cell describes scores 2%;
  and `benchmarks/core/heldout.py` names bfcl among the corpora where the grant is
  the benign side restated, with the honest held-out figure 18.04% in
  `scoreboard.json`.

### 2.10 Cross-session + drift

- **As written:** `Cross-session + drift | split spend; baseline poison | session ledger fails; rolling 0.5% | holds / 82%`
- **Should read:** split. Keep `Cross-session structuring | 40k split against a
  10k ceiling | 100% violation (Progent and CaMeL reproductions, n=20 per
  scenario) | 0% violation; progress 61% and 40%, friction 2.2 and 3.0`. Move the
  drift half to a labelled roadmap figure.
- **Evidence:** `python -m benchmarks.drift --actions 2000 --target {12,13,14}`
  gives anchored 15.0%, 47.3% and 82.1%, so 82% is a knob setting; and no anchored
  monitor exists in `agentauth/` (`clayseal/capabilities/monitor/drift.py` is
  CusumDrift with no anchored-versus-rolling distinction, and `notes/moonshots.md`
  line 34 lists anchored baselines as Moonshot 1, unbuilt).

### 2.11 Mandate quality

- **As written:** `Mandate quality | incomplete grant (held-out FB) | 47.9% FB on tau2 | 0.05% FB`
- **Should read:** `incomplete grant, held-out FB | no published comparable |
  AgentHarm 58.4% -> 1.8% held-out FB (mean of seeds 0-4, range 0.6-2.5) at a
  containment cost of 21.6% -> 20.9%; the same setting collapses Mind2Web-SC
  containment 98.0% -> 0.0%; not a shipped default`.
- **Evidence:** the 47.9% is our own pre-generalisation number, the "before"
  column of the same table in `benchmarks/results/generalisation.md` lines 22-28
  that the 0.05% is the "after" column of, and tau2 carries zero attack events so
  the corpus supplying both cells cannot measure the containment cost at all.

### 2.12 iVisor + latency

- **As written:** `iVisor + latency | syscall escape / egress; cost | floor misses BPL; CaMeL minutes | 8/8; ~20 us`
- **Should read:** `iVisor syscall floor: 0 denials on both volume scenarios (our
  replay, n=8); CaMeL 56 to 95 s per banking task, 0/5 completed (our run of the
  released code) | 5/8 contained by our layer and 8/8 with the floor, attack-only
  with no benign traces and a per-scenario egress budget; enforcement p50 19.7 to
  22.3 us and p99 188 to 264 us`.
- **Evidence:** rebuilding every scenario's capability with one uniform
  `egress_budget` gives a harness pass rate of 8/8 only for budgets in 2..6 and
  6/8 with the budget off, and the shipped values are 4 and 3 on exactly the two
  rows our layer wins; the 14 CaMeL logs on this machine that carry a duration
  have a maximum of 94.6 s, against the "over ten minutes" in
  `head_to_head_injection.md` line 48, which cites no log.

### 2.13 RedCode-Exec

- **As written:** `RedCode-Exec | granted tool, ungranted target | 0% (RBAC / capability token) | 99.9%`
- **Should read:** `RedCode-Exec, resource subset (718 of 750 parseable-target
  cases, 14 of 27 risk indexes) | our ladder ablation, not a third-party system:
  tool-name RBAC 0/718; capability tokens 0/718 when the token names one coarse
  resource, 709/718 when it names the target | 95.6% (717/750, unparseable-target
  cases counted as misses)`. Carry no false-block figure on this row.
- **Evidence:** I counted the corpus directly, 1,410 cases across 47 JSON files
  under `.benchmark-corpus/RedCode/dataset/RedCode-Exec/`, of which 750 sit on the
  14 resource risk indexes, while `python -m benchmarks.cli --dataset redcode` at
  HEAD prints 718 attack events; and re-running the same 768 tasks with the
  resource derived from the target instead of the hardcoded `workspace`
  (`benchmarks/datasets/redcode.py` line 312) moves capability-token from 0.0% to
  98.7% at unchanged 0.0% false block, so the competitor zero is our own naming
  choice.

### 2.14 AgentDojo (replay)

- **As written:** `AgentDojo (replay) | injection / arg swap on traces | 77.9% below binding | 100%`
- **Should read:** `AgentDojo (replay, 465 tasks) | injection / arg swap on
  traces | 77.8% at the rungs below binding (our ladder) | 95.6% at 0%
  false-block`.
- **Evidence:** `benchmarks/results/agentdojo_first_run.md` at HEAD prints both
  columns on the same line, task-scope+binding at 100.0% on the 77-task slice and
  95.6% on the six-times-larger 465-task run, and the table takes both its
  baseline and its headline from the smaller column.

---

## 3. Rows that should be added

Same four columns as the draft. Every figure is from HEAD.

| Benchmark | What it isolates | Best alternative | Ours |
| --- | --- | --- | --- |
| Idempotence / commit tokens | the same authorized action sent twice, every field identical | 0 / 2,412 across the whole per-call ladder (our ablation) | replay refused 100% (400/400); legitimate repeat allowed 100% (400/400) |
| Delegation (confused deputy) | same action, only the acting principal swapped | 0 blocked in every cell (our ladder) | 100% on four cells at the attacker's best of 13 strategies; rightful holder allowed 100%; held-out FB 0.00% |
| Observation freshness (semantic TOCTOU) | byte-identical attack and control, the world moved between read and act | 0 blocked of 232 (our ladder) | 100% on four arms; 0.00% FB on 1,254 real consequential actions; 1.8% extra tool calls |
| Re-identification / aggregation | granted reads assembling into a person, no single value sensitive | 0 of 870 arm actions blocked (our ladder) | 100% (145/145); 35.7 escalations per 100 quasi-identifier sessions |
| Mind2Web-SC | authority from the principal's attested attributes, not the tool or path | 0.0% at tool-allowlist (our ladder) | 98.0% at 1.00% FB, 100a / 100b; 48/50 matched pairs decided correctly on both sides |
| AgentHarm (content-defined harm) | harm is in what the action says, benign and harmful twins under one grant | nobody contains this: an Opus 4.6 monitor with extended thinking catches 32% of SLEIGHT at 1% FPR | 21.6% (141/652); real ceiling 28.8%; held-out FB 57.73% |

Verified for this audit in the clean worktree: `python -m benchmarks.mind2web_sc_report`
printed tool-allowlist 0.0%, capability-token 98.0% at 1.00% false block over
100a / 100b, containment first appearing at capability-token, "saturates at the
naive tool-allowlist rung: False", the oracle ceiling 100.0% reported separately,
and 48/50 matched pairs correct on both sides. The idempotence figures are read
from `benchmarks/results/idempotence.md` at HEAD, the delegation figures from
`benchmarks/results/deputy.md` at HEAD, the AgentHarm 21.6% from `benchmarks/results/scoreboard.md`
at HEAD.

Two conditions travel with these rows. Mind2Web-SC falls from 98.0% to 0.0% at
the first level of grant generalisation (`generalisation.md`), so it is quotable
only with resources declared exact. Re-identification is not publishable without
its 35.7% escalation rate, and idempotence is not publishable without the
legitimate-repeat arm.

Two missing columns, not rows:

- **False block.** The table asserts thirteen containment numbers with no
  denominator in the other direction. `scoreboard.md` at HEAD states in its own
  header that FB(granted) is 0.00% by construction on six corpora because the
  grant is the benign side restated. The held-out column on the same rows runs
  18.04% to 57.73%.
- **Attention.** `benchmarks/results/frontier.md` scores 8 of 9 workspace
  configurations as dominated on the attention axis alone. Without this column the
  two live rows are two-axis numbers that our own frontier files say are not
  decidable on two axes. It also hides our best measured operating point, 0.0% ASR
  at 100% clean utility for 1.50 interruptions per task on workspace.

---

## 4. What the table omits that a reviewer would demand

**A table with no content-harm row is not a fair summary of this system.** It is
the single largest structural distortion in the draft.

The repository measures harm along six axes and prints them as such in
`benchmarks/results/deputy.md`: target, volume, sequence, content, principal, and
idempotence. The draft table covers target across four separate rows, volume and
sequence in one row, and nothing else. Content is the axis we are weakest on and
it has no row. Principal and idempotence are the two strongest results and they
have no rows either.

The specific numbers a reviewer will find within minutes:

1. **Content.** AgentHarm containment is 21.6% (141/652) at HEAD, and the whole
   21.6% sits at the capability-token rung with nothing gained above it. The real
   ceiling is 28.8%, because 464 of 652 attack events carry no pinned destination
   and are undecidable by any target-binding mechanism. `scoreboard.md` at HEAD
   still carries the stale caveat that 6.3% is a loader limit, and 6.3% is now
   exactly what the naive rung scores.
2. **Class mix.** `benchmarks/results/coverage.md` at HEAD partitions attacks
   without consulting any engine: redcode is 717 of 718 surface-leaving, agentharm
   is 611 of 652 in-surface. Every one of the table's high cells is a
   surface-leaving corpus, and no cell tells the reader that. On redcode's single
   in-surface event the ladder is 0.0% at every rung.
3. **Saturated corpora.** ASB (2,040 attack events, 100.0%) and InjecAgent (1,598,
   99.9%) are absent from the table. Their absence is correct, because both are
   contained at the first rung, but the caption must say so or the omission reads
   as selection.
4. **Four rows, one mechanism.** RedCode, the adaptive red-team row, the IPI/ATB
   row and the AgentDojo replay row all rest on the same task-scope path binding
   against the same workspace boundary. That is one piece of evidence presented
   four times, and the table's structure conceals it.
5. **Task type.** The utility cell is an AgentDojo number, and AgentDojo tasks are
   largely specified up front. On AgentDyn, whose tasks require runtime planning,
   plan conformance alone gives 0.0% clean utility on shopping and on github with
   254 of 281 actions blocked. `benchmarks/results/agentdyn.md` says in its own
   words that this refutes any general claim about our utility cost.

An honest table says: we contain target-defined, volume-defined,
sequence-defined, principal-defined and duplicate-defined harm at 95% to 100%,
and we contain content-defined harm at 21.6%, which is where the field is. That
is a stronger paper than one that lists five wins and lets the reviewer discover
the sixth axis.

Two other omissions a reviewer will demand:

- **The only external audit of the confidentiality claim failed.** AgentLeak gives
  50.0% (11/22) for the flow mechanism as shipped, and on 2,000 real messages the
  channel arm reaches precision 0.518 against a corpus leak rate of 0.472, which
  is 4.6 points of lift over blocking everything. Two tests in
  `benchmarks/tests/test_agentleak.py` fail at committed HEAD on exactly this.
- **Blast radius.** Re-measured 2026-08-09, the cliff is at 12 characters, not
  10: every cross-write check in `confidentiality.py` skips a value whose
  compacted length is under `_MIN_RECONSTRUCTED = 12`. A length sweep from 4 to
  15 puts the whole value out at every length through 11 and holds it from 12.
  Split across two writes, an 8-digit account number, a 6-digit one-time code, a
  9-digit national id and an 11-character door code each leave whole in 200 of
  200 tau2 sessions and 171 of 171 BFCL sessions, with the rung below allowing
  every write. A 4-digit PIN, a 6-digit MFA code and a 9-digit SSN all fit inside
  the band. The `100% / 0% FA` cell reads as prevention.

---

## 5. The "Best alternative" column

This column makes claims about other people's systems. Of the 14 cells, **3
figures cite a paper and 1 is a real run of a third-party defense. The other 13
figures are our own code, our own ablations, or unsourced.**

### Sourced to a paper (3)

| figure | source |
| --- | --- |
| ARGUS ~5 pts utility | `INVESTOR_MEMO.md` line 49, arXiv:2605.03378, 92.5 -> 87.5 on AgentLure |
| CaMeL ~7 pts utility | line 52, arXiv:2503.18813, 84 -> 77 on AgentDojo |
| Progent ~19 pts utility | line 50, arXiv:2606.26479. Sourced but contradicted by our own head-to-head, which measures Progent's released code at 12.5 points on gpt-4o-mini |

### A real run of a third-party defense (1)

| figure | note |
| --- | --- |
| AgentDojo built-in `tool_filter` 5.6% | our run, but it is the per-suite minimum of a defense that ranges 5.6% to 33.3% across the four suites (`matrix-oai-4omini/summary.md`), set against a pooled figure of ours |

### Cannot be sourced to a head-to-head we ran or to a paper (13)

| row | figure | what it actually is |
| --- | --- | --- |
| RedCode-Exec | `0% (RBAC / capability token)` | our `CapabilityTokenEngine`, and 0% only because `redcode.py` line 312 assigns every event the single resource `workspace`; 98.7% when the resource names the target |
| AgentDojo (live) | `Progent 11-17%` | no Progent artifact anywhere under `benchmarks/results`; `progent` is not an ablation in `run_matrix.py`. Worse for Progent than the 4.2% our own investor memo cites |
| AgentDojo (replay) | `77.9% below binding` | our own tool-allowlist rung on the 77-task slice |
| IPI / ATB / ... | `0-40% below binding` | the best of our own allowlist and capability-token rungs across four corpora |
| Business-process | `approx 100% viol. (Progent / CaMeL)` | fifteen-line branches we wrote in `bpl_live.py` lines 133 and 146, published under two companies' names. The most exposed cell in the table |
| Burst + flow | `0% (per-call ladder)` | our ladder against an attack our own `attacks.py` synthesises by appending copies of an already-authorized read; the same velocity engine calibrated contains 100% of it |
| SLEIGHT | `approx 6% (n-gram)` | our own detector with the twin reference removed. SLEIGHT-Bench's own published baseline is 32% at 1% FPR |
| Adaptive red-team | `0% (RBAC / capability token)` | ours, and inert by construction: all 500 redcode tasks carry the same 6 capabilities, so a resource:action token has nothing to discriminate |
| Long-horizon | `0-83% (lower rungs)` | matches no measurement. Committed `trajectory.md` gives 0.0 / 0.0 / 72.5 / 75.0; 83.9 is the upper Wilson bound of a 72.5% interval, quoted as a point estimate |
| Cross-session | `session ledger fails` | our own `SessionValueBudget` in `benchmarks/structuring.py` |
| Drift | `rolling 0.5%` | a 55-line benchmark-local monitor over Gaussian draws (`benchmarks/drift.py` lines 39-95) |
| Mandate quality | `47.9% FB on tau2` | our own pre-generalisation number, the "before" column of the table the 0.05% is the "after" column of |
| iVisor + latency | `floor misses BPL; CaMeL minutes` | the floor is our own replay of a collaborator's traces; "minutes" is contradicted by the 14 CaMeL logs on this machine, max 94.6 s |
| ULB / IBM AML | `0.86 AUC` | no source. Repo-wide grep returns the `.tex` itself and one untracked file recording that it has no source |

Two structural problems with the column as a whole. First, a header reading "Best
alternative" beside cells naming Progent and CaMeL makes every ablation in the
column read as a measured competitor. Second, in four rows the figure is not even
the best alternative by our own files: `notes/above_sota.md` line 12 puts the
injection field at ARGUS 3.8%, Progent 4.2% under independent reproduction, and
CaMeL near zero, and `benchmarks/results/head_to_head_injection.md` states that we
do not claim to out-secure CaMeL on injection.

The fix is to rename the column and to mark provenance in every cell. Anything
that is our own ladder must say so in the cell, not in a caption.

---

## 6. Corrected table

Same format as `_results_table_draft.tex`. Every cell below is a figure I
read at HEAD or produced in the clean worktree. Rows the audit could not support
in any form are absent, and the caption says which and why.

```latex
\documentclass[11pt]{article}
\usepackage[margin=0.5in]{geometry}
\usepackage{booktabs}
\usepackage{array}
\usepackage{microtype}
\usepackage[T1]{fontenc}

\newcolumntype{B}[1]{>{\bfseries\raggedright\arraybackslash}p{#1}}
\newcolumntype{I}[1]{>{\itshape\raggedright\arraybackslash}p{#1}}
\newcolumntype{P}[1]{>{\raggedright\arraybackslash}p{#1}}
\newcolumntype{R}[1]{>{\bfseries\raggedright\arraybackslash}p{#1}}

\begin{document}
\pagestyle{empty}

\noindent
\begin{center}
{\scriptsize
\begin{tabular}{@{} B{2.7cm} I{3.2cm} P{4.6cm} R{5.0cm} @{}}
\toprule
\normalfont\bfseries Benchmark
  & \normalfont\bfseries What it isolates
  & \normalfont\bfseries Baseline (source marked)
  & \normalfont\bfseries Ours (containment / friction) \\
\midrule
\multicolumn{4}{@{}l}{\itshape Target-defined harm} \\
RedCode-Exec\footnotemark[1]
  & granted tool, ungranted target
  & our ladder: tool-name RBAC 0/718; capability token 0/718 coarse, 709/718 target-named
  & 95.6\% (717/750); 99.9\% on the 718 parseable cases \\
AgentDojo (replay, 465)
  & injection / arg swap on traces
  & 77.8\% at the rungs below binding (our ladder)
  & 95.6\%; FB 0.0\% \\
AgentThreatBench\footnotemark[2]
  & corpus-named recipient vs corpus-named allow list
  & 0/6 below binding (our ladder)
  & 100\% (6/6), CI [50, 100]; FB 0.0\% \\
Mind2Web-SC
  & composite rule over the principal's attested attributes
  & 0.0\% (tool allowlist, our ladder)
  & 98.0\%; FB 1.00\%, $n=$100a/100b\footnotemark[3] \\
\midrule
\multicolumn{4}{@{}l}{\itshape Volume, sequence, principal, state, duplicate} \\
Burst + flow
  & authorized bursts; single-write leaks
  & 0\% across the per-call ladder (our ladder)
  & burst 100\% at burst${\ge}$10, FA 0.0\% $\tau^2$ / 2.0\% BFCL; flow 200/200 single-write leak sessions, FB 0.00\% (0/1{,}230); chunked leaks NOT contained, 84/200 out at 22 fragments\footnotemark[4] \\
Long-horizon
  & one buried attack action per session
  & 0\% allowlist; 88--100\% capability token (our ladder, seed-dependent)
  & 100\% (40/40) at 4 seeds, flat from 10 to 2{,}000 actions\footnotemark[5] \\
Delegation (deputy)
  & same action, principal swapped
  & 0 blocked in all four cells (our ladder)
  & 100\% at attacker's best of 13 strategies; rightful holder allowed 100\%; held-out FB 0.00\% \\
Observation freshness
  & byte-identical action, world moved
  & 0 blocked of 232 (our ladder)
  & 100\% on 4 arms; FB 0.00\% (0/1{,}254); $+1.8\%$ tool calls \\
Idempotence
  & the same authorized action sent twice
  & 0 / 2{,}412, whole per-call ladder (our ladder)
  & replay refused 100\% (400/400); legitimate repeat allowed 100\%\footnotemark[6] \\
Cross-session structuring
  & 40k split against a 10k ceiling
  & 100\% violation, Progent and CaMeL \emph{reproductions we wrote}, $n=20$/scenario
  & 0\% violation; progress 61\% / 40\%; 2.2 / 3.0 interruptions per episode\footnotemark[7] \\
Re-identification
  & granted reads assembling a person
  & 0 of 870 (our ladder)
  & 100\% (145/145); 35.7 escalations per 100 QI sessions\footnotemark[8] \\
\midrule
\multicolumn{4}{@{}l}{\itshape Content-defined harm: the axis nobody contains} \\
AgentHarm
  & harm is in what the action says
  & Opus 4.6 monitor, extended thinking, 32\% at 1\% FPR on SLEIGHT (published)
  & 21.6\% (141/652); ceiling 28.8\%; held-out FB 57.73\% \\
\midrule
\multicolumn{4}{@{}l}{\itshape Cost} \\
Mandate quality
  & incomplete grant, held-out FB
  & no published comparable
  & AgentHarm 58.4\% $\to$ 1.8\% FB (seeds 0--4, range 0.6--2.5)\footnotemark[9] \\
Utility cost
  & clean-task cost, paired, deployable arm
  & ARGUS 5\,pts (2605.03378); CaMeL 7\,pts (2503.18813); Progent 12.5\,pts (our run of their code)
  & 18.8\,pts grok-4-1-fast; 21.9\,pts pooled, 96 paired clean tasks\footnotemark[10] \\
Attention
  & interruptions the protocol costs a human
  & 0 for undefended and for both BPL reproductions
  & 1.50 / task on workspace at 0.0\% ASR and 100\% clean utility \\
Enforcement cost
  & per-decision latency, replay path
  & no comparable per-decision figure published
  & p50 19.7--22.3\,$\mu$s; p99 188--264\,$\mu$s\footnotemark[11] \\
\bottomrule
\end{tabular}
}
\end{center}

\footnotetext[1]{718 of 750 parseable-target cases across 14 of RedCode-Exec's 27
risk indexes; the loader drops 32 cases whose target its regex cannot parse, which
are exactly the cases where the mechanism would have had no input, so 95.6\%
counts them as misses. No false-block figure is quoted for this row: 0 of 344
benign events lie outside the grant, so 0.00\% would be arithmetic.}
\footnotetext[2]{\texttt{data\_exfil} only. \texttt{memory\_poison} and
\texttt{autonomy\_hijack} are content-defined and contribute no attack events.}
\footnotetext[3]{Quotable only with resources declared exact: at the first level of
grant generalisation this containment falls from 98.0\% to 0.0\%. Oracle ceiling
using the corpus's own violation field is 100.0\%, reported here as a ceiling and
never as the result.}
\footnotetext[4]{The BFCL in-scope-burst detector is excluded from this row. Its
published 100\% / 0\% FA is measured on a 1{,}200-task slice in which every benign
session is one call; a held-out benign session that repeats its own authorized read
three times is blocked 100\% of the time. Blast radius is roughly 12 characters, so
a secret of 10 characters or fewer leaves whole. AgentLeak, the only external audit
of this mechanism, scores it 50.0\% (11/22).}
\footnotetext[5]{35 of 40 detections come from the capability rung, 4 from argument
binding, 1 from a protected zone, 0 from path scope. False alarms are 0 only
against the granted mandate, which on BFCL is the benign side restated; the
held-out figure is 18.04\%. When the needle carries the session's own verb and args
and only the target is wrong, detection is 2\%.}
\footnotetext[6]{Single-process replay. The cross-instance arm refuses 0/400 under
the in-memory development store; the production path fails closed and Redis and
DynamoDB stores ship.}
\footnotetext[7]{Both baseline figures are reproductions we wrote inside
\texttt{benchmarks/live/bpl\_live.py}, grounded in the published mechanisms.
Neither system's own code was run. The principal-keyed ledger is unit-tested but
not yet called by the shipping broker, which still enforces the session-scoped
budget.}
\footnotetext[8]{2.4\% of all benign sessions and 35.7\% of quasi-identifier
sessions escalate. Evasions that score 0\%: split-unlinked, undeclared schema,
coarsen-below-threshold.}
\footnotetext[9]{Ships as a measured transform with a per-dimension level in the
mandate, never as a default. The same setting collapses Mind2Web-SC containment
from 98.0\% to 0.0\% and RedCode from 99.9\% to 33.3\% on the path dimension, and is
inert on six attack-only corpora.}
\footnotetext[10]{\texttt{envelope-taint}, the same arm every security row reports.
$n=32$ per model, task-binary scoring, so nothing here resolves a difference below
about 25 points. AgentDojo tasks are largely specified up front; on AgentDyn, whose
tasks require runtime planning, plan conformance alone gives 0.0\% clean utility on
two suites.}
\footnotetext[11]{Replay decision path, not an inline syscall filter, and two rungs
below the shipped full stack. The velocity rung adds 24--27\,$\mu$s p50 and the
delegation rung has no latency measurement.}

\end{document}
```

### Rows deliberately absent, and why

- **AgentDojo (live).** The 216 recorded runs were produced by a taint rule
  deleted from HEAD in commit `721a8bb`. Nothing has re-measured the live ASR
  since. Re-run before publishing anything on this axis.
- **SLEIGHT (twins).** 94 of the 98 points come from a paired clean run of the
  same task, which no deployment has. The commit-then-reveal replacement is
  untracked in the working tree and is not backed by any committed measurement.
- **Adaptive red-team.** Deny-all ties task-scope at 100.0% on all four objectives
  at all three knowledge levels, and the tier has no benign arm.
- **IPI, AdvBench, MCP, ToolEmu.** ToolEmu contributes 0 attack events. IPI's
  attack targets are four hardcoded strings. MCP and AdvBench are fixtures we
  wrote, at n=5 and n=6.
- **Business-process live as a competitor claim.** Both competitor branches are
  ours, and the ceiling enforced is the same Python variable as the ceiling scored.
- **Cross-session drift.** No anchored monitor exists in `agentauth/`; the 82% is
  the tail probability of a chosen threshold at a chosen target, over Gaussian
  draws with no agent in the loop.
- **ULB / IBM AML.** The baseline is unsourced and the shipped sensor is beaten by
  a label-free rung beneath it on the same fit.
- **ASB and InjecAgent.** 100.0% and 99.9% over 3,638 attack events, both reached
  at the first rung. Excluded because the number belongs to the tool allowlist.
  This must be stated in the caption or the omission reads as selection.

### Files to fix before the table goes out

At HEAD the internal ledger no longer reproduces from the code beside it. A
reviewer who runs the repo finds this in minutes.

- `benchmarks/results/scoreboard.md`: `sleight[detector] 27.8%` where HEAD prints
  94.4% with the corridor, and an AgentHarm caveat that still calls 6.3% a loader
  limit when the number is 21.6%.
- `benchmarks/results/scoreboard.json`: 5.6% for the same SLEIGHT tier that
  `scoreboard.md` puts at 27.8%.
- `benchmarks/results/flow.md`: FIXED 2026-08-09. The file was rewritten from a
  full re-measurement. Real-traffic false block is 0.00% (0/1,230 sink writes and
  0/1,242 all benign events) on tau2 and 0.00% (0/691 and 0/1,044) on BFCL, and
  the file now carries the splitting, concurrency, composed and padding arms that
  the single number hid.
- `benchmarks/results/structuring.md`: the detection sub-table and the prose around
  it both name the wrong counts against the current run.
- `benchmarks/results/agentharm_ceiling.md`: asserts a 6.3% to 11.1% ceiling; the
  measured ceiling is 28.8%.
- `benchmarks/results/pooled_asr.md` line 45: states that envelope-taint costs 3
  points on grok-4-1-fast, contradicted by its own `live_ladder.md` table and by a
  per-task recount, which give 18.8.
- `benchmarks/results/redcode.md`: cited by the loader docstring as where the
  resource/logic split and the drop count live. The file does not exist.
- `benchmarks/tests/test_agentleak.py`: two tests fail at committed HEAD.
