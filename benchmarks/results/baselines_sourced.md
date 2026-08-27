# Published baselines, sourced

Every figure here was read from the paper or from one of our own results files.
Nothing is estimated. Where a cell is still unsourced it says so, because a
mis-attributed competitor number is worse than a missing one.

## Latency, per action

This is the comparison the sandbox row needs, and it is much stronger than the
"CaMeL minutes" claim it replaces. Membrane Table 5 measures per-query defense
overhead in seconds, averaged over seven evaluation settings.

| system | mean | p95 | source |
| --- | --: | --: | --- |
| SmoothLLM | 156.93 s | 248.20 s | Membrane Table 5 |
| AGrail | 25.22 s | 31.13 s | Membrane Table 5 |
| GuardAgent | 5.94 s | 10.52 s | Membrane Table 5 |
| MEMBRANE lite | 2.43 s | 3.85 s | Membrane Table 5 |
| CaMeL | not reported as wall clock | | CaMeL section 6.5 |
| **ours, `broker.authorize`, model-free** | **94 us** | **145 us** | `full_stack_benchmark.md` |

Ours is 63,000 times faster than GuardAgent and 268,000 times faster than
AGrail. That is the claim the sandbox row should make.

**"CaMeL minutes" must be removed.** CaMeL section 6.5 says the opposite:
"CaMeL is designed to be lightweight and efficient, focusing on tracking data
provenance and enforcing security policies without significant computational
overhead". They report a token increase, not a wall-clock cost. Publishing a
latency claim that the cited paper contradicts is the most attackable thing in
the table.

### Our own latency, which needs one number rather than four

| file | number | what it measures |
| --- | --: | --- |
| `latency_redcode.md` | 18.9 us p50, 180.8 us p99 | the deterministic replay ENGINE `decide()` |
| `full_stack_benchmark.md` | 94 us median, 145 us p95 | `broker.authorize`, the full live stack |
| `head_to_head_injection.md` | ~200 us | the same broker, quoted loosely |

The table currently says ~20 us, which is the replay engine and not the broker
the live results run through. **94 us is the defensible number.** It is still
five orders of magnitude below every published guardrail, so nothing is lost by
quoting the honest one.

### The syscall half of that row

8/8 is a REPLAY of captured iVisor fd-3 traces, not a live sandbox run, and
`syscall_tier.md` says so. Two of the eight (05-host-escape, 06-audit-evasion)
pass with `ivisor_denies=0, clay_denies=0` because they are non-events on fd-3
by design. So the honest cell is 6/8 contained plus 2 documented non-events, or
8/8 with "trace replay" attached.

For the syscall mechanism itself the comparator is gVisor, whose systrap
platform costs roughly 2.2x native on simple syscalls. That is a different
mechanism from a policy decision and should not be put in the same cell.

## Security baselines by row

### Sourced and materially different from what the table credits

| row | table says | published | source |
| --- | --- | --- | --- |
| AgentDojo (live) | Progent 11-17% | **CaMeL: 0 successful attacks of 949**, every suite. Tool Filter 8, Spotlighting 5, Prompt Sandwiching 24, undefended 44 | CaMeL Table 7 |
| SLEIGHT (twins) | ~6% (n-gram) | **32% catch rate at 1% FPR**, Opus 4.6 monitor with extended thinking | SLEIGHT-Bench |
| Mind2Web-SC | 0% at tool-allowlist | **AGrail 98.4 F1** (GPT-4o); GuardAgent 89.0; AgentMonitor 68.9; LLaMA-Guard3 23.0 | AGrail Table 2 |
| Utility cost | CaMeL ~7 | Confirmed: 77% task completion against 84% undefended | CaMeL |

CaMeL reaching 0/949 on AgentDojo is the single most important correction. Our
differentiators against it are utility cost, 3 points against their 7, and the
composite class, where our own head-to-head puts CaMeL at 100% violation on all
four aggregate-budget scenarios because its dataflow gate never fires on a task
the trusted prompt fully specifies.

### Sourced and the low number is genuinely theirs

| row | published | source |
| --- | --- | --- |
| AgentLeak | **0% on internal channels** across eight defense configurations including LLaMA-Guard and PromptGuard. Best is 98% on the final output only. Tool-argument leakage 62-86% across five production models | AgentLeak Table IX, Finding 7 |

### Defensible as an absence, not as a percentage

Burst, flow, cross-session structuring and the aggregate-budget rows have no
published competitor because no published agent-security system carries
cumulative state over effects.

- **Progent** enforces a per-call, per-argument JSON schema with no cross-call
  state, verified in its source at `secagent/policy_type_check.py`.
- **CaMeL** gates dataflow, so on a task fully specified by the trusted prompt
  the gate never fires.
- **Gateway budgets** (LiteLLM and similar) do carry cumulative state, but they
  meter TOKENS AND DOLLARS PER API KEY, not the agent's effects. A ceiling on
  spend with the model provider does not bound how much money the agent moves.

That distinction is what the cell should say. Written as an absence it is a
stronger claim than a low percentage and it cannot be attacked as a strawman.

## Still unsourced. Do not publish these.

| row | cell | status |
| --- | --- | --- |
| RedCode-Exec | 0% (RBAC / capability token) | search indicates hierarchical guardrails cut ASR to 23.4%, so roughly 76.6% containment. Paper not confirmed |
| IPI / ATB / AdvBench / MCP / ToolEmu | 0-40% below binding | our own rungs. No published defense found on these exact corpora. Note the row still names ToolEmu, which contributes zero attack events |
| ULB / IBM AML | 0.86 AUC | no source. Fraud detection has a large literature and an unsourced AUC is trivially challenged |
| Utility cost | ARGUS ~5 | no source found |
| Mandate quality | 47.9% FB on tau2 | this is OUR OWN held-out false block before pattern generalisation. It is not an alternative system |
| Adaptive red-team | 0% (RBAC / capability token) | our own rungs, and the adversary is ours |
| Long-horizon | 0-83% (lower rungs) | the cell already admits these are our rungs |

## Sources

- CaMeL, Defeating Prompt Injections by Design, arXiv:2503.18813
- SLEIGHT-Bench, A Benchmark of Evasion Attacks Against Agent Monitors, arXiv:2605.16626
- AGrail, A Lifelong Agent Guardrail, ACL 2025 long 399
- GuardAgent, arXiv:2406.09187, ICML 2025
- AgentLeak, arXiv:2602.11510, IEEE Access 2026
- Membrane, A Self-Evolving Contrastive Safety Memory for LLM Agent Defense, arXiv:2606.05743

## The five rows whose baseline was our own ladder

Audited 2026-08-09, adversarially against our own table. Every figure below was
read in a paper, a repository or one of our results files, with table number or
file line given. Four of the five rows lose to a published system on a
comparable measurement. One survives, as an absence and not as a win.

### 1. The rows we lose

#### 1.1 ULB / IBM AML (drafted baseline "0.86 AUC", ours 0.914 and 15/15)

**We lose the ULB half to nine published methods measured in our exact
protocol, including a plain KNN.** Kurtosis-Guided DSM (arXiv:2605.06955)
trains on a random 50% subset of normal samples only and tests on held-out
normals plus all anomalies (lines 453-454), which is our setup, not ADBench's.
Table 13, `fraud` row: KNN 0.956, DDAE 0.955, ICL 0.950, MSM 0.949, K-DSM
0.945, LOF 0.945, DTE 0.944, SLAD 0.944, DSM 0.942. Unsupervised ceiling on the
same dataset is higher still: Table 7 gives DSM-EMA 0.961, DDAE-EMA 0.958, MCD
0.957. ADBench (arXiv:2206.09426) Table D4 best unsupervised is SOD 94.97,
Table D18 best label-informed is XGB 96.41. AUCPR ceilings: 0.697 K-DSM-EMA
(Table 6) unsupervised, 0.625 DTE (Table 12) semi-supervised, 62.77 RF (ADBench
Table D19) label-informed. We report no AUCPR anywhere.

Our ULB headline at `benchmarks/results/aml_validation.md:11` is single-seed.
Rerunning `evaluate(seed=0..4)` gives 0.9140, 0.9219, 0.8982, 0.8942, 0.9108,
so the honest headline is 0.908 +/- 0.011 and the gap widens against every
comparator. ROC-AUC is prevalence-invariant under the uniform 15% negative
subsample at `benchmarks/fraud_validation.py:43`, so subsampling does not
rescue the number. The drafted 0.86 baseline has no source and sits below 9 of
ADBench's 14 unsupervised methods, so it is a strawman on its face.

The IBM AML half also loses, and by more than the prior pass reported. FraudGT
(ICAIF 2024) Table 2 gives PE-FraudGT 76.41 +/- 1.45 and Multi-FraudGT 76.13
+/- 0.95 minority-class F1 on HI-Small. MEGA-GNN (arXiv:2412.00241) Table 2
gives MEGA-GenAgg 74.88 +/- 0.38. Egressy AAAI 2024 Table 2 Multi-PNA+EU 68.16
+/- 2.65 is third tier. On our own claimed typology, Egressy Table 13 (HI-Small,
ground-truth pattern labels) fan-out recall is Multi-GIN+EU 95.42, Multi-PNA
93.13, +Ports 91.60.

**Verdict: withdraw the row.** If it is retained the baseline cell must carry
0.956 for ULB and 76.41 for HI-Small, and the Ours cell must carry 0.908 +/-
0.011.

#### 1.2 Burst + flow + BFCL detector (drafted "100% / 0% FA")

**We lose, and the first refutation is our own data.** The draft cell rested on
a version of `benchmarks/results/flow.md` that predated both `benchmarks/flow.py`
and `clayseal/capabilities/confidentiality.py`. That file tested 8 evasion
shapes and 2 split families. It has since been rewritten from a full
re-measurement and now agrees with the runs below; the counts here stand.
The current runs test 22 evasion shapes and 7 split families and disagree with
the draft cell.
`flow_tau2.json` (200 sessions) whole-value-out counts at k=2/4/11/22
fragments: chunked 0/0/9/84, fan-out 0/0/7/81, shuffled 0/4/84/162, reversed
0/5/84/93, concurrent chunked 0/0/42/161. `flow_bfcl.json` (171
sessions) is worse: chunked 0/4/75/122, shuffled 7/37/107/167. Shuffled at k=22
on bfcl is 167 of 171 leaked, 2.3% contained. Three evasion shapes fail:
caesar+1 contained 0.0 and digit-arithmetic+1 contained 0.0 (both keyed), and
base85 contained 0.735 on tau2 and 0.7719 on bfcl and NOT keyed, so base85 is a
plain miss. Two arms `flow.py` does not run are worse still, from
`benchmarks/flow_probes.py`: two writes with 300 characters of prose in each
walk the whole value out 200/200 on tau2 and 171/171 on bfcl, and a value of 11
characters or fewer has no cross-write check at all. The 0% false-alarm claim is
already false on bfcl:
`burst_bfcl.json` reports `false_alarm_rate` 0.0199 at every row.
`benchmarks/tests/test_flow_invariants.py` reruns at working-tree HEAD as 2
failed, 16 passed, failing
`test_the_false_block_rate_does_not_grow_with_session_length` on both bfcl
cases.

The strongest published system is **Praetor** (arXiv:2604.26274v1), which
compiles verified benign tool-call telemetry into a parameterized DFA and names
its target class "context-sequential injection attacks, wherein an adversary
navigates through individually benign, syntactically valid tool calls to achieve
a malicious objective". That is our in-scope-burst class defined verbatim.
Table 3 on Agent Security Bench (arXiv:2410.02644, ICLR 2025): Praetor
Multi-Step Exfiltration ASR 0.0%, overall 2.2%, against Aegis 35.0 / 12.8 and
PromptArmor 75.0 / 32.9 and no firewall 89.5 / 79.0. Table 4, context-sequential
payloads over 200 attempts: Praetor 0.0 and 0.7 at 500 traces, 0.0 and 0.0 at
5k traces, against Aegis 75.0 and no firewall 94.0. Splicing experiment: of
1,000 multi-step exfiltration payloads, 14 matched benign structural paths and 0
achieved a meaningful objective, 95% CI [0%, 23.2%]. Benign task failure rate
2.0% at default theta=3, 0.2% once long-tail paths are discovered, 2.0 ms per
call. Our detector on tau2 is 66.7% containment at 5.4% false-block
(`detector.md:47-51`). Praetor beats us on both axes and its BTFR denominator
is stricter than our per-event false-block rate, so the gap is understated.

Two architectural refutations of the "no per-call layer can see a value split
across writes" premise, both stronger than CaMeL. **ChainCaps**
(arXiv:2605.26542) is an MCP proxy that maintains an online dataflow DAG and
computes `B_agg = B_ctx` intersected over all argument dependencies, then
propagates `B(y) = Pass(t) ∩ B_agg` on the response path, so every fragment of a
split secret inherits the source budget by construction. Table 1, 82 tasks over
3 runs: ASR falls from 67.8/25.2/31.5/53.6/53.0% to 4.8/3.6/3.6/2.4/0.0% with
benign completion 100/100/96/100/96%. **FIDES** (arXiv:2505.23643, Microsoft
Research) attaches confidentiality and integrity labels to every piece of
content and enforces before a sensitive tool runs. It ships in the Microsoft
Agent Framework security module and in GitHub Copilot CLI, so a reviewer who
knows it will not accept a cell asserting the class is undefended.

DLP for the prose only, never the cell: ibHH (arXiv:2307.02614) Table V detects
FrameworkPOS, which splits card numbers one per DNS query, at TPR 1.0 and FPR
0.0038.

Checked and excluded as comparators: TraceAegis (arXiv:2510.11203) reports
detection F1 with no burst or chunked class; AgentWall (arXiv:2605.16265) Table
1 is 15 policy unit tests; PAuth (arXiv:2603.17170) contains no instance of
chunk, split, fragment, burst, aggregate, cumulative or quota anywhere in its
text.

**Verdict: do not publish the current cell.** Rerun the row against the current
flow harness, then publish per split family with the fragment count named.

#### 1.3 Mandate quality (drafted "47.9% FB", ours 0.05%)

**We lose the friction axis on AgentDojo and we cannot claim it on AgentDyn.**
The strongest comparator is AgentDyn (arXiv:2602.03117), which our own
repository already cites and whose logs we already ship. Table 3, GPT-4o, benign
utility with no attack: no defense 53.33, Tool Filter 8.33, CaMeL 0.00, Progent
6.67, DRIFT 30.00. Tool Filter is an incomplete tool grant fixed from the
initial task description, and the paper's diagnosis is ours word for word:
"during initial planning, the tool filter usually blocks essential tools
required for later dynamic interactions because they appear unnecessary for the
original user task". Aggregating the released per-task logs on
`gpt-4o-mini-2024-07-18`, our exact model, over 20 open-ended tasks per suite
(shopping/github/dailylife): undefended 35/65/40%, tool_filter 0/10/10, CaMeL
0/0/0, Progent 0/15/5, DRIFT 10/35/10, PIGuard 20/20/10.

Second: Permission Denied (arXiv:2608.02670) Table 3, Terminal-Bench 2.1 under
a fixed 205-domain egress allowlist deliberately not fitted to the tasks,
72.5% to 65.1% success on the 82 solvable-witness tasks over 2,952 runs per
condition, 7 of 89 unsolvable, 51.6% of 764 trials blocked on the affected
subset, and up to 18.3 points of loss per bundle. Third: Progent
(arXiv:2504.11703v2) Table 1, AgentDojo no-attack utility 79.38% undefended
against 80.41% with Progent, and Table 3 Progent-LLM 76.29% from a policy
generated out of the user query alone at 1.02% ASR. Fourth: GuardianAgentBench
(arXiv:2607.20982v1) Table 7, 2 of 429 originally-passing scenarios blocked,
0.5%. Fifth, the only published number strictly better than our 0.05%:
"Provably Secure Agent Guardrail" (arXiv:2605.29251) claims zero attack success
and zero false positive rate, on a denominator of 30 compliant requests.

Two systems a reviewer will propose that do not measure this axis. RTBAS
(arXiv:2502.08966) reports 10% and 7.4% no-attack utility degradation on
AgentDojo for its two screeners (section 8.1.2), carries no grant and never
tests partial observation. AC4A (arXiv:2603.20933) is demonstrated on one
flight-booking task with no over-denial rate at all.

Corrections carried forward. AGrail Table 1 Safe-OS Norm is 95.6 for AGrail on
both backbones, 100 for LLaMA-Guard 3, 100 for AgentMonitor, and GuardAgent is
absent from Safe-OS. The 49.2% figure exists only in section 6.1 prose and
reconciles with no cell in Table 1, so do not publish "LLaMA-Guard blocks up to
49.2% of benign actions" as a table figure. Policy-mining context: DLBAC
(CODASPY 2022) reports held-out TPR of 0.2 to 0.85 on Rhapsody and 0 to 0.25 on
XuStoller, and Unicorn (CCS 2019) attributes low ABAC TPR to logs containing
only 7% of possible requests. That literature makes 47.91% unremarkable, which
argues against dramatising the before number.

**Verdict: publish with the concession in the cell.** See section 2 for why the
0.05% is not a comparison.

#### 1.4 Cross-session + drift (drafted "session ledger fails; rolling 0.5%")

**We lose, and "session ledger fails" is refuted in print.** CSTM-Bench
(arXiv:2604.21131) Table 15: the per-session judge scores Det. Rate 1.000 on the
dilution shard, 26 of 26 attack scenarios in isolation. It falls to 0.538 (14 of
26) only on the cross-session shard and only after a closed-loop adversarial
rewriter has been run against it, at FPR_hard 0.643. The Coreset Memory Reader
at K=50 holds 19 of 26 on the cross-session shard at FPR_hard 0.214, and the
Full-Log Correlator holds 13 of 26. A flat "session ledger fails" cell is
overturned by one search. Second on this axis: SLEIGHT-Bench (arXiv:2605.16626)
Table 1 multi-session row, 3 of 10 caught at 1% FPR.

ANTIDOTE (Rubinstein et al., IMC 2009) is verified but is not a system that
beats us, because it measures a different quantity. PCA baseline FNR 3.67%,
Boiling Frog at g=1.15 raises FNR above 70% over 3 weeks with chaff rejection
pinned near a constant 5% so the poisoning is invisible, and the robust defense
keeps evasion below 20% after 10 training periods. That is evasion success under
poisoning on 144 real Abilene OD flows, not alarm rate at an objective, so it
belongs in the prose. Counter-result: "Can't Boil This Frog"
(arXiv:2002.02741) finds an online-trained autoencoder on SWaT resilient to all
ten relevant poisoning attacks, so "rolling monitors get retrained by the
attacker" is detector-dependent and must not be stated as general.

**This row also breaks the absence claim recorded above at "Defensible as an
absence".** Agent Behavioral Contracts (arXiv:2602.22302) is a runtime
enforcement framework whose governance policies include spending limits and
whose drift bounds are enforced across extended sessions. It is evaluated on
AgentContract-Bench over 1,980 sessions with 7 models from 6 vendors and reports
88-100% hard constraint compliance, drift bounded to D* < 0.27, and under 10 ms
per check. Its section 2.2 further characterizes Ye and Tan 2026 "Agent
Contracts" as formalizing multi-dimensional cost budgets over delegation
hierarchies with conservation laws. That characterization was read inside ABC,
not in Ye and Tan directly, so treat it as a lead. Either way, the sentence "no
published agent-security system carries cumulative state over effects" is now
challengeable and must be narrowed to effect-denominated ledgers that survive
adversarial rewriting, or dropped.

**Verdict: do not publish the current cell.**

### 2. The rows that are not comparisons

These are not losses. They are measurements of a different task on the same
data, and the cell has to say so or the reader will assume a head-to-head.

**IBM AML, our 15 of 15.** Ours is account-level typology flagging. Every
published number on HI-Small is transaction-level classification on a 60-20-20
temporal split (Altman line 418, Egressy lines 273-276). Worse, the denominator
is defined by the feature being scored: `aml_sequence_validation.py:86` computes
`legit_fanout_max` from the data, `:88` defines the denominator as laundering
accounts whose fan_out exceeds it, and `:92` counts those clearing a 1%-FPR
threshold on `peer_z_score` over {velocity, fan_out}. With legitimate fan-out
capped at 36 and laundering hubs at 500 to 14,000 the outcome is effectively
determined by construction, on n=15. Our own file concedes at
`aml_validation.md:31` that a naive AUC over every labeled account is about
0.55. The IBM AML data is absent on this machine, so 15/15 could not be
reproduced.

**Mandate quality, our 0.05%.** tau2 is a purely benign corpus.
`benchmarks/datasets/tau2.py` builds every task through `benign_task_from_calls`
and never emits an attack event, which is why tau2 appears in no containment
table in `generalisation.md`. The loader docstring states that every task in a
domain shares the same tool surface. The level-3 pattern that produces 0.05% is
defined at `benchmarks/core/patterns.py:23-26` as the goal bucket's own surface
learned from other clean sessions, which is the domain's entire closed catalog.
So the mechanism is to grant the whole closed catalog and then measure false
blocks against held-out events drawn from that same catalog. The number is close
to arithmetically forced by the loader, and the safety price cannot be measured
on this corpus at all. Where it can be priced, the same setting zeroes
Mind2Web-SC containment, 98.0% to 0.0% (`generalisation.md:48-55`). A reviewer
who opens `tau2.py` overturns the cell in one file. Denominators do not line up
either: ours is per benign event in deterministic replay (7,143 false blocks),
AgentDyn and Progent are per task success with a live agent, Permission Denied
is per task success and per trial, GuardianAgentBench is per scenario over 429.

**Cross-session structuring, our "holds".** `structuring.py` line 50 calls its
attacker deliberately the dumbest possible. `structure()` splits a total evenly
across N sessions, and a ledger keyed to the principal contains that by
definition. There is no error rate, no benign denominator, no confidence
interval. The detection sub-table is n=5 patterns, 3 of them benign, against
CSTM-Bench's 28 benign scenarios with reported FPR. "Holds" is not a number.
Both halves of the drift cell are also ours: `benchmarks/drift.py` names rolling
and anchored as the same `Monitor` class differing only in whether `window` is
None, the stream is `rng.gauss` synthetic Gaussian with no agent traffic, one
seed, and the 82.1% has no false-alarm counterpart because nothing in the
benchmark exercises legitimate business growth.

**Burst and flow, Praetor.** Praetor is on ASB, not tau2 or BFCL, and its
denominator is per attack attempt while ours is per session whole-value-out. The
cells are not like for like. The comparison still lands, because its
context-sequential class is defined identically to our in-scope-burst, its BTFR
denominator is stricter than ours, and its own structured-to-open-ended
degradation (2.2% overall on structured scenarios, 8.6% on Travel Planner,
12.6% on Research Agent) mirrors our bfcl-versus-tau2 gap. The mismatch cuts
both ways rather than in our favour.

### 3. The row where the absence is real

**Long-horizon needle in the session's own tool.** No published system reports
100% detection at zero false alarms on a comparable long-session enforcement
task. Our checked-in numbers are 100.0% [98.1, 100.0] at 0.00 false alarms per
1k over 200 sessions of 500 benign actions (`rigor_pass.md:186-192`), with the
rung table tool-allowlist 0.0% [0.0, 1.9], capability-token 82.0% [76.1, 86.7],
task-scope 83.0% [77.2, 87.6], task-scope+binding 100.0%. The 40-session run in
`trajectory.md` agrees. **The row as drafted says "ours 95%". No 95% figure for
this tier exists anywhere in the results tree. Publish 100% or rerun.**

Searches that justify the absence: "runtime enforcement LLM agent long-horizon
trajectory 500 steps policy violation detection benchmark 2026" returned VIGIL
(arXiv:2606.26524), StepShield (arXiv:2601.22136), TRACE (arXiv:2606.00611),
ProbGuard (arXiv:2508.00500), DreamGuard (arXiv:2608.05695), AgentSpec
(arXiv:2503.18666, ICSE 2026), The Verifier Tax (arXiv:2603.19328). "agent
guardrail 100% detection zero false positives long session thousands of steps
needle injected tool call benchmark" returned LlamaFirewall (arXiv:2505.03574),
GuardianAgentBench (arXiv:2607.20982), OpenClaw PRISM (arXiv:2603.11853). None
evaluates a session longer than roughly 25 turns.

The two systems a reviewer will name, and why neither measures this.

- **VIGIL** (arXiv:2606.26524) is the closest framing, runtime enforcement of a
  declared behavioral specification against the actual execution trace. Table 1
  on SkillsBench + Skill-Inject, 152 tests: 69 TP, 8 FP, 89.6% precision, 95.8%
  recall, 92.6% F1, which is 69 of 72 violating executions caught with 8 false
  positives on 80 benign runs, FPR 10.0%. On AgentDojo 89.5 / 99.3 / 94.2, on
  SafeAgentBench 98.3 / 94.4 / 96.3. Macro balanced enforcement error 5.4%
  against LLM-as-judge 12.5% and AgentSpec 15.2%. It does not run long sessions:
  its unit is a single skill execution, and its benign denominator is 80 runs.
- **StepShield** (arXiv:2601.22136, NeurIPS 2026) is the closest instrument,
  9,429 incident-grounded code-agent trajectories with step-by-step
  pre-execution monitoring and no look-ahead. Table 2 on the 216-trajectory
  held-out set: LLMJudge Acc 0.95, F1 0.95, EIR3 0.89, FPR 5.6%, Recall 95.4%;
  StaticGuard, an 847-rule pattern guardrail which is what our engine is, Acc
  0.54, F1 0.65, EIR3 0.23, FPR 77.8%, Recall 86.1%. It carries no mandate to
  check against and its trajectories are not long-horizon, but its thesis is a
  published deficiency in our row: a rule guardrail can score high recall while
  firing at random timing (EIR3 0.23 against a 0.24 random baseline, p=0.66),
  and that gap is invisible to accuracy, recall and F1. We report no timing
  metric at all.

VIGIL also supplies published numbers for the real systems our rungs imitate, on
the same 152 cases: Progent 46.0% precision, 55.6% recall, 50.3% F1, with all 47
of its false positives being benign calls its allowlist rejects; AgentSpec 73.9
/ 47.2 / 57.6. Those replace "lower rungs" with named competitors.

The absence is real but the cell must concede the fixture.
`benchmarks/trajectory.py` lines 112-114 fill each session by resampling one
task's benign events with replacement. Measured live:
`get_loader('bfcl').load(limit=300)` yields 300 tasks with exactly 1 benign
event each, and `build_trajectories(length=500, count=200, seed=0)` yields
100,000 benign events with 137 globally distinct actions by (tool_name,
resource, path, args) and exactly 1 distinct action per session. A 500-action
session is one authorized action repeated 500 times plus a needle, and the
Wilson interval that matters is over 137, not 100,000. Lines 116-133 plant the
needle by overwriting a RedCode attack event's tool_name and resource with the
host session's carrier while keeping its path and args, so with a mandate
authorizing exactly one path the task collapses to set membership against a
haystack of size one. Correction to an earlier pass: TraceSafe-Bench Figure 4b
does show models outperforming their baseline at 15+ steps and flat accuracy to
22k characters, but its x-axis tops out near 17.5 steps, so it cannot be cited
for or against a 500-action premise. Nobody has published evidence either way at
our scale.

### 4. Ready-to-paste LaTeX

```latex
% ROW 1. ULB / IBM AML. RECOMMENDATION: WITHDRAW.
% If retained, use exactly these two cells.
ULB / IBM AML
  & peer deviation $+$ fan-out
  & ULB, normals-only training (our protocol): ROC-AUC
    0.956 (KNN), 0.955 (DDAE), 0.950 (ICL)~\cite{kdsm2026},
    Tab.~13; unsup.\ ceiling 0.961~\cite{kdsm2026}, Tab.~7;
    AUCPR ceiling 0.697~\cite{kdsm2026}, Tab.~6.
    IBM AML HI-Small 76.41\% minority-class F1
    (PE-FraudGT)~\cite{fraudgt2024}, Tab.~2; 95.42\%
    edge-level recall on the fan-out pattern
    itself~\cite{egressy2024}, Tab.~13
  & ULB ROC-AUC $0.908 \pm 0.011$ over five seeds (the 0.914
    in our results file is single-seed), below all nine
    published methods in the same protocol; no AUCPR
    reported. IBM AML fan-out separation measured on a
    denominator defined by the scored feature, $n{=}15$;
    full-population figure $\approx$0.55 AUC \\

% ROW 2. BURST + FLOW + DETECTOR. RECOMMENDATION: RERUN BEFORE PUBLISHING.
Burst $+$ flow
  & authorized bursts, single-write leaks
  & Praetor (ASB): 0\% multi-step exfiltration ASR, 0\%
    context-sequential ASR over 200 attempts, at 2.0\%
    benign task failure~\cite{praetor2026}, Tab.~3--4.
    ChainCaps: 67.8\%$\to$4.8\% ASR at 100\% benign
    completion~\cite{chaincaps2026}, Tab.~1
  & burst 100\% at $\geq$5 calls (2.3--6.5\% at 2);
    in-scope-burst 66.7\% ($\tau^2$) to 100\% (BFCL);
    single-write leak 100\% at 0.00\% FB (0/1{,}230 $\tau^2$,
    0/691 BFCL); chunked containment falls with fragment
    count, 100\% at 2 to 58\% ($\tau^2$, 84/200 out) and
    28.7\% (BFCL, 122/171 out) at 22; two padded writes leak
    200/200 and 171/171; values under 12 characters have no
    cross-write check; base85 uncontained at 0.735 \\

% ROW 3. MANDATE QUALITY. RECOMMENDATION: PUBLISH WITH THE CONCESSION.
Mandate quality
  & incomplete grant (held-out FB)
  & AgentDyn open-ended tasks, \texttt{gpt-4o-mini}: a tool
    grant fixed from the initial task keeps 0/10/10\% clean
    utility (shopping/github/dailylife) against 35/65/40\%
    undefended; CaMeL 0/0/0, Progent 0/15/5, DRIFT
    10/35/10~\cite{agentdyn2026}.
    Terminal-Bench 2.1, fixed 205-domain allowlist not
    fitted to the tasks: $-7.4$\,pts success
    (72.5\%$\to$65.1\%), 7/89 unsolvable, 51.6\% of trials
    blocked on the affected subset~\cite{permdenied2026},
    Tab.~3
  & 0.05\% held-out FB on $\tau^2$ (from 47.9\%) at
    tool$+$verb namespace, non-default. $\tau^2$ is
    benign-only and its domains are closed tool surfaces, so
    the namespace level grants the surface the held-out
    events draw from; this corpus cannot price the change.
    Where it can be priced the same setting zeroes
    Mind2Web-SC containment (98.0\%$\to$0.0\%) \\

% ROW 4. LONG-HORIZON. RECOMMENDATION: PUBLISH AT 100\%, NOT 95\%.
Long-horizon
  & needle in the session's own tool
  & VIGIL 95.8\% recall at 10.0\% FPR (SkillsBench$+$
    Skill-Inject, 80 benign runs)~\cite{vigil2026}, Tab.~1;
    StepShield LLMJudge 95.4\% recall at 5.6\% FPR,
    EIR$_3$ 0.89, against an 847-rule guardrail at 86.1\%
    recall and 77.8\% FPR~\cite{stepshield2026}, Tab.~2;
    Progent 55.6\% and AgentSpec 47.2\% recall on the same
    152 cases~\cite{vigil2026}
  & 100\% [98.1, 100.0] over 200 sessions of 500 actions,
    0.00 FA per 1k; but the haystack holds only 137 distinct
    benign actions and 1 per session, and we report no
    intervention-timing metric \\

% ROW 5. CROSS-SESSION + DRIFT. RECOMMENDATION: DO NOT PUBLISH AS DRAFTED.
Cross-session $+$ drift
  & split spend; baseline poison
  & CSTM-Bench: per-session judge 26/26 on dilution, 14/26
    under adversarial rewriting at FPR$_{\text{hard}}$
    0.64; coreset reader $K{=}50$ 19/26 at
    FPR$_{\text{hard}}$ 0.21~\cite{cstm2026}, Tab.~15.
    ANTIDOTE: evasion still $<$20\% after 10 poisoning
    periods, against $>$70\% FNR for
    PCA~\cite{antidote2009}
  & principal-scoped ledger contains by construction, no
    error rate, $n{=}5$ patterns; anchored monitor 82.1\% at
    the objective against 0.5\% rolling, on synthetic
    Gaussian traffic, one seed, false-alarm cost unmeasured \\
```

### Fix before publishing anything from these tables

- `generalisation.md:26` gives AgentHarm held-out FB before as 57.73% while
  `incomplete_mandate.md:11` gives 58.44% for the same measurement.
- The long-horizon row says "ours 95%". Every results file says 100%.
- `benchmarks/results/flow.md` is stale by seven hours against both the
  mechanism and the harness and must not be cited.
- Our AgentDyn utility figures come from a 6-task subset whose undefended
  baseline is 66.7% shopping and 83.3% github (`agentdyn.md:18,21`), roughly
  double what the AgentDyn authors measure over 20 tasks on the same model.
  They are not comparable to their table without rerunning the full 20.
