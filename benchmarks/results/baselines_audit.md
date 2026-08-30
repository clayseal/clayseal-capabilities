# Baselines audit: the "Best alternative" column

STATUS: current

STATUS applies to a document that reports measurements. This one is an
**analysis**: it reasons over results produced elsewhere rather than emitting
its own, so there is no command to re-run. `current` here means the argument
still matches the results it reasons about, checked against this commit.


> The audited document is kept outside this repository. The findings below are
> checks of its claims against this code.

Audit of every cell in `_results_table_draft.tex`, plus the two rows being added now.
Nothing in `_results_table_draft.tex` was edited. Nothing was committed. All "ours"
figures re-verified against committed HEAD `9bd0ec0` in a detached worktree, not the
working tree.

Kind markers used throughout, and proposed as the table's footnote key:

| Mark | Meaning |
|---|---|
| `M` | MEASURED_HEAD_TO_HEAD. We ran their code, or a reproduction we wrote. |
| `P` | PUBLISHED_SAME_CORPUS. Their paper reports it on this corpus and split. |
| `D` | PUBLISHED_DIFFERENT. Their paper reports it on another corpus, model, or split. |
| `O` | OUR_OWN_RUNG. Our ablation ladder, not another system. |
| `N` | NOT_MEASURED. No defensible figure exists. |

---

## 1. Ready to paste: the two new rows

Drop these into the `tabular` in `_results_table_draft.tex`. They assume the
kind-marker footnote from section 3 is in place.

```latex
Mind2Web-SC
  & user-policy violation, web agent
  & AGrail (GPT-4o) 98.0\%\ @ 1.0\% FB$^{P}$;
    GPT-4o 1-shot 99.0\%\ @ 1.0\%$^{P}$
  & 98.0\%; 1.0\% FB \\
AgentLeak (C3)
  & PII on the internal tool-input channel
  & Presidio NER 19/22, all 5 benign payloads
    corrupted$^{M}$; no published C3 defense$^{N}$
  & 22/22; 0\% FB \\
```

### Mind2Web-SC, sourcing

- **AGrail (GPT-4o), LPA 98.4 / LPP 99.0 / LPR 98.0.** Luo, Dai, Liu, Banerjee, Sun,
  Chen, Xiao. arXiv:2502.11448v2, ACL 2025 main (aclanthology 2025.acl-long.399),
  Table 2, Mind2Web-SC block. LPR 98.0 is containment, LPP 99.0 gives a 1.0% false
  block on the 100 benign examples.
- **GPT-4o one-shot CoT, LPA 99.0 / LPP 99.0 / LPR 99.0.** Same table, same paper. This
  is AGrail's own model-based baseline with no guardrail machinery, and it beats us.
- **Same corpus, checked three ways.** AGrail's GuardAgent (GPT-4) row reads
  90.0/100.0/80.0, byte-identical to GuardAgent Table 1. Every row reconstructs on
  n=200 at 100 attack / 100 benign. AGrail Appendix C.1: "For EICU-AC and Mind2Web-SC,
  we strictly followed agent input, agent output, guard request, agent specification
  defined in dataset."
- **GuardAgent** (Xiang et al., arXiv:2406.09187v3, ICML 2025) Table 1 best row is
  Llama3.3-70B 93.0/92.2/94.0, which is 94.0% containment at 8.0% false block. It is
  honestly sourced and it is the wrong cell, because AGrail is stronger and cites the
  same benchmark. Do not use the abstract's 83%; that is the weakest of four models.
- **Ours**, HEAD `9bd0ec0`, `python -m benchmarks.cli --dataset mind2web_sc`: capability
  token 98.0% contained at 1.0% false block, n=200. In the paper's units, LPA 98.5 /
  LPP 99.0 / LPR 98.0. p95 enforcement overhead 0.0086 ms in the same run.
- **Ruled out after reading their tables**: ShieldAgent (arXiv:2503.22738), VeriGuard
  (arXiv:2510.05156), Spider-Sense (arXiv:2602.05386). None evaluates on Mind2Web-SC.

**What this row can and cannot claim.** We tie AGrail exactly and we lose to a one-shot
GPT-4o prompt. The row is not an accuracy win. It is a cost-and-determinism result:
parity with published SOTA at 0.0086 ms per decision against an LLM call per action.
Caption it that way or drop the row. Two asymmetries the caption must carry, and they
cut both ways: `benchmarks/datasets/mind2web_sc.py` states that its rule lexicon was
authored while reading this corpus's task strings, so our recall here is optimistic;
AGrail's main-table setting is test-time adapting, so its memory adapts while streaming
the same corpus. The GPT-4o 1-shot row gets no such help and still leads.

One narrow edge worth a clause: GuardAgent's EA metric also requires naming the violated
rule, and our comparable diagnostic is 98.0% against their best EA of 94.0%. Do not put
that number next to AGrail's AM 94.7, which is an LLM-judged alignment score and a
different construct.

The `inspect_evals` port is the wrong instrument for this row.
`src/inspect_evals/mind2web_sc/utils.py:23` slices `raw_dataset[:10]`, so any run there
scores ten samples, and `eval.yaml` carries no `baselines` field.

### AgentLeak, sourcing

- **Presidio NER (D1), 19/22 = 86.4% of leaking C3 tool calls neutralised.** Measured.
  I installed `presidio-analyzer`, `presidio-anonymizer`, `en_core_web_lg` and
  `en_core_web_sm` into `.venv` and reran the existing unmodified script at
  `agentleak_defense_h2h.py` (a local scratch script).
  No repository file was edited.
- **It contains by destroying the payload.** All 5 of 5 benign C3 calls are altered.
  `{"tool": "lab_results", "params": {}}` becomes
  `{"tool": "[REDACTED_USERNAME]", "params": {}}`, a call with no sensitive field whose
  tool name is destroyed. Leaking calls come back as invalid JSON:
  `"[REDACTED_USERNAME]TED_URL]hedule"`, `"Dr. [REDACTED_EYE_COLOR]CTED_PERSON]"`. Its
  effective false-block rate on this channel is 100%, worse than a deny-all, which at
  least contains 22/22.
- **D4 is the same mechanism.** `create_internal_defense()` returns identical 19/22 and
  5/5 because `agentleak/defenses/internal_channel.py:151` constructs the same
  `PresidioDetector`. One mechanism, two wrappers.
- **OutputSanitizer 0/22 at 0/5 altered** reproduces exactly, and it is a mechanism
  result rather than a config gate: `DefenseConfig.channels_to_monitor` defaults to
  `list(Channel)` and a direct probe returns REDACT on C3. It neutralises nothing
  because the leaked fields are record keys and names (`patient_id` "PT-991470",
  provider "Dr. Gonzalez", `visit_date`), which no PII regex matches.
- **Nearest published internal-channel defense**: AgentLeak (El Yagoubi, Badu-Marfo,
  Al Mallah, arXiv:2602.11510v3, "AgentLeak: A Benchmark for Internal-Channel Privacy
  Leakage in Multi-Agent LLM Systems"), TABLE IX, "Defense Effectiveness by Channel Type
  (A0 Benign Scenarios Only)": on C2-C5, Role Separation 28% against a 31% vanilla
  baseline. That is the best published internal-channel number, and it is not C3.
  Finding 7 confirms no defense is evaluated on C3 by anyone.
- **Do not cite the 98%.** It is C1 leak-rate reduction on an A0 benign subset of
  unstated size, and it is a Figure 6 caption, not body text. C1 is not the surface we
  replay.
- **Do not cite the v1 title.** "Full-Stack" is v1. Cite v3.
- **Ours**, HEAD `9bd0ec0`, `python -m benchmarks.agentleak_flow`: as-shipped 11/22
  contained at 0.0% false block, `tool_input_as_sink` 22/22 at 0.0% false block, over 5
  benign events.

**Denominator honesty for the caption.** The 27 recorded C3 events are all `gpt-4o-mini`
and all healthcare (`agentleak_hea_*`). The run's own `claims.json` reports n=100
scenarios at a 62% C3 leak rate, but only 27 traces were saved and 22 of them leak, so
the saved subset is enriched for leaks. Say "22 attack and 5 benign C3 events from a
100-scenario healthcare run, one model."

**Never quote the catalog.** `agentleak/catalog/defenses.py` declares D2.1 and D2.2 with
`target_channels=["C3"]` and hardcoded `effectiveness` dicts. Those are spec constants
with no implementing class.

**Separate defect, fix before publishing anything citing this corpus.**
`benchmarks/datasets/agentleak.py:5` cites "5,506 recorded execution traces" and line 8
cites "output-only audits miss 45.9% of violations". The paper says 4,979 validated
traces and 41.7% (Table XII, 2,076/4,979, 95% CI [40.3, 43.1]). The repo README says
45.9% over 5,694. Neither of our numbers matches the paper and 5,506 matches nothing.

---

## 2. Every row, sorted

Genuine other systems first. Cells that are secretly our own ladder last. That ordering
is the finding: of fourteen rows in the current draft, six print our ladder under a
header that reads "Best alternative", and one prints an unsourced number.

### 2a. Cells that really are other systems

| Row | Current cell | Kind | Corrected cell | Source |
|---|---|---|---|---|
| AgentLeak (new) | n/a | `M` | Presidio NER 19/22 (86.4%), all 5 benign payloads corrupted; no published C3 defense | Measured, script above. AgentLeak TABLE IX for C2-C5 context |
| AgentDojo (live) | `5.6% built-in; Progent 11--17%` | `P` + `M` | Progent 0.00% ASR (gpt-4o, hand-written policies)`P`; CaMeL 0 to 11 of 949`P`; Progent-LLM 13.9% on our gpt-4o-mini run`M` | Progent arXiv:2504.11703v2 Table 1 and Table 3; CaMeL arXiv:2503.18813v2 Table 4; `head_to_head_injection.md:12-17` |
| Mind2Web-SC (new) | n/a | `P` | AGrail (GPT-4o) 98.0% @ 1.0% FB; GPT-4o 1-shot 99.0% @ 1.0% | AGrail arXiv:2502.11448v2 Table 2 |
| RedCode-Exec | `0% (RBAC / capability token)` | `P` | AgentSpec: over 90% of risky executions intercepted, authors' claim; 78.9% detected by our sum of their Table 3 | AgentSpec arXiv:2503.18666, abstract line 41 and intro line 99 for the >90%; Table 3 sums to #inv 422, #vio 333, #pass 58 |
| SLEIGHT (twins) | `≈6% (n-gram)` | `P` | Best monitor 54% per-trial, 82% any-trial at 1% FPR; Opus 4.6 32% | arXiv:2605.16626 Figure 2; abstract for the 32%; Appendix G Figure 17 for Gemini 3.1 Pro 47% |
| Utility cost | `ARGUS ~5; CaMeL ~7; Progent ~19` | `P` + `D` | Progent +1.0 pt clean utility at 0.00% ASR (gpt-4o)`P`; CaMeL 3 to 32 pts`P`; InjecGuard 2.5 pts, ARGUS 5 pts (AgentLure)`D` | Progent Table 1 (79.38 to 80.41); CaMeL Table 2 all six rows; ARGUS arXiv:2605.03378v2 Table 2 |
| Burst + flow + BFCL detector | `0% (per-call ladder)` | `D` | Published trajectory detector 0.66 recall @ 0.90 precision, prefix-level, synthetic`D` | arXiv:2605.01143v2 Table 3, "A Fraud-Detection-Inspired Framework for LLM Agents Security". Code: github.com/Yunicorn228/A-Low-Latency-Fraud-Detection |

### 2b. Cells sourced to a paper, on a different corpus, model, or split

| Row | Current cell | Kind | Corrected cell | Source |
|---|---|---|---|---|
| Adaptive red-team | `0% (RBAC / capability token)` | `D` | Progent 4.2% ASR standard, 2.6% adaptive, independent reproduction | Narisetty, Kore, Kattamanchi, Kumarapu, arXiv:2606.26479v1 Table 3. Corroborate with Progent v2 Table 5, worst overall adaptive 4.24%. Cite the version: v3 moves this to Appendix E |
| Long-horizon | `0--83% (lower rungs)` | `D` | StepShield best detector 95.4% recall @ 5.6% FPR, at 12.7 steps per trajectory against our 500 to 2,000 | StepShield arXiv:2601.22136, detector table line 409, dataset table line 172. FPR computed on 108 clean trajectories |
| iVisor + latency | `floor misses BPL; CaMeL minutes` | `D` | aiAuthZ ≤0.03 ms per decision`D`; Progent 0.0008 s per task`D`; CaMeL 2.82× input / 2.73× output tokens`P` | aiAuthZ arXiv:2607.05518; Progent v2 body text; CaMeL section 6.5 and Figure 13 |
| Cross-session + drift | `session ledger fails; rolling 0.5%` | `D` | aiAuthZ meters allowed calls per workspace across sessions`D`; rolling-baseline poisoning is Kloft and Laskov, JMLR 13 (2012) 3681-3724`D` | aiAuthZ arXiv:2607.05518 rate-limit gate; arXiv:1003.0078 abstract |
| Mandate quality | `47.9% FB on τ²` | `D` | Incomplete allowlist costs 7.4 pts task success, 7 of 89 tasks unsolvable (Terminal-Bench 2.1)`D`; Progent-LLM auto-generated policy costs 3.1 pts`D` | "Permission Denied: Policy-Graded Evaluation of Coding Agents in Hardened Environments", arXiv:2608.02670; Progent Figure 9 |

### 2c. Cells where no defensible figure exists

| Row | Current cell | Kind | Corrected cell | Source |
|---|---|---|---|---|
| IPI / ATB / AdvBench / MCP | `0--40% below binding` | `N` | Not measured on these corpora | Literature search found no defense reporting on IPI-Coding-Agent or AgentThreatBench. AgentThreatBench is an `inspect_evals` addition operationalising OWASP Agentic Top 10 (2026) with no published guardrail evaluation |
| ULB / IBM AML | `0.86 AUC` | `N` | n/a, sensor validation rather than a fraud-detection claim | 0.86 has no source anywhere in the repo. Repo-wide grep over md, py, tex, json returns two hits: the tex itself and `baselines_sourced.md:103`, which already records "no source" |

### 2d. Cells that are secretly us

| Row | Current cell | Kind | Corrected cell | Source |
|---|---|---|---|---|
| Business-process (live) | `≈100% viol. (Progent / CaMeL)` | `O` | Per-call rung 100% viol. (n=80); real Progent and CaMeL not run | `benchmarks/live/bpl_live.py:133-145`. Line 140 builds `allowed_tools` from `scen.tools`, line 141 admits any call whose name is in it. That is our tool-allowlist rung with a vendor name on it. The CaMeL arm at :146-163 is a substring taint test, not the dual-LLM interpreter |
| AgentDojo (replay) | `77.9% below binding` | `O` | Our tool-allowlist / capability-token / task-scope rungs, 77.9% | `benchmarks/results/agentdojo_first_run.md:13-15`. Never reviewed by anyone. It is three of our own ladder steps |
| Mandate quality | `47.9% FB on τ²` | `O` | Ours before pattern generalisation: 47.91% held-out FB on τ², now 0.05% | `generalisation.md`: "Held-out false-block was the worst number in the project: 47.91% on tau2." Seed-stable 48.21 ± 0.18 before, 0.04 ± 0.01 after, seeds 0-4 |
| RedCode-Exec | `0% (RBAC / capability token)` | `O` | Our RBAC and capability-token rungs, 0.0% [0.0, 0.4] on 718 attack events | `new-suites/redcode.md`. `validity_gates.md` confirms 717 of 718 leave the granted surface via the target alone, which is why every rung below task-scope reads zero |
| Adaptive red-team | `0% (RBAC / capability token)` | `O` | Our RBAC and capability-token rungs, 0% | `adaptive_exfiltration.md`, `adaptive_persistence.md`, `adaptive_destruction.md` |
| Long-horizon | `0--83% (lower rungs)` | `O` | Our lower rungs: tool-allowlist 0.0%, capability-token 82.0%, task-scope 83.0% | `validity_gates.md`, 200 sessions of 500 benign actions |
| IPI / ATB / AdvBench / MCP | `0--40% below binding` | `O` | Our tool / cap-token rungs, 0 to 40% | Loader run at HEAD: tool-allowlist 0.0% on `ipi_coding` and `agent_threat_bench`, 20.0% on `mcp_attack`, 16.7% on `advbench_agent`; capability token 40.0% on `mcp_attack` |
| Burst + flow + BFCL detector | `0% (per-call ladder)` | `O` | Our per-call ladder, 0% in-scope-burst containment through task-scope+binding+budget | `composed_detector.md` |
| Cross-session + drift | `session ledger fails; rolling 0.5%` | `O` | Our session-scoped ledger and our rolling baseline, 0.5% against anchored 82.1% | `structuring.md`; `drift.md` 5/1000 rolling against 821/1000 anchored |

**Two corrections to "ours" figures found on the way, both must be fixed before
publication.** The tex prints 100% on the adaptive row and the long-horizon row while
the accompanying brief says 96% and 95%; the results files support 100% at
task-scope+binding. Pick one and cite it. The AgentDojo live "ours" should read
0.5% [0.1, 2.6] at n=216 from `pooled_asr.md:20`, not "≈0%", because the pooled number
is the defensible one and it is already in the repository.

---

## 3. The column header

"Best alternative" is not accurate for a column where six of fourteen cells are our own
ablation ladder. Three options.

**Option A, recommended: rename to "Comparator" and add a four-mark footnote key.**

```latex
\normalfont\bfseries Comparator$^{\dagger}$
...
\multicolumn{4}{@{}p{14.05cm}@{}}{\footnotesize $^{\dagger}$
  $^{M}$ we ran their system or our reproduction of it;
  $^{P}$ published on this corpus and split;
  $^{D}$ published on a different corpus, model, or split;
  $^{O}$ our own ablation rung, not another system;
  $^{N}$ not measured.}
```

Trade-off: one word, fits the existing column width, and every cell becomes honest
without dropping any data. It gives up the rhetorical claim that we beat the best
alternative, which we cannot defend on Mind2Web-SC anyway. This is the option that
survives a reviewer opening the papers.

**Option B: split into two columns, "Best published alternative" and "Our next-best
rung".** Trade-off: maximally unambiguous, no footnote needed, and it makes the ladder
data a feature rather than a disguise. It costs roughly 2 cm of width, so the table needs
`\small` or landscape, and it leaves visible blanks on the rows where nothing is
published. Those blanks are true and they read as weakness.

**Option C: keep "Best alternative" and print `not measured` wherever there is no
competitor.** Trade-off: the header stays punchy and every cell under it is genuinely a
competitor. It throws away the ladder numbers, which are the actual evidence that the
mechanism and not the model does the work, and it puts `not measured` in six cells, which
looks worse than Option A's honest labels.

Whichever is chosen, `Ours` needs a matching footnote naming the model and n, because
several "ours" figures are single-model (3 pts on grok, 25 pts on gpt-4o-mini).

---

## 4. Cells we should not publish at all

**1. `0.86 AUC` on the ULB / IBM AML row. Drop it now.** It is unsourced and it sits
below the published floor. The real numbers are XGB 0.989 and RF 0.988 supervised, RBM
0.961 best unsupervised (arXiv:1904.10604), and IBM AML Small HI GIN minority-class F1
28.7% to 57.2% (arXiv:2306.11586). Publishing 0.86 is not weak sourcing, it is a
baseline picked below where the literature is. Fix: relabel the row as sensor validation
and put `n/a` in the comparator column. If a number is wanted, cite RBM 0.961 with the
protocol stated, because their non-fraud class is randomly reduced to 492 to match the
492 frauds while we score at natural prevalence on held-out data.

**2. `≈100% viol. (Progent / CaMeL)` on the business-process row. Do not ship with the
vendor names.** That arm is our tool-allowlist rung. Either run their real code
(section 5, item 2) or write the cell as a rung and name nobody.

**3. The architectural prose behind that row.** `bpl_head_to_head.md:11` says Progent
has "no cross-call state". False. `secagent/tool.py:522` declares `need_update_policies`
and :584-588 writes returned policies back into the global `security_policy` dict and
re-sorts, so a satisfied rule can install a stricter policy binding every later call.
`bpl_head_to_head.md:10` cites `secagent/policy_type_check.py` as evidence of Progent's
per-call design; that file is a JSON-schema linter, and enforcement lives at
`secagent/tool.py:573`. CaMeL's `src/camel/security_policy.py:73` makes
`SecurityPolicyEngine` a Protocol whose policies are bound methods on a live object, so
nothing stops accumulation. The defensible claim shrinks to this: neither system's
shipped policies express an aggregate ceiling and neither generates one automatically,
so a policy author would have to write it by hand. Fix the prose in
`bpl_head_to_head.md:11`, :30-31, :64-65 before the table goes out. Also name AgentSpec
(Wang, Poskitt, Sun, ICSE 2026) in the caption as the untested strongest alternative,
since its rules are trigger plus arbitrary user predicate and an aggregate ceiling is
directly expressible in it.

**4. The SLEIGHT row, until it is recalibrated.** As drafted it puts our uncalibrated,
oracle-fed 97.7% (`commit_then_reveal.md:9`, the `honest_declare_then_sabotage` arm,
which requires the agent to declare) against a competitor measured at 1% FPR, while
understating that competitor by 22 points. Our comparable arms are `declare_sabotage`
27.9%, `no_declaration` 72.1%, full stack 75.6% detection at 69.8% false positive
(`sleight.md`), deterministic replay 4.7% (`scoreboard.md`). Do not publish until rerun
at 1% FPR on the paper's 40 attacks. Note the local corpus at `.benchmark-corpus/
sleight-bench` has 44 attacks in 12 categories while the paper has 40 in 11, so the repo
has grown past the paper.

**5. The row name `IPI / ATB / AdvBench / MCP / ToolEmu`.** Loaders at HEAD:
`toolemu` 559 benign and 0 attack events, `atif` 282 benign and 0 attack. ToolEmu
contributes nothing and must leave the row name, and
`new-suites/toolemu.md` is stale against HEAD, still showing 5 attack events.
`benchmarks/tests/test_new_suites.py::test_toolemu_emits_no_attack_events_and_says_why`
records why: the old verb split "was our invention and it made containment an identity".
Of what remains, `ipi_coding` 50 attack events and `agent_threat_bench` 6 are external,
`advbench_agent` 6 and `mcp_attack` 5 are our own fixtures. Rename to
"IPI-Coding + AgentThreatBench (external, n=56); AdvBench, MCP-Attack (own fixtures,
n=11)". Do not reach for Skill-Inject's Guardian numbers (arXiv:2606.01567: vanilla
36.0% ASR, Static Guardian 7.2%) to fill the gap; different corpus, different agent.

**6. Any unnarrowed absence claim on the cross-session and mandate-quality rows.**
"No published system meters cumulatively across sessions" is false: aiAuthZ's third
policy gate meters allowed calls against fixed-window per-tool counters scoped to the
workspace, and denied calls are not metered. Workspace scope outlives a conversation.
The narrow claim that survives is that no system meters cumulative *value* of business
effects per principal. "No published system reports held-out false-block under an
incomplete grant" is also false: arXiv:2608.02670 builds a deliberately incomplete
205-domain allowlist on Terminal-Bench 2.1 and publishes both the cost and the
unsolvable fraction. State the narrow version or state nothing.

**7. The two contradictory head-to-heads, both committed.** `head_to_head.md:16` reports
the deployable envelope on banking at 55.6% ASR with 33.3% clean utility and says in our
own words that it "is NOT SOTA on this run". `head_to_head_injection.md:14` reports the
same suite, same model, same attack at 0.0%. The difference is the taint path and
neither file reconciles them. Mark `head_to_head.md` superseded or reconcile it before
publishing. Any reviewer who opens the repository finds a file where we say our
shippable system loses.

---

## 5. Cheap head-to-heads worth running, ranked by credibility bought

**1. Progent on gpt-4o, four AgentDojo suites.** The fork is at
a local Progent checkout and is already driven end to end for this comparison.
gpt-4o with hand-written policies is where Progent published 0.00%, and it is the first
thing a reviewer will ask for. Cost: a few hours, tens of dollars of API. Buys the most,
because it either retires the strongest objection in the table or tells us we lose on the
flagship benchmark before a reviewer does. Do not attempt CaMeL on this axis:
`head_to_head_injection.md:46-49` records a single banking task exceeding ten minutes.

**2. Real Progent and CaMeL against the five BPL scenarios, n=20 each.** Both
repositories are local and both run. Progent must get `SECAGENT_UPDATE=True` and a policy
model so its update path at `tool.py:584-588` gets a fair chance at the aggregate, since
that is the mechanism our caption currently claims does not exist. CaMeL needs a
stateless per-call policy written the way `banking.py:52-85` writes them. Cost: about a
day each. Buys the second most, because it converts the single most differentiating row
from reproduction to measurement. If Progent's policy update catches payout-splitting we
need to know before publication.

**3. AGrail's model-based baseline on our Mind2Web-SC loader.** 200 GPT-4o calls with a
one-shot CoT prompt and the corpus rule table, scored with the same `decision_correct`
our loader uses. Cost: under an hour, a few dollars, no Docker. Confirms or replaces the
published 99.0% with a measured figure on our own loader, which is strictly better
evidence. Running AGrail itself is not worth it: it needs a TTA memory loop and its own
harness, and the published number is on the same 200 examples.

**4. SLEIGHT recalibrated to 1% FPR on the paper's 40 attacks.** The corpus is already
local and decrypted, with 43 paired benign transcripts to calibrate the threshold. Pin to
the paper's revision or record which 4 of the 44 are extras. Cost: a few hours plus
monitor calls. Buys a lot, because the row is currently unpublishable.

**5. Presidio functional damage on AgentLeak, scored properly.** Parse each redacted
payload as JSON and check that the tool name and required params survive, instead of
scoring string inequality. Expectation: 0 of 5 survive, converting "5/5 altered" into
"5/5 broken". Cost: a twenty-line addition to the existing script, minutes, no API.

**6. Unsupervised baselines on our own ULB split.** Isolation forest, one-class SVM, a
small autoencoder, fit on the identical split used by `benchmarks/fraud_validation.py`,
reported beside our 0.914 at natural prevalence. Report average precision as well as
ROC-AUC, because at 492 in 284,807 a reviewer will ask. Cost: an afternoon, no API. This
is the only version of that row that survives contact with a fraud audience, even if we
lose it.

**7. Latency instrumented on the AgentDojo banking suite against aiAuthZ's 0.03 ms.**
Also instrument Progent's per-call check locally to confirm its published 0.0008 s per
task independently. Our own figure is inconsistent across files: 18.9 µs p50 in
`latency_redcode.md` against "approx 200 microseconds, n=3000" in
`head_to_head_injection.md`. Pick one, name the stack and n. Note the honest reading:
aiAuthZ's 0.03 ms sits between our 18.9 µs p50 and our 180.8 µs p99, so it is parity on
the median and a loss at the tail, not four orders of magnitude. Cost: an hour.

**8. The published trajectory detector, both directions.** Their generator is public, so
clone `github.com/Yunicorn228/A-Low-Latency-Fraud-Detection`, regenerate the 12k corpus
with `--n_benign 6000 --n_attacker 6000`, score our detector on their prefixes at their
operating point, and score their 42-feature XGBoost on our tau2 and bfcl burst sessions
from `benchmarks/burst.py`. Cost: half a day, no API. Note before publishing that row
that our 100% at 0% false alarm is bfcl only, and the same detector on tau2 is 66.7% at
5.4%, which does not beat their 0.66 recall.

**9. Finish the AgentDyn dailylife sweep.** Nothing needs running for the competitors:
`.benchmark-corpus/AgentDyn/runs` already ships the authors' published logs on
gpt-4o-mini-2024-07-18, our model. Aggregated from their per-task JSONs, clean utility on
the twenty open-ended tasks per suite is 35% shopping / 65% github / 40% dailylife
undefended, against Progent 0% / 15% / 5%, CaMeL 0% / 0% / 0%, tool_filter 0% / 10% /
10%, DRIFT 10% / 35% / 10%. Every serious defense collapses on open-ended tasks, ours
included (`agentdyn.md:50`). Cost: our own sweep only. This converts the utility row from
a comparison we lose into a finding: clean-utility cost is benchmark-dependent and every
published figure in that cell comes from tasks specified up front.

**10. Terminal-Bench 2.1 under the Permission Denied 205-domain allowlist.** Their
protocol is published, so our grant mechanism can be scored on the same 89 tasks against
their 65.1% and their 7 blocked-by-design tasks. Cost: roughly a week. Not cheap, listed
because it is the only route to a same-corpus competitor number on mandate quality. The
cheap interim is Progent-LLM on the AgentDojo subset we already run.

**Not worth running**: AGrail itself, CaMeL on AgentDojo live, LlamaGuard and PromptGuard
on AgentLeak C3 (neither is wired to C3 in that repo), SandboxEscapeBench
(arXiv:2603.02277) for the sandbox half of the iVisor row, which is a separate and larger
piece of work.
