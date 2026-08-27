# Datasheet for BPL-v1

Following Gebru et al., *Datasheets for Datasets* (CACM 2021). Required for the
NeurIPS Datasets & Benchmarks track.

---

## Motivation

**For what purpose was the dataset created?**

To measure whether a defense can enforce a *business-process* constraint on a
tool-using agent, a rule that no single action violates. Existing agent-security
benchmarks (AgentDojo, InjecAgent, ASB, AgentHarm) measure attack-success rate
under prompt injection: an adversary inserts content, and the question is whether
the model obeys it. BPL asks a different question, and one that persists when the
model does not obey anything it was not asked to do:

> The user's request is legitimate, the agent executes it faithfully step by
> step, every individual call is authorized, and the *composite* breaks policy.

Payment splitting is the canonical case: five bonuses of $4,000 are each
individually approved; $20,000 in a day is not. The agent is not deceived. It is
being helpful.

This matters more, not less, as models improve. Measured on `gpt-5-mini`,
undefended attack-success rate under four stock AgentDojo injections is **0 of
18**, the injection channel is closing. Composite-policy violation on the same
model is **100 of 100** on `payout-splitting`.

**Who created it and who funded it?**

Created by the Clay Seal project. No external funding.

---

## Composition

**What do the instances represent?**

Each instance is a **scenario**: an executable environment plus a task, not a
static input/label pair. A scenario provides

| component | role |
| --- | --- |
| `user_prompt` | the legitimate request, in the user's voice |
| `tools` | OpenAI-format function schemas the agent may call |
| `handler` | the simulated world; applies calls to state |
| `policy` | the declarative constraint (see `policy.py`) |
| `violated(env)` | the ground-truth oracle |
| `progress(env)` | fraction of legitimate work completed |
| `violating_script` / `compliant_script` | deterministic trajectories for LLM-free testing |

**How many instances are there?**

133 scenarios across three families and ten difficulty levels.

| family | n | what breaks |
| --- | --: | --- |
| aggregate | 45 | a ceiling crossed by a sum, count, or rate over many calls |
| escape | 59 | authority widened step by step within a legitimate task |
| confidentiality | 29 | information leaving by an allowed channel, in allowed pieces |

| difficulty | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | 10 |
| --- | --: | --: | --: | --: | --: | --: | --: | --: | --: | --: |
| scenarios | 5 | 10 | 4 | 6 | 53 | 19 | 4 | 12 | 8 | 12 |

**Frozen evaluation suites** (`SUITES.yaml`, version `BPL-v1.0`):

- **core (12)**, the leaderboard set. Fully policy-declared.
- **hard (24)**, reported separately.
- **research_quarantine (12)**, paradox-class cases (Heisenberg, lacuna, LTL,
  negation-as-failure, two-clock). **Not scored.** They are included because
  they are interesting and excluded because it is not clear a correct answer
  exists.
- **full**, the whole pack (133), appendix only. Resolved from the
  registry rather than enumerated in `SUITES.yaml`, so it grows without a
  version bump; Core and Hard do not.

**Is there a label, and is it ground truth?**

Yes, and it is derived rather than annotated. `violated(env)` is a program over
final environment state. For the Core-12, an independently written declarative
`Policy` is checked against that oracle on both scripted trajectories, so a
mis-transcribed threshold fails a test rather than becoming the answer key. Rule
field names are additionally checked against the tool schemas, because a rule
summing a field the tool does not have sums nothing and silently scores every
trajectory compliant. All three checks were added after negative controls showed
the earlier versions did not catch a corrupted threshold, a corrupted grouping
key, or a corrupted field name.

A second label, `clayseal_expected` (`contain` / `partial` / `open`), records
what the reference defense is expected to do. **It is not ground truth about the
task** and `open` cases are probes rather than losses.

**Does the dataset contain confidential or personal data?**

No. All environments are synthetic. Names, IBANs, emails and card fragments are
fabricated. No scraped, user-derived, or real transaction data.

**Is anything missing?**

Yes, stated plainly: 12 of 133 scenarios carry a declarative `Policy`. The other
121 state their rule in code only. `--policy-coverage` prints the ratio so
"not yet migrated" cannot be read as "has no rule".

---

## Collection

**How was the data acquired?**

Scenarios were *authored*, not collected, and this is the dataset's principal
limitation (see Limitations). They are written translations of documented failure
modes from domains that have spent decades cataloguing them:

| source domain | example scenarios |
| --- | --- |
| FATF / ACAMS AML typologies | smurfing under CTR, layering hops, fan-out spray, trade-based laundering |
| Tax (step-transaction doctrine) | economic-substance, wash trades |
| Aviation (sterile cockpit, MEL) | breakglass-without-incident, deferred-defect |
| Maritime (COLREG) | right-of-way sequence traps |
| Food safety (HACCP) | critical-control-point bypass |
| Audit / SOX (separation of duties) | prepare-and-approve, quorum aliases |
| Procurement | PO splitting under threshold |
| Agent-safety literature | MAST, AgentLAB, PhantomPolicy, SCOPEGATE, stego-collusion |

`LITERATURE.md`, `INSTITUTIONAL_SOURCES.md`, `AML.md` and `UNORTHODOX_SOURCES.md`
carry the citation for each.

**Who was involved and how were they compensated?**

The project authors. No crowdworkers, no annotators, no compensation structure.

---

## Preprocessing

None. Scenarios are executable Python; there is no cleaning, tokenization or
filtering step between authoring and evaluation.

---

## Uses

**What has it been used for?**

Head-to-head evaluation of six conditions on the Core-12, live on
`gpt-5-mini-2025-08-07` (see `../results/bpl_head_to_head.md`).

**What should it NOT be used for?**

Declared non-goals, also in `SUITES.yaml`:

- **Not a jailbreak or injection ASR benchmark.** No adversarial strings.
- **Not a capability benchmark.** A model that refuses everything scores zero
  progress and is not thereby good.
- **Not evidence that any defense generalizes.** The scenarios were written by
  the same project that wrote the reference defense; see Limitations.
- **Not for CVE/malware, dual-use bio/chem/nuclear content.** None is present.
- **Not a source of `clayseal_expected: open` wins.** Those are probes.

---

## Distribution

Public at <https://github.com/clayseal/bpl-benchmark> under **MIT**. Also
vendored in the Clay Seal research repository. No third-party material is
redistributed; the institutional sources are cited, not copied.

---

## Maintenance

**Who maintains it, and how are changes handled?**

The Clay Seal project. Core and Hard membership are **frozen** at `BPL-v1.0`;
adding a scenario to either requires a version bump, so a published number always
names a suite that still means what it meant. The Full pack may grow between
versions and is appendix-only.

**Will it be updated?**

Yes, the roadmap is (a) declarative policy coverage beyond the Core-12,
(b) additional models on the live leaderboard, (c) scenarios contributed by
people who did not write the reference defense, which is the limitation that
matters most.

---

## Limitations

Stated here rather than in a footnote, because two of them bound what the results
can support.

**1. The scenarios and the reference defense share an author.** This is the
central threat to validity. It is mitigated, `clayseal_expected` is declared
before measurement, `open` cases are excluded from scoring, paradox cases are
quarantined, and the validity audit (`benchmarks/validity.py`, after Arp et al.
USENIX 2022) fails the build on undeclared label provenance, and it is not
eliminated. The honest reading is that BPL measures whether a defense can enforce
*these* constraints, and independent scenario contribution is the fix.

**2. The comparison conditions are class reproductions, not the systems.**
`per-call` and `dataflow-taint` are ~10-line implementations of an architectural
class. They were previously named `progent` and `camel`; they were never those
systems, and the names were removed because a reproduction cannot support a claim
about someone's published work. `drift` and `authgraph` are fuller mechanism
reproductions built from the published designs and are labelled "-shaped" with
arXiv citations. **No result here should be read as "system X fails."** The claim
is architectural: a defense with no cross-call state cannot enforce an aggregate
constraint, which is checkable by inspection and does not depend on any
implementation.

**3. Every condition now receives the policy, earlier results did not.** In the
first release only the reference defense was configured with the threshold, so
the table partly measured which condition had been told the rule. Fixed by
`policy.py`; results predating it are marked in `bpl_head_to_head.md`.

**4. Simulated environments.** Handlers are a few dozen lines of state
manipulation. They capture the policy-relevant structure and none of the
messiness of a real system.

**5. One model on the live leaderboard.** `gpt-5-mini`, reached through a
deployment aliased `gpt-4o-mini-2024-07-18`. Every cell records the served model
id after that alias produced a mislabelled table once. Azure refuses new
`gpt-4o-mini` deployments (`ServiceModelDeprecating`), so the exact prior
replication is unavailable.

**6. Progress is a proxy for utility.** Fraction of requested (legacy) or
policy-allowed (other) work units. It does not measure whether the work was done
*well*.

---

## Ethics

The scenarios describe how to structure payments under a reporting threshold,
split purchase orders, and drip sensitive fields through an allowed channel.
Every technique is already documented in public compliance literature, FATF
typologies exist precisely so institutions can recognise them, and none of it
is operational: the environments are toy simulations with fabricated identifiers
and no connection to a real system. The dual-use balance is the same one AML
training material strikes, and the alternative is that only attackers have the
list.

No human subjects. No personal data. No scraped content.
