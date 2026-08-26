# The 2026 frontier, and what to take from it

Written 2026-08-07 after reading the current defense literature against our own
measurements. The conclusion is uncomfortable and useful: our security is at the
frontier and our utility mechanism is a generation behind. Four systems now
publish better utility than we manage on a weak model, and each does it with a
mechanism we do not have.

## Where the field actually is

| System | Mechanism | Benchmark, model | ASR | Utility |
| --- | --- | --- | --- | --- |
| AuthGraph (arXiv:2605.26497) | dual graph, parameter-source policy, runtime replan | AgentDojo, GPT-4o | 0.40 to **0.01** | UR **0.79** |
| DRIFT (arXiv:2506.12104, NeurIPS 2025) | secure planner, dynamic validator, injection isolator | AgentDojo | 51.7% to 1.5% | UR 0.70 |
| ARGUS (arXiv:2605.03378) | influence-provenance graph, span segmentation, entailment | AgentLure, gpt-4o-mini | 28.8% to 3.8% | 5-point cost, **7.5% refusal** |
| Progent (indep. repro, arXiv:2606.26479) | symbolic least-privilege over arguments | AgentDojo, Qwen2.5-7B | 25.8% to 4.2% | UR 0.76, ~19-point cost |
| RTBAS (arXiv:2502.08966) | IFC labels, dependency screening | AgentDojo | targeted prevented | ~2 points under attack |
| CaMeL (arXiv:2503.18813) | dual-LLM, capabilities, data-flow | AgentDojo | near zero | 7-point cost |
| VeriGuard, Provably Secure Agent Guardrail (arXiv:2605.29251) | formal verification of declared intent | ASB | zero | zero FPR claimed |
| **Clay Seal** | target and destination binding, budgets, plan conformance | AgentDojo, gpt-4o-mini | **0.5%** [0.1, 2.6] pooled | 29-point cost weak, 3-point strong |

Our attack-success figure is the lowest and the only one pooled over repeated
sweeps. Our weak-model utility is the worst in the table.

## The four mechanisms we are missing

### 1. Parameter-source provenance, not just destination binding

**What they do.** AuthGraph builds an Authorization Graph in an isolated context
from the user prompt and tool catalog alone, which makes it impossible for an
injection to influence, and that graph specifies *parameter source policies*:
which tool's observations may legitimately supply which parameter. Enforcement
then checks that a parameter value actually originated from a declared source,
using string matching against raw observations rather than LLM reasoning over
text that may itself be poisoned. This catches the "correct tool, wrong
parameter source" attack: flight codes lifted from a hotel listing instead of
from a flight search.

**What we do.** `observe_output` widens one global set of trusted recipients
from structured fields of any tool output. The set has no memory of which tool
produced which value, so once a destination is trusted it is trusted for every
subsequent call regardless of where it came from.

**Why this is our slack failure.** On slack our taint mode produced 10 hard
denials against the plain envelope's zero, and the reasons were all legitimate
values discovered from message content. We concluded that free text and
injections share a channel so no field-type rule can separate them. That is
true, and it is the wrong axis. The separating question is not *what kind of
field* the value sat in, it is *which observation produced it and was that
observation an authorized source for this parameter*. A recipient sourced from
reading a channel the user's goal named is a legitimate source for a message
recipient. The same string appearing in a fetched webpage is not.

**Integration.** `Action.args` would carry a per-argument source reference
recorded at `observe_output` time, and `EgressPolicy.check` would consult the
declared source policy for that parameter rather than a flat allow-set. The
compiled scope gains a `parameter_sources` map alongside `allowed_paths`.

### 2. Runtime replan instead of hard denial on plan deviation

**What they do.** AuthGraph makes its authorization graph *runtime-extensible*
under least-privilege constraints, so a legitimate step the planner did not
foresee extends the graph rather than failing. DRIFT's Dynamic Validator does
the same job differently, assessing whether a deviation complies with privilege
limits and user intent instead of rejecting it for being off-plan.

**What we do.** The intent envelope hard-denies an off-plan consequential
action. Our own diagnosis found this rule causes **100% of hard false blocks on
the shippable path**, 11 denials of which 10 turned a succeeding task into a
failing one, on ordinary work like `create_calendar_event` and `send_money`.

**Why the obvious fix failed and this one should not.** We tried simply allowing
the action when the destination floor had cleared it (`deferallow`). That took
travel from 5.6% to 27.8% ASR and workspace from 0.0% to 27.8%, because the plan
check was doing real containment work the floor does not do. The lesson is that
the plan constraint must be *extended*, not *dropped*. An extension derived from
trusted input only (the sealed goal, the tool catalog, prior authorized
observations) preserves the property that injected text cannot widen authority,
which is exactly what dropping the check gave away.

**Integration.** `SessionBroker.reclear` already exists and adopts a fresh
sealed envelope mid-session, verifying signature and recording the swap on the
audit chain. It is currently used nowhere. The work is a policy that decides
when to regenerate and what inputs are admissible to the regeneration.

### 3. Benign data hints on denial, and a re-audited retry

**What they do.** When ARGUS blocks a call it extracts the relevant benign values
from its provenance graph and attaches them to the block response, so the agent
can retry with trusted candidates. The retry goes through the full audit again,
so nothing is bypassed. Their refusal rate on legitimate actions is **7.5%
against 25 to 35% for comparable secure defenses**, and this is the mechanism
they credit.

**What we do.** We return a denial and a reason string. The agent has no
trusted-candidate information and typically fails the task.

**Why this is the cheapest large win available.** It requires no new security
reasoning at all. We already know the trusted set at the moment we deny, since
denying is what consulting it produced. Handing that set back converts a hard
task failure into a corrected action, and every retry is re-authorized on the
same path. This is a pure utility gain with no new attack surface, which is
rare.

**Integration.** `BrokerDecision` gains a `hints` field populated from
`EgressPolicy.allowed_recipients`, `scope.allowed_paths`, and the authorized
argument shapes, filtered to the parameter that failed.

### 4. Span-level segmentation instead of whole-object trust

**What they do.** ARGUS segments each observation into spans and labels each
span rather than the observation. A span is benign when it fills an expected
evidential role (a payee, an amount in an invoice) and anomalous when it
attempts task-level manipulation (redirecting a recipient, adding a side effect)
or control-level steering (ignoring constraints, hiding information). The
distinction is role-relative rather than keyword-based, so imperative language
inside ordinary evidence stays benign while instructions exceeding the evidential
role are flagged. Trust is then computed per node as base trust scaled by the
benign fraction of its characters.

**What we do.** We trust structured fields and distrust free text, at whole-field
granularity. Our own code documents the limit: a goal-named bill file contains
the legitimate recipient and the injected attacker IBAN side by side as free
text, and no source-provenance predicate separates two tokens sharing one
source. Span labelling is precisely the predicate that does, because it
separates them by evidential role rather than by origin.

**Caution.** This introduces an LLM into the decision path, which the
deterministic core deliberately avoids. It belongs as an advisory tier feeding
the existing two-signal gate, not as a blocker in its own right, the same
subordination we already apply to the statistical detector.

## The class nobody contains, and the one published idea for it

Our coverage analysis puts 18% of pooled attack events **in-surface**: granted
tool, granted resource, in-scope target, authorized argument shape. Every
per-call authorizer scores near zero there, and AgentHarm is 94% that class.

ARGUS's **entailment verifier** is the only published mechanism aimed at it. It
asks two questions of a proposed action: is it entailed by the benign evidence
alone, and could anomalous content plausibly have shaped it. An action is
blocked when both hold, which catches the case where every argument grounds in a
benign value but the *choice* of action was steered by anomalous framing. That
is the in-surface attack stated precisely.

We should treat this as the research direction rather than a feature to copy.
Our aggregate tier already contains the volume form of in-surface attack, which
is why bulk exfiltration over an allowed channel is caught, and velocity and
novel-counterparty controls extend that without an LLM in the loop. The
entailment idea and the aggregate idea are complementary: one reasons about
whether a single action is justified, the other about whether a pattern of
justified actions is.

## What remains ours alone

Nothing in this literature reports any of the following, and each is defensible:

- **Aggregate and business-process limits.** No comparable system has value or
  call budgets, so none contains fragmented spend or bulk exfiltration over an
  allowed channel.
- **Long-horizon evaluation.** Published trajectories average about three calls.
  We measure 500 and 2,000-action sessions and report false alarms per thousand
  benign actions, which is the number that decides whether an operator leaves
  the system switched on.
- **Human attention as a priced, bounded resource.** No comparable system
  reports interruptions per task, and our own frontier shows a configuration
  reaching identical 0% ASR at five times the attention cost for half the
  utility.
- **The surface-leaving versus in-surface split**, which tells a reader what a
  containment headline is weighted by.
- **Adaptive evaluation with a checked-in negative control** that must keep
  failing, so a 100% figure is bounded by a search known to work.
- **Syscall-boundary enforcement**, unbuilt and uncontested. Symlink resolution
  and time-of-check to time-of-use are undecidable from userspace path strings.

## Order of work

1. **Benign hints with re-audited retry.** Largest utility gain per unit of risk
   in the whole list, and no new security reasoning.
2. **Parameter-source provenance.** Fixes the slack failure on the correct axis,
   and closes "correct tool, wrong source" which we do not currently detect at
   all.
3. **Runtime replan through `reclear`.** Targets the rule responsible for every
   hard false block, in the way that does not repeat the `deferallow` mistake.
4. **Velocity and novel-counterparty controls.** Extends the aggregate tier, the
   one thing we hold alone, into the class nobody contains.
5. **Span segmentation as an advisory tier.** Highest ceiling on the utility
   axis, and the only route past the structured-versus-free-text wall.
6. **Syscall boundary.** Highest ceiling overall, unchanged from prior planning.

## Evaluation debt this creates

AgentDyn (referenced by DRIFT's current implementation) extends AgentDojo with
shopping, github, and dailylife suites and dynamic environments, and the
published critique is that static benchmarks overstate deployability. Any of the
above should be measured there as well as on AgentDojo, and every one of them
should be run against our adaptive harness before it is believed, because two of
our own claims died this month to single-suite and single-model artifacts.
