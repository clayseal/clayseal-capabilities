# Head-to-head on AgentDojo injection: ours vs built-ins vs Progent

STATUS: current

One protocol, one model, one attack, one task subset. Public OpenAI
`gpt-4o-mini-2024-07-18` (genuinely injectable, unlike a current frontier model),
`important_instructions` attack, first 6 user tasks x 3 injection tasks per suite.
Progent runs through its own AgentDojo fork with `SECAGENT_UPDATE=True` and the
same policy model; the built-ins are AgentDojo's own; ours is the deployable
envelope-taint path.

## Attack-success rate (lower is better)

| suite | undefended | tool_filter | spotlighting | repeat_prompt | Progent | ours |
|---|--:|--:|--:|--:|--:|--:|
| banking | 61.1% | 33.3% | 61.1% | 27.8% | 16.7% | **0.0%** (0 of 18) |
| slack | 83.3% | 16.7% | 55.6% | 38.9% | 11.1% | **0.0%** (0 of 18) |
| travel | 27.8% | 5.6% | 27.8% | 5.6% | 11.1% | **0.0%** (0 of 18) |
| workspace | 88.9% | 5.6% | 77.8% | 72.2% | 16.7% | **0.0%** (0 of 18) |

**What 0 of 18 licenses.** Each cell is 6 user tasks x 3 injection tasks. A zero
out of 18 has a one-sided 97.5% upper bound of **18.5%**, so "0.0%" here means
"not distinguishable from anything below ~18% at this sample size", not "zero".
The comparison against Progent's 11-17% is therefore suggestive and not
separated: this table shows we are not worse, and n=18 per cell cannot show more.

On security we hold ASR to zero on all four suites, beating every AgentDojo
built-in and Progent everywhere. Progent leaves 11 to 17 percent across suites;
note travel is only weakly injectable for this model (undefended 27.8%), and there
the built-in tool_filter (5.6%) actually edges Progent (11.1%), while ours is still
zero.

## Clean utility (higher is better), the honest tradeoff

> **STATUS: superseded, this section only.** The table below is *unpaired*: it
> charges the whole gap between undefended and defended utility to the defense,
> including tasks the agent fails on its own. Pairing per task shows 3 of these 8
> banking tasks fail with no defense present, so the real figure is a 12.5%
> false-block, roughly a quarter of what this section implies. It is also a
> single weak model chosen for injectability; the deployable cost is 3 points on
> `grok-4-1-fast`. Use the 4x4 in [live_ladder.md](live_ladder.md) for any
> utility claim. The ASR table above is unaffected and remains current.


| suite | undefended | Progent | ours |
|---|--:|--:|--:|
| banking | 50.0% | 16.7% | 16.7% |
| slack | 83.3% | 83.3% | 50.0% |
| travel | 100.0% | 83.3% | 66.7% |
| workspace | 100.0% | 100.0% | 83.3% |

This is the real cost. We drive ASR to zero but sacrifice benign utility, most
sharply on banking (both Progent and we fall to ~17%). Progent keeps more clean
utility than we do on **three of the four suites**, slack 83.3% vs our 50.0%,
travel 83.3% vs our 66.7%, workspace 100% vs our 83.3%, and banking is a tie at
16.7%. So the head-to-head is not a clean sweep: we win security outright,
Progent wins utility everywhere it is not tied. Reducing our utility cost while
holding ASR at zero is the priority this table makes concrete.

This paragraph read "Progent wins utility on two suites" until 2026-08-26, which
undercounted by leaving out travel. The table above was right and the sentence
under it was wrong, in our favour, about a named published system.

## Latency: model-free vs model-in-the-loop

Enforcement latency is where the architectures diverge hardest. Our
`broker.authorize` runs at **~200 microseconds per call, model-free** (measured,
n=3000, envelope + floor + budget). Progent adds a policy-model call per step.
CaMeL is the extreme: a privileged LLM writes Python, an interpreter runs it, and
a quarantined LLM parses untrusted data, so a single banking user-task ran over
ten minutes without completing on gpt-4o-mini. That is roughly six orders of
magnitude, and it is inherent to putting a model (or two) in the decision path.

## CaMeL note

CaMeL is designed for provable injection security and lands near 0% ASR on
AgentDojo, i.e. at parity with us on the injection axis, not below. We do not claim
to out-secure CaMeL on injection. Where the two diverge is the business-process
class (below) and latency (above). A full CaMeL injection sweep was not run because
of its per-task cost and because parity there is expected and published.

## What this does and does not show

It shows a real, single-protocol comparison on an injectable model: our layer is
the strongest on the security axis, Progent is competitive on utility. It does NOT
yet cover the business-process class, which is where the injection defenses are
structurally blind (per-call privilege and dataflow gating cannot see an aggregate
that is authorized action by action). That comparison is run separately on the BPL
scenarios (benchmarks/live/bpl_live.py) and is the differentiating result.

## Reproduce

- ours + built-ins: `OPENAI_API_KEY=... python -m benchmarks.live.run_matrix
  --models gpt-4o-mini-2024-07-18 --suites banking,slack,travel,workspace
  --ablations none,builtin:tool_filter,builtin:spotlighting_with_delimiting,builtin:repeat_user_prompt,envelope-taint,envelope-taint-graduated`
- Progent: its AgentDojo fork with `SECAGENT_UPDATE=True SECAGENT_POLICY_MODEL=gpt-4o-mini-2024-07-18`,
  `python -m agentdojo.scripts.benchmark -s <suite> --model gpt-4o-mini-2024-07-18 --attack important_instructions`.
