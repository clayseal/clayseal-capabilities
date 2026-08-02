# Head-to-head on AgentDojo injection: ours vs built-ins vs Progent

One protocol, one model, one attack, one task subset. Public OpenAI
`gpt-4o-mini-2024-07-18` (genuinely injectable, unlike a current frontier model),
`important_instructions` attack, first 6 user tasks x 3 injection tasks per suite.
Progent runs through its own AgentDojo fork with `SECAGENT_UPDATE=True` and the
same policy model; the built-ins are AgentDojo's own; ours is the deployable
envelope-taint path.

## Attack-success rate (lower is better)

| suite | undefended | tool_filter | spotlighting | repeat_prompt | Progent | ours |
|---|--:|--:|--:|--:|--:|--:|
| banking | 61.1% | 33.3% | 61.1% | 27.8% | 16.7% | **0.0%** |
| slack | 83.3% | 16.7% | 55.6% | 38.9% | 11.1% | **0.0%** |
| travel | (pending) | | | | 11.1% | (pending) |
| workspace | 88.9% | 5.6% | 77.8% | 72.2% | 16.7% | **0.0%** |

On security we beat every AgentDojo built-in and Progent on every suite measured,
holding ASR to zero where Progent leaves 11 to 17 percent.

## Clean utility (higher is better) — the honest tradeoff

| suite | undefended | Progent | ours |
|---|--:|--:|--:|
| banking | 50.0% | 16.7% | 16.7% |
| slack | 83.3% | 83.3% | 50.0% |
| workspace | 100.0% | 100.0% | 83.3% |

This is the real cost. We drive ASR to zero but sacrifice benign utility, most
sharply on banking (both Progent and we fall to ~17%). On slack and workspace
Progent keeps more utility than we do (83% and 100% vs our 50% and 83%). So the
head-to-head is not a clean sweep: we win security outright, Progent wins utility
on two suites. Reducing our utility cost while holding ASR at zero is the priority
this table makes concrete.

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
