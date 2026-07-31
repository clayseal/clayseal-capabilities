# Head-to-head vs published defenses (escapes)

Clay Seal against AgentDojo's own built-in defenses on the identical subset, so
the comparison is apples to apples. Live agent (gpt-4o-mini), banking suite,
standard important_instructions attack, 6 user x 3 injection tasks (n=18 for ASR,
n=6 for clean utility).

## Result

| configuration | clean utility | ASR | utility under attack |
|---|--:|--:|--:|
| none (baseline) | 50.0% | 72.2% | 33.3% |
| tool_filter (published) | 50.0% | 27.8% | 33.3% |
| spotlighting_with_delimiting (published) | 50.0% | 77.8% | 33.3% |
| repeat_user_prompt (published) | 50.0% | 22.2% | 22.2% |
| Clay Seal envelope (deployable, no oracle) | 33.3% | 55.6% | 16.7% |
| Clay Seal full stack (oracle scope + binding) | 33.3% | **0.0%** | 33.3% |

## Honest reading

The win: the full stack drives ASR to 0 percent, beating every published defense
here (best published is repeat_user_prompt at 22.2 percent, tool_filter at 27.8
percent). On the security axis, with oracle scope and destination binding, Clay
Seal dominates the standard baselines.

The problem, stated plainly: the deployable envelope (no oracle) is NOT SOTA on
this run. Its ASR is 55.6 percent, worse than the two simple published defenses,
and its clean utility is lower. Only the privileged full stack wins. This is the
same oracle gap the adaptive-adversary run exposed, now visible head-to-head: the
0 percent number depends on ground-truth destination seeding, and without it the
deployable path underperforms a prompt-repetition baseline. The provenance /
taint keystone (v0.2 keystone 2) is what has to close this. Until it does, the
SOTA claim on escapes holds for the ceiling, not for the shippable system.

Also note spotlighting at 77.8 percent (above baseline) and the general noise:
these are AgentDojo built-ins known to be weak on banking, and n is small.

## What this means for the SOTA claim

- Escapes, ceiling: SOTA. Full stack beats all published defenses on ASR.
- Escapes, deployable: not yet. The oracle gap is decisive and names the exact
  build (provenance) that would make the shippable path SOTA.
- Rigor gap: n=18 (ASR) and n=6 (clean) are too small for a defensible published
  claim, and spotlighting above baseline shows the noise. The real head-to-head
  is the full AgentDojo benchmark, all four suites, larger n, on a VM, ideally
  adding the transformers PI detector and, where runnable, CaMeL and Progent.
