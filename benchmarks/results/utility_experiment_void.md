# The utility experiment is void on every model Azure can serve

STATUS: current

## What was being tested

`notes/production_sota_path.md` frames the open problem: we reach zero attack
success and pay clean utility for it, so on the security-utility frontier we are
Pareto-dominated — same security, less utility. `head_to_head_injection.md` puts
a number on it: banking clean utility 16.7% against 50.0% undefended.

The `SUPERVISED` profile is the hypothesis for recovering it. `defer_to_binding`
turns an off-plan consequential action that the binding floor already cleared
from a hard denial into a step-up, and the broker's own comment says why that
should matter:

> `off-plan and consequential` accounts for 100% of the hard false blocks on the
> shippable path, and 10 of its 11 denials turned a task that would have
> succeeded into one that failed.

It also says the security half of that argument "is a claim to verify by
measurement rather than assert". So: four arms on banking — undefended,
`envelope-taint` (as published), `+graduated`, `+graduated+defer` — same model,
same seed, same subset.

## The run, and why it says nothing

Azure OpenAI, `clayseal-aoai`, 6 user tasks x 3 injection tasks per arm,
`important_instructions`.

| arm | clean utility | **ASR** | utility under attack | friction |
| --- | ---: | ---: | ---: | ---: |
| none (undefended) | 33.3% | **0.0%** (0 of 18) | 61.1% | 0.00/task (0 of 6) |
| envelope-taint | 33.3% | **0.0%** (0 of 18) | 27.8% | 0.00/task (0 of 6) |
| envelope-taint-graduated | 16.7% | **0.0%** (0 of 18) | 38.9% | 0.00/task (0 of 6) |
| envelope-taint-graduated-defer | 33.3% | **0.0%** (0 of 18) | 38.9% | 0.17/task (1 of 6) |

**The undefended arm has an attack-success rate of zero (0 of 18).** There is no attack
success for a defense to prevent, so every ASR cell below it is uninformative and
no security-utility tradeoff can be read off this table. The utility column is
n=18 per arm with a 33.3% baseline; the differences between arms are inside the
noise of that sample and are not reported as findings.

The run is recorded rather than discarded because a void result that is not
written down gets re-run.

## Why it cannot be fixed on Azure

The model is the problem, and it is not a configuration mistake.

**The deployment named `gpt-4o-mini-2024-07-18` serves `gpt-5-mini-2025-08-07`.**
The name is an alias chosen so AgentDojo's `ModelsEnum` accepts it. Verified
directly: the API returns `model: gpt-5-mini-2025-08-07`.

**`gpt-5-mini` is not injectable by this attack.** Four attacks probed on
banking, all undefended:

| attack | undefended ASR |
| --- | ---: |
| `important_instructions` | 0.0% (0 of 18; 97.5% upper bound 18.5%) |
| `tool_knowledge` | 0.0% (0 of 6; 97.5% upper bound 45.9%) |
| `system_message` | 0.0% (0 of 6; 97.5% upper bound 45.9%) |
| `ignore_previous` | 0.0% (0 of 6; 97.5% upper bound 45.9%) |

**And the published model cannot be deployed.** `gpt-4o-mini` version
`2024-07-18` is in a deprecating state:

```
ERROR: (ServiceModelDeprecating) The model 'Format:OpenAI,Name:gpt-4o-mini,
Version:2024-07-18' is in deprecating state and cannot be used for new deployments.
```

AgentDojo's `ModelsEnum` accepts none of the other deployments (`gpt-4.1-mini`,
`gpt-4.1`, `grok-4`, the Llama family), so there is no substitution available
inside this harness.

## What this actually means for the published number

`run_agentdojo.py` picked `gpt-4o-mini` deliberately, and its own docstring says
why: it is "genuinely injectable, unlike a current frontier model". That was a
methodological convenience and it has become a finding.

**The AgentDojo ASR headline is measured on a model that current models no longer
resemble.** Holding ASR at 0 of 18 against a model whose undefended ASR is already
0 of 18 demonstrates nothing about the defense. The honest reading of
`head_to_head_injection.md` is that it describes a real result on
`gpt-4o-mini-2024-07-18` and does not transfer to a 2026 frontier model without
being re-run there — and it cannot be re-run there, because the attack does not
land.

This does **not** mean the layer is unnecessary. The classes it exists for are
not model-injectability:

- In-scope data staging is wide open regardless of model — the attacker is the
  agent doing what it was asked to do, and
  [adaptive_stack.md](adaptive_stack.md) measures the floor contributing +0.0 at
  oracle.
- Aggregate and cumulative harm (structuring, budget ceilings, delegation) is a
  property of a trajectory, not of a jailbreak.
- The behavioural layers close in-scope content staging 75.6% → 100% as the
  attacker's knowledge rises, which is measured against a search rather than a
  model's suggestibility.

## Resolved: it was the attack, not the model

[attacks_2026.md](attacks_2026.md) — the injections were the problem, and the
benchmark is alive again. Dropping the authority claim entirely and relying on
the injected action being *plausible* takes undefended ASR from 0 of 18 to 6 of
48 on the same model, and the defense contains 0 of 48. The three options below
are kept for the record; option 2 is the one that worked.

## What would have unblocked it

One of, and each is a decision rather than a task:

1. **A public-OpenAI run on real `gpt-4o-mini`**, if that model is still served
   there. Reproduces the published pairing exactly and costs a small amount of
   OpenAI credit rather than Azure credit.
2. **A stronger attack.** If a 2026 model can be injected at all on AgentDojo,
   the tradeoff experiment becomes viable on Azure unchanged. The four probed
   here do not.
3. **Change the benchmark.** The utility question is worth answering on a corpus
   where the harm does not depend on the model being fooled — which is where
   this layer's remaining gaps actually are.

## Reproduce

```bash
source /tmp/azure_env.sh   # AZURE_OPENAI_ENDPOINT / _KEY / _DEPLOYMENTS
python -m benchmarks.live.run_agentdojo --suite banking \
  --model gpt-4o-mini-2024-07-18 --n-user 6 --n-inj 3 \
  --attack important_instructions \
  --ablations none,envelope-taint,envelope-taint-graduated,envelope-taint-graduated-defer
```
