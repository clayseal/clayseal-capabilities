# An observed grant is not an authorization of its own gaps

STATUS: current

```bash
python -m benchmarks.observed_grant --sweep
```

## The problem

Thirteen loaders build a task's grant from the tools its own benign events use,
and a deployment that derives a policy from a recorded session does the same
thing. Every tool the recording missed is then refused, **even where the same
mandate already authorizes that verb class**. The mandate says the agent may
modify; the tool list says which modify-tools happened to appear in the
recording.

Measured on held-out mandates, where the grant is built from half a task's
benign events and scored on the other half, this refuses **42.99% of 5,441
benign tau2 events**. Every top denial reason is the same shape:

```
221  tool 'grant_app_permission' not granted
209  tool 'enable_roaming' not granted
200  tool 'toggle_roaming' not granted
```

This is the deterministic form of [agentdyn.md](agentdyn.md), where open-ended
tasks lose all utility because the next step cannot be enumerated in advance.

## Three enumerations, not one

The first attempt admitted the tool and moved the refusal one gate down, then
the next. A grant derived from traffic enumerates the same tools three times:

| gate | refusal after fixing the one above it |
| --- | --- |
| tool allow-list | `tool 'toggle_roaming' not granted` |
| capability list | `no capability for mcp:tool:toggle_roaming:write` |
| resource scope | `resource 'mcp:tool:toggle_roaming' out of scope` |

They have to move together or not at all, which is why `grant_is_observed` is
one flag rather than three and why the unit test asserts that admitting the
tool alone is not enough.

## Result

`grant_is_observed=True` puts an out-of-grant tool to the same shape judge the
resource path already used: the deployment's own catalogue, the sealed goal and
the mandate's verb classes. No argument values, no tool output.

| | held-out false-block, tau2, n=5,441 |
| --- | ---: |
| shipped default | 42.99% |
| `grant_is_observed`, cap 8 | **0 of 5,441**, 97.5% upper bound 0.07% |

Cap sweep, showing the default already suffices:

| cap | off | 2 | 4 | **8 (default)** | 16 | 32 | 64 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| tau2 held-out FB | 42.99% | 5.70% | 0/5441 | **0/5441** | 0/5441 | 0/5441 | 0/5441 |

## What it costs, and which rows are evidence

| corpus | contained off | on | tools admitted |
| --- | ---: | ---: | ---: |
| agentharm | 55.3% | 55.3% | 33 |
| asb | 100.0% | 100.0% | 408 |
| injecagent | 100.0% | 100.0% | 179 |
| mcp_attack | 100.0% | 100.0% | 1 |
| redcode | 100.0% | 100.0% | **0** |
| sleight | 31.0% | 31.0% | **0** |
| ipi_coding | 100.0% | 100.0% | **0** |
| advbench_agent | 100.0% | 100.0% | **0** |
| agent_threat_bench | 100.0% | 100.0% | **0** |

**The `admitted` column is the control and it is why five of these rows are not
evidence.** A corpus where the extension never fired cannot say anything about
what the extension costs, and reporting nine unchanged rows without it would
claim eight times the support this actually has. The load-bearing rows are
agentharm, asb and injecagent, where 620 tools were admitted and containment
did not move.

**Why containment holds where it was tested.** The judge refuses what the goal
does not imply, and the refusal simply arrives at a better-justified gate. On
ASB the denial text changes from `tool 'ResearchDataTheft' not granted` to
`tool 'ResearchDataTheft' not in the goal's plan`. The enumerated list was not
what caught these attacks; path scope, egress binding and argument binding
were, and they are untouched.

## Limits

- **This is the deterministic proxy for AgentDyn, not AgentDyn.** That suite
  needs a live model and has no loader here, so the 21.67 interruptions per task
  in [agentdyn.md](agentdyn.md) stand until someone re-runs it. What is measured
  is the same mechanism on replayed traffic.
- **bfcl is not applicable.** Its grant is not observed-derived, so
  `hold_out_corpus` corrects nothing and the row is blank rather than a rate.
- **Off by default, and it must stay off wherever a human wrote the tool
  list.** There the list is an authorization and widening it overrides the
  author. The flag is for grants that were transcripts.
- **One corpus carries the utility claim.** tau2 is the only fetched corpus
  whose grant is observed-derived and large enough to hold out.
