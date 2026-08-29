# Documentation

Start with the [README](../README.md) for what Clay Seal is and a runnable
example. This page says which document answers which question.

## Running it

| Document | Answers |
| --- | --- |
| `clayseal try` | What does it actually do? One minute, no key, no setup. |
| [DEV_GUIDE.md](DEV_GUIDE.md) | How do I install it, wire it into my agent, and call the API? |
| [POLICY.md](POLICY.md) | What can a policy file say, and what does each rule do? |
| [DEPLOYMENT_SHAPE.md](DEPLOYMENT_SHAPE.md) | Where does the gateway sit, and what does it need from the rest of my system? |
| [PRIVACY.md](PRIVACY.md) | What data does it hold, where does it write, and what leaves the process? |

## Judging whether to trust it

| Document | Answers |
| --- | --- |
| [EVIDENCE.md](EVIDENCE.md) | What has it been measured at, on whose data, and what does it cost? |
| [THREAT_MODEL.md](THREAT_MODEL.md) | What is it defending against, what is it not, and how are keys handled? |
| [CONTROLS.md](CONTROLS.md) | Which compliance controls does its evidence support? |
| [benchmarks/README.md](../benchmarks/README.md) | How is it measured? |
| [benchmarks/results/README.md](../benchmarks/results/README.md) | What do the measurements say? |

## How it works inside

These explain design decisions. Read them if you are changing the code or
checking a claim, not to use the library.

| Document | Subject |
| --- | --- |
| [intent_envelope_design.md](intent_envelope_design.md) | How a sealed goal becomes a set of checkable constraints |
| [intent_envelope_generation.md](intent_envelope_generation.md) | How that envelope is built from the goal text |
| [dynamic_sandbox.md](dynamic_sandbox.md) | The behavioural layer that watches a session over time |
| [ivisor_integration.md](ivisor_integration.md) | Enforcement at the syscall boundary, below the tool call |
| [cross_layer_integration.md](cross_layer_integration.md) | How this layer meets the identity and receipts layers |

## Method

How the numbers were produced and where they can mislead.

| Document | Subject |
| --- | --- |
| [benchmark_program.md](benchmark_program.md) | What each benchmark tier is for |
| [METHODOLOGY_MEMO.md](METHODOLOGY_MEMO.md) | Choices made when measuring, and why |
| [methodology_audit.md](methodology_audit.md) | Where the utility metric can mislead |
| [sota_trajectory_control.md](sota_trajectory_control.md) | Comparison against published systems |
