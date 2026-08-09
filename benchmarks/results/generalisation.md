# Pattern generalisation: the friction was a mandate-language problem

Held-out false-block was the worst number in the project: **47.91% on tau2**. A
grant rebuilt from half a session's benign events refused roughly half the rest.

The diagnosis settles what kind of problem it is. **7,143 of 7,143 held-out false
blocks on tau2 are `tool 'x' not granted`.** Not one is a path, a resource, an
argument or a rate. The whole number is one rung refusing a tool the same session
used, in the same domain, from the same small catalog, that happened to land in
the unobserved half.

That is not a scoping failure. Our loaders enumerate *what a session touched*;
an operator writes *what an agent is for*.

`benchmarks/core/patterns.py` restates a grant as patterns at a declared level
per dimension (tool, resource, path, verb), cumulative so containment can only
fall as the level rises. `BenchmarkTask.tool_patterns` and `resource_patterns`
default to `None`, which is today's exact behaviour, so level 0 is the identity.

## What it buys

| corpus | held-out FB before | after |
| --- | --: | --: |
| tau2 | 47.91% | **0.05%** |
| BFCL | 19.65% | 0.24% |
| AgentHarm | 57.73% | 0.92% |

Seed-stable: tau2 is 48.21% ± 0.18 before and 0.04% ± 0.01 after, over seeds 0-4.
`FB(granted)` is unmoved throughout.

Segment prefixes are nearly worthless on their own, buying 11 of the 48 points.
The namespace level buys the other 36. The verb dimension is load-bearing: tool
namespace alone leaves 8.59%, because a session's observed half may contain no
write and the capability rung then refuses the held-out one.

## What it costs, and the counterexample

**One knob is the wrong instrument.** RedCode falls 99.9% to 33.3% at the FIRST
path level, because a declared `app/**` generalised one segment up is the
filesystem root. But the tool dimension moves RedCode by zero at every level, and
the path dimension moves tau2 by zero at every level. The gain and the collapse
never touch, so the operating point exists only off the single-knob curve, and
the mandate format has to carry a level **per dimension**.

Measured only where generalisation can actually happen, at tool and verb
namespace with paths exact:

| corpus | clean tasks | contained | after | delta |
| --- | --: | --: | --: | --: |
| AgentThreatBench | 18 | 100.0% | 100.0% | 0.0 |
| RedCode | 50 | 99.9% | 99.9% | 0.0 |
| IPI-Coding | 10 | 100.0% | 100.0% | 0.0 |
| b3 | 21 | 66.7% | 66.7% | 0.0 |
| AgentHarm | 176 | 21.6% | 20.9% | **-0.8** |
| **Mind2Web-SC** | 100 | **98.0%** | **0.0%** | **-98.0** |

**Mind2Web-SC is the counterexample and it is decisive.** Its containment *is* the
exact resource, minted from the principal's attested attributes, so generalising
the grant admits everything. It breaks at the first level.

## The limit that invalidates the reassuring rows

Six corpora have **zero clean tasks**: ASB, InjecAgent, SLEIGHT, AdvBench-Agent,
MCP-Attack and the fixture. No namespace can be learned where every task carries
an attack, so the namespace level is **inert** on all of them.

Their unchanged containment means "generalisation did not happen", not
"generalisation is safe". Anyone quoting "containment held on most corpora"
without this sentence is quoting a decoration. The honest evidence base is the
six rows above.

ATIF is a related case: its gain (21.29% to 8.39%) comes entirely from segment
prefixes, because its 38 tasks sit in 38 singleton buckets with no peer traffic
to generalise to. **A corpus of one-off goals gets nothing from this mechanism,
and real deployments contain those.**

## The deployment risk no corpus here can measure

The namespace is learned from logs. Every corpus hands us a clean/attack
partition for free; in production that partition is exactly what you do not have.
A fortnight of real logs may contain a compromised session, and **a namespace
that absorbs an attacker's tool once grants it forever.**

That is a provenance problem rather than a pattern problem, and it is the reason
this ships as a measured transform with a per-dimension level in the mandate,
never as a default.

## One free improvement, taken

Rebuilding RedCode's path scope from clean traffic at one segment up (`app/*`
rather than the declared `app/**`) contains the single attack event the shipped
grant admits:

| grant | contained | false-block |
| --- | --: | --: |
| declared `app/**` | 99.86% | 0.00% |
| from traffic, exact | 100.00% | **15.12%** |
| from traffic, up1 | **100.00%** | **0.00%** |

The exact level is the instructive row: rebuilding a path grant from observed
instances alone costs 15% of benign traffic, and one segment of generalisation
removes all of it. This is a different mandate from the shipped one, so it
belongs in its own row rather than in the headline.

## Reproduce

```bash
.venv/bin/python -m benchmarks.generalize --typed tool+verb
.venv/bin/python -m benchmarks.generalize --typed path --paths-from-traffic
```
