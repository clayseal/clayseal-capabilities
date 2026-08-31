# Scoping the flow tier turns it from net-negative to net-positive

STATUS: current

```bash
python -m benchmarks.bpl_sweep --suite full --confidentiality scoped --observe-results
```

[flow_tier.md](flow_tier.md) reports the broadest declaration expressible,
`sensitive=("*",)` with no permitted destination. It contains 22 more attacks,
loses 53 benign tasks, and moves the joint score from 71 to 48. The falsifier
that declaration stated in advance fired.

The reason is visible in one trace: marking every read sensitive marks
`load_policy`'s prose, which the agent reads at the start of the session, after
which every subsequent write is carrying secret data.

## Result

| declaration | contained | completed | **joint** |
| --- | ---: | ---: | ---: |
| tier off | 73 | 130 | **71** |
| `sensitive=("*",)` | 95 | 77 | **48** |
| **scoped** | **76** | **130** | **74** |

Three gains, zero regressions, completion unchanged. Against the published
`clayseal` baseline the full stack is now **22 gains against 0 regressions,
exact McNemar p = 4.8e-07**.

## Where the scope comes from

**The catalogue, not the trajectory.** A tool named `fetch_credential` returns
credentials whatever the goal says, and the catalogue is fixed with the mandate
ahead of any untrusted content. A small lexicon over tool names decides what is
sensitive. Where no tool declares itself the policy is inactive and the tier
behaves exactly as before, so scoping can only cost what it earns.

**The sealed goal, resolved against the catalogue.** The permitted destination is
read from the goal summary and then resolved to a tool. Two bugs had to be fixed
to get there, and both were silent:

The destination regex required a TLD or a slash, so `"only on partner-api"`
yielded nothing. A goal that names its permitted sink and is not read produces a
rule refusing the sanctioned use while still containing the attack, which reads
as a working defense with an unexplained false block.

The sink was then emitted as a bare name and compared against a resource id, so
`partner-api` never matched `mcp:tool:call_partner_api`. The destination in that
scenario **is** the tool. Resolving names against the catalogue on a
separator-insensitive containment test is what the other rungs already do.

Sinks were also being read from `user_prompt` alone. The task text there never
names partner-api; the sealed goal summary does, and the summary is what every
other goal-derived rung reads. Deriving sensitivity from one input and sinks from
another refused the use the goal explicitly permits.

## What it does not reach

Only **2 of the 17** remaining confidentiality scenarios hold a tool whose own
name declares it confidential. The rest name no confidential object anywhere a
lexical rule can see, and reaching them needs a sensitivity classifier that this
work does not have.

The tier also requires the gateway to observe tool outputs, a stronger deployment
assumption than the rest of the ladder makes. It stays off in the published arm
for that reason, and is reported as its own configuration.
