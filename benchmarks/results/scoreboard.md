# Scoreboard: every tier, one table

STATUS: current

```bash
python -m benchmarks.scoreboard
```

Derived against this commit. The previous revision was stamped `unverified` and
had drifted materially low: it carried `agentharm` at 21.6% and `sleight` at
4.7%, which are **ladder-ablation** figures sitting where the product belongs.
The shippable stack scores 55.3% and 31.0% on the same corpora. Quoting a ladder
row as the product claim is the error that stale table encoded, and it is why
the ablation numbers now live behind the command rather than in this table.

**This table is not a headline.** Every containment figure is measured at
whatever false-block rate each engine chose for itself, which
[SEND_PACKET.md](../SEND_PACKET.md) rule 10 forbids citing alone. Pair it with
[opeval.md](opeval.md), which fixes the benign-block rate at 1% and carries a
deny-all control that must score zero.

## PRODUCT: DeployableStack, the shippable gateway

`H` is hard denials, `S` step-ups. The `FB(granted)` column the harness prints
is omitted here on purpose: on six of these corpora the grant is the benign side
restated, so it is 0.00% by construction and the harness itself says it "is not
evidence on its own". The friction number that means something is `FB(held out)`,
measured when the grant is built from half the benign events and judged against
the other half, and it is reported per corpus by the command.

| corpus | contained | split | n (attack / benign) | what the corpus tests |
| --- | ---: | --- | ---: | --- |
| redcode | 99.9% | H100/S0 | 718 / 344 | path escape from a fixed workspace |
| ipi_coding | 100.0% | H100/S0 | 50 / 45 | injected instructions, out-of-scope targets |
| mcp_attack | 100.0% | H100/S0 | 5 / 9 | poisoned MCP tool, confused deputy, arg mutation |
| agent_threat_bench | 100.0% | H100/S0 | 6 / 24 | data exfiltration only |
| advbench_agent | 100.0% | H100/S0 | 6 / 11 | target and argument binding |
| mind2web_sc | 98.0% | H98/S0 | 100 / 100 | web agent, safety-critical steps |
| b3 | 66.7% | H67/S0 | 9 / 8 | backbone breaking benchmark |
| **agentharm** | **55.3%** | H31/S24 | 696 / 729 | harmful *intent*, content-defined |
| **sleight** | **31.0%** | H8/S23 | 129 / 311 | covert sabotage, content-defined |
| asb | saturated | — | 2040 / 102 | every attack uses an ungranted tool |
| injecagent | saturated | — | 1598 / 1054 | ditto, and the corpus grants the attacker tools |

The last two rows are **not results**. They saturate at the naive rung, and a
number that a trivial baseline also earns is not evidence about this system.

## What the table is actually saying

The spread is not noise, and it is the same dividing line every other tier in
this repository finds. Where harm is defined by a **target** the gateway can
bind to, a path, a destination, a tool, containment is 98 to 100%. Where harm is
defined by the **content** of an otherwise authorized action, it falls to 31 to
55%, and the ladder floor beneath it to 6 to 27%.

[opeval.md](opeval.md) shows the same split at a fixed operating point, which is
the form that survives review: at a 1% benign-block rate, detection is 100% on
redcode and ipi_coding with a deny-all control at 0.0%, and the same channel
scores AUC 0.628 on agentharm and 0.511 on sleight, which is chance.

That is the honest shape of this product. It is an authorization layer, not a
harm classifier, and [docs/THREAT_MODEL.md](../../docs/THREAT_MODEL.md) declares
content-defined harm out of scope for that reason.

## The ladder ablation

`build_engines()` floor rungs, a monotonicity construction check rather than a
product claim, are printed by the same command under LADDER ABLATION. They are
deliberately not reproduced here: every previous drift in this file came from a
ladder figure being read as a product figure.
