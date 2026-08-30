# Cross-stack generalizability

STATUS: current

```bash
python -m benchmarks.cross_stack
```

SessionBroker via DeployableStack. hard = DENY (floor/declaration); soft = STEP_UP (content/sealed-plan); union = autonomous halt. Never quote soft as hard ASR. Tags: TARGET = path/dest escape; SATURATED = allowlist-shaped (~100% hard); CONTENT = meaning/covert; HONESTY = under-scored / constructed-event rows. AgentLeak is a flow probe (see `python -m benchmarks.agentleak_flow`), not a ladder ATTACK-event headline. ladder_* is the monotone floor ablation.

| Corpus | Tag | Hard | Soft | Union | FB (h/s) | J | Ladder | n |
| --- | --- | --: | --: | --: | --: | --: | --: | --- |
| redcode | TARGET | 99.9% | 0.0% | 99.9% | 0.0/0.0% | 1.00 | 99.9% | 718a/344b |
| agentharm | CONTENT | 30.9% | 24.4% | 55.3% | 0.0/0.0% | 0.55 | 27.2% | 696a/729b |
| sleight | CONTENT | 7.8% | 23.3% | 31.0% | 0.0/3.5% | 0.27 | 6.2% | 129a/311b |
| ipi_coding | TARGET | 100.0% | 0.0% | 100.0% | 0.0/0.0% | 1.00 | 100.0% | 50a/45b |
| mcp_attack | TARGET | 100.0% | 0.0% | 100.0% | 0.0/0.0% | 1.00 | 100.0% | 5a/9b |
| asb | SATURATED | 100.0% | 0.0% | 100.0% | 0.0/0.0% | 1.00 | 100.0% | 2040a/102b |
| advbench_agent | SATURATED | 100.0% | 0.0% | 100.0% | 0.0/0.0% | 1.00 | 100.0% | 6a/11b |
| agent_threat_bench | SATURATED | 100.0% | 0.0% | 100.0% | 0.0/0.0% | 1.00 | 100.0% | 6a/24b |
| mind2web_sc | HONESTY | 98.0% | 0.0% | 98.0% | 1.0/0.0% | 0.97 | 98.0% | 100a/100b |
| b3 | HONESTY | 66.7% | 0.0% | 66.7% | 0.0/0.0% | 0.67 | 66.7% | 9a/8b |
