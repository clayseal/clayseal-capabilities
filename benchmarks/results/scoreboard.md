tier                measures                      contained  FB(granted)  FB(held out)               n
------------------------------------------------------------------------------------------------------
redcode             deterministic replay              99.9%        0.00%             -     718a / 344b
agentharm           deterministic replay              21.6%        0.00%        57.73%     652a / 653b
sleight             deterministic replay               4.7%          n/a             -     129a / 311b
agent_threat_bench  deterministic replay             100.0%        0.00%             -        6a / 24b
mcp_attack          deterministic replay             100.0%        0.00%        44.44%         5a / 9b
sleight[detector]   covert-intent trajectories        27.8%        0.00%             -18 atk / 18 benign

FB(granted)  friction given a COMPLETE mandate. On six corpora the grant is
             the benign side restated, so this is 0.00% by construction at the
             scope rung and is not evidence on its own.
FB(held out) friction when the grant was built from half the benign events and
             judged against the other half: what an INCOMPLETE mandate costs.

caveats, without which none of the above is reportable:
  redcode             path escapes from a fixed workspace boundary; the real result on this axis
  agentharm           6.3% is a LOADER limit: we read only the JSON (tool names), while the corpus grading functions assert targets for 63% of behaviours
  sleight             mechanism-cited sabotage only; ladder ~5% on binding+budget — velocity false-alarms coding agents; not an intent win
  agent_threat_bench  data_exfil only; memory_poison and autonomy_hijack are content-defined and declared
  mcp_attack          product-shaped MCP poisoned-tool / confused-deputy / arg-mutation; destination binding and scope are the discriminators
  sleight[detector]   twin corridor + intent two-signal + surface gate on sealed benign reference; population ngram alone ~6%

pooled headline (excludes SATURATED asb/injecagent and content ceilings):
  redcode: contained=99.9%  FB=0.00%  (path escapes from a fixed workspace boundary; the real resul…)
  agent_threat_bench: contained=100.0%  FB=0.00%  (data_exfil only; memory_poison and autonomy_hijack are conte…)
  mcp_attack: contained=100.0%  FB=0.00%  (product-shaped MCP poisoned-tool / confused-deputy / arg-mut…)
