# AgentHarm, DeployableStack (current) vs stale ladder

STATUS: current

```bash
python -m benchmarks.cli --dataset agentharm --mode ladder --ci --json benchmarks/results/new-suites/agentharm.json
```

## DeployableStack (authoritative for product claims)

From `benchmarks/results/cross_stack.md` (det soft content, no LLM):

| Layer | Rate | Notes |
| --- | --: | --- |
| Hard | **27.2%** | Destination / grant pins (grading-function) |
| Soft | **18.1%** | `_HARM_CUES` STEP_UP; cue in body, absent from sealed benign goal |
| Union | **45.3%** | Autonomous halt; **FB 0%** |
| Soft (online LLM, prior) | 24.1% | Union ~51.3%; hard unchanged; never quote as hard ASR |

Behavior-prompt heuristic catch (`agentharm_content.md`): **88/176 (50.0%)**.

## Stale ladder table (pre–grading-targets / pre–DeployableStack)

The ladder numbers below are historical (~6.3% tool-allowlist era) and must not be
cited as the current product grade. See `cross_stack.md` instead.

| Engine | Attack prevented | False-block |
| --- | --- | --- |
| allow-all | 0.0% | 0.0% |
| tool-allowlist … velocity | ~6.3% | 0.0% |
| deny-all | 100.0% | 100.0% |
