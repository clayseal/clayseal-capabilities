# Head-to-head plan: closing the SOTA-bar gaps that need compute

The detector correctness gaps (label leak, false-alarm-bound overclaim) are fixed
in the code. The remaining gaps from the field's SOTA-claim bar all need real
runs, not code correctness, so they are staged as VM jobs here.

## The bar we are clearing

From the agent-security literature (CaMeL 2503.18813, Progent 2504.11703,
AgentDojo 2406.13352, and the adaptive-eval papers 2606.26479 / 2505.18333), a
defense earns a comparative "state of the art" claim only with:

1. Head-to-head vs published defenses on a shared benchmark under one protocol.
2. Utility and security reported jointly (not security alone).
3. A defense-aware adaptive attacker on the DEPLOYABLE path (the field's hard gate).
4. Multiple seeds, confidence intervals, more than one model.
5. Clean ablations; the headline config must not depend on oracle hints.

## What is staged and runnable now

`benchmarks/live/run_matrix.py` (dispatch: `benchmarks/azure/run_headtohead.sh`)
runs the shared-protocol matrix:

- Defenses under one protocol: undefended `none`; AgentDojo's three published
  built-ins (`tool_filter`, `spotlighting`, `repeat_user_prompt`); and the
  DEPLOYABLE Clay Seal path (`envelope-taint`, `envelope-taint-graduated`),
  provenance-seeded, never the oracle map.
- Attacks: `important_instructions` (static) and `envelope_aware` (defense-aware
  adaptive), so the adaptive gate is run on the deployable path, not the oracle.
- Models: gpt-4o-mini-2024-07-18 and gpt-4o-2024-05-13 (fixes the single-model
  weakness; gpt-4o-2024-08-06 is not a valid ModelsEnum, use 05-13).
- Suites: banking, slack, travel, workspace.
- Repeats: 3 (mean +- sd on every cell), reporting the triple (ASR,
  utility-under-attack, friction/task).

Launch order (azure-verify discipline: dry-run, then pilot, then full):

    python -m benchmarks.live.run_matrix --dry-run            # no API calls
    OPENAI_API_KEY=... MODE=pilot benchmarks/azure/run_headtohead.sh   # ~192 runs
    OPENAI_API_KEY=... MODE=full  benchmarks/azure/run_headtohead.sh   # ~6.9k runs

Watch the pilot ASR/utility/friction before spending on the full matrix. Rate
limits matter: gpt-4o-mini has the higher TPM; run the two models in series, not
in parallel with any other job on the same key.

## What is NOT built yet: CaMeL and Progent

CaMeL and Progent are not AgentDojo built-in defenses, so `builtin:<name>` cannot
reach them. A true head-to-head needs each integrated as a defense the same
harness can ablate:

- Progent (arXiv:2504.11703): programmable privilege control; released for
  LangChain / OpenAI Agents SDK. Integration path: clone its repo, wrap its policy
  layer as a `ToolsExecutor` equivalent to `BrokerToolsExecutor`, register it as an
  ablation `progent` in `build_pipeline`.
- CaMeL (arXiv:2503.18813): dual-LLM dataflow / capabilities; code released.
  Heavier: it restructures the agent loop (quarantined LLM + interpreter), so it
  is a distinct pipeline, not a `ToolsExecutor` swap. Integration is a separate
  pipeline builder plus a metrics adapter to the same (ASR, utility) reporting.

Both need the py3.12 agentdojo env. This is the next discrete task after the
built-in matrix confirms the harness end-to-end; it is scoped, not started.

## Reporting

`summary.md` / `summary.json` land in the `--out` dir. The headline table is the
deployable Clay Seal path vs the built-ins, per model and suite, with the triple
and its spread across repeats. The oracle configs stay out of the headline and are
run only as an upper-bound ablation.
