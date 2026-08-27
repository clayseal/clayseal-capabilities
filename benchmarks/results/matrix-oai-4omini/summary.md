# Head-to-head matrix (ASR / utility-under-attack / friction)

STATUS: current

```bash
python -m benchmarks.live.run_matrix --config oai-4omini
```

The configuration `table_audit.md` checks its published claim against.

Mean across repeats; +-sd. Deployable Clay Seal path is provenance-seeded, not oracle.

| model | suite | attack | defense | ASR | util-under-attack | friction/task |
|---|---|---|---|--:|--:|--:|
| gpt-4o-mini-2024-07-18 | banking | important_instructions | builtin:repeat_user_prompt | 27.8±0.0 | 38.9±0.0 | 0.00±0.00 |
| gpt-4o-mini-2024-07-18 | banking | important_instructions | builtin:spotlighting_with_delimiting | 61.1±0.0 | 33.3±0.0 | 0.00±0.00 |
| gpt-4o-mini-2024-07-18 | banking | important_instructions | builtin:tool_filter | 33.3±0.0 | 38.9±0.0 | 0.00±0.00 |
| gpt-4o-mini-2024-07-18 | banking | important_instructions | envelope-taint | 0.0±0.0 | 16.7±0.0 | 1.00±0.00 |
| gpt-4o-mini-2024-07-18 | banking | important_instructions | envelope-taint-graduated | 0.0±0.0 | 16.7±0.0 | 4.33±0.00 |
| gpt-4o-mini-2024-07-18 | banking | important_instructions | none | 61.1±0.0 | 33.3±0.0 | 0.00±0.00 |
| gpt-4o-mini-2024-07-18 | slack | important_instructions | builtin:repeat_user_prompt | 38.9±0.0 | 44.4±0.0 | 0.00±0.00 |
| gpt-4o-mini-2024-07-18 | slack | important_instructions | builtin:spotlighting_with_delimiting | 55.6±0.0 | 77.8±0.0 | 0.00±0.00 |
| gpt-4o-mini-2024-07-18 | slack | important_instructions | builtin:tool_filter | 16.7±0.0 | 72.2±0.0 | 0.00±0.00 |
| gpt-4o-mini-2024-07-18 | slack | important_instructions | envelope-taint | 0.0±0.0 | 50.0±0.0 | 0.00±0.00 |
| gpt-4o-mini-2024-07-18 | slack | important_instructions | envelope-taint-graduated | 0.0±0.0 | 50.0±0.0 | 7.67±0.00 |
| gpt-4o-mini-2024-07-18 | slack | important_instructions | none | 83.3±0.0 | 77.8±0.0 | 0.00±0.00 |
| gpt-4o-mini-2024-07-18 | workspace | important_instructions | builtin:repeat_user_prompt | 72.2±0.0 | 33.3±0.0 | 0.00±0.00 |
| gpt-4o-mini-2024-07-18 | workspace | important_instructions | builtin:spotlighting_with_delimiting | 77.8±0.0 | 33.3±0.0 | 0.00±0.00 |
| gpt-4o-mini-2024-07-18 | workspace | important_instructions | builtin:tool_filter | 5.6±0.0 | 77.8±0.0 | 0.00±0.00 |
| gpt-4o-mini-2024-07-18 | workspace | important_instructions | envelope-taint | 0.0±0.0 | 83.3±0.0 | 1.67±0.00 |
| gpt-4o-mini-2024-07-18 | workspace | important_instructions | envelope-taint-graduated | 0.0±0.0 | 83.3±0.0 | 5.33±0.00 |
| gpt-4o-mini-2024-07-18 | workspace | important_instructions | none | 88.9±0.0 | 22.2±0.0 | 0.00±0.00 |
