# Head-to-head matrix (ASR / utility-under-attack / friction)

Mean across repeats; +-sd. Deployable Clay Seal path is provenance-seeded, not oracle.

| model | suite | attack | defense | ASR | util-under-attack | friction/task |
|---|---|---|---|--:|--:|--:|
| gpt-4o-mini-2024-07-18 | banking | important_instructions | envelope-taint | 0.0±0.0 | 22.2±0.0 | 0.50±0.00 |
| gpt-4o-mini-2024-07-18 | banking | important_instructions | envelope-taint-graduated | 0.0±0.0 | 27.8±0.0 | 4.17±0.00 |
| gpt-4o-mini-2024-07-18 | banking | important_instructions | none | 61.1±0.0 | 33.3±0.0 | 0.00±0.00 |
| gpt-4o-mini-2024-07-18 | slack | important_instructions | envelope-taint | 0.0±0.0 | 44.4±0.0 | 0.00±0.00 |
| gpt-4o-mini-2024-07-18 | slack | important_instructions | envelope-taint-graduated | 0.0±0.0 | 50.0±0.0 | 6.67±0.00 |
| gpt-4o-mini-2024-07-18 | slack | important_instructions | none | 83.3±0.0 | 83.3±0.0 | 0.00±0.00 |
| gpt-4o-mini-2024-07-18 | travel | important_instructions | envelope-taint | 5.6±0.0 | 55.6±0.0 | 0.50±0.00 |
| gpt-4o-mini-2024-07-18 | travel | important_instructions | envelope-taint-graduated | 0.0±0.0 | 66.7±0.0 | 1.50±0.00 |
| gpt-4o-mini-2024-07-18 | travel | important_instructions | none | 38.9±0.0 | 66.7±0.0 | 0.00±0.00 |
| gpt-4o-mini-2024-07-18 | workspace | important_instructions | envelope-taint | 0.0±0.0 | 83.3±0.0 | 2.17±0.00 |
| gpt-4o-mini-2024-07-18 | workspace | important_instructions | envelope-taint-graduated | 0.0±0.0 | 83.3±0.0 | 4.50±0.00 |
| gpt-4o-mini-2024-07-18 | workspace | important_instructions | none | 88.9±0.0 | 22.2±0.0 | 0.00±0.00 |
