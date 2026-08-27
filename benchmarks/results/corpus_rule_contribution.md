# What the corpus-derived rules contribute: nothing

STATUS: current

```bash
python -m benchmarks.bpl_sweep --suite full
python -m benchmarks.coverage --datasets agentharm,sleight,redcode,asb,injecagent --limit 4000 --engines deployable-stack
```

Three places in the library held literals copied from specific benchmark
scenarios. Each was measured by removing it and re-running every scored
population. **All three contribute zero to every published number.**

## How they were found

A cross-reference, not a reading: every compound string literal in the shipped
library, matched against the text of the benchmark scenarios and corpora. A
literal that appears in both and nowhere else is the signature.

| where | literal | origin |
| --- | --- | --- |
| `session_rules._UPLOAD_ARTIFACT_WORDS` | `ocelot` | the project name in sleight-bench `weight-exfil-eval-symlink` |
| `monitor/entailment._FREE_TEXT_TOOLS` | 22 tool names | AgentHarm's tool catalogue |
| `monitor/sealed_plan` secret paths | `data/models`, `anthropic-config`, `deploy/auth`, `db/app.conf`, `sanitize_rules`, `checkpoint` | one corpus's directory layout |

## What each is worth

| arm | sleight in-surface | agentharm in-surface | BPL joint | BPL false blocks |
| --- | --- | --- | --- | --- |
| as published | 28/122 | 196/507 | 52/132 | 2 |
| `session_rules=False` | 28/122 | 196/507 | 52/132 | 2 |
| corpus secret paths removed | 28/122 | 196/507 | not reached | not reached |
| AgentHarm tool list removed | not reached | not reached | not reached | not reached |

Benign cost is 0 of 20,619 events in every arm.

The switch was verified to reach the broker before the result was believed,
because an arm that silently does nothing produces exactly this table.
`session_rules=False` sets `broker.session_rules` to `False`; the pack really is
off in the second row.

## Why the AgentHarm list was never reached

`_FREE_TEXT_TOOLS` only runs when the LLM entailment judge is enabled, and every
benchmark passes `entailment_judge=None`. It could not have moved a published
number, and in a deployment it is inert for a different reason: no real system
has a tool called `create_ransomware`. Thirteen of its 22 names were already
covered by the `post_`/`send_` prefix rule beside it, and the prose test catches
an AgentHarm-shaped sample without any of them.

## What changed

All three are removed. The generalisable half of each is kept: the
symlink-into-results-then-zip-then-upload technique is a real exfiltration
pattern and the rule for it stays, keyed on the technique rather than on one
corpus's project name.

`session_rules.py` already documented itself honestly as corpus-derived, named
`ocelot` in a constant rather than burying it in a regex, and made the pack
switchable. What was missing was this measurement: the pack is on by default,
every published number was produced with it on, and its contribution had never
been stated. It is zero.

## The test that had to be inverted

`test_the_upload_rule_still_carries_its_corpus_literal` asserted `ocelot` was
PRESENT, and said it should be removed deliberately rather than silently if the
literal ever went. It went. The test now asserts the absence, so the class
cannot return unnoticed.
