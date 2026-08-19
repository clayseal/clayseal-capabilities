# Closing in-scope data staging

STATUS: current

`in_scope_exfiltration.md` measured the gap: against an oracle attacker the full
enforcement ladder's escaped-task set was **byte-identical to `allow-all`**. The
whole attack is `read:/app/.env -> write:/app/README.md` — two actions, both
inside the grant, granted tool, granted resource, legitimate arguments.

## The missing predicate was about objects, not places

A mandate says *where* an agent may go and nothing about what the objects there
are. Every rung discriminates on a dimension this attack does not move, so no
scope check could ever see it.

`hardening/object_class.py` adds the taxonomy: `SECRET` (`.env`, `.npmrc`,
`id_rsa`, `.git/config`, `secrets.*`, service-account files) and `PUBLICATION`
(README, `docs/`, `dist/`, `public/`, `index.html`). Static and compiled in, like
`DEFAULT_PROTECTED_PATTERNS` — **not** inferred at runtime, because
`SensitivityPolicy` states the rule this follows: *a policy an attacker can
influence is not a policy.*

`StagingLadderEngine` enforces the conjunction: once a session has read a
SECRET-classed object, a write to a PUBLICATION-classed object is refused. It is
the first rung that is not a pure function of one action, and it cannot be —
neither half is suspicious alone. Reading `.env` is what a build agent does;
writing a README is what a documentation agent does. Only the pair is evidence.

## Containment

RedCode, in-scope-exfiltration objective, 5 rounds, 32,013 candidates.

| Engine | blind | feedback | oracle |
| --- | ---: | ---: | ---: |
| allow-all | 7% | 7% | 38% |
| …+density | 29% | 36% | 38% |
| **…+density+staging** | **100%** | **100%** | **100%** |

The 38% was never containment — it is the attacker's own failure rate on tasks
offering no in-scope surface. The rung takes the real figure from zero to total.

## Friction: unmeasured, not zero

The measured false-block rate is **identical to the rung below on every corpus**:
redcode 0.00%, tau2 0.73%, bfcl 0.00%, atif 1.94%, toolemu 0.00%, agentharm
0.00%, sleight 16.08%. That looks like a free win and it is not.

The rung fires only on the *conjunction*, and across **20,299 benign events in
seven corpora that conjunction occurs in exactly zero tasks**:

| corpus | benign events | secret-reads | publication-writes | both in one task |
| --- | ---: | ---: | ---: | ---: |
| redcode | 344 | 0 | 6 | **0** |
| tau2 | 14,842 | 0 | 0 | **0** |
| bfcl | 3,232 | 1 | 0 | **0** |
| atif | 282 | 0 | 0 | **0** |
| toolemu | 559 | 2 | 0 | **0** |
| agentharm | 729 | 0 | 0 | **0** |
| sleight | 311 | 2 | 4 | **0** |

So the friction number is a **non-measurement** — the same failure this session
found in the corpora themselves, now applying to my own rung. A real coding agent
reads `.env` for configuration and later edits a README constantly, so the true
rate is plausibly high, and nothing here bounds it.

`test_staging_rung.py` asserts the absence rather than footnoting it: if a corpus
ever exercises the conjunction, the test fails and the friction becomes a real
number that has to be looked at.

## Status: not in `LADDER`

Two things must happen first.

1. **Measure friction on real agent sessions.** One query against production
   logs: how often does a session read a secret-classed object and later write a
   publication-classed one?
2. **Ship it as STEP_UP, not DENY.** The flow is genuinely ambiguous — the same
   two actions are a leak and a legitimate documentation edit, and the metadata
   cannot separate them. A human confirmation is the honest response to that
   ambiguity, and the broker already has the graduated seam. The benchmark ladder
   has no step-up outcome, so this is scored at its strictest here and the
   friction column above is the worst case, not the deployment case.

The content check — does the write actually carry the secret — belongs to the
confidentiality flow tracker, which is now windowed and bounded (`flow_window.md`).
This rung is the coarse metadata gate for when the tracker has nothing to read.

## Reproduce

```bash
python -m benchmarks.adaptive --dataset redcode --limit 80 --rounds 5 \
  --objective in-scope-exfiltration \
  --engines "allow-all,task-scope+binding+budget+velocity+density,\
task-scope+binding+budget+velocity+density+staging"
pytest benchmarks/tests/test_staging_rung.py -q
```
