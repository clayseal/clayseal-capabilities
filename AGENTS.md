# Agent notes — Clay Seal

This directory is the **Clay Seal library** (`pip install clayseal`): a policy
gateway that authorizes each agent tool call against a reviewable file,
including running totals and argument provenance.

## Which section do you want?

- **Installing Clay Seal into some other app** → "Deploy into another project"
- **Changing this library** → "Changing this repository"

Do not start in `benchmarks/` or `demo/`. Neither is the product.

## Deploy into another project

You do not need this checkout. In the app you are editing:

```bash
pip install clayseal
clayseal try --fast
clayseal howto
clayseal policy new > policy.yaml
clayseal policy lint policy.yaml
clayseal skill --write
```

`howto` is the runbook (verbs, `paths.pathless`, proxy vs wrap, a worked
billing policy). `skill --write` drops `.cursor/skills/clayseal/SKILL.md` and
`.claude/skills/clayseal/SKILL.md`.

Enforcement:

- MCP (Claude Desktop, Cursor): `clayseal proxy --policy policy.yaml -- <server>`
  in `.cursor/mcp.json`. Not `clayseal serve`.
- Python: `Guardrail.from_policy_file("policy.yaml").wrap_all({...})`, bind
  the wrappers. Catch `Refused` (give `str(exc)` to the model) and
  `StepUpRequired` (ask a person). `guard.saw(source, text)` for documents
  that were not tool returns.

Effects are only `read`, `write`, `send`, `transfer`, `call`. Tools with no
file path go in `paths.pathless`.

https://github.com/clayseal/clayseal-capabilities/blob/main/docs/START.md · https://github.com/clayseal/clayseal-capabilities/blob/main/docs/POLICY.md · https://github.com/clayseal/clayseal-capabilities/blob/main/docs/API.md

## Changing this repository

- Library tests: `pytest python/tests -q`
- Do not point the CLI, README, or anything a `pip install` user sees at
  checkout-only paths. Use a GitHub URL or a command that ships in the wheel
  (`clayseal howto`, `clayseal policy new`).
- Product docs live under `docs/`. `benchmarks/` carries the measurement
  record and its own docs; do not mix
  its numbers into the README or the CLI.
- `AGENTS.md`, `llms.txt`, and the skill files are generated from
  `clayseal/capabilities/agent_guide.py`. Edit that module and copy, or the
  match tests fail.
