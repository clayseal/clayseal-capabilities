"""What a coding agent needs after `pip install clayseal`.

The README and `docs/START.md` are written for a person with a browser. An
agent that installed from PyPI has neither a checkout nor those paths, and
pointing it at them is the same class of bug as `clayseal try` naming
`docs/EVIDENCE.md`. These strings ship in the wheel. `clayseal howto` and
`clayseal skill` print them; the copies at the repository root exist so GitHub
and Cursor can find them without running anything.
"""
from __future__ import annotations

REPO = "https://github.com/clayseal/clayseal-capabilities"
DOCS = f"{REPO}/blob/main/docs"

# Copied into `howto`. A first agent pastes this; it has to lint.
WORKED_POLICY = """\
version: 1
goal:
  id: billing-run
  summary: Refund disputed invoices and email ops@acme.example.
expires_at: 2030-01-01T00:00:00Z
profile: supervised
tools:
  allow: [read_ticket, send_email, issue_refund]
  harmless: [read_ticket]
  effects:
    read_ticket: read
    send_email: send
    issue_refund: transfer
paths:
  pathless: [read_ticket, send_email, issue_refund]
egress:
  domains: [acme.example]
  recipients: [ops@acme.example]
  bind_recipients: true
budgets:
  value:
    ceilings: {refunds: "1000.00"}
    tracked:
      issue_refund: {arg: amount, budget: refunds}
  calls:
    ceilings: {sends: 20}
    tracked: {send_email: sends}
"""


def _indent(text: str, n: int) -> str:
    pad = " " * n
    return "\n".join((pad + line) if line else line for line in text.splitlines())


HOWTO = f"""\
Clay Seal authorizes each agent tool call against a policy file a person can
review. It sees the whole session (running totals, where arguments came from),
not one call at a time.

Do these in order. After `pip install clayseal` you do not need this git repo.

1. Prove it
   clayseal try --fast

2. Write a policy in the project you are editing
   clayseal policy new > policy.yaml

3. Edit policy.yaml (the file comments say what each key is). `policy new`
   matches `clayseal try`: a read, a send, a refund. Rename the `your_*`
   tools. Required:
   - goal.summary  one sentence: what this session is for
   - tools.allow   the real tool names (not your_read_tool)
   - tools.effects exactly one of: read, write, send, transfer, call
        read_ticket / list_*     -> read
        send_email / slack_*     -> send
        issue_refund / pay_*     -> transfer
        write_file / patch       -> write
        unknown RPC              -> call
   - paths.pathless  every tool that does NOT take a file path
        (email, refunds, HTTP). If you skip this, `clayseal proxy` refuses
        the call: "no path argument was found".
   - A ceiling on something countable:
        money  -> budgets.value  (tracked arg: amount)
        counts -> budgets.calls
   - egress.recipients  actual mailboxes if the agent can send.
        Keep egress.domains too. An empty recipients list is domain-only
        (every mailbox), not "nobody". A mailbox on the domain that is not
        in recipients is StepUpRequired (HELD) — the reason says
        "not in egress.recipients". Off-domain mail is also HELD/refused.
        A spent budget is Refused.

4. clayseal policy lint policy.yaml
   Exit 1 with errors means the template is still unedited. Warnings are
   decisions you have not made yet; read them. `unaccounted-tool` means add a
   budget or list the tool in harmless. Re-lint until errors are gone.

5. Enforce — pick ONE. If you only have Python functions, do B. Do not point
   `clayseal proxy` at a .py file that is not an MCP server.

   A. MCP client (Claude Desktop, Cursor, Claude Code)
      Point the client at Clay Seal, not at the server. Use `proxy` (stdio).
      Do not use `clayseal serve` here; that is HTTP.

      clayseal proxy --policy policy.yaml -- <your mcp server command>

      .cursor/mcp.json / Claude Desktop MCP config:

      {{
        "mcpServers": {{
          "billing": {{
            "command": "clayseal",
            "args": ["proxy", "--policy", "policy.yaml",
                     "--", "npx", "@your-org/mcp-server"]
          }}
        }}
      }}

      Replace the command after `--` with the server you already run.

   B. Python tools (LangGraph, OpenAI Agents SDK, CrewAI, a loop)
      Wrap the functions, then hand the WRAPPERS to the framework.

      from clayseal.capabilities import Guardrail, Refused, StepUpRequired

      guard = Guardrail.from_policy_file("policy.yaml")
      tools = guard.wrap_all({{
          "read_ticket": read_ticket,      # your functions
          "send_email": send_email,
          "issue_refund": issue_refund,
      }})
      # One Guardrail per session. A new one is a new session: ceilings start over.

      try:
          tools["issue_refund"](invoice="INV-001", amount=900.0)
      except Refused as exc:
          # budget / not granted — give this to the model; do not retry
          return str(exc)
      except StepUpRequired as exc:
          # off-list recipient, etc. Ask a person. try prints this as HELD.
          return str(exc)

      If the agent read a document that was not a tool return (pasted ticket,
      RAG chunk): guard.saw("tickets/T-1042.txt", ticket_body)

6. Leave the skill in this project so the next session has it
   clayseal skill --write

Worked policy (refunds + email). Copy, then rename tools to yours:

{_indent(WORKED_POLICY, 2)}

Do not:
- Invent verbs. compile.k (only if you compile from a document) narrows
  tools.allow; it cannot add a tool. Skip it for a hand-written policy.
- Use `clayseal serve` for Claude Desktop or Cursor.
- Catch Exception and retry a Refused call with the same arguments.
- Point a pip-install user at files that live only in the git checkout.

{DOCS}/POLICY.md  (every key)
{DOCS}/API.md     (Guardrail, Refused, StepUpRequired)
{DOCS}/START.md   (human walkthrough)
"""


SKILL = f"""\
---
name: clayseal
description: >-
  Installs and deploys Clay Seal so each agent tool call is authorized against
  a policy.yaml (session budgets, argument provenance, prompt-injection). Use
  when adding guardrails, an MCP proxy, wrapping LangGraph or OpenAI or CrewAI
  tools, writing policy.yaml, authorizing refunds or email, or when the user
  mentions clayseal, tool allowlists, Claude Desktop MCP, Cursor MCP, or
  putting a policy in front of an agent.
---

# Clay Seal

Gateway in front of agent tools. Judging one call at a time is not enough;
this judges the session.

Prefer `clayseal howto` (ships in the wheel) over fetching docs.

## Runbook

```bash
pip install clayseal
clayseal try --fast
clayseal policy new > policy.yaml
# edit, then:
clayseal policy lint policy.yaml
clayseal skill --write
```

Then pick ONE enforcement. Python functions → wrap. An MCP server → proxy.
Do not point `proxy` at a plain .py module.

| How the agent calls tools | What to do |
| --- | --- |
| Python callables (this is the usual case) | `Guardrail.from_policy_file("policy.yaml").wrap_all({{...}})`. Bind the **wrappers**. Keys must match `tools.allow`. |
| Claude Desktop / Cursor / any MCP client | `clayseal proxy --policy policy.yaml -- <mcp server>`. Put that in `.cursor/mcp.json`. Do **not** use `clayseal serve` (HTTP only). |

## What to edit in policy.yaml

`policy new` is already a read + send + refund, like `clayseal try`. Rename
the `your_*` tools.

- `goal.summary` — one sentence for this session
- `tools.allow` — real names, not `your_read_tool`
- `tools.effects` — `send_email` is `send`; `issue_refund` is `transfer`;
  `write_file` is `write`. Only `read`, `write`, `send`, `transfer`, `call`.
- `paths.pathless` — every tool with **no file path**. Missing this is the
  usual `clayseal proxy` failure: "no path argument was found".
- Money: `budgets.value.ceilings.refunds: "1000.00"` and
  `tracked.issue_refund: {{arg: amount, budget: refunds}}`
- Send count: `budgets.calls.ceilings.sends: 20` and
  `tracked.send_email: sends` — otherwise lint warns `unaccounted-tool`
- Mail: keep `egress.domains: [acme.example]` and set
  `egress.recipients: [ops@acme.example]` with `bind_recipients: true`.
  Empty `recipients: []` is every mailbox on the domain, not "nobody".
  A mailbox on the domain that is not in the list is HELD
  (`StepUpRequired`); the reason says "not in egress.recipients".
- Lint `unaccounted-tool` means track it or list it under `tools.harmless`.

`Refused` is a spent budget or a tool not granted. `StepUpRequired` is a
person should look (off-list email under `profile: supervised`). `clayseal
try` prints the second as HELD.

## Python

```python
from clayseal.capabilities import Guardrail, Refused, StepUpRequired

guard = Guardrail.from_policy_file("policy.yaml")
tools = guard.wrap_all({{
    "read_ticket": read_ticket,
    "send_email": send_email,
    "issue_refund": issue_refund,
}})
try:
    tools["issue_refund"](invoice="INV-001", amount=900.0)
except Refused as exc:
    return str(exc)          # budget; do not retry the same args
except StepUpRequired as exc:
    return str(exc)          # ask a person (held)
guard.saw("tickets/T-1042.txt", ticket_body)
```

Construct `Guardrail` once per session and keep the wrappers. A new
`Guardrail` is a new session: ceilings start over.

## MCP config (only if you already run an MCP server)

```json
{{
  "mcpServers": {{
    "billing": {{
      "command": "clayseal",
      "args": ["proxy", "--policy", "policy.yaml",
               "--", "npx", "@your-org/mcp-server"]
    }}
  }}
}}
```

Replace the command after `--` with *your* MCP server, not a tools.py file.

{DOCS}/POLICY.md · {DOCS}/API.md
"""


AGENTS = f"""\
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
- Python: `Guardrail.from_policy_file("policy.yaml").wrap_all({{...}})`, bind
  the wrappers. Catch `Refused` (give `str(exc)` to the model) and
  `StepUpRequired` (ask a person). `guard.saw(source, text)` for documents
  that were not tool returns.

Effects are only `read`, `write`, `send`, `transfer`, `call`. Tools with no
file path go in `paths.pathless`.

{DOCS}/START.md · {DOCS}/POLICY.md · {DOCS}/API.md

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
"""


CONSUMER_AGENTS = """\
# Clay Seal

This project authorizes agent tool calls with Clay Seal.

```bash
clayseal howto
clayseal policy lint policy.yaml
```

1. Policy file: `policy.yaml` (`clayseal policy new` if missing). Edit TODOs,
   put non-file tools in `paths.pathless`, set `tools.effects` to one of
   `read`, `write`, `send`, `transfer`, `call`.
2. Python: `Guardrail.from_policy_file("policy.yaml").wrap_all({...})` and
   bind the wrappers. Construct the Guardrail once per session.
3. MCP (only if you already run a server): `.cursor/mcp.json` should run
   `clayseal proxy --policy policy.yaml -- <server>` (not `clayseal serve`).
4. Catch `Refused` (give `str(exc)` to the model) and `StepUpRequired` (ask a
   person). `guard.saw(source, text)` for documents that were not tool returns.
"""


LLMS = f"""\
# Clay Seal

> Policy gateway for AI agents. Authorizes each tool call against a reviewable policy.yaml: the grant, running totals, argument provenance, and the rest of the session.

## Start (run in order)

1. `pip install clayseal`
2. `clayseal try --fast` — demo, no key
3. `clayseal howto` — full deploy runbook (ships in the wheel)
4. `clayseal policy new > policy.yaml` then `clayseal policy lint policy.yaml`
5. MCP: `clayseal proxy --policy policy.yaml -- <server>` (Claude Desktop / Cursor). Python: `Guardrail.wrap_all`.
6. `clayseal skill --write` — drop a Cursor/Claude skill into this project

Non-file tools (email, refunds, HTTP) must be listed under `paths.pathless`. Effects are only `read`, `write`, `send`, `transfer`, `call`. Do not use `clayseal serve` for Claude Desktop; that command is HTTP. A mailbox on the granted domain that is not in `egress.recipients` is held (`StepUpRequired`), not allowed.

## Docs

- [First ten minutes]({DOCS}/START.md)
- [Policy reference]({DOCS}/POLICY.md)
- [API]({DOCS}/API.md) — `Guardrail`, `Refused`, `StepUpRequired`, `clayseal proxy`
- [Developer guide]({DOCS}/DEV_GUIDE.md)
- [Evidence]({DOCS}/EVIDENCE.md)
- [Threat model]({DOCS}/THREAT_MODEL.md)
- [Deployment shape]({DOCS}/DEPLOYMENT_SHAPE.md)

## Optional

- [Repository]({REPO})
- [Changelog]({REPO}/blob/main/CHANGELOG.md)
- [Security]({REPO}/blob/main/SECURITY.md)
"""


def howto_text() -> str:
    return HOWTO


def worked_policy_text() -> str:
    return WORKED_POLICY


def skill_markdown() -> str:
    return SKILL


def agents_markdown() -> str:
    return AGENTS


def consumer_agents_markdown() -> str:
    return CONSUMER_AGENTS


def llms_txt() -> str:
    return LLMS
