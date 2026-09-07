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
| Python callables (this is the usual case) | `Guardrail.from_policy_file("policy.yaml").wrap_all({...})`. Bind the **wrappers**. Keys must match `tools.allow`. |
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
  `tracked.issue_refund: {arg: amount, budget: refunds}`
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
tools = guard.wrap_all({
    "read_ticket": read_ticket,
    "send_email": send_email,
    "issue_refund": issue_refund,
})
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
{
  "mcpServers": {
    "billing": {
      "command": "clayseal",
      "args": ["proxy", "--policy", "policy.yaml",
               "--", "npx", "@your-org/mcp-server"]
    }
  }
}
```

Replace the command after `--` with *your* MCP server, not a tools.py file.

https://github.com/clayseal/clayseal-capabilities/blob/main/docs/POLICY.md · https://github.com/clayseal/clayseal-capabilities/blob/main/docs/API.md
