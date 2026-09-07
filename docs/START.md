# Your first ten minutes

STATUS: current

From nothing installed to your own agent behind the gateway. Four steps, and
each one ends with something you can see working.

If you are a coding agent, run `clayseal howto` (it ships in the wheel) and
follow it. Put non-file tools in `paths.pathless`. Use `clayseal proxy` for
Claude Desktop / Cursor, not `clayseal serve`. `clayseal skill --write` leaves
a skill in the project you are editing.

If you want the reasoning behind any of it, [POLICY.md](POLICY.md) covers what a
policy can say and [EVIDENCE.md](EVIDENCE.md) covers what it has been measured
at. This page is just the path.

## 1. Watch it work

```bash
pip install clayseal
clayseal try
```

Two attacks, about a minute. The first is a run of eleven refunds that are each
inside the limit and together are not. The second is an email address that
arrived in a support ticket instead of from you.

Nothing there is a recording. Add `--explain` to see which layer answered each
call.

## 2. Write a policy

```bash
clayseal policy new > policy.yaml
```

Every section is present and every line says what it is for. Edit the parts
marked TODO, which are the decisions nobody can make for you: what this agent
is for, which tools it may reach, what each tool does, and where its limits sit.

Then check it:

```bash
clayseal policy lint policy.yaml
```

Lint exits non-zero while the TODOs are still there, so an unedited template
cannot reach production quietly. Once they are gone you get warnings instead,
and each one names a decision you have not made yet. They are worth reading.
The one that matters most says a tool can spend and debits no budget, because a
limit nothing counts against is not a limit. Fill `egress.recipients` with the
mailboxes this job may use: a mailbox on the granted domain that is not in that
list is held (`StepUpRequired`), not allowed.

If you already run an MCP server, `clayseal policy init -- npx @your-org/server`
reads its catalogue and fills in the tool names for you. If your organisation
already has a written policy, `clayseal policy draft rules.md` reads the
ceilings out of the prose. Both write a draft for a person to finish.

## 3. Put it in front of your agent

Pick whichever matches how your agent calls its tools.

**An MCP server, no code change:**

```bash
clayseal proxy --policy policy.yaml -- npx @your-org/mcp-server
```

Your agent connects to the proxy and the proxy runs the real server. A refused
call is answered with a JSON-RPC error and the server never sees it. Tools your
policy does not grant are removed from the catalogue, so the agent is never told
they exist.

Point Claude Desktop, Cursor, or `.cursor/mcp.json` at the proxy, not at the
server:

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

**Python functions in your own loop:**

```python
from clayseal.capabilities import Guardrail, Refused, StepUpRequired

guard = Guardrail.from_policy_file("policy.yaml")
tools = guard.wrap_all({"send_email": send_email, "read_ticket": read_ticket})
```

Call them exactly as before, positionally or by name. The wrappers keep the
name, docstring and signature of your originals, so any framework that inspects
them sees what it saw before. That covers LangGraph, the OpenAI Agents SDK,
CrewAI and hand-written loops.

If the agent just read something that was not a tool return - a ticket pasted
into the prompt, a RAG chunk - tell the gateway, or every destination looks
equally well-sourced:

```python
guard.saw("tickets/T-1042.txt", ticket_body)
```

## 4. Handle a refusal

Two things can stop a call and they are not the same.

`Refused` means the gateway has positive evidence of a problem. Hand the reasons
back to the model. They are written to be read by one, and a refused agent that
knows why will usually do the right thing next.

`StepUpRequired` means a person should look. This is the common one, because a
wrong refusal is expensive and an attacker running unattended is stopped just as
hard by a call that waits. An approval covers that one call with those exact
arguments, and it expires.

```python
try:
    tools["send_email"](to=address, body=summary)
except Refused as exc:
    return f"I could not do that: {exc.reasons[0]}"
except StepUpRequired as exc:
    return f"This needs a person to approve: {exc.reasons[0]}"
```

## How sure the compiler has to be

If you compile rules from a document (a handbook, a goal sentence) instead of
writing every rule by hand, you can ask more than once and keep only what the
answers agree on. That cutoff is `k` in the policy file.

```yaml
compile:
  draws: 5
  k: 0.0001          # showed up at least once
  k_for:
    send_email: 0.5  # this one has to show up in half the answers
```

A tool that never appeared is not granted for this session, even if it is on
`tools.allow`. Raise `k` to be stricter; that is the same tradeoff as
`relative_loss`, which is how many of your own good actions you will let
inferred rules refuse. A draw that fails or will not parse votes for nothing
and still counts, so a compiler that answers once in five is not unanimous.
[examples/06_how_sure.py](https://github.com/clayseal/clayseal-capabilities/blob/main/examples/06_how_sure.py)
shows the knob with no key.

A domain grant is every mailbox on that domain. If the real set is smaller,
name the addresses under `egress.recipients`. An injection that names another
mailbox at the same company is inside a domain-only grant; listing the
mailboxes is what closes it. `clayseal policy lint` warns when a sending tool
has a domain and no mailbox.

[examples/07_other_jobs.py](https://github.com/clayseal/clayseal-capabilities/blob/main/examples/07_other_jobs.py)
is the same adapter on a coding agent, a
prepare/approve mutex, and a same-domain mailbox. The refund demo is not the
only shape this holds.

## What to read next

Write your limits as ceilings on something countable. That is the single thing
that decides whether this helps you. "No more than $1,000 of refunds per
session" is enforced. "Do not do anything inappropriate" is not.

[EVIDENCE.md](EVIDENCE.md) has the measurements, including where the gateway
fails and what it costs in refused good work. Read it before you rely on this
for something that matters.
