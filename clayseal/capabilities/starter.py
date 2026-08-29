"""`clayseal policy new`: a starter policy, commented, that lints on the way out.

The two scaffolding commands that already existed both need something first.
`policy init` needs an MCP server to interrogate and `policy draft` needs a
written delegation-of-authority document. Someone who has just watched
`clayseal try` has neither, and the honest answer to "what do I do now" was to
copy a block out of the README and guess at the rest.

This writes a policy with every section present and every line explained, so
the first file is edited and never composed. What it does NOT do is grant
anything real: the tools are named `your_*` and the goal says to replace it, so
a file that reaches production unedited fails its own lint rather than quietly
authorizing a tool nobody meant to name.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

TEMPLATE = """\
# A Clay Seal policy. Everything here is a decision you are making about an
# agent, so it is a file a person reviews and a pull request can gate.
#
#   clayseal policy lint  {name}     what a reviewer should ask about
#   clayseal policy show  {name}     what it actually authorizes
#
# Edit every line marked TODO. The file lints with errors until you do.
version: 1

goal:
  id: {goal_id}
  # One sentence saying what this session is for. It is sealed when the session
  # starts, so nothing the agent reads afterwards can widen it. Content checks
  # and destination provenance are both derived from this sentence, so a vague
  # one weakens both.
  summary: TODO describe the job in one sentence

# After this the grant is dead and every action is refused. Short is safer.
expires_at: {expires}

# autonomous | supervised | benchmark
#   supervised  a step-up waits for a person, which is what you want first
#   autonomous  no person is there, so ambiguity is refused instead of asked
profile: supervised

tools:
  # Nothing outside this list is reachable. Behind `clayseal proxy` the others
  # are also withheld from the catalogue, so the agent is never told they exist.
  allow: [your_read_tool, your_write_tool]

  # What each tool DOES. The verb decides which rules apply, and guessing it
  # from the name works on `send_email` and fails on `terraform_destroy`.
  # One of: read, write, send, delete, execute.
  effects:
    your_read_tool: read
    your_write_tool: write

  # Tools that spend nothing and change nothing. Saying so here is what stops
  # lint asking you about them.
  harmless: [your_read_tool]

paths:
  # Where file actions may happen. A tool whose path cannot be resolved is
  # refused, so the failure is loud.
  allow: ["out/**"]
  deny: [".env", ".git/**", "**/*.pem"]

  # Which argument carries the path. The gateway looks for file_path, path,
  # filename and file on its own; anything else has to be named here.
  arg_names: {{your_write_tool: path}}

  # Tools that act on no path at all, like sending mail or calling an API.
  pathless: []

egress:
  # Where data may go. A domain grant is every mailbox on that domain, so name
  # the addresses too if the real set is smaller.
  domains: [your-company.example]
  recipients: []
  bind_recipients: true

budgets:
  # The part that catches a sequence of individually legal calls. Without a
  # ceiling on something countable, a run of authorized actions that adds up to
  # something you would never approve has nothing to trip over.
  calls:
    ceilings: {{writes: 20}}
    tracked: {{your_write_tool: writes}}

  # For money, use a value budget instead, naming the argument that carries
  # the amount:
  #
  # value:
  #   ceilings: {{refunds: "1000.00"}}
  #   tracked:
  #     issue_refund: {{arg: amount, budget: refunds}}
"""


def starter_policy(*, goal_id: str = "TODO-name-this-run", days: int = 30,
                   name: str = "policy.yaml") -> str:
    """The template, with a real expiry so the first lint is about your choices.

    A placeholder date would put `expired` at the top of the first lint run,
    which teaches the reader that lint findings are noise on their very first
    encounter with it.
    """
    expires = (datetime.now(timezone.utc) + timedelta(days=days)).replace(
        microsecond=0).isoformat().replace("+00:00", "Z")
    return TEMPLATE.format(goal_id=goal_id, expires=expires, name=name)
