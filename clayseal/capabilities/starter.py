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

The shape matches `clayseal try`: a read, a send, and a refund. Rename the
`your_*` tools and keep non-file tools under `paths.pathless`.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

TEMPLATE = """\
# A Clay Seal policy. Same job as `clayseal try`: read, email, refund.
# A person reviews this file; a pull request can gate it.
#
#   clayseal policy lint  {name}     errors until TODOs are gone; then warnings
#   clayseal policy show  {name}     what it actually authorizes
#
# Edit every line marked TODO. The file lints with errors until you do.
#
# Two different stops, on purpose:
#   Refused          the gateway said no (a spent budget, a tool not granted)
#   StepUpRequired   a person should look (typical for off-list email when
#                    profile is supervised). `clayseal try` prints this as HELD.
version: 1

goal:
  id: {goal_id}
  # One sentence saying what this session is for. It is sealed when the session
  # starts, so nothing the agent reads afterwards can widen it. Content checks
  # and destination provenance are both derived from this sentence, so a vague
  # one weakens both. Naming a mailbox here is why that address can be used
  # without guard.saw().
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
  # Rename these to the tools you actually have.
  allow: [your_read_tool, your_send_tool, your_refund_tool]

  # What each tool DOES. The verb decides which rules apply, and guessing it
  # from the name works on `send_email` and fails on `terraform_destroy`.
  # One of: read, write, send, transfer, call
  # send_email is send. issue_refund / pay_vendor is transfer. write_file is
  # write. terraform_destroy is write — say so; the name is classified as call.
  effects:
    your_read_tool: read
    your_send_tool: send
    your_refund_tool: transfer

  # Tools that spend nothing and change nothing. Saying so here is what stops
  # lint asking you about them (`unaccounted-tool`).
  harmless: [your_read_tool]

  # Ordering and state, as withdrawals from the grant. Uncomment if you have
  # one. `mutex` is the same-session form of "the agent that did A may not
  # also do B". Two different people is an identity question this file cannot
  # see.
  # when:
  #   - requires: [your_read_tool]
  #     deny: [your_refund_tool]
  #     reason: "read first"

paths:
  # Where file actions may happen. Unused by the try-shaped tools below.
  # If you add a write-to-disk tool, put its argument under arg_names.
  allow: ["out/**"]
  deny: [".env", ".git/**", "**/*.pem"]
  arg_names: {{}}

  # Tools that never touch a file. Email, refunds, and HTTP APIs go here.
  # `clayseal proxy` refuses them with "no path argument was found" if you
  # leave them out. The Python wrapper is more lenient; the proxy is not.
  pathless: [your_read_tool, your_send_tool, your_refund_tool]

egress:
  # Where data may go. Keep the domain AND name the mailboxes. A domain-only
  # grant is every mailbox on that domain. An empty recipients list is
  # domain-only, not "no one may be emailed". A mailbox on the domain that is
  # not in this list is HELD (StepUpRequired), not allowed.
  domains: [your-company.example]
  recipients: []
  bind_recipients: true

budgets:
  # The part that catches a sequence of individually legal calls.
  value:
    ceilings: {{refunds: "1000.00"}}
    tracked:
      your_refund_tool: {{arg: amount, budget: refunds}}
  calls:
    ceilings: {{sends: 20}}
    tracked: {{your_send_tool: sends}}

# How sure a compiled rule has to be. Leave this commented until you compile
# from a document with `ask` at build time. k only narrows tools.allow.
#
# compile:
#   draws: 5
#   k: 0.0001
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
