# Examples

Each file runs on its own from a checkout, with no key and no network:

```bash
python examples/01_gateway.py
```

| file | shows |
| --- | --- |
| [01_gateway.py](01_gateway.py) | The gateway in-process: a prompt injection planted in a ticket the agent was allowed to read, and the send that gets held because the injected destination is not on the egress allow-list. See below for which layer that is, and for the variant where it is provenance. |
| [02_the_proxy.py](02_the_proxy.py) | The same policy in front of an MCP server instead of inside the agent. Eleven $900 refunds against a $1,000 ceiling: the second is refused, and the server's own ledger proves it never ran. |
| [03_commit_token.py](03_commit_token.py) | Minting and verifying a commit token, which binds a decision to the exact arguments it was made about. |
| [04_cross_provider_commit.py](04_cross_provider_commit.py) | The same flow against each of the five built-in identity providers, to show the seam is real. |
| [05_from_a_document.py](05_from_a_document.py) | A written delegation-of-authority document and a tool catalogue becoming an enforced policy, including the rule this layer cannot hold: segregation of duties is about WHO acts, so it stays a TODO for a reviewer rather than going quiet. |

Two support files rather than examples: [refund.yaml](refund.yaml) is the policy
`02` enforces, and [refund_server.py](refund_server.py) is the MCP server it runs.
[policy.yaml](policy.yaml) is the one `clayseal policy lint` is demonstrated on.


## Which layer answers, in `01`

The injected address in `01` is off-domain, so the **egress allow-list** stops
it. That is a per-call rule. It reads one call's arguments, keeps nothing
between calls, and a stateless gate handed the same policy refuses the same
send. The run prints the layer with the reason so this is visible:

```
HOLD send_email     step_up  {'to': 'collector-metrics.example', ...}
       floor: egress to 'collector-metrics.example' not on allow-list
```

The gateway runs cheapest and strictest first, so this is the right answer in
the wrong order for a demonstration: the layer the rest of this project is about
never ran. Take the domain list away and it does:

```bash
python - <<'EOF'
import re, pathlib
src = pathlib.Path("examples/01_gateway.py").read_text()
exec(re.sub(r'"egress": \{[^}]*\}', '"egress": {"bind_recipients": True}', src))
EOF
```

```
HOLD send_email     step_up  {'to': 'ops@acme-internal.com', ...}
       floor: 'ops@acme-internal.com' came from a structured field of the sealed goal
HOLD send_email     step_up  {'to': 'collector-metrics.example', ...}
       floor: egress to 'collector-metrics.example' not on allow-list
```

Both sends are now held, and that is the honest shape of the layer rather than a
flattering one. **Grounding earns supervision, not autonomy.** A destination the
sealed goal named is admissible evidence and not an authorization, because an
injected instruction can sit in a structured field of the very resource the goal
named, so the best any grounding earns is a step-up. The attacker gets no
unattended send and the legitimate recipient is one approval away.

## The gap `01` does not show

An address the policy's own domain covers. `01` grants `acme-internal.com` and
the injection names `collector-metrics.example`, which is the easy case. Change
the injection to `mirror-archive@acme-internal.com` and the domain grant covers
it, so the floor allows the send.

Binding the mailbox rather than the domain is what closes that, and it is a
declaration you have to write:

```yaml
egress:
  domains:    [acme-internal.com]
  recipients: [ops@acme-internal.com]     # the mailbox, not just the domain
  bind_recipients: true
```

`clayseal policy lint` warns when a policy grants a domain to a sending tool and
enumerates no recipient on it, because a domain grant is every mailbox on that
domain and an injection only has to name one of them.
