# Examples

Each file runs on its own from a checkout, with no key and no network:

```bash
python examples/01_gateway.py
```

| file | shows |
| --- | --- |
| [01_gateway.py](01_gateway.py) | The gateway in-process: a prompt injection planted in a ticket the agent was allowed to read, and the send that gets refused because its destination came from the document rather than the sealed goal. |
| [02_the_proxy.py](02_the_proxy.py) | The same policy in front of an MCP server instead of inside the agent. Eleven $900 refunds against a $1,000 ceiling: the second is refused, and the server's own ledger proves it never ran. |
| [03_commit_token.py](03_commit_token.py) | Minting and verifying a commit token, which binds a decision to the exact arguments it was made about. |
| [04_cross_provider_commit.py](04_cross_provider_commit.py) | The same flow against each of the five built-in identity providers, to show the seam is real. |
| [05_from_a_document.py](05_from_a_document.py) | A written delegation-of-authority document and a tool catalogue becoming an enforced policy, including the rule this layer cannot hold: segregation of duties is about WHO acts, so it stays a TODO for a reviewer rather than going quiet. |

Two support files rather than examples: [refund.yaml](refund.yaml) is the policy
`02` enforces, and [refund_server.py](refund_server.py) is the MCP server it runs.
[policy.yaml](policy.yaml) is the one `clayseal policy lint` is demonstrated on.
