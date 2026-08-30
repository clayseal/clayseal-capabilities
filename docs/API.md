# API reference

`clayseal.capabilities` exports 57 names. **Four of them are the API most
integrations use**, and the rest exist for deployments that need to build the
pieces themselves. This page is the map; the per-symbol detail lives in the
module docstrings, which is where it stays correct.

Everything resolves on first access, so importing the package does not pull the
whole library. See `clayseal/capabilities/__init__.py`.

---

## The four you probably want

```python
from clayseal.capabilities import Guardrail, Refused, StepUpRequired
```

| name | what it is |
| --- | --- |
| `Guardrail` | Wraps the tools you already have. `Guardrail.from_policy_file(path)` then `guard.wrap_all({...})`. The wrappers keep the name, docstring and signature of your originals, so a framework that introspects them sees what it saw before. |
| `Refused` | Raised instead of running the tool. `.reasons` is the stable code tuple to match on; `str(exc)` is the explained form to hand back to an agent. |
| `StepUpRequired` | Raised when the call needs a person. Deliberately NOT a subclass of `Refused`: a caller that treats them alike turns a supervised deployment into an autonomous one, or into one that cannot act at all. |
| `GuardrailError` | Base of both, for `except` clauses that genuinely mean either. |

The fourth thing most deployments touch is not a symbol at all — it is
`clayseal proxy`, the CLI that puts the gateway in front of an MCP server with no
code change. See [DEPLOYMENT_SHAPE.md](DEPLOYMENT_SHAPE.md).

## One level down: the stack itself

| name | what it is |
| --- | --- |
| `DeployableStack` | What `Guardrail` wraps. Use it directly to pass options `Guardrail` does not surface — `house_rules`, `session_rules`, `enable_flow`, a custom `entailment_judge`. `DeployableStack.from_goal(...)`. |
| `StackDecision` | What it returns: `outcome`, `layer`, `reasons`. |
| `GoalSpec` | The sealed goal. Captured before any tool output can reach it, which is what stops an injected instruction widening the grant. |
| `TaskScope`, `compile_task_scope` | The path and action scope a session runs under. |

## Budgets — the layer that sees a sequence

The only checks that can see individually-legal calls adding up to something
illegal. Each has a `would_allow` query and a `reserve` that holds under the same
lock; the two are alternatives and are asserted to agree.

| for | names |
| --- | --- |
| money | `SessionValueBudget`, `ValueBudgetConfig`, `ValueReservation`, `value_budget_config_from_mandate`, `session_value_budget_from_mandate` |
| call counts | `SessionCallBudget`, `CallBudgetConfig`, `CallReservation`, `call_budget_config_from_mandate`, `session_call_budget_from_mandate` |
| from a mandate | `MandateBudgets`, `session_budgets_from_mandate`, `UnsupportedBudgetType` |

Prefer `with budget.reserve(...) as res:`. It commits on a clean exit and
releases on an exception, which is the direction that cannot overcharge.

## Precedence — the layer that sees an ordering

A budget bounds a running **total**. These bound a running **order**: an action
that may not proceed until another has. "Full checklist before irreversible
commit" is not expressible as a counter, and the scenarios stating that shape are
where containment is lost, 83.3% where the grant states a countable limit against
18.9% where it does not.

| export | what it is |
| --- | --- |
| `derive_obligations` | reads `"A before B"` and `"no B without A"` out of the **sealed goal**, returning nothing rather than guessing when either side fails to resolve to a tool |
| `Obligation` | one rule: `gated` may not run until every tool in `requires` has |
| `ObligationLedger` | session state; `observe(tool)` records, `check(tool)` gates |

```python
from clayseal.capabilities import derive_obligations, ObligationLedger

rules = derive_obligations(goal.summary, catalog=set(allowed_tools))
broker.obligations = ObligationLedger(obligations=rules)
```

Same trust basis as the derived-count rung: the rule comes from the goal sealed before
any untrusted content exists, never from tool output and never from an argument.
Off unless a caller sets it, because deriving a rule from a sentence is
inference, and an invented obligation refuses work nobody prohibited.

## Entity binding: which counterparty

The egress policy bounds the **host** an action may reach. This bounds the
**entity** it may name. "Pay Acme and Beta only" is not a domain rule, and a session that
held exactly that list in its own sealed goal still paid a third party, because
nothing read the list back out.

| export | what it is |
| --- | --- |
| `bindings_from_intent` | entity lists the goal states in **structured** form; `verbs` is skipped, being the intent envelope's |
| `derive_bindings` | entity lists stated in a goal **sentence**, `"<verb> A and B only"`, returning nothing rather than guessing |
| `EntityBinding` | one list: which argument it governs, the permitted values, and whether it was declared or derived |
| `EntityLedger` | `check(tool, args)` returns `(allowed, reason, declared)` |

```python
from clayseal.capabilities import (
    EntityLedger, bindings_from_intent, derive_bindings)

bindings = (bindings_from_intent(goal.structured_intent)
            or derive_bindings(goal.summary))
broker.entities = EntityLedger(bindings=bindings)
```

**The verdict follows the source, which is what `declared` is for.** A list the
goal states in structured form is part of the sealed authority, so naming an
entity outside it is a fact and the broker denies. A list read out of a sentence
is an interpretation of that sentence, so it escalates and never denies. The
ledger accumulates nothing and has no way to learn a name, so injected tool
output cannot widen it.

Matching is exact on a canonical form, case and punctuation folded. It is
deliberately not a prefix match: `"Acme Holdings Ltd"` is not `"Acme"` until a
registry says so, and this rung has no registry.

## Authority: mandates, delegation, commit tokens

| name | what it is |
| --- | --- |
| `Mandate`, `issue_mandate`, `verify_mandate_signature` | The signed grant a session runs under. |
| `DelegationToken`, `issue_delegation`, `sign_delegation`, `verify_delegation_chain` | Sub-agent authority. Attenuation is checked at every hop: a chain that narrows then widens is a chain that widens. |
| `CommitToken`, `SignedCommitToken`, `issue_commit_token`, `verify_commit_token` | Binds a decision to the exact arguments judged, single-use, so a mutated or replayed call is detectable. |
| `trusted_minting_keys_from_env` | Pins who may mint. Unpinned, anything that can sign can authorize. |

**Replay defence needs storage.** `InMemoryUsedTokenStore` is correct for one
process and wrong for a deployment running several, because two processes with
separate memories each see a token as fresh. Use `RedisUsedTokenStore` or
`DynamoDBUsedTokenStore`; `load_used_token_store_from_env`,
`default_used_token_store` and `set_default_used_token_store` wire them up, and
production posture refuses to start without one.

`UsedTokenStore` is the Protocol all of them satisfy — implement it to back
replay defence with a store this package does not ship. It is the interface, so
the contract is what matters: a `mark_used` that is atomic against concurrent
callers, since two processes each seeing a token as fresh is precisely the hole
the store exists to close.

## Dynamic scoping

`CapabilityLease`, `build_capability_lease`, `build_repo_chunk_index` — narrowing
a grant to the part of a repository a goal actually needs. The trade to know is
that a lease which is too *narrow* is the failure mode to watch: a refusal for a
file the scoper did not find looks exactly like a refusal on purpose. See the
`clayseal/capabilities/scoping/` docstrings.

## Seams you can replace

| name | for |
| --- | --- |
| `cedar_authorizer`, `opa_authorizer`, `openfga_authorizer`, `external_authorizer` | Delegating the decision to a policy engine you already run. |
| `register_capability_layer`, `get_capability_layer`, `list_capability_layers`, `default_capability_layer`, `AgentAuthCapabilityLayer` | The plugin registry. Third-party packages register through entry points under `clayseal.<group>`; see `clayseal/core/plugins.py`. |
| `capability_allows`, `operation_for_action`, `operation_for_mcp_tool` | Turning a call into the capability question it asks. |
| `SessionMemory` | Per-session state a custom layer can carry. |

## What is deliberately not exported

The behavioural and content layers — the confidentiality flow tracker, the
intent envelope, the trajectory detector — are reached through `DeployableStack`
rather than constructed directly. They carry per-session state whose lifecycle
the stack owns, and a caller holding one across sessions would be sharing
detection state between them.

`clayseal.core` holds the shared contracts (action, outcome, signing) that the
identity and receipts layers also read. Import from there when you are building a
layer, not when you are using one.
