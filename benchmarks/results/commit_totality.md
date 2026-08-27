# The commit-token verifier: sound binding, three total-function gaps

STATUS: current

Produced by `python -m benchmarks.stress_commit`. The commit token is the
cryptographic root, scope, budgets, egress and the whole behavioural layer
presuppose that a verified token means *this authority, this tool, this resource,
these exact arguments, this query, not expired, not already spent*. If the
verifier can be made to say yes when any one of those is false, nothing above it
matters.

## The headline is a positive result

The property tested is total, not a list of scenarios: take a genuinely valid
(token, context) pair, change **any** single field of either to **any** value
from a hostile corpus, and verification must fail. There must be exactly one
input that verifies, and it must be the untouched one.

**336 verifications. Zero mutations verified.**

| property | violations |
| --- | ---: |
| NO_MUTATION_VERIFIES | **0** |
| NEVER_RAISES | 0 *(was 46)* |
| REPLAY_IS_REFUSED | **0** |
| BASELINE | **0** |

Confirmed sound, by measurement rather than by reading:

- every field of the signed token is genuinely bound, `token_id`, `issued_at`,
  `expires_at`, `query_id`, `authority_id`, `authority_version`, `permit_epoch`,
  `tool_name`, `resource_ref`, `arguments_hash`;
- every field of the caller-supplied context is genuinely compared;
- a **different valid keypair** minting a perfect token is rejected, signature
  integrity is not mistaken for authority;
- an expired token fails an hour later;
- a token presented twice against a used-token store fails the second time;
- and a **rejected** token does not burn its `token_id` slot, so the genuine
  token still works afterwards.

That last one is subtle and it holds. The verifier consults the replay store only
after every other check passes, exactly as its docstring claims.

## Three total-function gaps, all closed

None of these was a fail-open. Every one was the verifier raising instead of
returning a verdict, which is a denial of service at best, and behind a broad
`except Exception` upstream it becomes an allow.

**1. `CommitToken.to_dict()` raised before the signature check.** It coerces the
two integer fields with `int()`, and it is the *first* line of
`verify_commit_token`. A token holding `authority_version='x'` therefore raised
`ValueError` from inside the verifier, ahead of every check that would have
rejected it. 37 of the 46 raises were this.

Fixed by validating in `CommitToken.__post_init__`, so the unserializable token
cannot be constructed at all. No shipped path produced one, `from_dict` coerces
with `int()`, `issue_commit_token` reads integers off the context, but the
dataclass permitted the state, and **a type that permits a state whose only
expression is an exception deep inside a security check is the wrong shape.**

**2. A non-string `action_name` on the context raised `AttributeError`.** The
context is caller-supplied and unsigned, so it is untrusted input in exactly the
way the token is not. `ActionDescriptor` performs no validation and lives in the
sibling core package, so the guard belongs in the verifier. Nine variants; both
call sites guarded.

**3. The wire boundary had no total entry point.** `SignedCommitToken.from_dict`
is a constructor for *trusted* data, it indexes required keys and coerces, so
hostile JSON produces three different exception types, none of them a verdict:

```
authority_version='PWNED'  -> ValueError
authority_version=[1]      -> TypeError
permit_epoch='NaN'         -> ValueError
token_id absent            -> KeyError
token not a mapping        -> ValueError
signature absent           -> KeyError
```

This is the point where attacker-controlled bytes enter the system, so it now has
`parse_signed_commit_token(raw) -> (token | None, reason | None)`, which returns
a verdict for **any** input including `None`, a list, or a string, and raises
nothing. `from_dict` keeps its strict behaviour and its docstring now names the
distinction. Separating "construct from trusted data" from "parse untrusted
input" is the fix; making `from_dict` lenient would have been the wrong one.

## What the harness got wrong first

Recorded because a harness that cries wolf is worse than none, and this one cried
four times before it was right:

- `token.authority_version = '1'` against an original of `1` was reported as a
  verification. Both sides are compared with `int()`, deliberately, so `'1'` and
  `1` are **the same value**, a textual difference is not a semantic one.
- Same for `permit_epoch = '0'`.
- `ctx.action_name` and `ctx.resource_ref` set to the values they already held
  were counted as mutations. The no-op skip existed for token fields and not for
  context fields.

All four were the verifier working. The corrected harness compares int-typed
fields numerically and skips no-op context assignments.

## Residual

- **`ExecutionContext` is unvalidated by construction.** The verifier now guards
  `action_name`, but `resource_ref`, `query_id` and `authority_id` are compared
  with `==`, which is total for any type, so they deny rather than crash. That is
  correct behaviour and not a gap, noted so the asymmetry is not read as one.
- **The used-token store seam is only tested with `InMemoryUsedTokenStore`.** The
  Redis and DynamoDB stores that ship for multi-instance gateways have not been
  put through this, and a store that fails open under partition would defeat
  replay defense without any of the above changing.
- **Signature verification itself is not fuzzed here.** It is delegated to
  `clayseal.core`, and the mutation stress confirms it rejects every tampered
  token, but the Ed25519 path has not been attacked directly.

## Reproduce

```bash
python -m benchmarks.stress_commit
pytest python/tests/test_commit_totality.py -q
```
