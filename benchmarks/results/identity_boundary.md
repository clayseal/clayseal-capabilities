# The identity adapters: two defects, one of them ledger-critical

STATUS: current

`python -m benchmarks.stress_identity`. The adapters in
`agentauth/capabilities/identity_adapters/` were the last unfuzzed wire boundary
in the library. Every other one gave up a fail-open when fuzzed, and so did this.

115 malformed claims dicts across five adapters, plus a differential authority
probe and three principal-identity checks.

## 1. Claims could assert their own capabilities

Three adapters normalize *conditionally* and fall back to passing the caller's
dict through untouched:

```
oidc.py:30        claims_from_oidc(raw)   if "sub" in raw and "iss" in raw  else raw
auth0.py:33       claims_from_auth0(raw)  if "auth0.com" in iss             else raw
spiffe_jwt.py:34  claims_from_spiffe(raw) if "sub" in raw                   else raw
```

The fallback is for input already in internal form. It cannot tell
already-normalized from attacker-authored, and the internal form has fields the
claims form does not. Measured:

```json
{"subject_id": "alice", "iss": "https://evil.example",
 "capabilities": ["payments.transfer:*"], "has_capability_grant": true}
```

| adapter | before | after |
| --- | --- | --- |
| oidc | `caps=['payments.transfer:*'] grant=True` | `caps=[] grant=False` |
| auth0 | `caps=['payments.transfer:*'] grant=True` | `caps=[] grant=False` |
| spiffe_jwt | `caps=['payments.transfer:*'] grant=True` | `caps=[] grant=False` |

No signature is involved anywhere in that. The dict asserts its own authority and
the adapter agrees. Note the shape of the guard: the dict gets this treatment
*because* it does not look like a real token, so the more obviously forged the
input, the less validation it receives.

`evidence_verified` stayed `False` throughout, because the constructor keyword
beats the claim. That is a property of the current call site rather than of the
data, so the fix strips it too.

Closed by `identity_adapters/_claims.py::strip_authority_fields`, applied on all
three fallback paths. Ten fields, listed there.

**This is the sixth instance of one shape**: a control that stops applying when
its input does not match what it expected, and reports success. The others were
`1e999` against a value ceiling, a `NaN` compute ceiling, a list handed to
`is_protected_path`, the planner's three fail-open paths, and the replay store's
outage branch.

## 2. `subject_id` collides across issuers, and the ledger keys on it

| adapter | `sub=alice @ good.example` vs `@ evil.example` |
| --- | --- |
| oidc, auth0, azure_ad, aws_sts, gcp | **same `subject_id`** |
| spiffe_jwt | cannot collide; see below |

The adapters are not wrong. `sub` is unique only within an issuer — OIDC Core
says so — and reporting it unqualified is correct. The defect is a *ledger* keyed
on it, and that is exactly what this repository just built:
`principal_ledger.py` is the fix for the session-restart escape in
[aggregation_residual.md](aggregation_residual.md), so its key is now the thing
an attacker has reason to attack.

In a deployment trusting more than one issuer, two distinct principals share one
ceiling. Either can exhaust the other's budget, and the spend attribution in the
log is wrong for both.

Closed by `principal_ledger.principal_key(binding)`, which is length-prefixed
rather than delimiter-joined:

```
20:https://good.example5:alice
20:https://evil.example5:alice
```

A plain `f"{iss}|{sub}"` is forgeable — `sub` is attacker-chosen at their own
issuer, so `sub="|https://good.example|alice"` spells another principal's key.
Length prefixes make the encoding injective. Verified: a `sub` crafted to spell
the good principal's key does not collide with it.

**SPIFFE is the one that got this right**, and it is worth naming: a SPIFFE ID is
`spiffe://<trust-domain>/<path>`, so the trust domain is inside the subject, and
the adapter *refuses* a bare `sub` outright. It is the only adapter here whose
subject is issuer-qualified by construction.

## 3. What did not fail

- **Authority inflation elsewhere: 0 of 20 probes.** The first version of this
  probe reported 7, all of them the adapters' own default `trust_tier`. Rewritten
  as a differential — build the binding with and without the injected claim, count
  only a difference — it drops to the 2 real ones, both closed above. A fuzzer
  with a false-positive rate is one whose true positives get waved off.
- **Separator injection into `sub`**: no adapter builds a composite id, so
  nothing to forge at that layer.
- **Stability**: `subject_id` and `principal_key` are both unchanged by
  irrelevant claims. Instability would split the ledger, which is the
  session-restart escape reappearing one layer down where the principal ledger
  cannot see it.

## 4. Open

**Ten raises, one shape.** Every adapter raises `KeyError` on an empty dict or a
`None` subject:

```
KeyError: 'verified credential requires subject_id, spiffe_id, agent_id, or sub'
```

Refusing to build a binding for an unidentified principal is correct and
fail-closed. Raising a bare `KeyError` out of an authorization path is not the
right way to do it — a caller cannot distinguish it from a genuine bug, and the
message is the only thing carrying the intent. This should be a typed error.
Left open deliberately: it is a hygiene issue with no security consequence, and
changing an exception type touches every caller.

## Reproduce

```bash
python -m benchmarks.stress_identity
pytest benchmarks/tests/test_identity_boundary.py -q
```
