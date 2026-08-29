# Threat model and key management, Clay Seal Layer 2

STATUS: current

This document exists because "who signs what, and what happens when they don't"
was answered only by `CLAYSEAL_COMMIT_TOKEN_TRUSTED_KEYS` and a reader's
inference. Writing it found two live gaps, both now closed and both recorded
below rather than quietly fixed, a threat model whose first draft finds nothing
was not a threat model.

---

## 1. What this layer defends, and what it does not

Layer 2 answers one question: **may this agent perform this exact action, right
now, against this resource, with these arguments?** Everything below is scoped
to that.

**In scope.** An agent whose instructions have been subverted by content it
read at runtime (prompt injection); an agent pursuing a goal that is legitimate
in aggregate but harmful in a particular step; a sub-agent exceeding the
authority it was delegated; an attacker replaying a captured authorization; an
attacker splitting a spend across sessions to stay under a ceiling.

**Out of scope, and load-bearing.** A compromised control plane; a compromised
host; a compromised model *provider*; the correctness of the mandate itself. If
the process that mints commit tokens is owned, this layer authorizes whatever
that process says. Layer 2 is an enforcement point, not a root of trust.

**The gap this layer does not close.** In-scope data staging: a read of a
secret-classed object inside the grant, followed by a write of its content to a
publication-classed object inside the same grant. Measured against an oracle
attacker, the escaped-task set is byte-identical to `allow-all`
([in_scope_exfiltration.md](../benchmarks/results/in_scope_exfiltration.md)).
The confidentiality flow tracker covers part of it as a STEP_UP layer; wide
fragment splits and unkeyed encodings remain open. Any containment claim for a
coding agent has to carry this.

---

## 2. Trust boundaries

```
  ┌── TRUSTED ─────────────────────────────────────────┐
  │  Control plane: mints commit tokens, seals and     │
  │  signs intent envelopes, issues mandates, holds    │
  │  the human approval UI                             │
  └───────┬────────────────────────────────────────────┘
          │  signed objects cross here
  ┌───────▼────────────────────────────────────────────┐
  │  ENFORCEMENT POINT (this layer)                    │
  │  SessionBroker: floor → behavioural tiers          │
  └───────┬────────────────────────────────────────────┘
          │  decisions, and only decisions
  ┌───────▼────────────────────────────────────────────┐
  │  UNTRUSTED: the agent, its model, its tool output, │
  │  every argument it constructs                      │
  └────────────────────────────────────────────────────┘
```

The one asymmetry that makes the design work: **the planner runs before any
untrusted content exists.** It reads the user's request and the tool catalog,
both trusted, and emits a sealed plan. By the time injectable content arrives,
the plan is already fixed. That is the CaMeL privilege split, and it is why an
LLM appears in the control plane and never in the decision path.

Two corollaries, both enforced rather than assumed:

- `LLMQueryPlanner.plan()` takes a query and a catalog and nothing else. There
  is no parameter through which tool output could reach it.
- Runtime replanning (`PlanExtender`) sees the goal, the tool catalog and the
  action's SHAPE. Never argument values, never tool output.

---

## 3. Who signs what

| Object | Signer | Verifier pins | Unpinned, in production | Bound to |
| --- | --- | --- | --- | --- |
| Commit token | Control-plane minter | `CLAYSEAL_COMMIT_TOKEN_TRUSTED_KEYS` or `trusted_minting_keys=` | **Refused** | tool, resource, `arguments_hash`, authority id + version + epoch, `query_id` |
| Intent envelope | Control-plane sealer | `trusted_keys=` on `verify_intent_envelope` / `reclear` | **Refused** | the sealed goal it was compiled from |
| Step-up approval | Human approval service | request commitment | **Unsigned refused** | `(tool, arguments_hash)`, the rule codes shown, one use |
| Delegation token | Parent principal | chain verification | — | the narrower rights it conveys |

A signature proves **integrity**, not **authority**. Any keyholder can produce
an internally consistent object; the pin is what says *this* keyholder is the
control plane. Every row above enforces that distinction, which was not true
until this document was written.

### 3.1 Two gaps this document found

**The intent envelope accepted any signer.** `verify_commit_token` had refused
an unpinned minter in production for some time; `verify_intent_envelope` did
not. It mattered more than the asymmetry suggests, because the envelope is the
object `SessionBroker.reclear` swaps *mid-session*, the supported way a running
session's plan is legitimately widened. A self-signed envelope replaced the
sealed plan wholesale, and every later conformance check then measured the agent
against the attacker's plan. Now fails closed in production.

**The unsigned-approval escape worked in production.**
`CLAYSEAL_STEP_UP_ALLOW_UNSIGNED=1` disabled approval authentication entirely.
An approval is the one object in this protocol whose job is to grant something
the floor refused, so one environment variable converted a refusal into a grant.
Its siblings (`AGENT_RECEIPTS_ALLOW_STUB`, `CLAYSEAL_DEV_ATTESTOR`) were
already in the production deny-list; this one was not. Now refused in production
regardless of how it is spelled, the env var and the explicit
`allow_unsigned=True` argument are the same fail-open.

Both are the defect class `principal_ledger.py` already names: *a control that
stopped applying when its input was unusual, and reported success.* Pinned by
[`test_production_posture.py`](../python/tests/test_production_posture.py),
which asserts all three signed objects share one posture so a fourth cannot be
added without answering the question.

---

## 4. Key management

### 4.1 The keys

| Key | Held by | Used for | Rotation |
| --- | --- | --- | --- |
| Commit-token minting key | Control plane / governor | Signing one-side-effect authorizations | Overlap: publish both public keys, mint with the new one, retire the old after max TTL (default 300s) |
| Envelope sealing key | Control plane | Signing compiled plans | Same overlap; an envelope lives as long as its session |
| Approval signing key | Human approval service | Signing step-up approvals | Same overlap, bounded by `step_up_ttl_seconds` (default 600s) |

Every pin is a **set**, which is what makes overlap rotation possible without a
flag day: publish `{old, new}`, cut minting over, then drop `old` once nothing
signed by it can still be within its TTL. Because every signed object here is
short-lived and bound to a specific action, there is no long-lived artifact that
has to survive a rotation.

### 4.2 What this layer must never hold

Layer 2 processes authorization *context*: subject identifiers, tenant ids,
resource names, action names, input **hashes**, budget values, token ids, replay
state. It should not receive raw secrets or full sensitive payloads where a hash
or a stable reference is enough. See [PRIVACY.md](PRIVACY.md).

The verification keys are public. The only private key an enforcement point ever
needs is none: it verifies, it does not mint. A deployment that finds itself
putting a minting key on the enforcement host has collapsed the control plane
into the data plane, and the boundary in §2 with it.

### 4.3 The production switch

`CLAYSEAL_ENV=production` (or `AGENT_RECEIPTS_ENV`) turns on every fail-closed
guard in this table. It is a single environment variable and it is the most
consequential one in the system.

Verified in production posture:

- commit tokens require a pinned minter **and** a replay store;
- intent envelopes require pinned control-plane keys;
- step-up approvals must be signed;
- the replay store denies when it cannot be reached, and that is not configurable;
- the shared ledger denies when it cannot be reached, unless `on_unavailable="allow"`
  is explicitly chosen, and it counts either way.

---

## 5. Attacks, and where they are stopped

| Attack | Stopped by | Evidence |
| --- | --- | --- |
| Injected instruction sends to an attacker address | Egress destination binding + parameter provenance | ASR 0.0% on four AgentDojo suites ([head_to_head_injection.md](../benchmarks/results/head_to_head_injection.md)) |
| Mutated tool argument after authorization | Commit-token `arguments_hash` | 37 mutations, none verified ([stress_commit](../benchmarks/stress_commit.py)) |
| Replayed commit token | Single-use store; shared for multi-instance | [replay_defense.md](../benchmarks/results/replay_defense.md) |
| Path escape from the workspace | Task scope + protected zones | 99.9–100% ([four_axes.md](../benchmarks/results/four_axes.md)) |
| Sub-agent exceeding delegated rights | `DelegationBoundary`, principal read from `action.meta` | 100% contained |
| Spend split across sessions | `PrincipalLedger` keyed to the mandate, not the session | [structuring.md](../benchmarks/results/structuring.md) |
| Spend split across processes / hosts | `SharedPrincipalLedger` (fcntl), `RedisPrincipalLedger` (fenced lock) | 400→100 landed; cross-host tests |
| Step-up exhaustion (ask until the human stops reading) | `audit_budget`, charged at every step-up site | `SUPERVISED` profile sets 8 |
| Approval replayed for a second action | `(tool, arguments_hash)` keying + single-use `approval_id` | `test_step_up_resolution.py` |
| Nested destination hidden in an object argument | Egress walk covers dicts, bounded | Found by this pass; `test_egress_floor_properties.py` |
| Destination placed **past** a scan bound (beyond 16,384 characters, or nested deeper than 6 levels) | The bounds still hold; an argument the scan could not finish is refused as undecidable rather than read as clean | `test_egress_scan_bounds.py`; both were ALLOWED before this pass while the same address in a short flat argument was refused. Failing closed costs 0 of 10,716 benign events across seven corpora |
| Destination re-spelled so the allow-list cannot read it (IP literal in any base, bracketed IPv6, single-label host, non-ASCII homograph) | Host parse canonicalises to one form before matching: `inet_aton` rules for IPv4, IDNA for non-ASCII | `test_egress_destination_spellings.py`; all five were ALLOWED before the 0.6 pass while the dotted form was refused |
| Denied path re-spelled so `fnmatchcase` cannot match it (case, Win32 trailing dot or space) | Extra readings widen DENY only; a path is denied if any reading is denied | `test_path_scope_same_file_spellings.py`; `workspace/SECRETS/key.pem` was ALLOWED under `denied_paths=["workspace/secrets/**"]` |
| **Content-defined harm** (authorized action, harmful meaning) | **Not stopped** | 6.3% ([why_we_fail.md](../benchmarks/results/why_we_fail.md)) |
| Secret obfuscated behind enough padding to exhaust the variant budget | The three base renderings are always produced; the budget now bounds only the decoded variants, where the attacker controls the count | `test_flow_variant_budget.py`; 8 KB of padding defeated reversal, rot13 and base64 at once and were ALLOWED. Costs nothing measured |
| Secret longer than the match bound, exfiltrated as its tail | The value is spanned by bounded half-overlapping windows and scored against the window that matched | `test_flow_long_value_windows.py`; a 376-character value sent as its last 120 was ALLOWED while the same value sent whole was refused, single write, no encoding. Costs nothing measured |
| Secret encoded and pushed past the decoder's token budget | An argument with more opaque tokens than the decoder opens cannot support "carries no value"; the tracker escalates instead | `test_flow_decode_budget.py`; 8 harmless base64 tokens in front of a base64'd secret were ALLOWED while the same secret as the first token was refused. Costs 0.33% false-block on `flow[tau2]`, containment unchanged |
| **In-scope data staging** | **Not stopped** | byte-identical to allow-all ([in_scope_exfiltration.md](../benchmarks/results/in_scope_exfiltration.md)) |

---

## 6. Residual risk, stated plainly

1. **A compromised control plane defeats everything here.** Every guarantee is
   downstream of "the thing that mints and seals is honest".
2. **Content-defined harm is open.** 77% of missed attacks carry no target at
   all, so nothing binds. The obvious fix, escalate every untargeted
   consequential action, blocks 55% of legitimate work on tau2 and was
   rejected on measurement, not on taste.
3. **In-scope staging is open**, as above.
4. **Adaptive adversaries are under-tested.** The published sweep replays
   attacks its own authors wrote. See
   [validity_gates.md](../benchmarks/results/validity_gates.md) P10, and the
   adaptive work that addresses it.
5. **The Redis ledger lock is single-instance, not Redlock.** A failover that
   loses the lock key admits two holders. For a spend ceiling the window is one
   transaction; it is stated rather than implied.
6. **The session store is a serialisation, not a distributed store.**
   Read-modify-write across hosts needs the store's own compare-and-set.

---

## 7. Checklist for a deployment

- [ ] `CLAYSEAL_ENV=production` is set.
- [ ] A named profile is chosen and logged at startup (`profile.describe()`).
- [ ] `CLAYSEAL_COMMIT_TOKEN_TRUSTED_KEYS` pins the minter.
- [ ] `trusted_keys` pins the envelope sealer wherever `reclear` can be reached.
- [ ] A shared replay store is configured (`CLAYSEAL_COMMIT_TOKEN_REDIS_URL`).
- [ ] A shared ledger is configured if more than one process or host runs.
- [ ] A decision sink is configured; `dropped` and `evicted` are alerted on.
- [ ] `totals_verified: false` and `late_breaches > 0` page someone.
- [ ] `CLAYSEAL_STEP_UP_ALLOW_UNSIGNED` is **not** set.
- [ ] The in-scope staging gap is accepted in writing, or the workload does not
      grant an agent both secrets and a publication surface.
