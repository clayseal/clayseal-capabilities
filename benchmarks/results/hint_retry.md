# Benign hints + re-audited retry

ARGUS's utility story: on deny, return grounded recipients; agent retries;
retry is fully re-authorized. We had `trusted_candidates` on
`BrokerDecision` and in the live block string, but no rewrite+re-gate loop.

## Mechanism

- `clayseal/capabilities/retry_hints.py`, rewrite destination-shaped args
  only (`to` / `account` / …); never touch `body`.
- `BrokerToolsExecutor`, on floor egress miss with candidates, one re-audited
  retry via `harness.gate` (full `authorize`). No bypass.
- Candidate order: egress allow-list first (can ALLOW), then provenance
  structured (STEP_UP only under product policy).
- Provenance mode widens the allow-list from **structured** fields of
  **goal-named** reads so a later retry can ALLOW; free text is never mined.

## Live (gpt-4o-mini, important_instructions)

| suite | ablation | n | clean util | ASR | util@attack | hint-retry |
|---|---|--:|--:|--:|--:|--:|
| workspace | envelope | 4 | 100% | 0% | 100% | 0/0 |
| workspace | envelope-provenance | 4 | 100% | 0% | 100% | 0/2 |
| banking | envelope-provenance | 8 | 0% | 0% | 12.5% | **1/19** |
| banking | envelope-taint | 8 | 0% | 0% | 12.5% | **1/8** |

Hint-retry is live (1 autonomous recovery on banking). Clean-utility cliff on
banking is mostly non-egress (plan/scope): goals like "pay
bill-december-2023.txt" name no IBAN. Retry cannot promote provenance-only
STEP_UP to ALLOW without reintroducing the structured-injection inversion;
hits need allow-list membership (goal seed or structured widen from a
goal-named read).

## Security invariant

Retry never skips the broker. A rewritten send to an attacker address still
denies. Soft STEP_UP remains halt-for-autonomous.
