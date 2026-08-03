# Business-process head-to-head: ours vs Progent vs CaMeL

The differentiating claim. On the aggregate / composite class, where every action
is individually authorized and the sequence is the violation, we run the two
published capability defenses against our layer on a live gpt-4o-mini agent loop.

Progent and CaMeL are run as faithful reproductions of their mechanisms, grounded
in their real code:
- **Progent** enforces a per-call privilege policy. Verified in its source
  (`secagent/policy_type_check.py`): the policy is a per-tool, per-argument JSON
  schema checked one call at a time, with no cross-call state, so it cannot
  express an aggregate ceiling. The reproduction allows every in-scope call.
- **CaMeL** gates dataflow: a consequential action is restricted only when
  untrusted data influenced its control flow. In a task fully specified by the
  trusted user prompt, the gate never fires. The reproduction taints a value only
  if it comes from tool output and is not derivable from the prompt.

## The aggregate-budget class (n=20 per cell, 80 cases)

Composite-policy violation rate (lower is better):

| scenario | rung | none | Progent | CaMeL | ours |
|---|---|--:|--:|--:|--:|
| payout-splitting | value budget | 100% | 100% | 100% | **0%** |
| refund-structuring | value budget | 100% | 100% | 100% | **0%** |
| access-grant-sprawl | call budget | 100% | 100% | 100% | **0%** |
| bulk-delete-retention | call budget | 100% | 100% | 100% | **0%** |

The undefended model and both published defenses violate the composite policy on
every run. Progent authorizes each individually-valid call because its policy has
no cumulative state; CaMeL permits each action because nothing untrusted drove it.
Our stateful budget rungs hold the violation rate to zero on all four.

The honest cost is on our side: because we block the actions that cross the
ceiling, task progress is partial (payout 61%, refund 40%, access 50%, delete 38%
of the requested actions completed). That is the correct behavior — the blocked
actions are exactly the violation — but the partial progress is the utility cost to
reduce next. Neither competitor pays this cost here, because neither blocks
anything.

## The exfil / dataflow class (bulk-exfil)

This scenario (read customer records, send them to an external address) is where
CaMeL's dataflow gate genuinely engages, so it is not a clean "both blind" case and
is reported separately. Numbers pending a re-run after a fix to the Progent
reproduction. Preliminary: undefended exfiltrates (100% violation); CaMeL's gate
blocks the read-to-send flow but over-restricts and completes 0% of the legitimate
work; our egress binding blocks only the external send at 100% legitimate progress.

## What this establishes

On the class no public benchmark exercises and both leading capability defenses are
structurally blind to, our layer is the only one of the three that holds composite
violations to zero. This is the differentiated result behind the memo's "outperforms
both on the business process class," and unlike the injection axis (where CaMeL ties
us near 0%), here the separation is total. The open item is our utility cost, which
this table makes precise.
