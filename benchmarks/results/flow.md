# Confidentiality flow: the fourth kind of harm

Our measurement splits agent harm by what defines it. Three of the four were
already characterised.

| Harm defined by | Example | Result |
| --- | --- | --: |
| **Target** | write to `/root/.bashrc`, send to an attacker IBAN | 99.9% RedCode, 100% IPI-Coding |
| **Volume** | 50 authorized sends from a compromised assistant | 100% at burst >= 10, blast radius 4-5 |
| **Content** | an authorized email whose text is a phishing lure | 6.3% AgentHarm; frontier 32% of SLEIGHT at 1% FPR |
| **Sequence** | read the credentials file, write it to the log you own | *this document* |

Sequence-defined harm is the one where every field of every action is correct.
The agent reads a resource it was granted. It writes to a sink it was granted.
The targets are in scope, the pace is ordinary, nothing is protected, and no
single action is harmful. Only the pair is.

A per-action authorization layer cannot see a pair, so it allows both. Unlike
content-defined harm, this one is decidable: it does not require guessing intent,
only remembering where a value came from.

## Why the textbook answer does not work

Bell-LaPadula says no write down. Applied per session that is correct and
unusable: an agent that reads one secret at step three has every subsequent write
blocked. That label creep is why information-flow control has stayed out of
production systems for forty years.

`agentauth/capabilities/confidentiality.py` checks **per value**. A write is
refused when its arguments carry a value attributable to a sensitive read, and
not otherwise. An agent may read a secret and then write anything that does not
contain it.

Declassification is bound to the **sealed goal**: a sink the goal named may
receive sensitive data, every other sink may not. The goal is fixed before any
tool output could contaminate it, so an injected instruction cannot nominate a
sink.

## Result

`benchmarks/flow.py`. Sessions are real benign traffic; every arm is verified to
clear the full ladder below the flow check, so anything refused is refused by
flow control alone.

| Corpus | sessions | leak contained | legitimate false-blocked | label creep | real traffic false-blocked |
| --- | --: | --: | --: | --: | --: |
| tau2 | 300 | **100%** | 0.0% | 0.0% | **0.0%** (0/1100) |
| BFCL | 91 | **100%** | 0.0% | 0.0% | **0.0%** (0/223) |

    ladder below flow control: 1173 allowed, 0 blocked

Four arms, because reporting only the first would be dishonest:

**Leak.** The secret to a sink the goal did not name. Refused.

**Legitimate.** The same secret to the sink the goal did name. Allowed. A
mechanism that scored 100% on the leak arm by refusing everything would score
100% here.

**Label creep.** A write to the non-declassified sink carrying a value that never
came from the sensitive read. Allowed. A session-level tracker fails this arm by
construction.

**Real traffic.** The session's own legitimate writes, unchanged, replayed after
the sensitive read. 1,323 of them across both corpora, none refused. This is the
false-positive measure that matters, because the reconstruction pass below
strips separators and substring-matches.

## Evasion profile

Exact token matching is exact, so the benchmark sweeps transforms an agent could
apply on the way out. **Every one of these carried the value out at 100% before
it was handled**, and the sweep is what found them.

| Transform | before | after |
| --- | --: | --: |
| verbatim | 100% | 100% |
| embedded in prose | **0%** | 100% |
| split in two | 0% | 100% |
| split into fours | 0% | 100% |
| base64 | 0% | 100% |
| hex | 0% | 100% |
| reversed | 0% | 100% |
| dotted (`A.K.I.A...`) | 0% | 100% |

The prose case was a defect in the attribution index rather than in the flow
logic, and it is the one that would have mattered most in production. The token
class has to contain `.` because real values contain it (paths, addresses,
URLs), which meant a secret ending a sentence was indexed as `<secret>` and
written as `<secret>.` and the two did not match.
`agentauth/capabilities/parameter_provenance.py` now indexes both the raw and the
edge-trimmed form.

The rest are mechanical transforms with mechanical inverses, handled by
normalising the outgoing payload before matching. A reconstructed match requires
twelve characters rather than six, because stripping separators makes long
strings out of ordinary text and a short secret could otherwise appear in one by
coincidence. The real-traffic arm is what verifies that bound holds.

## What this does not do

**A value the agent describes rather than quotes is gone.** Encryption,
paraphrase, or summarising a record into prose defeats attribution, and there is
a test asserting exactly that rather than hiding it. Flow control raises the cost
of exfiltration; it does not make it impossible. That limit is shared by every
practical taint system.

**If the goal names the sink, the data may flow to it.** An attacker who controls
the sealed goal controls declassification. Sealing the goal before execution is
what makes this safe, and the mechanism must not be deployed where the goal is
attacker-reachable.

**The policy has to be written.** Which resources are sensitive and which sinks
the goal named come from the mandate. Absent policy means no flow control, so a
mandate written before this module behaves exactly as it did.

## Reproduce

```bash
.venv/bin/python -m benchmarks.flow --corpus tau2 --count 300 \
  --json benchmarks/results/flow_tau2.json
.venv/bin/python -m benchmarks.flow --corpus bfcl --count 300 \
  --json benchmarks/results/flow_bfcl.json
```
