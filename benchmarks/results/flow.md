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

## The chunked arm, which was the cheapest bypass of all

Splitting the value across several writes defeated the whole mechanism. Velocity
does not fire, because a handful of writes is not a burst. Flow control did not
fire, because no single write carried the value and each fragment sat below the
reconstruction floor. **Two writes was enough**, and one character per write
walked the secret out just as easily.

That is the seam between the volume axis and the sequence axis, and neither
mechanism owned it.

The check now accumulates per sink and asks whether the value appears as a
SUBSEQUENCE of everything that sink has received, which survives filler between
fragments, and only ALLOWED content accumulates, because a refused write never
happened.

| Value split across | whole value out, tau2 | whole value out, BFCL | mean characters leaked |
| --- | --: | --: | --: |
| 2 writes | 0/300 | 0/91 | 11.0 |
| 4 writes | 0/300 | 0/91 | 6.0 |
| 11 writes | 0/300 | 0/91 | 10.0-11.5 |
| 22 writes (one character each) | 0/300 | 0/91 | 11.0-15.8 |

Two bounds make a subsequence match evidence rather than coincidence. The match
must cover at least twelve characters, and for a PARTIAL match the span it is
found in must be at most 32 times its length. A COMPLETE in-order match of twelve
or more characters is exempt from the span bound, because it is not coincidence
at any span: holding complete matches to it was what let BFCL's larger write
arguments inflate the span until the value escaped in 45 of 91 chunked sessions.

Both constants come from sweeps against real traffic, not from taste.

## The fan-out arm, which was the obvious bypass of that fix

A per-sink accumulator is defeated by using more sinks. One fragment to each of
twenty-two attacker addresses reassembles perfectly, and every individual sink
sees a single character. Measured: **the whole value escaped at every fan-out
width.**

An attacker controls every sink they send to, so the pool of sinks the sealed
goal did NOT name is one adversary and is now accumulated as one. Content sent to
a declassified sink stays out of that pool, so authorized traffic cannot make a
later unrelated write look like a leak.

| Value split across | whole value out, tau2 |
| --- | --: |
| 2 sinks | 0/300 |
| 4 sinks | 0/300 |
| 11 sinks | 0/300 |
| 22 sinks (one character each) | 0/300 |

The legitimate case is asserted next to it, because pooling every sink is the
aggressive half of the fix: a session that writes to fifty different recipients
after a sensitive read is not stopped, 50 of 50 allowed.

Pooling raises the measured false-positive rate from 1 to 2 of 8,040 real benign
writes (0.012% to 0.025%).

### The blast radius is a constant, not a proportion

The mean characters column is the honest cost. A value cannot be recognised
before enough of it has left, which is information-theoretic rather than an
engineering failure, and the floor is twelve characters.

| Payload size | characters leaked | proportion |
| --: | --: | --: |
| 22 | 8 | 36.4% |
| 60 | 28 | 46.7% |
| 200 | 96 | 48.0% |
| 1,000 | 124 | 12.4% |
| 5,000 | 124 | **2.5%** |

So a bulk exfiltration is prevented and a short credential is only detected. For
anything under about a hundred characters the operational response is rotation,
not blocking, and the memo should say so rather than quote the containment number
alone.

### False positives at scale

Subsequence matching over an accumulated buffer is exactly the shape that
produces false alarms, so it was measured on real traffic with deliberately
awkward secrets rather than only the synthetic key:

| Sensitive value | flagged / real benign writes |
| --- | --: |
| synthetic API key | 0 / 1,372 |
| customer email address | 0 / 1,318 |
| short customer id | 0 / 1,319 |
| a common phrase ("customer service request ticket") | 1 / 1,367 |
| bare digits (a card number) | 0 / 1,352 |
| a filesystem path | 0 / 1,312 |
| **total** | **1 / 8,040 = 0.012%** |

### Cost

The scan is bounded, because it runs inside the authorization path where the rest
of the stack costs 35us at the median: at most 256 characters of a value are
matched and at most 32 start positions are tried. Unbounded, a 5,000 character
payload against a 64KB buffer did not finish in two minutes, which would have
made the check a denial of service on itself. Bounded, it costs 0.04ms to 1.1ms
per write depending on payload size.

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
