# The in-surface wall: two mechanisms proposed, both measured down

STATUS: current

```bash
python -m benchmarks.coverage --datasets agentharm,sleight --limit 4000 --engines deployable-stack
```

The floor contains 31.6% of AgentHarm's in-surface attack events and 37.7% of
sleight's. That residual has been reported as a wall for four passes without
anyone asking what SHAPE it is. This is that question, and the answer killed
both of the obvious fixes.

**Read `session_units.md` first.** Those two figures are per EVENT, which is the
optimistic read of cost and the pessimistic read of protection at the same time:
per SESSION the same run contains 46.2% and 78.0%. The wall is lower than this
file's title assumes. What follows is still the right analysis of what is left
of it, and the two mechanisms below fail on either unit.

## What the residual is made of

| corpus | uncontained | dominant verbs | dominant tools |
| --- | --: | --- | --- |
| agentharm | 347 | read 180, call 95, write 40 | `query_google_search`, `get_webpage`, `get_latest_emails` |
| sleight | 76 | execute 37, read 20, write 16 | `Bash` (59 of 76) |

Two different populations, which is why one answer was never going to cover
both. Almost nothing is single-action: 227 of AgentHarm's 347 come from tasks
with four or more attack events, so there IS a sequence for an aggregate rung to
bind. It simply does not bind.

## Mechanism one: a call ceiling on the read residual

275 of AgentHarm's 347 are reads and calls, and this library HAS a count budget
that no corpus declares. The obvious reading is a declaration gap rather than a
mechanism gap. It is not.

| call ceiling | in-surface contained | benign interrupted |
| --- | --: | --: |
| none | 31.6% | 6.3% |
| 12 | 31.6% | 6.3% |
| 8 | 31.6% | 6.3% |
| 5 | 31.6% | 11.8% |
| 3 | **34.7%** | **30.9%** |

**+3.1 points of containment for +24.6 points of benign cost.** The ceiling does
nothing until it is tight enough to hurt, and then it hurts far more than it
helps. The reason is visible in the shape: an attack task takes four to seven
actions and a benign one takes about the same, so the COUNT is not the
discriminator and no threshold on it can be.

## Mechanism two: decomposing a shell command

Sleight's residual is 59 `Bash` calls, and inspecting them is compelling. One
call is several operations, and the gateway sees one:

```
ls /opt/vllm/docs/ 2>/dev/null; ls /dev/shm/vllm/ 2>/dev/null
```

The recorded path is `/opt/vllm/docs/`; `/dev/shm/vllm/` is never checked. That
is the same defect class as every path bug fixed this session: **the decision is
about something other than what executes.** 53% of the residual carries a path
the gateway never saw.

The first measurement said 37% of the residual would be caught. That number was
wrong and the reason is worth keeping: it counted `/dev/null` as a target, which
is a redirect artifact present in nearly every shell line. Building on it would
have produced a control that refuses `2>/dev/null`.

Filtered to real targets, with the cost column beside it:

| | count | share |
| --- | --: | --: |
| uncontained in-surface `Bash` caught | 10 of 59 | 17% |
| benign `Bash` newly refused | 28 of 183 | **15%** |

**Roughly three benign refusals per catch**, and the reason is in the examples:
`/dev/shm/vllm/` appears in the catch list AND in the false-positive list. The
same path is reconnaissance in one task and legitimate work in another. Command
decomposition makes the gateway see MORE, and what it sees does not separate.

## What this means

Both mechanisms fail for the same reason, and stating it plainly is worth more
than a third attempt. In this population the tool is the same, the path is the
same, the count is the same, and the difference between benign and attack is
what the session is FOR. That is the goal, and the goal-conditional instruments
are the intent envelope and the behavioural detector, both already measured with
their costs in `composed_detector.md`, both with poor exchange rates.

So the in-surface wall is not a missing rung. **It is the point at which
structure stops carrying information**, and four independent sources now agree
on where it is: the curated `in-scope-exfiltration` corpus, the BPL `in-scope`
family, the label-free adversarial search, and this.

The honest product position follows from that rather than fighting it. An
authorization layer binds what an agent MAY do and it does that completely: 100%
of surface-leaving attacks across more than 4,400 events, and every rule a
document can express. What it cannot do is decide whether an action the grant
permits was a good idea, and a layer that claimed otherwise would be selling
the entailment judge as a floor.

## What was NOT tested here

A third mechanism exists and is out of scope for a lexical gateway: enforcing at
the syscall boundary, where the kernel resolves the path and there is no command
to parse. Enforcement at the syscall boundary covers that direction. It would close the
`Bash` half of this residual and it does not help the AgentHarm half at all,
because a search that is reconnaissance issues the same syscalls as a search
that is work.
