# The HTTP gateway under randomized stress

STATUS: current

```bash
python -m benchmarks.stress_http --cases 40000 --seed 7
```

40000 generated request pairs against the only component here that parses
input arriving from a socket.

| property | violations |
| --- | --: |
| TOTAL | 0 of 40000 |
| JSON-RPC | 0 of 40000 |
| NO-BYPASS | 0 of 40000 |
| HEADER-HONEST | 0 of 40000 |

No property was violated.

## What the fix cost

Nothing measurable, and the question is worth asking because `settle` releases a
correlation the stdio path relies on. The stdio side is untouched: `settle` is
called only by the HTTP front end, where one exchange per connection makes the
request the correlation. Timing on a correct upstream is unchanged at 0.00s for
three calls, the 21 gateway tests pass, and the four properties below hold over
40,000 generated pairs. No benign request is refused that was not refused
before: the change releases a wait, it does not add a check.

## The defect this found

**A mismatched response id stalled the gateway for 15 seconds per call.**

`McpProxy` correlates a forwarded request with its reply by JSON-RPC id, which
over stdio is the only correlation available: replies arrive interleaved on one
stream and nothing else says which request they answer. `serialize_effects`
therefore waits for the outstanding set to empty before letting another
effectful call through, and `settle_timeout` bounds that wait at 15 seconds.

Over HTTP the request IS the correlation, one exchange per connection, and the
id is a formality the server may get wrong. When it does, the entry is never
cleared and the NEXT effectful call waits out the full timeout. Measured: three
calls in **30.02 seconds** against 0.00 with a correct id.

That is an availability failure a malicious or merely non-compliant upstream can
trigger deliberately, and it is the same class this repository already flagged
for an unbounded judge call on the authorization path. `McpProxy.settle` marks
one exchange answered whatever id came back, the HTTP front end calls it in a
`finally`, and the stdio path is untouched.

The same release covers the other upstream failures, which had the same shape:

| upstream behaviour | before | after |
| --- | --: | --: |
| echoes the correct id | 0.00s | 0.00s |
| echoes a wrong id | 30.02s | **0.00s** |
| raises | not measured | 0.00s |
| returns text that is not JSON | not measured | 0.00s |

## How it was found, which is the point

Not by the fuzz reporting a violation. **The fuzz timed out**, because a canned
upstream reply with a fixed id made every generated request stall, and 20,000
cases at 15 seconds each does not finish. A harness too slow to run is a signal
in its own right, and chasing why turned a benchmark problem into a gateway
defect.

The four properties then held clean over 40,000 generated request pairs, which
is what the file is for the rest of the time.

**And one of the four was mis-specified.** `NO-BYPASS` counted any response of
400 or worse beside a forwarded message as a bypass, which made a 502 one. A 502
is the upstream failing AFTER the gateway allowed and forwarded, so the property
was measuring the test's own stub rather than the gateway. It counts a 4xx now,
which is a gateway refusal. Third time this session a probe has been wrong
before the code was.

