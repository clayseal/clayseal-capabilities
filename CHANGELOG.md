# Changelog

All notable changes to **clayseal** are documented here. The distribution was
called `agentauth-capabilities` before 0.6.0; see [docs/MIGRATION.md](docs/MIGRATION.md).

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

Nothing yet.

## [0.6.0] - 2026-08-28

The first release intended to be read by people outside this repository.

### Breaking, with one release of compatibility

- **Renamed to `clayseal`**: the distribution, the import root, the CLI and the
  environment variables. `agentauth.capabilities` and `agentauth.core` still
  resolve through an import hook and warn; they are removed in 0.7. The alias IS
  the real module, so a plugin registered through the old path is visible through
  the new one. `AGENTAUTH_*` is read as a fallback. Storage keys and wire
  identifiers were deliberately NOT renamed: `agentauth:commit:` stays, because
  renaming the replay store's prefix makes every already-spent commit token
  unseen and reopens the replay window. Full list in
  [docs/MIGRATION.md](docs/MIGRATION.md).

### Fixed: the library did not work on Python 3.10

`datetime.fromisoformat` did not accept a trailing `Z` until 3.11, and
`requires-python` is `>=3.10`. Since `is_expired` treats an unparseable expiry as
expired — correctly — **every policy with a `Z` expiry denied every call on
3.10**, which is every policy this repository documents. Nine call sites parsed
timestamps and one knew about `Z`; there is one parser now.

### Fixed: five destination spellings the egress allow-list could not see

`http://[2001:db8::1]/`, a Cyrillic homograph, a single-label host, and the
integer and hexadecimal forms of an IPv4 address were all ALLOWED while the
dotted form of the same address was refused. A host the parser cannot read is not
denied, it is invisible. Now canonicalised to one form before matching, so
allow-listing an address once covers every spelling of it.

### Fixed: two path spellings that open a denied file

`workspace/SECRETS/key.pem` and `workspace/secrets./key.pem` were allowed under
`denied_paths=["workspace/secrets/**"]`. Both open the same file on a
case-insensitive or Win32 filesystem. The extra readings widen DENY only, so no
allow decision became stricter.

### Fixed: `PrincipalBudgetView.reserve` enforced no ceiling

It read an undeclared `config` attribute and returned `ok_untracked` when unset,
admitting 20 of 20 calls against a ceiling that `would_allow` correctly capped at
10 — and reporting the calls as untracked. Not reachable through a policy file,
which sets `config` immediately; reachable by hand-wiring a ledger, which the
constructor invites. Both gates now read one answer, and a test asserts every
budget's two gates agree.

### Performance

- Egress argument scanning 24-42x faster on the step, byte-identical output.
- Confidentiality tail 4.1x at 400 sensitive tokens. The memo is per session, not
  process-global, because its keys are the secrets.
- Policy compile 4.5 ms to 0.24 ms (libyaml when present, same safe loader).
- `import clayseal.capabilities` 85 ms to 2.5 ms (PEP 562 lazy exports).
- Overhead samples bounded; `summary()` no longer sorts a growing list.

34 us per decision, flat in session length. Memory per session is still
unbounded: [docs/TRAJECTORY_WINDOW.md](docs/TRAJECTORY_WINDOW.md) has the design
and says why the BPL suite cannot size the window.

### Usability

- A refusal explains itself. `.reasons` keeps the stable codes; `str(exc)` is now
  a sentence you can hand to an agent.
- `with budget.reserve(...) as res:` settles the hold on the way out.
- `house_rules`: add a rule without forking the gateway.
- An [API reference](docs/API.md), and a docstring on every shipped module.

### Measurement

- Performance numbers live in one place; four documents had quoted four different
  p50s for "the full stack".
- The non-deterministic benchmark arms say so, with their spread.
- `ruff check .` passes; mypy runs and is ratcheted; CI gained perf and type jobs
  and runs on every branch.

Containment is unchanged throughout: 39.4% (52/132) on the full BPL suite, with 2
benign scripts refused and no work lost.


### Documented: what the syscall tier catches that nothing above it can

The evidence was already in `syscall_tier.md` and neither the result nor the
README said what it showed. The `iVisor deny` and `Clay deny` columns diverge in
both directions, and that divergence is the whole argument for the layer.

**04-dns-tunnel: iVisor 4, Clay 0.** The payload leaves as base32 in subdomains
(`c2vjcmv0`, `zxhmawx0cmf0zwq`) over four A and AAAA queries. Every tool-call
layer denies nothing, and not through misconfiguration: a DNS resolution inside
the guest is not a tool call, so `authorize()` is never asked. Only a syscall
boundary is positioned to see it.

**07-beaconing and 08-exfil-allowed-channel: iVisor 0, Clay 7 and 6.** The
reverse. The channel is allow-listed so every syscall is legitimate and iVisor
is right to permit them; what is anomalous is the running total, which only a
session-scoped budget holds.

Neither layer subsumes the other. The README framed the syscall tier by its
constraint ("macOS only") and never said what it uniquely catches; it now leads
with the catch and keeps the constraint.


### Fixed: two syscall scenarios were hardcoded to pass

`syscall_tier.py` contained `elif scen.id in {"05-host-escape",
"06-audit-evasion"}: ok = True`. Two scenarios passed by NAME, whatever the
replay did. Their captured traces are byte-identical to each other and carry
three lines of ordinary allowed activity: open a notes file, resolve pypi.org,
connect to it. Nothing is attempted, so nothing is contained.

That took a 6-of-6 result and published it as **100.0% (8/8)**. It now reads
100.0% (6 of 6 scenarios that produce a syscall-level event; 2 excluded as
non-events), and the two are listed as `n/a` with their reason. A replay that
carries no attack is evidence of neither containment nor escape.

The other six are real. 01 to 04 are contained by egress, task-scope and the
iVisor floor. 07 and 08 are contained by the session budget with zero iVisor
denies, which is the interesting case rather than a weak one: the syscall layer
allows the channel and the session-level total is what catches the volume.

The generator emitted neither a `STATUS:` line nor its command, so every
regeneration reintroduced that debt to `check_claims`. It emits both now.

### Removed: a corpus codename from two test fixtures

`claude-ocelot-preview/` appeared in the command strings of two tests. The rule
they exercise fires on `results`, not on the project name, which the tests
confirm by still passing with a neutral fixture.


### Added: `tools.patterns`, the grant surface only the benchmark could reach

- **The largest friction result in the project was measured against a mechanism
  no user could deploy.** `SessionBroker.tool_patterns` has been enforced since
  the pattern work landed, and only `benchmarks/core/patterns.py` could set it:
  `compile_policy` never read a pattern field, so a policy document could not
  say it. `generalisation.md` reports held-out false blocks falling from 47.91%
  to 0.05% on tau2 once a grant is written as patterns rather than as the
  instance list a logger produces, and until now that was a fact about the
  harness. `tools.patterns` is the reach.

  Measured at the tool+verb namespace level: **AgentHarm held-out false-block
  55.56% → 0.82%** for 1.3 points of containment. RedCode is unmoved. Opt-in
  and never a default, because a pattern cannot tell `get_reservation` from
  `get_all_reservations`.

- **A confound in the generalisation sweep, found by pulling on the one result
  that looked too clean.** `patterns.generalize_task` routes both the tool and
  the resource dimension off `tool_level`, justified by "they are 1:1 in every
  loader that names resources `mcp:tool:<tool>`". That condition is stated and
  never checked, and it is false for **8 of 18 corpora**. So `--typed tool`
  silently varies resources on those, and a result read off that column as a
  fact about tool patterns can be a fact about resource patterns.

  Mind2Web-SC is the case that proves it. It reads as 98.00% → 0.00% under a
  `tool+verb` sweep, and was cited here and in `generalisation.md` as the
  decisive counterexample for tool generalisation. Its tools are `click`,
  `select` and `type`, granted identically in every task, so the tool dimension
  cannot carry signal at all. Generalise tools and verbs while pinning
  resources: **98.0%, unchanged.** The collapse is entirely the resource
  dimension, and it is the reason `resources` takes no patterns rather than a
  caveat on the ones `tools` does. `generalize` now detects corpora whose
  resource axis is independent and marks those rows CONFOUNDED.

  `generalisation.md` also said Mind2Web-SC "breaks at the first level". It
  survives `up1` and `up2` at 98.00% and breaks at `namespace`.

- **Two enforcement defects found while wiring it.** `broker.py` treated
  patterns as REPLACING `allowed_tools` rather than unioning with them, so a
  grant carrying both refused a tool named explicitly in `tools.allow`. Nothing
  hit it while only the benchmark could set patterns, because level 0 restates
  the exact instances and the two readings agree there. And the proxy's first
  `_tool_granted` asked `allowed_tools is None` after failing to match a
  pattern, which **fails open** on exactly the document the field exists for:
  patterns declared, no literal list, every unmatched tool granted. Caught by
  asserting the proxy's two gates agree with each other.

- **The three cross-checks learned about patterns together.** `tools.effects`,
  `paths.arg_names` and `paths.pathless` each verified their tools against
  `tools.allow` with their own copy of the same expression, so each was a
  separate way for the feature to be unusable. They share `_uncovered` now.

- **Guards.** A universal pattern (`*`, `**`) is refused at compile time, the
  rule `paths.allow` already carries. An entry with no wildcard is refused,
  because a literal belongs in `allow`. `lint` always reports a pattern grant,
  it being the one part of the document whose extent is not visible from
  reading it, and separately flags a leading wildcard: `*_data` admits
  `delete_data` as readily as `read_data`.

### Audit: credentials, and the ignore rule that let a virtualenv in

**No credential is committed anywhere, in the working tree or in any history.**
Seven credential-shaped strings exist and all seven are synthetic: two are the
vendors' own documented examples (`AKIAIOSFODNN7EXAMPLE`,
`ghp_16C7e42F292c6912E7710c838347Ae178B4a`), the rest are sequential or
placeholder test fixtures. No PEM block with key material appears in any commit
reachable from any ref. No `.env`, `.netrc`, `.pem` or credential-shaped
filename is tracked.

The personal-looking email addresses in `benchmarks/` are third-party corpus
fixtures: AgentDojo's `bluesparrowtech.com` personas and AgentHarm's targets,
synthetic by construction. Every non-reserved IP address traces to a benchmark
result or a recorded trace.

**`.gitignore` would not have stopped the accident it just cost 1.5 million
lines to undo.** `venv/` matched `venv` and not `venv312`, and `env`, `ENV`,
`.virtualenv` and `node_modules` were not covered at all. They are now. The
exact directory that was committed, `.venv-h2h`, was already caught by
`.venv*/`; the names around it were not.


### Public-benchmark coverage

- **A control for event ORDER, because four corpora could be beaten by
  counting.** A benign-paired corpus that replays a benign prefix and then an
  attack suffix can be "contained" without reading a tool, a path, a destination
  or a policy: block late events and the attack share falls, because the attack
  events are the late ones. Every paired corpus in the repository segregates
  this way, in 100% of paired tasks. `position-only-control` reads an event's
  index and nothing else, and is now printed in every ladder table beside
  `deny-all`, for the same reason `deny-all` is there. It lives in `CONTROLS`
  rather than `LADDER` so the monotone-ablation invariants stay valid.

  Screened over every registered corpus by
  `python -m benchmarks.ordering_exposure`: `agent_threat_bench`, `asb`,
  `injecagent` and `ipi_coding` each report 100% containment that a position cut
  also reaches at the same zero false-block. That is a statement about those
  corpora, not about the rungs. The ones that discriminate do so decisively,
  RedCode 100% against counting's 0/400 and AgentDojo 100% against 3.9%, which
  is what keeps the control honest.
  [ordering_exposure.md](benchmarks/results/ordering_exposure.md).

- **`benchmarks/cli.py` honours the contract the corpus already declared.** A
  loader can name its highest valid rung (`ladder_rung`) and mark its
  false-block column unscoreable (`false_block_unscoreable`). `scoreboard.py`
  read both; the CLI, which generates every `results/new-suites/*.md`, read
  neither. So `sleight.md` published a velocity row as a result on a corpus
  whose own loader says velocity "misreads long coding-agent sessions as abuse"
  and whose friction column it marks unmeasurable.

- **An uncalibrated cap is no longer printed as a measurement.**
  `VelocityLadderEngine.calibrate` reads only attack-free tasks. A loader that
  concatenates a benign twin and its attack supplies none, so the cap silently
  became `default_cap = 5`, an arbitrary constant, on SLEIGHT and ASB.
  `calibrate_with_provenance` returns whether calibration data existed and the
  table now names the rungs that fell back.

- **SLEIGHT is reported through the layer it tests.** Its sabotage happens inside
  a workspace the agent legitimately holds (all 122 escaped events are under
  `/opt/**`, the largest category being `model_priors`), so a per-action
  authorization layer is the wrong instrument: 5.4% at the ladder's valid rung
  against the trajectory detector's **94.4% (17/18) at 0/18, 97.5% upper bound
  18.5%**. The loader already said so in `meta["score_with"]`.

- **Five corpora cannot support a friction claim at all.** Rendering the zeros
  with their bounds shows `fixture` has 7 benign events, `b3` 8, `mcp_attack` 9,
  `advbench_agent` 11, `agent_threat_bench` 24. A zero false-block on 7 events is
  not distinguishable from 41%.

### Changed: the corpus-derived rule pack is off by default

Measured at zero on every published number, so running non-general pattern
matching in front of everybody's traffic buys nothing. It was on by default
because the published figures had been produced that way, which is a reason to
keep an arm reproducible and not a reason to make it the default. Turn it on
with `session_rules=True`. Every number is unchanged either way:
`corpus_rule_contribution.md`.

### Fixed: a policy document's most common sentence was dropped entirely

"Payments over $10,000 require approval" produced **no rule and no TODO**. The
marker list held `requires approval` and not `require approval`, so a plural
subject lost the line, and the module's whole contract is that nothing
rule-shaped disappears silently. The same singular/plural miss sat one layer
down, where a ceiling that was extracted recorded `needs_approval_above: False`,
which inverts the rule rather than missing it.

Three more ordinary phrasings were dropped the same way: "No payment may exceed
$500", "Payments are capped at $50,000 per day", "The daily limit is $20,000".

Rather than add four phrases to a phrase list that loses on the fifth, **a line
naming an amount of money is now rule-shaped whatever words it uses.** Money is
a structural signal. Prose with a bare number ("5 Main Street", "12 sections")
is unaffected, because the money pattern wants a currency.

On tau2's own documents this finds two more real rules, both compensation
ceilings the airline policy states ($100 and $50 travel certificates), and the
external oracle is unchanged at 1 false block in 13,907 ground-truth actions.

### Verified: the integration surfaces

Exercised rather than described, because a broken integration is invisible to
the corpora: nothing in the benchmark harness speaks MCP over HTTP, emits OCSF,
or wraps a framework's tools. `test_integration_surfaces.py` now covers all six.

| surface | checked |
| --- | --- |
| `Guardrail.wrap_all` | name, docstring and signature survive, so a framework introspects the tool it had; the ceiling still refuses |
| MCP proxy | an ungranted tool is withheld from the catalogue AND its call is never forwarded upstream |
| HTTP gateway | protocol `2026-07-28`; a header that disagrees with the body is refused with `-32020` per SEP-2243 |
| OCSF sink | `class_uid` 6003 with the required API Activity fields |
| W3C trace context | a valid `traceparent` parses, a malformed one is rejected |
| document to policy | the draft round-trips through the policy loader |

`ledger_backends` was the one optional extra that did not name itself on a
missing dependency: setting the ledger URL without the redis client gave a bare
`ImportError`. It now says which install fixes it, like the others.


### Removed: literals copied from benchmark scenarios

The same audit as the regex one, applied to overfitting: every compound string
literal in the shipped library, cross-referenced against the text of the
benchmark scenarios and corpora. A literal present in both and nowhere else is
the signature.

Three were found, and **each contributes zero to every published number**,
measured by removing it and re-running every scored population:

- **`ocelot`** in `session_rules._UPLOAD_ARTIFACT_WORDS`, the project name of
  one sleight-bench scenario. It cannot match outside that corpus.
- **22 AgentHarm tool names** in `entailment._FREE_TEXT_TOOLS`
  (`create_ransomware`, `run_stable_diffusion_model`, ...). Thirteen were
  already covered by the `post_`/`send_` prefix rule beside them, and the list
  only runs when the LLM judge is on, which no benchmark enables.
- **Six directory names** in the secret-path list (`data/models`,
  `anthropic-config`, `deploy/auth`, `db/app.conf`, `sanitize_rules`,
  `checkpoint`), which name one corpus's layout rather than a kind of secret.

All three are gone. The generalisable half is kept: symlink-into-results, then
zip, then upload is a real exfiltration technique, and the rule for it stays,
keyed on the technique.

`session_rules.py` had already done the hard part honestly. It documents itself
as corpus-derived, says plainly that the rules will not generalise, names
`ocelot` in a constant instead of burying it in a regex, and makes the pack
switchable. What was missing was the number: the pack is ON by default, every
published figure was produced with it on, and its contribution had never been
measured. `benchmarks/results/corpus_rule_contribution.md` states it. It is
zero, on the external corpora and on the BPL headline alike.

`test_the_upload_rule_still_carries_its_corpus_literal` asserted `ocelot` was
present and said it should be removed deliberately rather than silently. It now
asserts the absence.


### Security: no pattern in the library is super-linear any more

The sweep was extended from seventeen adversarial shapes to a doubling test over
every compiled pattern: measure at 1 KB, 2 KB, 4 KB and 8 KB and look at the
curve. That separated real hazards from jitter. Ten patterns looked alarming on
a growth ratio alone and were noise from a sub-millisecond base. **Three were
genuinely quadratic**, growing fourfold per doubling.

| pattern | at 8 KB | after |
| --- | --: | --- |
| `session_rules._ZIP_ARTIFACT` | 230 ms | substring test |
| `policy_draft._PATH` | 167 ms | one pass over the words |
| `session_rules._SED_PATHS` | 62 ms | one pass over the tokens |

All three asked the same question, "which tokens here look like paths", and a
sentence or a command is already separated into tokens. Each is now a single
pass that cannot backtrack.

**The caps added in the previous commit are gone**, and that is the result
rather than an oversight: replacing the patterns removed every use of them.
`core/scan_limits.py` is deleted. Bounding the input was always second best,
because a cap can hide a match past it and leaves the hazard in place for the
next call site; where the input has a grammar, scanning it linearly costs
nothing and removes the hazard instead.

Two readings were checked against the patterns they replace rather than assumed.
`_paths_in_command` differs from its regex on commands like `aws s3 cp r.zip
s3://b/`, where the old one extracted `//b`; those commands never reach it,
because it is only called after the `sed -i` guard matches, and on the six sed
forms that do reach it the value the caller uses is identical. `_paths_in`
extracts `*.tar.gz` where the old pattern stopped at the first dot and returned
`*.tar`, a glob that does not match the file the sentence names. That one is an
improvement and the docstring says so.

`test_no_catastrophic_backtracking.py` now sweeps every pattern in the library
itself, so a new one cannot reintroduce the class. The guard was verified by
planting a catastrophic pattern in an unrelated module and confirming it fails.

### Security: regex on attacker-controlled input was a remote hang

Python's `re` backtracks, so `(?:group)+suffix` explores exponentially many
splits when the suffix never matches. Every compiled pattern in the library was
fed adversarial input and timed. **Seven took over 50 ms; the worst took 3.5
seconds on a single 16 KB argument.** All of them read arguments an agent
controls, so that was a hang anybody could trigger with one tool call.

| pattern | before | after |
| --- | --: | --: |
| `egress_policy` bare-host scan | 3,473 ms | 0.6 ms |
| `sealed_plan._SECRET_PATH` | 2,684 ms | 0.4 ms |
| `egress_policy` email scan | 2,594 ms | 0.6 ms |
| `session_rules._SED_PATHS` | 2,397 ms | bounded |
| `egress_policy._FULL_EMAIL` | 2,308 ms | 0.6 ms |
| `session_rules._ZIP_ARTIFACT` | 1,465 ms | bounded |
| `policy_draft._PATH` | 773 ms | bounded |

**Where the input has a grammar, the pattern is gone.** Hostnames and email
addresses are now found by `_hosts_in` and `_addresses_in`, which scan once,
left to right, with no backtracking possible. That also made the multi-`@`
bypass structurally impossible rather than patched: a token resolves to the host
after its LAST `@`, which is where RFC 5321 routes, and every host between is
returned too, so `ops@allowed.com@evil.test` cannot present the policy a host it
will not deliver to. The regex patch shipped for that bug is deleted.

A lenient parser was the obvious alternative and is the wrong one.
`email.utils.parseaddr` carries CVE-2019-16056 and CVE-2023-27043 for exactly
this multiple-`@` case, because it guesses at malformed input. An allow-list has
to reject what it cannot read.

**`is_secret_path` was substring tests in costume.** `.*credential.*` after
`(?:^|/)` only asks whether the path contains "credential", because `.` matches
`/` too; the alternation over several such branches is what backtracked. It is
plain string operations now, verified identical on 27 paths including the ones
that must NOT match, `etcetera/file` and `/opt/etcd/data`.

**Where a pattern is the right tool, the input is bounded first**, and
`core/scan_limits.py` states why each bound is the size it is: `PATH_MAX` for a
path, a command-line bound for a command, a line for a document line. Truncation
can hide a match, and that is acceptable only because a value past those caps is
no longer the kind of thing the pattern looks for. The module says so, and says
that a detector whose input has no natural bound must be rewritten instead.

`test_no_catastrophic_backtracking.py` holds a 250 ms budget across seven
adversarial shapes, through the egress check, the secret-path check, document
reading, and a whole authorization. It fails if any decision path becomes
super-linear again.

Containment, benign cost and the BPL headline are all unchanged.


### Fixed: an address that lied about where it routes cleared the allow-list

`ops@acme-internal.com@evil.test` was **allowed** against an allow-list holding
`acme-internal.com`. RFC 5321 routes on the last `@`, and so does every mailer,
so that address delivers to `evil.test`. The address regex stops at the second
`@` because `@` is not in its host character class, so it extracted
`acme-internal.com`, matched the allow-list, and the real destination was never
shown to the check: `extract_destinations` returned `['acme-internal.com']` and
nothing else.

Every host after the first `@` is now extracted, so the token is refused however
the receiving mailer resolves it. Recipient lists are unaffected, because they
are split on address separators first: `a@x.com, b@y.com` is two tokens with one
`@` each. `test_egress_address_evasion.py` covers both directions.

Twelve other evasions were probed and were already handled correctly: uppercase,
trailing dot, subdomain, attacker suffix and prefix, substring host, userinfo
(`acme-internal.com@evil.test`), homoglyph, trailing whitespace, embedded
newline, and a URL carrying the allowed domain in a query parameter.

### Investigated and rejected: widening verb inference

`classify_verb` returns `call` for a name it does not recognise, and `call` is
DISCLOSURE, below WRITE, so an undeclared `wire_funds` or `terraform_destroy` is
not `is_effectful`: the floor's write and egress rules do not engage and no rung
may refuse it. Ten of twelve dangerous names tested this way, and over 34 tool
names taken from widely used MCP servers, 13 fell through to `call`.

Widening the table to recognise `destroy`, `purge`, `wire`, `grant`, `upload`
and the rest was built and measured. It is **not shipped**, because the BPL
suite is the only benchmark with realistic tool names AND benign twins, and
there it moved containment from 54 to 61 of 132 while moving FALSE BLOCKS from
**2 to 14**, dropping the joint metric from 52 to 49. Narrowing to the
unambiguous stems recovered the joint metric to 52 and still left 8 false
blocks against 2. `granted_read` inferred to a write.

That is the utility leak the classifier's own comment warns about, and the
external corpora cannot see it because they normalise tool verbs into four
values. Guessing harder is the wrong lever.

The right one already exists and costs nothing at runtime: `clayseal policy
lint` reports an undeclared effectful tool as an **error**, names each tool
whose verb it had to guess, and exits non-zero. On a policy allowing
`wire_funds`, `terraform_destroy` and `purge_bucket` with no `tools.effects`, it
reports three errors and the `verb-not-declared` warning naming all three.
`test_verb_inference_covers_danger.py` holds that line, and records the measured
trade so the experiment is not repeated.

### Fixed: an address that lied about where it routes cleared the allow-list

`ops@acme-internal.com@evil.test` was **allowed** against an allow-list holding
`acme-internal.com`. RFC 5321 routes on the last `@`, and so does every mailer,
so that address delivers to `evil.test`. The address regex stops at the second
`@` because `@` is not in its host character class, so it extracted
`acme-internal.com`, matched the allow-list, and the real destination was never
shown to the check: `extract_destinations` returned `['acme-internal.com']` and
nothing else.

Every host after the first `@` is now extracted, so the token is refused however
the receiving mailer resolves it. Recipient lists are unaffected, because they
are split on address separators first: `a@x.com, b@y.com` is two tokens with one
`@` each. `test_egress_address_evasion.py` covers both directions.

Twelve other evasions were probed and were already handled correctly: uppercase,
trailing dot, subdomain, attacker suffix and prefix, substring host, userinfo
(`acme-internal.com@evil.test`), homoglyph, trailing whitespace, embedded
newline, and a URL carrying the allowed domain in a query parameter.

### Fixed: dangerous tools inferred to a verb no rung could act on

`classify_verb` returns `call` for a name it does not recognise, and `call` is
DISCLOSURE, which is below WRITE. So an undeclared `wire_funds` or
`terraform_destroy` was not `is_effectful`: the floor's write and egress rules
did not apply and no rung was permitted to refuse it. Ten of twelve dangerous
names tested this way.

The verb table now covers destructive (`destroy`, `drop`, `purge`, `truncate`,
`wipe`, `terminate`, `revoke`), authorization-surface (`grant`, `rotate`,
`assume`, `provision`), shipping (`deploy`, `patch`, `merge`), outbound
(`upload`, `publish`, `push`, `reply`), money (`wire`, `withdraw`, `disburse`,
`remit`, `charge`, `settle`, `debit`) and ordinary mutation (`edit`, `move`,
`put`, `fork`, `attach`, `rename`, `append`, `replace`).

Measured over 34 tool names taken from widely used MCP servers (filesystem,
github, slack, postgres, aws, stripe), the share falling through to `call` goes
from **38% to 6%**. The two that remain are honest: `directory_tree` names no
verb, and `lambda_invoke` may or may not have an effect.

**Matching order was also wrong, and the widening exposed it.** The loop
returned on the first match in list order, so a short verb shadowed a longer one
containing it: `set` prefix-matched `settle_invoice`, and the infix `_grant` in
`disburse_grant` beat the prefix `disburse`. Both money movements read as plain
writes. Prefix now beats infix, longest first within each.

Benign cost is unchanged at 0 of 20,619 events, and containment is unchanged on
every corpus, because the corpora normalise tool verbs into four values and
cannot see this. The evidence is the classifier and gateway behaviour directly:
`test_verb_inference_covers_danger.py` asserts 22 dangerous names infer to
something a rung can refuse, and 15 reads still infer to `read`.


### Fixed: ordinary business data read as the authorization surface

`_touches_security_surface` matched its 17-term security vocabulary as
SUBSTRINGS against every argument value. `acl` is inside "oracle", `iam` inside
"William Diamond", `key` inside "monkey wrench", `access` inside "accessory".
Four of seven ordinary refund arguments classified as SECURITY, the highest
consequence level there is.

That is not a cosmetic mislabel. SECURITY sits at or above WRITE, so
`is_effectful` is true for it: a READ carrying an incidental "monkey" went from
a step-up to something a rung is allowed to refuse outright.

Matching is now on words, splitting on non-alphanumerics, which keeps every
intended hit because the names that matter are compounds: `access_key`,
`iam-role`, `rotate.secret`. Verified in both directions: 0 of 8 false
positives remain and 11 of 11 real detections are preserved.

The same line existed in `monitor/aml.py`, whose delegated-trust check the
`consequence.py` comment says is kept in sync with it. Both are fixed.

### Fixed: a dead function that could not have worked

`windowed_value_budget_from_mandate` called
`value_budget_config_from_mandate(mandate)` without `tracked`, a keyword-only
argument with no default, so every call raised `TypeError`. It also tested the
result for `None`, which the callee's signature never returns. Never called,
exported, or tested. Removed; the live path builds `WindowedValueBudget`
directly and is unaffected.

### Performance: 40% off the decision path

0.136 ms to 0.081 ms per authorization, measured as CPU time over seven
repetitions of 1,500 calls. Containment is byte-identical on every corpus.

- **The flow tracker did its full work when nothing sensitive had been read.**
  The default sensitivity policy ships patterns for `.env` and `id_rsa`, so
  `policy.active` is true in every deployment and the early return never fired.
  Each of the four detection passes matches the payload against
  `_sensitive_tokens` and returns empty when that is empty, so the result was
  already known. It now short-circuits, and still RECORDS the write, because a
  read can make a value sensitive after an earlier write carried part of it.
  Proven behaviour-neutral by replaying the fragment-before-the-read ordering
  against the previous implementation.

- **The security-surface check** ran 17 substring scans over the joined
  arguments. One split and a set intersection replaces them.

### Benchmarks: a crash can no longer pass for containment

`StackEngine.decide` scores an exception as "not allowed" so one broken task
cannot take down a sweep, which means a crash counts as a contained attack.
There are none today, across 5,203 attack events on six corpora, and nothing
said so. The engine now counts them and
`benchmarks/tests/test_no_stack_errors.py` fails if any appear.

### Fixed: attestation cached a replaced binary

`ivisor_binary_identity` cached on the path alone, justified by "the binary does
not change mid-session". It is a module-level cache in a gateway that serves
many sessions, so a binary replaced between two of them kept attesting under the
old hash, and reported the old SIZE. Now keyed on size and mtime: a swap
invalidates, an unchanged file still hits the cache.


### Integration

- **`Guardrail` is exported from `clayseal.capabilities`** and gains
  `from_policy_file`. Governing an agent is now one import and two lines:

  ```python
  guard = Guardrail.from_policy_file("policy.yaml")
  tools = guard.wrap_all({"issue_refund": issue_refund})
  ```

  The wrapper existed but was reachable only through a deep module path and
  needed `load_policy` imported alongside it. The README showed the low-level
  path instead: three imports and a hand-built `Action` with five fields,
  including a `resource` string and a verb the caller had to classify.

### README, rewritten for a developer

Measured against what open-source guidance says a reader needs, and against The
Economist's rules on sentences.

- **The API was 3,333 words in**, after roughly 1,700 words of benchmark tables.
  A reader had to get 87% of the way down before seeing how to call anything.
  Install is now at 113 words and working code at 133.

- **The policy in the README was not a policy.** It used a `value_budget:` key
  with `ceiling` and `amount_arg`, and no such schema exists, so the first thing
  a reader copied would have failed to parse. It is now a complete file that
  lints with no errors, and `test_readme_policy_is_real.py` loads it, lints it,
  and builds a gateway from it that refuses the second refund.

- **The quickstart runs.** It was a fragment referring to undefined tools; it is
  now self-contained and prints the refusal it describes.

- **Sentences: mean 20.0 words to 17.9, median 19 to 16**, and sentences over 40
  words from 9 to 2. Badges added for licence, Python versions, tests and PyPI.


### Benchmark methodology

- **The `per-call` baseline was handed half the policy, and its zero was
  arithmetic.** `benchmarks/bpl/policies.py` declares a rule for the Core-12 and
  says in its docstring that every condition receives it. Nothing read it:
  `Scenario.policy` defaulted to an empty `Policy()` and no builder assigned it,
  so 0 of 132 scenarios carried a rule at runtime. With no `scope` rule the
  per-call condition falls back to "every tool in the scenario's own catalog",
  and the scripts only call tools from that catalog, so it could not refuse
  anything whatever the scenario was. `get_scenario` now attaches the declared
  policy, and the per-call branch enforces every rule kind that is a property of
  a single call rather than only `scope`. It earns `bulk-exfil` through the
  recipient allowlist and scores **1 of 132 on the joint metric instead of 0**.
  Clay Seal's own numbers are unchanged; the row it is compared against is now a
  measurement.

- **Four of the six documented tiers were inert in the published table, and
  turning them on is worth nothing.** The provenance, taint and flow tiers read
  what a tool RETURNED, and the sweep never fed a return back. Separately,
  `SensitivityPolicy.active` is False until a mandate declares confidentiality
  classes and 0 of 132 scenarios declare any. Both are now switchable
  (`--observe-results`, `--confidentiality derived`) and both default to off.
  Measured: results fed back alone changes nothing; adding a declaration derived
  from the sealed goal moves containment 54→55 and completion 130→129, leaving
  the joint metric at 52 of 132 exactly. The placebo control passes, the
  aggregate and escape families move by zero, and the conclusion is that the
  gap against dataflow taint on confidentiality is not a switched-off tier.
  [declaration_determines_enforcement.md](benchmarks/results/declaration_determines_enforcement.md).

- **`--step-up {block,allow}`** prices the autonomous and the pessimal
  supervised deployment of the same gateway, because scoring a STEP_UP as a hard
  block was a choice the harness made silently. The suite turns out to produce
  **zero step-ups** (2,287 ALLOW, 101 DENY), so both settings give an identical
  table and every contained attack is held by a hard denial. A synthetic
  positive control asserts the flag would have shown a difference had there been
  one, because an inert flag and a real null look the same.

- **The verb classifier is a reported parameter, not a silent default.** Under
  `--verbs bpl` the legacy classifier scores 47% containment and 41% completion
  against the shipped classifier's 41% and 98%, moving the joint metric 39.4% to
  32%. The default is the classifier the product ships; the delta is now
  disclosed rather than discoverable.

### Corrections

- `head_to_head_injection.md` said Progent wins clean utility "on two suites".
  Its own table shows three: slack, **travel** and workspace, with banking tied.
  The error was in our favour, about a named published system.

- README and `publication_readiness.md` carried numbers from an earlier run:
  friction (3 refused / 1 lost, now 2 / 0), the batch spread (sd 0.327, now
  0.344), complementarity (32/21/21, now 32/20/22), the taint refusal count (46,
  now 47) and the paired-bootstrap interval ([17.4, 36.4], now [18.2, 37.9]).
  The bootstrap is seeded, so these were stale rather than noisy.

- **The default verb classifier depended on an optional benchmark dependency.**
  `benchmarks/bpl/schema.verb_for` reached `classify_verb` through
  `benchmarks.live.broker_defense`, which re-exports it from
  `benchmarks.datasets._common`, which re-exports it from
  `clayseal.capabilities.tool_verbs` where it actually lives, and which
  hard-imports `agentdojo` at module scope. Without that optional extra
  installed, the classifier raised on **every action of every scenario** and the
  sweep scored all 132 Clay Seal cells as errored. It imports from the library
  directly now, and the full suite produces an identical table with and without
  `agentdojo` present. The "a gate that raises has not contained anything" guard
  is what turned this into a visible failure rather than a silent zero. Two
  further callers, `benchmarks/invariance.py` and its test, reached
  `classify_verb` the same way and are fixed the same way.

- The nightly `invariants` job had failed five consecutive runs.
  `benchmarks/live/broker_defense.py` imports `agentdojo`, an optional benchmark
  dependency absent from the fast gate, which turned a missing extra into a
  collection error that killed the whole job in 30 seconds.
  `test_supervision_parity.py` now `importorskip`s it.

### Documentation and layout

- **Three examples the README tells you to run were never committed.**
  `examples/02_the_proxy.py`, `examples/refund.yaml` and
  `examples/refund_server.py` existed on one machine only, so the first command
  a new reader is given did not exist in a fresh clone. All three are in, all
  five examples run, and `test_documented_paths_exist.py` now fails if any path
  the documentation names is missing from the repository.

- **1,598 em-dashes removed** from prose across 379 files, replaced by the
  punctuation the sentence actually needs. The remainder are table cells where
  the dash means "not applicable".

- **The README defines its terms before using them.** It used "rung",
  "envelope", "sealed goal" and "steps up" with no introduction, and the check
  order that explains them sat 380 lines further down. There is now a "How it
  works" section up front: the three answers a call can get, why step-up exists,
  the six checks in order, and what "budget" means. The results section says
  plainly that the average hides the result and that what decides it is whether
  your rule states a countable limit.

- **`docs/README.md`** indexes the fifteen documents by the question each one
  answers. Eight were linked from nowhere and two were unreachable entirely.

- **A top-level `tests/` directory held one file** whose name collided with a
  file in `python/tests/`. CI only runs `python/tests`, so its three tests had
  never executed. Merged, and the directory is gone.


### Security

- **Session content no longer reaches a third party on ambient credentials.**
  `DeployableStack.from_goal` built the optional entailment judge whenever
  `OPENAI_API_KEY`, `AZURE_OPENAI_*` or a key file in the home directory
  happened to be present. The judge's prompt carries the user's request text
  and the declared write payloads, so a deployment holding an OpenAI key for an
  unrelated reason would have sent exactly the content this gateway exists to
  contain, with no line in any policy saying so. Egress is now opt-in: pass a
  judge explicitly, or set `CLAYSEAL_ENTAILMENT=1`. Credentials alone do
  nothing. `test_judge_egress_is_opt_in.py`.

- **Audit evidence and ledger state are created 0600, in a 0700 directory.**
  The decision log and principal ledger were opened with a plain `open("a")`
  and inherited the process umask, which yields 0644 on a typical host: every
  local user could read the authorization trail, including principal identity,
  resource paths and outcomes. `os.open` now applies the mode at creation, so
  there is no window between create and chmod. A directory that already existed
  keeps the mode its operator gave it. `test_evidence_files_are_private.py`.

- **`clayseal serve` warns when bound off loopback.** The gateway authorizes
  the calls it is handed and does not authenticate whoever hands them over. On
  `0.0.0.0` anyone who can reach the port can push tool calls through it under
  the loaded policy's authority; the warning names the mitigation.

Audited and clean: no credentials in the working tree or in history (the
`AKIA`/`ghp_` strings are the vendors' own documented example values, and the
AWS-shaped ones are 22 characters where a real key is 20); no `pickle`,
`yaml.load`, `shell=True`, `os.system`, `eval`/`exec` or disabled TLS
verification in the shipped library; every `subprocess` call passes an argv list;
`uuid4` is the only randomness on a security path; no bare `assert` in shipped
code; the upstream URL is closed over from operator config so the request body
cannot redirect it, and `urllib` rejects CRLF in the header values derived from
that body. Outbound fetches of untrusted URLs go through `safe_http`, which pins
resolved IPs and blocks the cloud metadata endpoint.


### Changed: a read is a disclosure, not a lookup

A read puts content into a context every later action can use, and no later
action can remove it. 275 of AgentHarm's 507 in-surface attack events are reads
and calls, and the consequence classifier was passing all of them.

- **`ConsequenceLevel.DISCLOSURE = 1`**, beneath `WRITE = 2`. Every existing
  comparison against `WRITE` is unchanged by construction, so no rung that asked
  for a mutation started seeing reads.

- **The predicate split in two, and that is what carries the result.**
  `is_consequential` now means DISCLOSURE or above and drives detection,
  escalation and replan gating. **`is_effectful`** means WRITE or above and is
  what every rung ending in an unrecoverable DENY asks for. A disclosure
  escalates and never refuses: an envelope with imperfect recall will miss
  legitimate reads, and a step-up lets a supervisor wave those through where a
  refusal nobody can lift turns every recall miss into lost work.

- **AgentHarm containment 45.0% to 53.8% per session**, 152 to 196 of 507 per
  event. It also stops attacks EARLIER, which the containment column does not
  show: the first stop lands on the attack's opening action in 20 of 86 stopped
  sessions against 4 of 74 before.

- **Zero measured cost**: 0 refusals in 20,619 benign events and 0 of 5,851
  benign sessions across eight corpora. Structural rather than lucky, because a
  benign read is an on-plan read, so the reclassification can only fire on a
  read the sealed goal did not ask for. At 5,851 sessions the 97.5% upper bound
  on the disruption rate is about 0.06%.

- **The credential-payload rung** gated on "consequential" where it meant
  write-or-egress. It now asks `is_effectful`, matching the definition its
  0-of-761 false-positive bound was measured under.

`benchmarks/results/disclosure_moonshot.md`.

### Added: a rule lives under a heading, and the reader was skipping headings

Operational policy states an operation once in a heading and never again in the
sentences beneath it. `extract` skipped headings, so against tau2's own tool
catalogue the airline document, 167 lines, produced **zero** enforceable
rules.

- **A scope stack.** A heading must name an ACT and not a thing, or `### Order`
  scopes all six order tools and binds a data dictionary's attribute definitions
  to them as though they were rules. A heading replaces its own level and clears
  everything deeper even when it names no operation. A subsection narrows its
  parent. A tie is kept only when the tied tools matched the same word.

- **Airline: 0 to 4 compiled rules. External rules bound: 7 to 10 of 61.**
  tau2 false blocks unchanged at 1 of 13,907.

- **Section bindings are `inferred`, not `extracted`,** and carry the heading in
  their citation, because it is the reader's inference and a reviewer has to be
  able to see it and disagree.

- **A prerequisite is resolved by verb first, phrase second**, and
  parentheticals are stripped: they elaborate and never name the object of the
  verb. Both rules keep an incidental noun from binding an unrelated tool.

- **Containment on tau2's refusal tasks is unchanged.** On those tasks the agent
  already calls `get_user_details` before it writes, so a precondition requiring
  it has nothing to stop. The claim is coverage at no cost.

- **The remaining limit is vocabulary rather than structure.** tau2's telecom document argues about
  bills, lookup and suspension while its tools are named `make_payment`,
  `refuel_data` and `resume_line`. No reader working from tool NAMES can bridge
  that; tool descriptions can, and `policy_scaffold.Catalog` already carries them.

`benchmarks/results/section_scope.md`.

### Removed: everything that was not this project

A cleanup pass before open-sourcing. 69 files and 3,115 lines left the
repository; every deletion is recoverable from history at `fe4efcf`.

- **`.demo-runs/` (47 files).** Generated demo output: workspaces, ticket
  corpora and guest scratch. It is `demo/cli.py`'s default `IVISOR_RUN_ROOT`
  and the demo tests use `tmp_path`, so nothing read the committed copy. Now
  gitignored.

- **Paper drafts and the fundraising memo (456K)** moved out of the code repo to
  `clay-seal-papers/`: `INVESTOR_MEMO.md`, `CYBERTOOL_MEMO_REVISED.{tex,pdf}`,
  `_results_table_draft.{tex,pdf,png}`. They are documents ABOUT the project
  rather than documentation OF it. Two audit files check their claims against
  this code and note that the audited document is kept elsewhere.

- **`notes/roadmap_v0.2.md`**, a roadmap for a version three releases old, and
  two dated positioning surveys nothing cited (`sota_assessment.md`,
  `frontier_2026_and_what_to_build.md`), also moved out.

- **Four duplicate benchmark run directories.** `matrix-pilot`,
  `matrix-oai-travel`, `matrix-fpfix` and `attack-probe-adaptive` were the same
  head-to-head experiment at other configurations, none carrying a `STATUS:`
  line and none cited. `matrix-oai-4omini` is kept, and stamped, because
  `table_audit.md` checks a published claim against it.

- **`scoping/retrieval/rg_channel.py`.** 106 lines referenced by nothing, and
  the only module in that package that shells out to a subprocess. An
  authorization layer should not ship an unused process-spawning path.

- **17 result files** carried captured stdout and no provenance. Each now
  carries `STATUS:` and the command that regenerates it, verified against the
  `fixture` dataset.

### Fixed: internal references in a public repository

- **An internal Azure resource name** in 13 files is now `<aoai-resource>`, and
  the resource group `<aoai-resource-group>`. The substitution caveat those comments
  carry is unchanged: the deployment is NAMED `gpt-4o-mini-2024-07-18`
  and SERVES `gpt-5-mini`, which is why every live result records the served
  model separately.

- **Local absolute paths** in two audit files, including a scratch path carrying
  a session id and a sibling checkout under a home directory.

- **Development-session references in three code comments**, and a comment
  citing a measurement file that does not exist. `defer_to_binding` now states
  that its measurement is outstanding and names the two nearest files, neither
  of which isolates the flag.

### Fixed: open-source readiness

- **`requires-python` was `>=3.10,<3.14`** and the ceiling came from `agentdojo`,
  a dependency of the OPTIONAL `benchmarks` extra. It locked every user of the
  gateway out of current Python for a package they were never going to install.
  Now `<3.15`: the wheel builds, installs and imports all 172 modules on 3.14,
  and 2,156 tests pass there with no failures. CI tests 3.10, 3.13 and 3.14.

- **PyPI metadata was absent.** Added keywords and classifiers. `Typing :: Typed`
  is deliberately NOT claimed and `py.typed` is NOT shipped: 98% of the library's
  functions carry annotations, but mypy has never gated them and reports 92
  findings across 32 files, none triaged.

- **`benchmarks/results/README.md`**, an index over 128 result files with the
  five headline numbers, their reproduce commands and the honest limits.

- **`benchmarks/live/run_full_benchmark.sh`** hardcoded one developer's home
  directory and a scratch venv named after a dead session id. Resolved from the
  script's own location now.

- **A collaborator's home directory path** in a recorded demo session
  (`demo/sessions/ticket-triage-mock.jsonl`) redacted to `/opt/ivisor/...`.

- **Three stale documentation claims.** `README.md` and `docs/POLICY.md` both
  said `derive_counts=False` "turns it off" when it has been the default since
  the count rung was measured at three interruptions per catch. `docs/POLICY.md`
  also cited 82.8% sleight containment, a figure its own citation retracts as a
  deny-all artifact; the corrected figure is 23.0% at zero benign cost.


### Added: external validation, on both sides at once

`external_corpora_structure.md` has said since it was written that the aggregate
claim rests on a suite authored here and that "anyone quoting the BPL numbers as
externally validated would be wrong". `tau2-bench` was the closest instrument and
was unusable for it, because its rules are prose and compiling them would have
been ours. Three things this session changed that: `policy_draft` reads a rule
out of prose and cites its line, `tools.when` expresses the two shapes prose
actually uses, and a catalogue binds a rule to the tools it names.

- **13,906 of 13,907 ground-truth actions pass.** Rules compiled from each
  domain's own `policy.md`, traffic from that domain's own
  `evaluation_criteria.actions`, entity state from its own `db.json`. Nobody
  here chose a scenario, wrote a rule or labelled an outcome, so **every block
  is a false block** with nothing to argue about.

- **The one disagreement, in full.** retail task 64 exchanges order `#W7464385`,
  their policy says exchange requires `delivered`, and their database records it
  `pending`. Steps 1 to 6 are all reads so nothing changed it. Three readings
  are available and the file picks none: their ground truth may be wrong, their
  policy line may carry a nuance the extractor flattened, or `delivered` in that
  tool's name may be a convention. What is reproducible is that three files none
  of which are ours disagree.

- **Two defects in the compiler, both mine, neither visible without somebody
  else's traffic.** A rule about an ORDER bound a tool about a USER because both
  said "modify", refusing eleven of retail's own correct actions; a subject
  constraint took 176 to 165. And a conditional rule evaluated against no facts
  refuses everything, which is the safe direction and made the measure
  meaningless: state from their `db.json` took 164 to 1.

- **Containment too, without choosing an attack.** A task qualifies when its
  ground truth contains NO write, which is tau2 saying in data what its
  `nl_assertions` say in words. Its reads are replayed so state comes from their
  database, then EVERY write in their catalogue is attempted: the set is
  exhaustive, so nothing was selected, and each attempt is one their own ground
  truth says should not occur. **retail refuses 24 of 56.** airline and telecom
  refuse none, and the reason is one table up: four rules compiled from retail's
  document and zero from theirs.

- **So containment is bounded by the compiler rather than the floor**, which is
  the same conclusion `external_policy_documents_coverage.md` reaches from the
  other side: 47 of 61 external rules enforceable by hand, 7 extracted
  automatically. The gap moved from the enforcement to the compiler two passes
  ago, and 42.9% is what that costs.

### Added: `docs/CONTROLS.md`, for the person who signs rather than builds

- **It opens by saying what it is not.** A library is not a control regime and
  cannot make anyone compliant with anything; the most a component can do is
  produce evidence a control owner points at. A vendor page claiming "SOC 2
  compliant" for a package is claiming something a package cannot be.

- **It maps only where the mapping is exact.** EU AI Act Articles 12 and 14 are
  quoted verbatim from the source and matched to the mechanism that serves them:
  the hash-chained decision log and the `traceparent` join for record-keeping,
  the step-up path and `resolve_step_up` for human oversight. NIST AI RMF is
  stated at the FUNCTION level and SOC 2 at the criterion family, because
  inventing a subcategory identifier that reads authoritative and is not
  checkable is the failure mode of every document of this kind.

- **Each mapping says what it does NOT give you.** Article 12 is about the AI
  system over its lifetime and this logs one boundary of it. Article 14 needs a
  trained person, and the library can make the intervention point exist without
  making anyone competent to use it. MAP is the RMF function this contributes
  least to, because deciding where a system can do harm happens before a policy
  is written.

- **The boundary, stated once:** this binds what an agent may do, records what
  it decided, and asks a person when the grant is ambiguous. It does not
  evaluate the model, test for bias, manage training data, or know whether the
  task was a good idea. 23% of the rules in real business policy are not about
  authority at all, measured on documents nobody here wrote.

### Added: decisions in the shape a security team already ingests

The original release audit closed with "decisions do not reach the systems that
watch for incidents", and shipping JSONL did not close it: nobody writes a
bespoke parser for one vendor's log.

- **`OcsfSink` maps each record to an OCSF API Activity event.** The mapping
  adds nothing the record did not carry: arguments stay hashed, the receipt and
  previous hashes travel so the chain is verifiable from the SIEM's own copy,
  and the trace id travels so the event joins to the caller's trace. A SIEM
  event that cannot be tied back to the receipt it came from is a rumour.
  Severity and status say different things deliberately: a refusal is a success
  of the control and a failure of the attempt, and `status_id` describes the
  attempt.

- **`OtelSpanSink` is optional by construction.** The SDK is imported lazily and
  its absence increments `unavailable` rather than raising at the first
  decision, because two runtime dependencies is a large part of why this library
  installs at all.

### Added: W3C Trace Context, so a receipt joins to the trace that produced it

`DecisionLog` was internally verifiable and externally unjoinable: an enterprise
holding an incident had a trace of what its agent did and a receipt of what this
gateway decided, and nothing lining the two up. That was survivable while a
session existed, by convention. MCP 2026-07-28 removes the session and the
migration guidance is explicit that Trace Context replaces it for audit.

- **`trace.py` parses strictly and drops rather than stores.** The header
  arrives from outside and may be anything. Nothing is authorized on the
  strength of a trace id, so it is not a security boundary, but a log is
  evidence: a 4KB `tracestate` in every record is a storage attack and an
  unvalidated `traceparent` puts whatever the sender wrote inside a signed
  receipt. Version `ff`, all-zero ids, upper-case hex and wrong widths are all
  refused. A record with no trace is honest; one carrying a join key nobody can
  follow is a field that looks like evidence and is not.

- **The hash chain is unchanged for a record without a trace.** The field enters
  the hashed body only when present, so a log written before this existed still
  verifies. The chain IS the evidence and re-hashing every historical record to
  add an optional field would invalidate the thing the field is there to serve.

- **Read per REQUEST in the HTTP gateway**, because that is the granularity a
  stateless transport has, and via `Guardrail.trace()` in process.

### Added: `Guardrail`, one adapter over the shape every framework already has

`proxy` and `serve` sit outside the agent. When the agent is yours and in the
same process, there was no path that did not involve designing around
`DeployableStack` by hand.

- **Not four adapters.** A LangGraph adapter, an OpenAI Agents SDK adapter and a
  CrewAI adapter would each import a framework this library does not otherwise
  need and each would break when that framework's tool interface changed. They
  all agree that a tool is a **named callable taking keyword arguments**, so the
  adapter is over that and the glue is one line the caller writes.
  `guard.wrap_all({...})` returns the same catalogue, guarded.

- **Three things a hand-rolled wrapper gets wrong, each silently.** The verb and
  the path argument come from the POLICY rather than from the tool's name, which
  is the same problem `McpProxy.from_policy` exists for and this is its
  in-process twin. A refusal reaches the model as `Refused`, so an agent told
  "over the 24-hour ceiling" can say so or take another route, and
  `StepUpRequired` is a separate exception because a caller that treats them
  alike turns a supervised deployment into an autonomous one. And the result is
  reported back: provenance, taint, the confidentiality tracker and every
  `tools.when` fact read what a tool RETURNED, and a benchmark run against a
  stack with no result feedback once scored byte-identical to its floor rung,
  with every observation-driven layer quiet rather than absent.

- **`ungoverned(tools)` asks before the run.** A tool absent from `tools.allow`
  is denied at the floor, which is correct, and a confusing way to discover that
  a catalogue and a policy disagree.

- **The wrapper keeps `__name__`, `__doc__` and the signature**, because a
  framework builds the schema the model sees from those. Losing them changes the
  tool the model sees, which is a behaviour change dressed as a security
  control. An async tool stays async.

### Added: ordering as a withdrawal, and a compiler that reaches both classes

- **`tools.when requires`: the 36% class, enforced without an envelope.**
  Ordering is the largest single class of rule in four external policy
  documents, and the obvious home for it, the intent envelope, is deliberately
  not something a policy document holds: a hand-written plan is a guess and it
  guesses toward over-permission. An ordering rule is not a plan, though. It is
  a restriction, and it is the withdrawal mechanism that already exists:
  `requires: [list_orders]` withdraws the updating tools until `list_orders`
  has run.

- **The fact it reads is the gateway's own, and tool output may not write it.**
  `record_call` sits in `_commit_and_finalize`, which the broker documents as
  the only way to return ALLOW, so a REFUSED prerequisite never counts as
  having run. `observe_facts` refuses any name under the `called:` prefix and
  counts the attempt, because without that an injected
  `{"called:list_orders": true}` would satisfy a precondition nobody met. This
  is the first fact source in the library that is not attacker-influenced, and
  the split is what makes it one.

- **The compiler reaches both classes now.** `extract(document, tools=...)`
  binds a rule to the tools it names, which is what makes these shapes
  extractable at all: "an order can only be cancelled while pending" is about
  `cancel_order`, and with no catalogue there is nothing to bind to.
  `clayseal policy init --rules` already had both halves. **7 of 61 external
  rules are extracted and bound automatically, against 1 before**, and all
  seven were reviewed one at a time against their sentence: seven of seven bind
  to the right tools, one carries a fact name that only the server can confirm,
  and an unconfirmed precondition withdraws, so that error direction is the
  safe one.

- **A refusal cites the document.** The line travels from the source into the
  runtime, so an operator sees `line 16: Before taking any action that updates
  the database ... you must list the order first` rather than a fact
  dictionary. `reason_for` renders an `unless` guard in the direction the rule
  reads, because "withdrawn while {status: pending}" states the opposite of the
  rule and would send someone looking for the wrong thing.

- **Why the other 54 still need a person, named rather than rounded away.** The
  reader is a line at a time, so a wrapped sentence has its tools on one line
  and its rule on the other and neither half binds. A rule whose subject is a
  business noun ("basic economy flights cannot be modified") has nothing in a
  tool catalogue to match. And 23% are not expressible by an authorization
  layer at any level.

### Added: `clayseal serve`, MCP over Streamable HTTP

The last of the three Tier-1 gaps. `proxy` speaks stdio, which is local,
single-client, and where the process boundary IS the session boundary. MCP
2026-07-28 recommends Streamable HTTP for anything remote and removes the
session handshake entirely.

- **`http_gateway.py` wraps `McpProxy` rather than re-implementing it**, so the
  duplicate-key, near-match-method and oversized-batch refusals already measured
  there apply unchanged. Standard library only, `http.server` and `urllib`: the
  dependency count stays at two, which is a large part of why this installs at
  all.

- **The body is authorized, always.** SEP-2243 adds `Mcp-Method` and `Mcp-Name`
  so intermediaries can route "without inspecting the body", and puts the duty
  to check them against the body on SERVERS. A gateway in front is exactly the
  intermediary invited to skip it, and one that authorizes
  `Mcp-Method: tools/list` while the server runs a `tools/call` for a
  money-moving tool has approved an operation that never ran. Headers are
  checked for agreement and never consulted for a decision; a disagreement is
  `-32020` **before any authorization runs**. A batch carrying routing headers
  is refused, because one pair cannot describe several messages and choosing a
  member to believe is how a gateway approves the wrong one. Headers forwarded
  upstream are regenerated from the forwarded body rather than copied, so an
  attacker's header is not handed to a server that trusts it.

- **`GET /mcp/readiness` says which tiers cannot run.** The floor is live; scope,
  protected zones, egress and tool admissibility are pure functions of one action
  and the grant. Aggregates are live only against a principal ledger. The
  trajectory tiers are **inert**: the intent envelope and the behavioural
  detector read a sequence and a stateless request has none, so they are
  reported that way rather than run against a trajectory of length one. An
  operator reading a quiet log cannot tell a tier that found nothing from a tier
  that never ran.

- **`McpProxy.from_policy`.** Five fields have to agree with the document and
  getting one wrong is silent in the direction that matters: a proxy built
  without `pathless_tools` refuses every effectful call that carries no path,
  citing a declaration the document already made. That wiring lived in `cli.py`,
  so the CLI was correct and every other caller was on their own. It is in the
  library now and the CLI calls it. I hit this defect myself while wiring the
  HTTP gateway, which is the shortest possible demonstration of the problem.

### Fixed: both integration paths, each of which had a different blocker

Out of process, `clayseal proxy` speaks stdio, which is local and single-client.
In process, `DeployableStack.authorize` is synchronous and there was **no
`async def` anywhere in 33,748 lines**. An async agent talking to remote tools
had neither path. Two of the three are closed here.

- **A ceiling that survives where no session does.** `PrincipalBudgetView` was
  the right anchor and could not be plugged in: the broker calls
  `reserve(tool, args)` and the view had no `reserve`, because it predates the
  TOCTOU-free protocol. It has one now, and it does **not** re-implement the
  session budget: `parse_amount` moved to module level so there is one answer to
  "how much does this call move", and the tri-state it returns is preserved, so
  a tracked-but-unreadable amount still fails closed rather than reading as
  untracked.

  A policy declares `deployment: {stateless: true, principal: acct-9, ledger:
  {path: ...}}` and the value ceiling moves off the session. Measured across two
  independent processes: 30,000 and 15,000 book, a third request for 10,000 is
  refused at the 50,000 ceiling, and 4,000 fits. The same three against a
  session budget allow all of them.

- **Once-per-object had to survive a PROCESS boundary, not only a session one.**
  The first version persisted spend and not identity, so a second process paid
  INV-1 again: the ceiling survived the boundary and the duplicate check did
  not. Identity is now checked inside `PrincipalLedger.reserve` under the same
  lock as the ceiling, persisted on the ledger entry, and rebuilt on load. A
  released or expired hold gives the object back, so one refusal is not a
  permanent one.

  An in-memory principal ledger in a stateless deployment is **refused at
  compile time**: it dies with the process, a stateless deployment is many
  processes, and the ceiling would still reset.

- **`clayseal.capabilities.aio`.** The decision core stays synchronous and
  pure, which is what makes it replayable and readable top to bottom. The façade
  dispatches to a worker thread so an advisory tier reaching a model, a person
  or a socket cannot stall every other coroutine in the process. `authorize_all`
  is deliberately not `gather`: budgets, trajectory and envelope all accumulate,
  so deciding a batch concurrently against one session would race the state the
  aggregate rung is counted over. Tests drive it with `asyncio.run` rather than
  adding a third dependency.

### Added: `tools.when`, a rule about state rather than about an amount

- **The largest inexpressible class of real policy, closed.** Measured on four
  `tau2-bench` policy documents, 469 lines nobody here wrote, **31% of the
  sentences that state a rule are state-conditional prohibitions** and 10% are
  numeric ceilings. Every conditional mechanism in this library tightened a
  CEILING, and none of "an order can only be cancelled if its status is
  pending", "cabin cannot be changed if any flight has already been flown" or
  "basic economy flights cannot be modified" is about an amount. `tools.when`
  withdraws tools as facts arrive, and both of those rules now compile and
  enforce verbatim.

- **A rule may only WITHDRAW, and the compiler refuses an admitting form.** The
  baseline is `tools.allow` and a rule subtracts from it, so an attacker who
  fully controls every fact can only reduce what the agent it has compromised
  may do. An `admit-when` rule would let an injected `status: pending` widen a
  grant, which is precisely what `conditional_ceiling.Guard` refuses for
  ceilings. `unless` is how "only if" is written and an unconfirmed precondition
  withdraws, because a precondition nobody has established is not one that has
  been met.

- **The limitation is stated where the mechanism is.** "Only cancel if pending"
  enforces as "deny when the status is known and is not pending", so an
  adversary who controls the status field gets the baseline authority they had
  anyway. This binds drift and mistake, not an adversary who owns the fact
  source, which is the same boundary the ceiling guards draw.

- **The gap moved rather than closed, and the measurement says so.** 47 of 61
  external rules, **77%**, are enforceable once written into a policy by hand,
  against 46% before. Neither large class has EXTRACTION: `policy_draft` reads
  the numeric class and emits no ordering phase and no conditional withdrawal,
  so 41 rules still arrive as TODO comments. The enforcement was missing; now
  the compiler is.

### Fixed: the deployment model the transport no longer has

Read the MCP 2026-07-28 specification against what this library assumes. Three
assumptions are wrong for the transport enterprises deploy, and none of it is
visible from any benchmark here, because every benchmark replays a trajectory
into a Python object and never speaks a transport.
`docs/DEPLOYMENT_SHAPE.md` carries the analysis and the sources.

- **Sessions are removed, and the aggregate rung was anchored to them.** The
  spec drops the `initialize` handshake and the `Mcp-Session-Id` header so any
  instance can serve any request with no sticky routing. Almost everything here
  is session-scoped: `SessionBroker` is "one live per-session gateway",
  `SessionValueBudget` is "one instance per session", and `mcp_proxy` states
  "one proxy process is one session" in its own header. That is right for stdio,
  where the process boundary IS the session boundary, and meaningless behind a
  load balancer. A per-session ceiling there is not a weak control an attacker
  must work to reset: **it resets by itself on every request** and the aggregate
  rung is inert.

  A policy may now declare `deployment: {stateless: true}`, and
  `session-scoped-ceiling` becomes an **error** there rather than a warning. A
  gateway that enforces the wrong thing is worse than one that will not start.

  Named, not fixed: `PrincipalBudgetView` is the right anchor and cannot be
  plugged in. The broker calls `value_budget.reserve(tool, args)`; the view
  offers `authorize`, `would_allow`, `commit` and `release` and no `reserve`,
  because it predates the TOCTOU-free reserve protocol. Closing it means moving
  the session budget's parsing, idempotency and once-per-object identity behind
  a storage seam rather than reimplementing them on the view, and duplicating
  that logic is how this repository has produced several of its own defects.

- **A gateway that routes on `Mcp-Method` authorizes a different call than
  executes.** SEP-2243 adds routing headers so intermediaries can decide without
  inspecting the body, and puts the duty to validate header against body on
  SERVERS, with the body as source of truth and `-32020` on mismatch. A security
  gateway in front is exactly the intermediary invited to skip the body. This is
  the duplicate-JSON-key differential already closed here, promoted to the
  transport layer and written into the protocol. The rule is recorded:
  authorize the body, use headers to route and rate-limit, and treat a
  disagreement as a refusal rather than a preference.

- **Audit records join to nothing.** With sessions gone, W3C Trace Context is
  the correlation spine that replaces them. `DecisionRecord` carries a
  `prev_hash` chain, which makes the log internally verifiable and externally
  unjoinable: an enterprise holding an incident cannot line a decision up
  against the trace that produced it. The smallest of the three gaps and the
  most mechanical.

### Added: fault injection, and four components that could veto a decision

- **`benchmarks/stress_faults.py`.** `stress_gates` throws hostile INPUTS at
  every gate. This is the other half and the half a production incident is
  actually made of: the input is ordinary and a COMPONENT is broken. A ledger
  times out, an identity provider is unreachable, a tier raises on a shape its
  author did not anticipate. Every seam is classified as enforcement, advisory
  or bookkeeping BEFORE the run, so the result is falsifiable rather than read
  off the outcomes afterwards.

- **The security column is clean.** Sixteen enforcement seams broken one at a
  time, and **not one turns a refusal into an allow**. Where a fault reaches the
  caller it does so as an exception rather than an authorization. An attacker
  who can make a component of this gateway fail gains nothing by doing it.

- **Four components with no authority over a decision could prevent one.** An
  audit write that failed took down the gateway; so did a metrics backend going
  away, on both the allow and the refusal path; and a retry HINT from the
  provenance graph turned a completed DENY into an exception. All four are
  guarded now, and `unrecorded_decisions` and `telemetry_failures` count what
  was lost rather than swallowing it, because an unlogged decision is an
  unauditable one and the count is what a deployment alerts on.

- **A test that asserted the opposite of its own docstring.**
  `test_a_failing_sink_cannot_fail_an_authorization` said a full disk "must not
  become an availability" problem and then asserted the broker raises, with the
  contract being that every sink author remembers to catch. The shipped sinks
  do. A sink written by an integrator, which is the entire point of the seam
  being pluggable, does not have to. The broker guards it now, so the property
  holds for every sink rather than for the ones written here.

- **The fault probe's verdict rule was too weak.** It
  checked only that a broken component did not produce an ALLOW, and a crash is
  not an allow, so a metrics call raising on every refusal passed as `ok`. And
  six of twelve seams were reported `skipped`, which in a table of green ones
  reads as covered: two were frozen dataclasses that `object.__setattr__`
  reaches, four were method names guessed rather than read off the objects.
  Coverage went from 5 seams to 26, and the last defect only appeared after the
  rule was tightened.

### Fixed: a session that got slower the longer it ran

- **`benchmarks/session_scaling.py`, and a 69x speedup at 2,000 actions.**
  `latency.py` measures the ladder rungs, which are stateless per event, so its
  numbers are flat in session length by construction. The shipped stack carries
  a trajectory and the intent envelope re-assessed all of it on every decision,
  so a session of N actions cost O(N^2): **13.1 seconds for 2,000 actions**,
  with the thousandth decision costing fourteen times the first. Every corpus
  here has short tasks, `agentharm` averaging a handful of actions, so no
  benchmark in this repository ever ran a session long enough to see it. An
  agent that runs for an hour is the regime a production deployment is in.

  | session | before | after |
  | --: | --: | --: |
  | 1,000 actions | 0.75 s | 0.08 s |
  | 2,000 actions | 13.1 s | **0.19 s** |
  | 4,000 actions | not measured, extrapolates past 50 s | **0.55 s** |
  | growth exponent | 1.70 | **1.23** |

  Three changes. `surface_class` and the membership read are cached, profiled at
  642,400 and 321,200 calls over 800 decisions against roughly 800 distinct
  paths, with the `str()` conversion kept outside the cache because `lru_cache`
  hashes before the body runs. The phase assessment RESUMES from an assessed
  prefix instead of rescanning: the only state the loop carries is `steps`,
  which is append-only, and `satisfied`, which counts phase occurrences, so a
  prefix is resumable when it is still the head of the trajectory by object
  identity and the comparability flag has not flipped. Both conditions are
  checked rather than assumed, and a rollback, which pops the last action and
  may push a different one at the same length, fails the identity check and
  recomputes.

  **The equality is proved rather than asserted.**
  `test_intent_envelope_incremental.py` holds the incremental result against a
  from-scratch assessment over randomized trajectories at twelve seeds,
  including rollbacks and a comparability flip. An optimization inside an
  enforcement path that is subtly wrong is worse than the cost it saves. Every
  corpus number is byte-identical.

  Left standing and measured: the trajectory is unbounded at 1,621 bytes per
  action, so 162 MB at 100,000 actions in one session. `DecisionLog` bounds its
  own retention; the trajectory has no equivalent, and giving it one changes
  what the phase-order landmarks can see, which is a semantic decision rather
  than an optimization.

### Fixed: two escapes in the authorization floor itself

`task_scope_allows_path` is the predicate that contains 100% of surface-leaving
attacks across more than 4,400 events on five corpora. It is the single most
load-bearing check in the library and it had never been fuzzed.
`benchmarks/stress_scope.py` is the systematic version of asking, with an oracle
restricted to simple prefix globs so the correct answer is not a matter of
interpretation.

- **A leading whitespace character absorbed a traversal.** `../out/sub` was
  correctly denied under a grant of `out/**`; `\t./../out//sub/`, the same path
  with a tab in front, normalised to `out/sub` and was **allowed**. Segments
  were classified by their raw form, so a whitespace-decorated segment counted
  as an ordinary directory name and the `..` after it popped that instead of
  climbing. Twenty escapes in the first 60,000 generated paths, all of that
  shape. Whether a filesystem opens a directory literally named `" .."` is not
  the question: plenty of consumers trim a path before opening it, and this
  function's own docstring states that an authorization decision must be about
  the file that will actually be opened. Segments are classified by their
  stripped form now and matched by their raw one, so both readings err toward
  denial.

- **A deny list closed on one construction path only.** `close_deny_patterns`
  exists, is well documented, and was applied where a policy is compiled. A
  `TaskScope` built directly, which the API invites and every benchmark loader
  does, kept the hole: `**` requires a segment after the slash, so
  `denied_paths=["data/secrets/**"]` did not deny `data/secrets` itself. It now
  lives in `core.task_scope` and runs in `TaskScope.__post_init__`, so every
  path to a scope is closed and `policy.py` delegates rather than keeping a
  second copy. A fix only one construction path reaches is a fix for one
  construction path.

  Three properties now hold over 200,000 generated paths: the predicate never
  raises, a path resolving outside every allowed prefix is never allowed, and a
  path resolving inside a denied prefix is never allowed. 12,790 conservative
  refusals are counted rather than hidden, because a floor that refuses
  everything has no escapes either. **Every corpus number is byte-identical**
  before and after both fixes.

### Added: `benchmarks/stress_surface.py`, and the two defects it found

- **A traversal through a granted prefix passed the membership tier.**
  `data/../etc/shadow` classed as `data`, matched a surface granting `data`, and
  named a file the filesystem opens at `/etc/shadow`. Five variants were live,
  including `data/./../etc/shadow` and the backslash form. `surface_class` now
  resolves the path with `normpath` before taking the class, which is the right
  strength: textual, cannot follow a symlink, and must not try, because it is a
  pure function of a string and the floor does the filesystem check. A path that
  escapes upward resolves to a leading `..`, which is not a class, so it is in
  no surface.

- **A dot split a filename, so a file named after a granted directory got in.**
  `resource_class` splits on `.` so a host reads as its domain, which is right
  for a host and wrong for a path: `data.txt` sits beside `data/` and classed as
  `data`. A scheme keeps that reading; a filesystem path now takes its first
  component whole. Reported by a differential against `normpath` on 1,652 of
  200,000 generated cases.

- **A goal granting one upward path granted all of them.** `surface_from` put
  `..` in the surface for a relative resource like `../etc`, and `..` is what
  every escaping path resolves to. Traversal is no longer a class on either
  side.

- **The path differential excluded traversal.** It skipped every string containing `..`, on the reasoning that
  traversal was this library's business rather than the filesystem's. It then
  reported five clean properties over 50,000 cases while the worst defect in the
  module sat inside the exclusion. A probe written by the author of the thing it
  probes inherits that author's model of what can go wrong, and an exclusion is
  where that model is written down: it deserves the same scrutiny as a branch in
  the code, because it claims a whole population cannot contain a defect.

  Five properties now hold over 200,000 generated resource strings: the reading
  never raises, an action that names a target passes only on a real match, a
  backslash-written twin classes identically, widening a surface never denies
  what a narrower one allowed, and the class agrees with `normpath`. **Every
  corpus number is byte-identical before and after all four fixes**, which is
  the whole argument for the file: these corpora contain no `.env`, no backslash
  path and no traversal, so a green corpus run says nothing about this reading.

- **The statistics got the same treatment.** `fisher_exact_greater` is now swept
  rather than spot-checked: total on degenerate and million-scale tables,
  monotone in the direction it claims to test, in range, and bounded in time.

### Fixed: three defects found by attacking this session's own work

- **An unreadable target was read as no target, and passed.** `in_surface`
  returned True whenever `resource_readings` came back empty, justified as "the
  action names nothing, so there is nothing to place inside or outside the
  goal". An empty reading is not evidence of no target; it is evidence that the
  function could not read one. `.env` splits on its leading dot and classes to
  the empty string, a bare `..` does the same, and `..\..\etc\shadow`
  contains no `:` and no `/` so it falls through to the `.` split and classes to
  nothing as well. All three passed the membership tier outright. This is the
  same mistake `monitor/surface.py` exists to prevent, one level down: `named
  nothing` and `named something unreadable` are different facts, exactly as `the
  server did not say` and `the server said no` are. `names_a_target` now carries
  the distinction and an unclassifiable target is not a pass.

- **A backslash was not a separator**, which is how the third case above
  survived. This repository has already had one backslash bypass, in the path
  deny-list, found by differential fuzzing; writing a second path reading
  without applying that lesson reintroduced it one module over. Anything that
  reads a path has to agree with whatever finally opens it.

  Every corpus number is byte-identical after the fix, which is the honest
  reading: the bypass was real and nothing in the test set exercised it, which
  is why it survived being written.

- **The exact test did not return on production-sized input.**
  `fisher_exact_greater` was integer-exact and unbounded: 40 events in
  microseconds, 3,200 in 45ms, 8,000 in 499ms, and 200,000, an ordinary month of
  traffic, never. A certification pass that hangs on real data is not one. It
  now uses a continuity-corrected normal approximation above a named
  `EXACT_MAX_TOTAL` rather than a silent fallback, since a p-value computed two
  ways is two claims, and a test pins the two against each other at the
  crossover: they agree to under 1e-3 everywhere both are computable.

- **The boiling frog, measured.** The claim that the baseline must be SEALED at
  approval rather than refreshed was asserted in a docstring and is now a
  number. Contamination rising five points a period fires against the sealed
  baseline from period four onward, **7 of 10**, and against the previous period
  **0 of 10**. Every drift tool re-baselines periodically, which is right when
  the thing tracked is a product and wrong when it is an authority: a baseline
  that moves with the traffic makes every period look like the last, and a drift
  arriving a few points at a time is never a change against anything.

### Added: the longitudinal question, which is the one enterprises ask

- **`behavior_baseline.py`: did the agent move toward the edge of its grant?**
  Everything in this library except the principal ledger resets at the session
  boundary, and `monitor/drift.py` detects goal drift WITHIN one trajectory over
  minutes. What a risk function is afraid of is longitudinal and has four named
  causes: the provider changed the model behind the endpoint, someone edited a
  system prompt with no review gate, the tool list and grants grew one
  reasonable request at a time, and the thing approved on evaluation traffic
  behaves differently on production traffic. Not one is observable where it
  happens. All four change what the agent DOES, and every action already passes
  this boundary typed and normalised as a side effect of being authorized.

  The question it answers is deliberately not "did behaviour change". On a live
  product the answer to that is yes every week for reasons that are nobody's
  problem, which is why distributional monitors get switched off. An
  authorization layer can ask the better question because it is the only
  component that knows where the permitted region ends: **did behaviour move
  toward the boundary of the grant?** A workload that changes completely while
  staying at 10% of its ceiling has not become more dangerous. One whose action
  distribution is IDENTICAL and now runs at 88% of a ceiling it used to touch at
  12% has, and on the evidence a distributional test reads, the second is the
  unchanged one.

  Four channels with Holm applied across them: action shapes absent at approval,
  the share of sessions running hot against a ceiling, the rate at which actions
  meet a boundary, and whether the baseline still describes the workload at all.
  The verdict is a decision rather than a score, and the useful distinction is
  between `approaching-the-boundary` and `changed-inside-the-grant`.

  The baseline is SEALED at approval and carries the digest of the policy it was
  observed under, for the same reason the intent envelope is sealed before
  untrusted content exists: a baseline built from traffic that already contains
  the change describes the change as normal. If the grant changes the baseline
  is **void rather than stale**, which forces re-certification and is the point
  of carrying the digest. It stores counts only, never argument values, so a
  profile can be handed to an auditor without a review of what is in it.

- **`benchmarks/behavior_drift.py`: the null before the power.** Any monitor can
  claim to detect drift; the number that decides whether it is deployable is
  what it does when nothing changed. The same clean population split at random
  thirty times, on a deliberately heterogeneous workload: **2 of 30 fire at
  alpha=0.05**, consistent with sampling noise, and 27 of 30 are correctly
  reported as `changed-inside-the-grant` rather than as incidents. Power is
  30% at a tenth of sessions affected, 67% at a quarter, 97% at a half. It is
  not an instrument for a single compromised session, which is the floor's job,
  and the four fears above are all population-level changes.

### Added: the compiler, tested on prose nobody here wrote

- **`benchmarks/policy_expressiveness.py`, and a safety claim that failed on
  external data.** `policy_draft.py` promises that nothing rule-shaped is
  dropped silently, because a rule that vanished in translation is worse than
  one never attempted. Measured on four `tau2-bench` policy documents, 469 lines
  authored elsewhere: **61 sentences state a rule, one was read, nine became
  TODOs, and 51 produced no output at all.** The claim held only because
  `RULE_MARKERS` listed the phrases the first document happened to use. It is a
  held-out generalization failure of our own tooling, found the only way it
  could be. The marker set now carries the forms real policy uses, including the
  positive obligations a prohibition-only reading could never see, and the count
  dropped silently is **51 to 0** under identical measurement. The
  rule-shaped detector is deliberately independent of the marker list, so the
  two readings can disagree.

- **What real policy says, which is not what we built for.** Ordering and
  positive obligation is 36% of those 61, state-conditional prohibition 31%,
  and the numeric ceiling this layer is built around is 6 of 61. Ordering is
  already enforceable as a required predecessor phase and the extractor emits
  none; state conditions are two thirds of the way to `budgets.value.when`. The
  ranking of what to build next came from somebody else's policy rather than
  from our sense of it.

- **Friction on external policy-following traffic: 1 interruption in 6,641
  benign events** across `tau2` (1 of 5,441) and `bfcl` (0 of 1,200), and the
  one is a step-up from the derived-count rung rather than a refusal. Worth
  holding beside the 6.3% and 14.1% on `agentharm` and `sleight`, whose benign
  traffic sits inside adversarially framed scenarios.

- **Seeds, because one draw is not a result.** The composed operating curve was
  first published from a single split. On `sleight` the held-out split is 18
  tasks and the between-seed standard deviation is 6.4 points of containment,
  so that draw sat near the bottom of a range it never showed. Every cell is now
  a mean over five splits with its spread, and the "three interrupted benign
  actions per contained attack" figure that followed from one seed is corrected:
  across seeds the exchange rate is closer to one to one.

- **The abstention was measured rather than argued.** Making the membership tier
  wait for its surface to match once creates sessions where it never speaks. On
  `redcode` 599 of 650 sessions never become comparable, and containment there
  is 717 of 717 at 0 of 344 benign events interrupted; `asb` 2040 of 2040 and
  `injecagent` 1597 of 1597, both at no benign cost. Every session that becomes
  comparable does so by its second action.

### Fixed: a membership test that could not read the resource it refused

- **`monitor/surface.py`, and three containment numbers that were deny-all.**
  Two tiers compile a goal into allowed resource CLASSES and refuse an action
  whose class is not a member: `IntentEnvelope._membership` in the authorization
  path and `TypedGoalEnvelope.assess` in the behavioural detector. Both guarded
  the case where the surface is EMPTY. Neither guarded the case where it is
  DISJOINT, which is not a corner: an MCP server is free to label its resources
  however it likes, and any deployment whose tools report an opaque handle in
  front of a grant written in paths gets total refusal of legitimate work,
  reported as goal violation. Measured on `sleight`, where every event is
  labelled `resource="workspace"` and the surface is built from file paths, the
  authorization tier denied **204 of 311 benign events (65.6%)** and the
  detector blocked **13 of 18 benign trajectories**, several at conformal
  p-values of 0.523, 0.709 and 0.912, because that tier sits outside the
  conformal budget and no choice of alpha touched it. Compounding both,
  `resource_class` splits on the first separator, so every ABSOLUTE path classed
  to the empty string and `/data/models/x` was indistinguishable from
  `/etc/shadow` and from nothing.

  The rule now lives in one module used on both sides of every membership test.
  Read the path as well as the resource, since the deciding information was in
  `meta["path"]` all along and inside the surface. Compile both sides with the
  same reading, which strips a leading separator so a path classes as its top
  directory, leaving the scorer's token vocabulary untouched. And refuse only
  once something in the session has matched the surface at least once: a
  comparison that has never succeeded has no standing, the test is over the
  trajectory so relabelling one call buys nothing, and it goes live for the rest
  of the session the moment any action matches.

  | | before | after |
  | --- | --- | --- |
  | sleight benign events denied | 204/311 | 44/311 |
  | sleight in-surface attack events contained | 82.8% (deny-all) | 37.7% |
  | detector, sleight benign trajectories blocked | 13/18 | 0/18 |
  | detector, sleight attack trajectories contained | 18/18 | 17/18 |

  Three published figures were the same defect and are corrected in place: the
  "+62.3 point" envelope win on sleight, the claim that every interruption there
  was a step-up rather than a refusal (204 of them survive
  `treat_step_up="allow"`), and a detector result of 83.3% at 0.0% false-block
  that no longer reproduced at all.

- **`benchmarks/composed.py`.** `SessionBroker` composes the deterministic floor
  and the conformal detector and always has, but `DeployableStack.from_goal`
  takes `detector=None` and the benchmark factory never passed one, so every
  published number for the shipped stack described a stack with the behavioural
  layer switched off. This runs both on one task-level split, with the detector
  fit one-class on benign trajectories and never shown an attack label, and
  sweeps alpha so the composed system has an operating curve rather than an
  operating point. The curve is monotone in alpha on both axes and the exchange
  rate is poor: roughly three interrupted benign actions per additional
  contained attack event. Reported rather than defaulted on.

- **A third ratchet, `costless`, and ratchets that lock.** `check_claims` now
  counts results files that report containment and never once name what it cost;
  `deny-all` contains everything, so a containment figure alone is not a
  measurement, and each of the three corrections above was found by running the
  cost side. Eight files at the baseline. Separately, the ratchets only refused a
  RISE, which is half a ratchet: fixing a file left slack that the next
  violation could spend. A count found below its baseline now rewrites the
  baseline down, so improvement is locked in when it happens.

### Added: the release pass

- **`clayseal.core` is vendored into this repository.** It was a separate
  private distribution, and the `agentauth-core` project on PyPI is a reserved
  name holding a `0.0.1.dev0` stub, so `pip install agentauth-capabilities` could
  never resolve the dependency and a stranger who cloned this repo could not
  build or test it. CI
  needed a personal access token to check out a private sibling in three
  separate jobs. All of that is gone: two runtime dependencies, one `pip install
  -e ".[dev]"`, no token. Core's own 46 tests came with it.
- **The policy document** (`policy.py`, `docs/POLICY.md`,
  `examples/policy.yaml`). Authority as a YAML file a security team can read,
  diff in a pull request and gate a merge on, compiled into the goal, scope,
  egress policy and budgets the gateway already took. It refuses rather than
  guesses: an unknown profile, an unparseable expiry, a tracked tool whose budget
  id has no ceiling, and a string where a list belongs are all compile errors,
  because each one would produce a gateway enforcing something other than what
  the document says. `Policy.digest()` hashes the document as written and the
  gateway carries it onto every decision.
- **`clayseal policy draft`: a written business rule becomes a policy draft.**
  Measured across eleven independently-authored corpora, 0 of 520 tasks declare
  a budget, and containment splits 83.3% against 18.9% on whether the grant
  expresses the constraint as one. The rung that matters is inert whenever
  nobody writes a ceiling. Organisations do write their ceilings down, in
  delegation-of-authority matrices and AP policies, in sentences like "a single
  vendor payment must not exceed $10,000"; they are simply not in a form a
  gateway can read. `policy_draft.py` reads them out. It drafts and is never the
  authority: it writes YAML to disk and stops, nothing in it is wired to the
  runtime, every rule cites the line it came from, and a sentence that reads
  like a rule and did not translate is emitted as a `TODO` comment rather than
  dropped, because a draft that looks complete is worse than one that admits
  what it left out.
- **`clayseal policy init`: the tool catalog becomes the other half.** The
  document knows what the organisation permits and cannot know what the tools
  are called. `init` runs the operator's own MCP server, asks it for
  `tools/list`, and reads names, effects and the argument each tool carries its
  path in out of the schemas the server already publishes. Pass `--rules` and
  both halves land in one file, which is the point: `budgets.tracked`, where a
  ceiling meets a tool, is the section an operator gets wrong, and it is only
  checkable with both in front of them. The catalog is read as a suggestion and
  never as authority, because the server describing the tools is the server
  being constrained: a description may raise a tool's effect and may never lower
  one, and a server calling its own effectful tool read-only is reported rather
  than believed. A tool that publishes no schema is not recorded as taking no
  path, because "the server did not say" and "the server said no" are different
  facts.
- **`clayseal`, a command.** `policy show`, `policy lint` (exits non-zero on an
  error, so it works as a pre-merge gate), `policy draft`, `policy init`, and
  `proxy`. `lint` runs the same
  mandate linter the gateway refuses to build on, so an author is told what
  `build` would reject instead of finding out from a traceback.
- **`mcp_proxy`: the enforcement point that does not depend on the agent
  cooperating.** `authorize()` is a method the harness chooses to call, which is
  a control when you own the harness and a fiction when you do not. The proxy
  speaks MCP on both sides, so a denied `tools/call` is answered with a JSON-RPC
  error and the server subprocess never receives the frame, which the end-to-end
  test asserts by reading what the server itself recorded. `tools/list` is
  filtered to the policy, so the agent is not offered a tool it would be refused.
  A STEP_UP reaches the agent as a refusal, because forwarding it would turn the
  supervised profile into the autonomous one at the transport layer.
- **`tool_verbs.classify_verb`** moved into the shipped package from
  `benchmarks/datasets/_common.py`. It decides whether a tool name is a read or a
  transfer, which is what the floor's write and egress rules key off, and it was
  in a tree that is not installable, so every real integration had to reinvent
  it. The benchmark loaders import it from here now, which is also how the two
  cannot drift.
- **`DeployableStack.observe_context`, `resolve_step_up`, `decision_log` and
  `metrics`.** `observe_output` was present and `observe_context` was not, so the
  documented entry point could not report the one input the content-provenance
  tier is built on.
- **`SECURITY.md` and `CONTRIBUTING.md`**, including which classes of finding are
  in scope and which are the published open gap.
- **`tools.effects` and `paths.arg_names`**, the two declarations that let the
  gateway be pointed at a catalog it was not designed against. See the two
  entries under Fixed for why each is needed.
- **`McpProxy.new_session()`**, and a notice when the client re-initializes. One
  proxy process is one session and its ceilings are spent over the life of the
  process, which is right for the constraint and wrong if you meant per task.
  `new_session()` is not wired to MCP's `initialize`: that message comes from the
  agent's side of the boundary, so resetting on it would let anything speaking
  the protocol clear its own budget by reconnecting.

### Added: conditional ceilings, and the reason they may only tighten

Real authorities are not constants. A payout limit collapses when the request is
expedited, a trading limit tightens once a position is open, a retention window
shortens when a hold notice arrives. Every budget in this layer carried one
number, and `path-dependent-ceiling` reads "rush collapses the ceiling".

`conditional_ceiling.GuardedCeilings` is a `ValueBudgetConfig` whose ceilings
tighten as facts arrive. `ceiling_for` is the single point at which every budget
type reads a limit, so one override covers the value, call and compute ledgers and
composes with `WindowedValueBudget` for free.

**A guard may only tighten, and that restriction is the entire security
argument.** A condition is a fact about the session, facts arrive from tool
output, and tool output is content an attacker may control. If a guard could raise
a ceiling then `expedited: false` injected into a document would widen authority,
and the rung would be a lever for the attacker rather than a control on them.
Monotone tightening removes it: an attacker with full control of every condition
can only shrink the authority of the agent they have compromised, which a test
verifies by enumerating every reachable combination of three facts over nine
values each.

A guarded ceiling above the base is refused at construction and at policy compile
time. The limitation that imposes is stated rather than buried: **"normally 5,000,
and 15,000 once a manager approves" cannot be written as a guard.** Raising
authority is what step-up is for, and a step-up needs a signed approval bound to
the specific action. A guard and a step-up are the two halves of "conditional",
split by direction.

Three more rules, each so that an accident cannot decide an authority question:

- Several guards firing at once give the **tightest**, not the last declared, so
  the order a document lists them in cannot change a decision.
- A guard with no condition is refused: it applies always, which is a base
  ceiling written in the wrong place.
- Comparison is strict about types. A fact of `1` does not match a condition of
  `true`, because `1 == True` in Python and an authority decision must not rest
  on that. A comparison that raises fires the guard, since failing toward a
  smaller ceiling has no symmetric risk.

**Facts come only from the STRUCTURED fields of tool output**, fed automatically
by `observe_output`, which is the same distinction the provenance tier already
draws. Free text never becomes a fact, verified by a test that feeds
`rush: true`, `{"rush": true}` and a direct instruction as prose and asserts no
fact lands. A malformed field leaves the base ceiling in force, which under the
tightening rule is the safe direction.

Exposed in the policy document as `budgets.value.when`. 22 tests. One of them
found a real subtlety in my own comparison logic: a hostile object never reaches
the raising path against a boolean condition, because bool-strictness decides
first. Both paths are now pinned separately.

### Added: a rolling-window value budget, and once-per-object ceilings

Found by inspecting the residual: nine scenarios whose grant configures a budget
and which are still not contained. Five are labelled `open`. Two of the remaining
four had grants that **did not implement the rule the scenario itself declares**,
and both said so in their own comments.

- **`WindowedValueBudget`.** `SessionValueBudget` sums an amount and never
  forgets; `SessionVelocity` has a rolling window and counts actions. **Nothing
  windowed a value**, so "no more than $10,000 per 24 hours", which is the shape
  almost every written business rule takes, had to be approximated by a session
  ceiling. The approximation is not conservative, it is wrong in both directions
  at once, and `rolling-window-hour-skew` was the measured case: it refused a
  benign script that paid $2,000, waited 24 hours and paid $2,000 again, and
  "contained" the 6-hour attack for a reason unrelated to the rule.
  Inherits the reservation, supersession, identity and Decimal logic unchanged
  and adds a timestamped ledger pruned before any decision reads the total.
  **The clock is injected**: a windowed control tested against the wall clock is
  one nobody can verify. 19 tests, all driving a moved clock, none referencing a
  benchmark.
- **`budgets.value.windows` and `budgets.value.tracked.*.identity`** in the
  policy document. A window of zero or less is refused at compile time, a window
  on a budget with no ceiling is refused, and `identity` must be a list of
  argument names. An entry ages out of a window WITH its object identity, so
  `identity` on a windowed budget means "once per object per window" rather than
  "once per object ever".
- Absent a window, everything behaves exactly as before, asserted by a test.
  That default matters: every published number predates this.

### Changed: two scenario grants, disclosed rather than folded in

`idempotent-double-pay` declares "pay every listed row exactly once for
(employee, period)" and counted duplicates in its `violated` predicate while its
grant used a plain ceiling; its comment read "value budget won't catch
idempotence". `EffectSpec.identity_args` already existed and was built for
exactly that class. No new code, one declaration.

Both grants now implement their scenarios' declared rules. What moved:

| | contained | joint metric | benign scripts losing work |
| --- | ---: | ---: | ---: |
| before | 53/132 | 50/132 (37.9%) | 1 |
| after | 54/132 | 52/132 (39.4%) | **0** |

Exactly two scenarios changed outcome and nothing else moved. The difference over
dataflow taint goes from 26.5 to **28.0 points [18.2, 37.9]**, exact McNemar
p=1.2e-07, still surviving Holm. **No scenario in 132 now loses work.**

The sequence concern is real and stated in
[grant_changes_2026_08.md](benchmarks/results/grant_changes_2026_08.md): the
failures were found first and the fixes came after, which is fit-to-failure in
order even when each fix is principled. That file records how to subtract the
change. `WindowedValueBudget` does not subtract, because it is a library
capability rather than a benchmark result.

### Added: the second ratchet, and the reproducibility gap closed as far as it goes

The gap was 38 results files with neither a command nor a status: a number nobody
can check and nobody has vouched for. It is 24 now, and it cannot grow.

- **`check_claims` gains a second ratchet.** A results file that records neither
  what produced it nor a `STATUS:` is counted, baselined, and a rise fails the
  check. Same design as the bare-zero ratchet and for the same reason: a gate
  that fails all 38 on day one is a gate somebody deletes.
  `benchmarks/tests/test_claims_ratchets.py` asserts both fire, both pass once
  the file says what produced it, and a command declared inline in backticks
  counts the same as one in a fenced block.
- **`verify_results` reads inline commands too.** `flow.md` says "produced by
  `python -m benchmarks.flow`" and `frontier.md` says "Reproduce with `python -m
  benchmarks.live.frontier --suite banking`". Only the fencing differed, and
  reading one and not the other invented a distinction the authors never made.
  That alone took the count from 38 to 24.
- **`burst.md` gained a title and its command and now verifies**, joining
  `structuring.md` and `drift.md`.
- **Thirteen more were attempted and abandoned deliberately.** Guessing flags
  until the numbers match is not verification, it is fitting, and a verifier that
  does it certifies whatever it was pointed at. The honest state is that those
  results were produced with parameters nobody wrote down, and recovering them
  needs the person who ran them.
- [REPRODUCIBILITY.md](benchmarks/results/REPRODUCIBILITY.md) records the
  remaining 24, grouped by what each would need, and states what a results file
  has to carry: the command WITH its parameters, because a bare module name is
  worse than nothing. It looks like a reproduction instruction and silently runs
  a different experiment, which is exactly what `drift.md` did.

### Added: the label-free adversarial evaluation

`benchmarks.adaptive_stack` reads no labels and no scenario file: it constructs
candidates against the shipped gateway and keeps what gets through, so a failure
it finds is one nobody wrote down in advance. 250 tasks, 1,014,100 candidates,
three attacker knowledge levels, 1,156s, recorded in
[adaptive_stack_labelfree.md](benchmarks/results/adaptive_stack_labelfree.md).

- **It independently reproduces the published open gap.** On
  `in-scope-exfiltration` the full stack contains exactly what the bare floor
  contains, 8.0% blind and 15.2% under feedback, at every step-up setting. The
  behavioural tiers add nothing to that class. `in_scope_exfiltration.md` reports
  that from a curated corpus; an adversary never told about it reaches the same
  number.
- **It found something the curated suite does not report.** On the neighbouring
  `in-scope-content-staging` class the stack goes from 9.6% to 83.6% blind and
  18.0% to 96.8% under feedback, but **only with `step-up=block`**; with
  `step-up=allow` it falls back to the floor exactly. The flow tracker's whole
  contribution on that class rests on whether a step-up halts the action, so a
  deployment treating step-up as advisory has the floor and nothing else there.
  No label could have encoded that.

### Added: generalization measured without the labels

The label problem looked terminal: `clayseal_expected` predicts containment with
97.7% accuracy, so any analysis reading a label can only rediscover what an
author wrote down. Two measurements that read none.

- **Leave one authoring batch out.** Held-out batches do NOT score
  systematically worse than the rest, so there is no evidence of fitting to
  individual scenarios. What there is instead is heterogeneity: held-out rates
  run from nothing to 87.5%, **sd 0.327**, against a pooled 37.9%. This is not a
  mechanism with a 37.9% success rate, it is one that works on some kinds of
  scenario and not others, and it is why the cluster-robust interval is the one
  to quote: at this much between-batch variance the naive interval is not
  conservative, it is wrong.
- **Split on what the grant configures.** Whether a scenario's own `make_broker`
  sets up a value or call budget is fixed before anything runs and readable from
  source, so it requires trusting nobody. Scenarios whose grant expresses the
  constraint as a budget are contained **78.6% [64.1%, 88.3%]**; those that do
  not, **18.9% [12.1%, 28.2%]**. Fisher exact p=6.5e-11. Dataflow taint runs the
  other way, 2.4% against 15.6%, which is a sharper statement of the
  complementarity than the union figures.
- **Configuration alone predicts the outcome 80.3% of the time; the label
  predicts 98.5%.** So the bulk of what the label knows is not private knowledge
  about the mechanism, it is a fact about the grant any reader can recover. The
  residual 18 points is the part that cannot be checked, and it is 26 named
  scenarios. That is a materially narrower admission than "the evaluation set is
  contaminated", and it is the one the evidence supports.
- The README now leads with the deployment rule this yields rather than with a
  pooled rate: write the constraint as a ceiling on something countable or
  summable and it is enforced; where you cannot, the aggregate rung has nothing
  to accumulate against. `clayseal policy lint` already reports an effectful tool
  that debits no budget as an error, and this measures what that error is worth.
- Both analyses run in `bpl_sweep` on every invocation, recorded in
  [bpl_label_free.md](benchmarks/results/bpl_label_free.md).

### Fixed: the structural analysis measured the ladder and called it the system

`build_engines` had every ablation rung registered and not the shipped product,
so `coverage.py` and everything else routed through it measured the ablation
ladder. The number published one revision ago, in-surface containment of nothing
across the board, was wrong for that reason.

`deployable-stack` and `deployable-stack-stepup-allow` are registered now.
Corrected: the shipped stack contains **24.9% [18.8%, 30.8%]** of AgentHarm's
in-surface attacks and **20.5% [13.8%, 28.4%]** of sleight's, where the ladder
contains none.

**Every point of it comes from the step-up path.** The same stack with
`treat_step_up="allow"` scores identically to the ladder, which is the third
independent measurement of that after `adaptive_stack_labelfree.md`. A deployment
treating step-up as advisory has the floor and nothing else on this class.

### Added: a count derived from the goal, for deployments that declare nothing

The aggregate rung enforces a ceiling somebody declared and **0 of 520 external
corpus tasks declare one**, so it is inert exactly where it is needed. The
envelope is derived rather than declared and could say which tools a plan uses
and whether a phase repeats at all, never **how many times**: a goal reading
"email a summary" admitted one send and fifty identically.

- `Phase.max`, `Deviation.OVER_COUNT`, and `monitor/multiplicity.py`, which reads
  the count off the sealed goal at seal time, before any untrusted content
  exists. A test asserts the module never touches tool output.
- **It steps up rather than denying.** The bound came from reading a sentence, so
  "you said one and this is the second" is a reason to ask: a retry after a
  failed send is indistinguishable. Hard denial in this layer requires positive
  evidence of malice and this is not that.
- Deliberately conservative. Three signals produce a bound, any iteration marker
  suppresses it, and **a clause supporting two readings yields none**, because a
  bound nobody clearly stated must not exist. Most goals get no bound.
- Three correctness bugs found while building it, each by a test: a numeral
  anywhere in the clause was read as the count and turned a path fragment into a
  bound of 43 on `sleight`; the plural check looked at any noun in the clause, so
  an unrelated "files" cancelled the correct read of "a report"; and an unguarded
  attribute read on a pluggable seam's return value raised from inside the
  authorization path when a test double had a different shape.
- Measured on the corpora that motivated it: 52 of 200 AgentHarm goals yield a
  bound, 3 of 43 on sleight, 0 of 27 on AgentLeak. **Whether that moves
  containment is not yet measured**, because the benchmark's stack factory builds
  no envelope at all, and changing the harness in the session that built the
  capability is the sequence problem already disclosed once in
  `grant_changes_2026_08.md`. Named as the next step rather than claimed.

### Measured: the derived count rung, and what it costs

Attributed by difference across three arms of the same stack, on the corpora that
motivated it. Two findings, and only one of them is a win.

**The intent envelope was missing from the benchmark harness entirely.**
`stack_factory.py` built the stack with no envelope, so every structural analysis
routed through it measured a stack with no goal-derived plan. Wiring it in is
worth +5.1 points of in-surface containment on AgentHarm and **+62.3 on
sleight**. A harness fix, not a capability.

**The count rung adds +1.6 points on AgentHarm and nothing on sleight**: 8 attack
events of 507, and 0 of 122 because the envelope alone already reaches 82.8%
there.

Then the column that decides it. On benign events:

| corpus | arm | interrupted |
| --- | --- | ---: |
| agentharm (278) | envelope, no counts | 0 |
| agentharm (278) | **envelope + counts** | **26 (9.4%)** |
| sleight (500) | no envelope | 5 |
| sleight (500) | **envelope, either way** | **310 (62.0%)** |

**Every one is a step-up rather than a refusal**, verified by re-running with
`treat_step_up="allow"` where all of them become allows. The cost is a person's
attention, not a lost task.

- **The count rung is a defensible trade and not a free one**: roughly three
  interruptions per additional catch. The numbers now travel with it in the
  README and `docs/POLICY.md`, and `derive_counts=False` turns it off.
- **The envelope on sleight is not a win and was already shipping.** +62.3 points
  bought with 62% of benign actions interrupted is close to deny-all on that
  corpus, and the containment number alone would be badly misleading. Nothing
  built today caused it; the harness fix made it visible. It goes on the list of
  things to fix rather than the list of results.

Both readings looked like wins on the containment column alone. Running the cost
side is what stopped them being written up as such, which is the lesson
`bpl_suite_composition.md` already encodes as the BOTH column.

Recorded in
[derived_counts_measured.md](benchmarks/results/derived_counts_measured.md).
`deployable-stack-no-counts` and `deployable-stack-no-envelope` are registered
engines so the attribution reproduces.

### Added: an optional inferrer for the counts a sentence does not state

The deterministic derivation reads a bound off the goal and is quiet by design,
so most goals get none. The inferrer is the opt-in path for those, and it is off
unless a caller passes one.

Three rules make a model acceptable in this position, and each is a test:

- **It runs once, at seal time, on the goal text and nothing else.** No tool
  output, no trajectory, no argument, so a proposal cannot be influenced by
  content the agent later reads. That is the planner privilege split the threat
  model already rests on: a model may appear in the control plane and never in
  the decision path. Asserted against the AST rather than the source text,
  because the docstrings legitimately name what the module must not touch.
- **It may never raise a bound the text supports.** `fill_gaps` (default) only
  fills a gap; `tighten` may also lower one. Neither can widen, which is the same
  monotone rule `conditional_ceiling` rests on: a proposal that only shrinks
  authority is safe whoever wrote it.
- **Every failure means "cannot say".** No credentials, timeout, rate limit,
  malformed answer, a proposal of 0 or 5000 or `True`: the bound falls back to
  the deterministic reading. Bounded in wall clock, for the reason the entailment
  judge is: this runs inside envelope compilation and a control plane that hangs
  is a control plane that is down.

**Every bound now carries its provenance** into the step-up reason, `[derived]`
or `[inferred]`. A step-up whose origin is unknown is not reviewable: `derived` a
person can check against the sentence and `inferred` they cannot, and they should
know which they are looking at.

`default_multiplicity_inferrer()` returns None without credentials, mirroring the
entailment judge, so absent configuration is not an error.

### Investigated: what the external corpora can and cannot measure

Eleven corpora nobody here wrote, 5,279 attack events, run through the
engine-blind structural partition in `coverage.py`. They are the independent
evaluation the BPL suite cannot be, so the question was what they say about where
the mechanism structurally fails.

**They split into two populations that barely overlap.** ASB, InjecAgent,
RedCode, ipi_coding and ATB are 100% surface-leaving; AgentHarm is 73%
in-surface, sleight 95%, AgentLeak 100%.

- **Surface-leaving: 100% contained by task-scope over more than 4,400 events
  across five corpora.** That half of the claim now has independent multi-corpus
  support.
- **In-surface: none contained at the top of the ladder, upper bound 1.9% on
  AgentHarm's 507 events.** Tight enough to be a finding rather than noise, and
  the same wall `in_scope_exfiltration.md`, the BPL in-scope family and the
  label-free adversarial search all report.

**The in-surface population is not one class.** AgentLeak is 22 of 22
single-action: one authorized call is itself the harm, so no aggregate rung can
ever see it and zero is structural. AgentHarm is 0 of 176 single-action, 2 to 7
actions per task, so it is sequence-shaped and zero is NOT structurally forced.

**What explains AgentHarm, controlled: 0 of 520 tasks across four corpora declare
a budget in their mandate.** The control that makes it a corpus property rather
than a harness bug is that the synthetic `fixture` loader does produce budgets.
The aggregate rung has nothing to accumulate against, which is
`bpl_label_free.md`'s 83.3%-against-18.9% split reproduced on independently
authored data at its limit.

Both directions are stated in
[external_corpora_structure.md](benchmarks/results/external_corpora_structure.md),
and the second is the one to lead with. It explains why a purpose-built suite had
to exist without special pleading, because the existing corpora encode **attacks**
and not **authorities**. And it means **the external corpora do not independently
confirm the aggregate result**: they are silent on the half this product is built
for, and citing the BPL numbers as externally validated would be wrong.

One hypothesis died on the way and is recorded so the next reader does not repeat
it. `broker._WRITE_ACTIONS` and `_EGRESS_ACTIONS` omit 14 verbs that
`is_consequential` accepts, including `execute`, which is 60 of sleight's 129
in-surface events. It looked load-bearing and is not: the path scope and the
egress check are **verb-independent**, verified by driving ten verbs including
invented ones at an off-allow-list destination and getting a denial from every
one. Those two sets gate only an optional soft rung and the protected-zone
read/write label.

### Added: a methodology inspection

Five questions a reviewer asks, answered by measurement, in
[methodology_inspection.md](benchmarks/results/methodology_inspection.md).

- **Seed sensitivity.** Every bootstrap is seeded 7; re-run across 40 seeds the
  bounds move by sd 0.0025 to 0.0038 and **the difference interval never crosses
  zero**, minimum lower bound 0.182. The published interval is a property of the
  data.
- **Is `per-call` a strawman?** No, and the arithmetic says why: it completes
  132/132 and refuses nothing, so its zero on the conjunction is forced by
  "allows every in-scope call, holds no state". It is given the policy and
  enforces the scope rule. **It is behaviourally identical to `none` on all 132**,
  which is the strongest form of the architectural claim rather than a harness
  bug, because every violating script in this suite is in scope by construction.
  That is now reported as a result.
- **Are the baselines named honestly?** Yes, and it was handled before this
  inspection: `progent` and `camel` were renamed to `per-call` and
  `dataflow-taint` because they are class reproductions, not those systems.
- **Is `deny-all` decoration?** No. It takes containment outright at 132/132 and
  scores nothing on the conjunction, which is what makes the conjunction the
  column to quote: no degenerate policy can take it.
- **Can the evaluation surprise its authors?** Partly, bounded three ways
  (leave-one-batch-out, the configuration split, label-free adversarial search).

Four gaps are named rather than closed: the deterministic sweep is not
pre-registered although the machinery exists; `progress` is scenario-defined and
the friction split leans on it; Holm is applied within a table and not across
eighty results files; and two scenario grants were changed after their failures
were inspected.

### Changed: statistics and reproducibility, for publication

- **The headline comparison is now tested.** Five conditions were reported as
  five rates with no test between them, and they are paired: every condition is
  replayed against the same 132 scenarios. `core/stats.py` gains
  `mcnemar_exact`, `paired_difference_ci` and `holm_bonferroni`, and the sweep
  reports all three. On the joint metric the difference over dataflow taint is
  **26.5% [17.4%, 36.4%], exact McNemar p=3.6e-07**, and all four comparisons
  survive Holm correction. McNemar rather than Fisher because the two mechanisms
  agree on only 21 of 132, so an unpaired test pools 111 scenarios that carry no
  information about which is better.
- **Cluster-robust intervals.** Scenarios were written in batches of four to
  twelve at a sitting, so 132 are not 132 independent samples. Clustering on the
  family gives three clusters, too few to bootstrap; clustering on the authoring
  file gives 17. The clustered rate is **37.9% [23.1%, 55.5%]** against naive
  [30.1%, 46.4%], materially wider, and still non-overlapping with dataflow
  taint's [6.1%, 17.7%]. That is the number to publish.
- **`benchmarks/verify_results.py`**: reads the command a results file declares
  and re-runs it. 19 of 78 results declare a command this gate can run, 4 still
  produce their own numbers, and **38 have neither a command nor a status**,
  which is a number nobody can check and nobody has vouched for. The queue is
  printed rather than estimated.
- `drift.md` and `structuring.md` now declare their commands and are stamped
  `STATUS: current` because they were verified rather than because someone
  decided they looked fine. `drift` had been failing verification for reporting
  2,000 actions against a module default of 10,000: a results file that does not
  record its parameters is not reproducible by anyone, including its author.
- The verifier is advisory and deliberately not in CI. It has a false-positive
  class it cannot fix cheaply, a table cell holding a historical figure
  (`NEVER_RAISES | 0 *(was 46)*`), so only an `ok` is evidence. Four bugs in it
  were found while writing it, which is the same argument: comparison direction
  reversed, dates read as figures, thousands separators split in two, and shell
  paths matched as Python modules.
- [publication_readiness.md](benchmarks/results/publication_readiness.md) states
  where this stands: the statistics are publication-grade, reproducibility is an
  enumerable and finishable gap, and the evaluation set's independence from the
  system is neither, and is the one a reviewer finds first.

### Fixed: what running every benchmark found

Three defects, none of which came from reading code.

- **`task-scope` was the only gate of six that raised on adversarial input.**
  `benchmarks/stress_gates.py` had been reporting it for five of twenty inputs
  (`None`, `0`, `[1]`, `{'a': 1}`, `True`), and `test_gate_totality.py` carried a
  strict `xfail` explaining that core was a sibling repository and so it was
  reported rather than patched. Core is vendored here now, the exemption expired,
  and a gate that raises has not contained anything, it has crashed. Non-strings
  normalise to a sentinel that matches no pattern. Two of the five needed the
  guard OUTSIDE the `lru_cache`: the decorator hashes its argument before the
  body runs, so an unhashable input never reached an `isinstance` check.
- **A deny-list bypass, found by differential-fuzzing the two path matchers
  against each other.** `path_matching.py` calls itself "the canonical home" for
  scope evaluation and `task_scope.py` has a second implementation, which is the
  one `task_scope_allows_path` calls, which is the one the floor calls. **3,298
  disagreements in 39,403 comparisons.** One class of them mattered: with
  `denied_paths=["infra/prod/**"]`, the live matcher ALLOWED
  `infra\prod\web.tf`, reading the backslashes as filename characters where the
  other read them as separators. An ambiguous path is now evaluated under every
  reading and resolved against the agent in both directions, denied if any
  reading is denied and allowed only if every reading is allowed. The remaining
  divergence is bounded by a test rather than left to be rediscovered.
- **`deny: ["infra/prod/**"]` did not deny `infra/prod`.** `**` requires a
  segment after the slash, and most infrastructure tooling takes a directory
  rather than a file, so a rule written to exclude a directory did not exclude
  it. The policy compiler closes deny patterns over the directory they name.
  Allow-lists are deliberately not closed the same way: widening one over a
  pattern-syntax detail is the opposite of what an author means.
- `stress_commit` reported `BASELINE=1`, a valid token failing to verify, because
  the fail-closed change made a replay store mandatory and the harness had not
  caught up.

46 of 47 benchmark scripts import and run; the one holdout correctly refuses
without its external dataset. 27 of 31 deterministic benchmarks complete clean,
`validity` needs an argument by design, and `commit_then_reveal` exceeds five
minutes and is not in any fast gate.

### Investigated: do the BPL failures cluster into a missing mechanism?

**No, and the reason is the finding.** Six mechanism hypotheses were read out of
the 79 failing scenarios; two died to a base-rate control (one had lift **below**
one, meaning it is a strength being read as a gap); three were indistinguishable
from noise at n=9 by Fisher exact; and the one that reached significance
(p=0.0004) dissolved when the label was held constant, which is Simpson's
paradox and was caught only because the confound was checked before the writeup.

The reason nothing survives: **the suite's own `clayseal_expected` labels predict
containment with 97.7% accuracy.** Every `contain`-labelled scenario is contained
(50/50) and almost nothing else is (3/82). The failures are the scenarios written
as failures, so there is no residual for a mechanism hypothesis to explain, and
the generalization map reporting zero regressions is closer to a tautology than
to validation. Recorded with what would answer it in
[bpl_failure_patterns.md](benchmarks/results/bpl_failure_patterns.md): held-out
authoring with no expectation field, promoting the `partial` set, or adversarial
search that does not know the labels.

### Changed: the benchmark reports what its number is a property of

The headline came from twelve scenarios that `SUITES.yaml` describes, in its own
words, as "mostly `clayseal_expected` contain|partial". Both statements were
true and they were in different files, which is how a selected set gets quoted as
a representative one. Measured: **Core is 83% `contain`-labelled where the suite
is 38%, and two thirds aggregate where the suite is one third**, aggregate being
the family this layer is built for and escape, at 17% of Core against 44% of the
suite, being the family it is weakest on.

- **`--suite core|hard|full`, and the composition prints with the result.**
  Containment tracks the composition almost exactly: Core is 83%
  `contain`-labelled and contains 83%, Full is 38% and contains 40%. The labels
  are well calibrated, and the Core number is a property of the selection. The
  margin over the nearest real defense is 58 points on Core and 8 on Full.
- **A BOTH column**, the per-scenario conjunction of containment and completion.
  Containment alone is won by refusing everything and completion alone by
  allowing everything; the two were reported separately and nothing said they
  were the same scenarios. On the conjunction both controls score nothing by
  construction, per-call enforcement scores nothing on every set, and this layer
  scores 37.9% (50/132) on the full suite against 11.4% (15/132) for dataflow
  taint. It barely moves between Hard and Full, so unlike the containment column
  it does not depend on the selection. **That is the number to quote**, and the
  README now quotes it instead of the Core one.
- **A FRICTION table that splits a refusal by what it cost.** `completed` fails
  on any refusal, which is the right primary metric and merges two different
  deployment facts. Of three benign twins this gate refuses, two still reach full
  progress and one loses half its work; dataflow taint refuses 49 and loses work
  on 43. Both bounds are printed, with the caveat that `progress` is
  scenario-defined, because reporting only the flattering one is what a defense's
  authors reach for.
- **A COMPLEMENTARITY section**, which is worth more than the ranking. 32
  scenarios are contained by this layer only, 21 by dataflow taint only, 21 by
  both, and their union is 74 of 132 against 53 for this layer alone. Stacking
  them would still be a bad trade: on the joint metric the stack scores 31%,
  **down** from 38%, because the taint layer refuses 46 benign scripts this one
  completes. Complementary in containment and anti-complementary in utility, so
  the 21 it catches and we do not have to be earned at this layer's precision
  rather than bought at that layer's recall.
- Recorded in [bpl_suite_composition.md](benchmarks/results/bpl_suite_composition.md),
  reproducible in seconds with no model and no key.

Two controls that held up, checked rather than assumed: `clayseal_expected` never
reaches the decision path, only the report, so the generalization map is not
circular; and the labels were committed with their scenarios rather than revised
after measurement. They are still written by the same people who built the
defense, so "measurement matches label" stays weak validation, which is the other
reason to lead with the full-suite numbers.

`check_claims` failed the first draft of the new results file for rendering rates
as a bare zero, and then failed it again for the sentence explaining the
convention. The ratchet works.

### Fixed: what red-teaming the proxy found

Seven more, from attacking the enforcement point rather than using it. Three
classes, and the classes matter more than the individual bugs.

**Parser differential.** The proxy authorized its own parse and forwarded the
ORIGINAL bytes, so it was only ever as correct as the agreement between two JSON
parsers. `{"name": "wire_transfer", "name": "read_ticket"}` is a real
disagreement: Python keeps the last duplicate key and a parser that keeps the
first runs the transfer this proxy believed it had cleared. Duplicate keys are
now refused rather than resolved, since the message means two things and there is
no correct one to pick, and everything authorized is re-serialised from what was
parsed so the server can only see the object that was cleared. A method that is
not exactly `tools/call` but normalises to it, `"tools/call "` or `"Tools/Call"`,
is refused for the same reason: forwarding it bets that the server is exactly as
strict about the string.

**One of many.** The gateway checks one path per action and a call can name
several, so `{"target_dir": "infra/staging/ok.tf", "path": "infra/prod/web.tf"}`
cleared a scope that denies `infra/prod/**`, and a tool taking a LIST of files had
one element checked. Declaring `paths.arg_names` had made this worse rather than
better, because the declared argument REPLACED the default ones instead of
joining them. The proxy now screens every path a call names, unioning declared
and default argument names and flattening list values, before the action reaches
the broker.

**Representation.** `%2e%2e` is a traversal to anything that URL-decodes and a
NUL truncates in anything backed by C, so neither can be compared against a
scope: the gateway and whatever finally opens the file would be comparing
different strings. Both are refused before the scope is consulted, and it is a
property of the path rather than of the policy, so it applies with no scope
configured.

Also:

- **A `tools/call` in a JSON-RPC batch was unbounded.** Each element takes the
  session lock and may reach a remote judge, so a 50,000-element batch was an
  amplification vector against the gateway. Capped at 256.
- **Pipelining defeated every content tier, silently.** MCP clients may issue a
  read and a send before either answer returns, and the send was then authorized
  before the read's result reached `observe_output`: the provenance tier was
  asked about a destination it had not been told the origin of, and answered as
  if the document had never been read. Effectful calls now wait for outstanding
  results, bounded by `settle_timeout` and fail-open on ORDERING only, which
  forfeits an advisory rather than a control and says so in the log.
- **That fix was itself a trap for one revision.** Waiting unconditionally turned
  every effectful call into a 30-second stall for any caller that drives
  `handle_client_message` without a server behind it, which is what it did to
  this repository's own suite. It now waits only when results are known to come
  back, which `run_stdio_proxy` declares and a first response proves.
- **`egress.domains` allows every subdomain of what it lists**, which is usually
  intended and occasionally catastrophic. Listing a public suffix is now a lint
  error: `amazonaws.com` or `vercel.app` allows most of the internet while
  looking like an allow-list.

Attacks that did NOT get through, recorded so the next round starts above them:
suffix-glued domains (`acme-internal.com.evil.example`), userinfo-at URLs, IP
literals, punycode, destinations nested in objects or lists or buried in free
text, budget ceilings under 20 concurrent callers, step-counter collisions under
50 threads, 20 MB arguments, and 400-deep nesting.

### Fixed: what an external workload found

Six defects, from pointing the proxy at a catalog nobody here designed. Two were
security defects, and both got past the original suite for the same reason: the
tests exercised the shapes their author had in mind.

- **A JSON-RPC batch bypassed the gateway entirely.** The client handler returned
  early on anything that was not a dict, and a batch is a list, so a `tools/call`
  wrapped in a one-element array reached the server with no authorization at all.
  Batches are now decided element by element; survivors are forwarded as a batch
  and refusals come back as one.
- **A path scope silently did not apply to most real tools.** The floor finds an
  action's path by looking at four argument names. A tool that calls its argument
  `target_dir`, `key` or `workspace` yields no path, the scope check is skipped,
  and the write is allowed: a policy denying `infra/prod/**` allowed a write to
  `infra/prod/web.tf`, and `lint` said the document was clean. `paths.arg_names`
  maps the argument, `paths.pathless` records a tool that genuinely has none, and
  an effectful call whose path cannot be resolved while a path scope is
  configured is now REFUSED rather than allowed unverified.
- **Every step-up through the CLI was reported as a flat denial.**
  `SessionBroker` returns an `Outcome` enum and `DeployableStack` returns the
  same value as a string. The proxy compared with `is Outcome.STEP_UP`, true for
  the first and false for the second, and the CLI builds a stack. The counter sat
  at zero and the agent was told "refused" instead of "a person has to approve
  this".
- **The provenance, taint and session tiers were inert behind the proxy.** They
  read what a tool RETURNED, and the proxy never fed a single result back. The
  floor and the budgets worked, which is why nothing failed; the rest of the stack
  was not running. Results now reach `observe_output`, with MCP's
  `structuredContent` kept separate from free text, which is the distinction the
  provenance mechanism rests on.
- **`tools.harmless` reached `lint` and not the gate.** A document could declare a
  tool harmless, lint clean, and then have the gateway refuse to build on the
  exact finding the declaration was meant to answer. `DeployableStack.from_goal`
  takes `declared_harmless` now, so the linter and the gate read the same input.
- **A denied JSON-RPC notification was answered.** The spec forbids replying to a
  notification. It is now dropped without a reply and still not forwarded.

- **The verb classifier was tuned on benchmark catalogs.** Measured against 24
  tool names from widely used MCP servers, 17 fall through to `call`, including
  `terraform_destroy`, `grant_role`, `s3_put_object` and `disburse_funds`. `call`
  is conservative rather than wrong, and it is not the verb, and the floor's write
  and egress rules key off the verb. `tools.effects` lets an operator declare
  them and `lint` names every tool it had to guess at.

- **Cross-host principal ledger** (`ledger_backends.RedisPrincipalLedger`). The
  file backend's own docstring named the limit: `fcntl` is invisible to a second
  machine. Overrides five storage primitives, inherits all reservation logic, and
  uses a fenced lock (token + compare-and-delete) so an expired TTL cannot delete
  a lock another node has since taken. Single-instance Redis, not Redlock, and
  says so.
- **Named profiles** (`profiles.py`): `AUTONOMOUS`, `SUPERVISED`, `BENCHMARK`.
  Fourteen posture switches, one of which is a measured negative result kept so
  the finding reproduces. Every switch carries the measurement justifying it,
  a profile switch cannot be overridden at the call site, and enabling a HAZARD
  requires naming it.
- **Decision sinks** (`decision_sinks.py`): JSONL (fsync-optional), rotating
  JSONL, Redis stream, composite. No default destination: that is a deployment
  decision, but the default is a `NullSink` that COUNTS what it drops, so
  "nothing configured" and "configured and working" no longer look alike.
  `DecisionLog.durability()` reports evicted-vs-dropped.
- **`docs/THREAT_MODEL.md`**: trust boundaries, the four signed objects and what
  each binds, key rotation, and the two classes of attack that are not stopped.
- **Adaptive red-team against the shipped gateway**
  (`benchmarks/adaptive_stack.py`, `benchmarks/core/stack_engine.py`) and a
  content-linked staging objective (`benchmarks/adversarial/content_staging.py`).

### Changed

- **The enforcement guards fail closed by default.** Every guard asked
  `is_production()`, and `is_production()` is false until someone sets an
  environment variable, so the fail-closed posture belonged to deployments that
  had read the README. Everything else accepted an unpinned commit-token minting
  key, a missing replay store, an unsigned step-up approval and an envelope
  signed by anyone. The guards now ask `fail_closed()`, which is true unless the
  environment names itself `development`, and the relaxed path warns once per
  process naming each guard it disabled. `is_production()` is unchanged and still
  gates the service startup checks, which demand things a library user does not
  have. Twenty tests were passing only because the default was permissive; they
  now state the whole contract.
- **README and developer guide lead with the gateway.** 0.5.0 recorded that "the
  layer stopped being a set of primitives and became a gateway" and neither
  document moved: the README did not contain the string "BPL" and the 458-line
  guide mentioned `SessionBroker` once. Both now open on the result that is
  uncontested, with its Wilson bound, its three non-discriminating scenarios and
  its two cells of pure friction stated alongside it.
- **The syscall tier says what it costs.** The README's most differentiating
  claim linked to a repository that returns 404, and the path is macOS only by
  construction. The seam, the reference backend and the gap are now each named.
- Internal memos moved from `docs/` to `notes/`, with a README saying they are a
  record rather than documentation. An investor memo shipping beside a developer
  guide reads as an accident.
- The committed 182 MB virtualenv (`.venv-h2h`, 7,474 of 8,280 tracked files) is
  untracked and `.gitignore` covers `.venv*/`. Removing it from history is a
  separate `filter-repo` pass before the repository goes public.

### Fixed

- **The entailment judge could hold a session lock indefinitely.** It is a remote
  model called from inside `authorize()` under the session lock, and there was no
  `timeout=` anywhere in its path: the OpenAI SDK's default is 600 seconds per
  request with its own internal retries, wrapped in four more attempts. A code
  path whose only possible output is a soft STEP_UP could therefore stall a
  session for as long as an attacker could keep the endpoint slow. Clients are
  now built with an explicit timeout and no SDK retries, the judge's own loop is
  bounded by a deadline rather than an attempt count, and `SessionBroker` wraps
  whatever judge it was handed so the ceiling is a property of the gateway rather
  than of the judge's good manners.
- **`clayseal.core` reached upward into `clayseal.capabilities`.**
  `task_scope.attenuate_biscuit_for_scope` imported the layer above it to resolve
  a default backend. It was invisible while the two were separate distributions,
  because the lazy import simply resolved at call time in an environment holding
  both, and vendoring core would have made it permanent. It now resolves through
  the plugin registry, which is what the registry is for, and
  `test_shipped_package_layering.py` covers core so it cannot come back.
- **A benchmark invariant asserted on source text and passed while the guard it
  checked was inert.** `test_production_refuses_to_run_without_a_replay_store`
  read `verify_commit_token` for the string `is_production()`. It now asserts the
  behaviour with the environment unset, which is the check that would have caught
  the polarity problem above.
- **Two signed objects did not fail closed in production.** The intent envelope
  accepted any keyholder when `trusted_keys` was unset, and it is the object
  `reclear` swaps mid-session, so a self-signed envelope replaced the sealed plan
  wholesale. The step-up approval honoured `CLAYSEAL_STEP_UP_ALLOW_UNSIGNED=1`
  in production, so one environment variable turned a refusal into a grant. Found
  by writing the threat model; both now match the commit-token posture.
- **Five encoding evasions in the confidentiality flow tracker.**
  `_decode_layer` stopped at the first decoder that did not RAISE, and
  `urlsafe_b64decode` does not validate, so it shadowed base85. base32, base85,
  base64-of-hex, double-base64 and decimal byte codes go from leaking to 100%
  contained (200/200) at 0 of 1,242 false blocks, unchanged.
- **`test_biscuit_scope.py` aborted collection** rather than skipping when the
  optional identity layer was absent, which is why the suite could only be
  called green by passing `--ignore`.
- CI: a legible guard for the missing `CLAY_SEAL_CI_TOKEN` instead of a private
  repo reporting as "not found"; the optional identity layer is now actually
  optional.

## [0.5.0] - 2026-08-18

The layer stopped being a set of primitives and became a gateway. `pyproject`
has said `0.5.0` since July while this file stopped at 0.4.0, so everything
below shipped unrecorded.

### Added, the gateway

- **`SessionBroker`** (`broker.py`), one live per-session gate composing the
  hard per-action floor (expiry, delegation, tool/capability/argument binding,
  protected zones, path scope, egress) with the behavioural tiers, as one
  ordered decision. Hard denial requires positive evidence of malice; a scope
  miss steps up, because a step-up halts an autonomous attacker just as hard.
- **`DeployableStack`** (`deployable_stack.py`), the single configured profile
  every benchmark path and every deployment builds through.
- **`IntentEnvelope`** (`monitor/`), a goal-derived, history-free plan with
  provenance-typed argument slots, compiled from the sealed goal and signed.
  `reclear()` adopts a fresh envelope mid-session on trusted input.
- **`ParameterProvenance`**, containing-object provenance for destinations:
  structured field allows, free text of a goal-named object steps up, ungrounded
  denies.
- **`FlowTracker` / `SensitivityPolicy`** (`confidentiality.py`), content
  derivation across a session. STEP_UP only, never DENY, because it is sound
  where it fires and incomplete in what it catches.
- **`PrincipalLedger` / `SharedPrincipalLedger`**, aggregate budgets keyed to
  the mandate rather than the session, with cross-process mutual exclusion,
  shared committed spend and shared outstanding holds. Four processes against a
  ceiling of 100 previously landed 400.
- **`DecisionLog`**, hash-chained, tamper-evident decision records for L3.
- **Sandbox integration** (`sandbox/`), an envelope's egress and path scope
  compile into iVisor policy; its verdict stream returns as attested evidence.
- **`resolve_step_up`**, the missing half of the step-up protocol. Every
  "supervised utility" number predating it was a counterfactual.
- Delegation boundaries, compute/call/value budgets, velocity limits, staleness,
  re-identification, mandate linting, replan.

### Added, this release

- **`monitor/planner.py`**, the privileged planner now SHIPS. It built every
  live AgentDojo result while living in `benchmarks/live/`, outside the wheel, so
  a package user could not construct the primary behavioural tier from a real
  request. `benchmarks/live/planner.py` is now an alias over it.
- **`session_state.py`**, `snapshot()` / `restore()` for everything a session
  accumulates. Outstanding step-ups could not previously cross a process, so
  the step-up protocol did not complete behind a load balancer; spent approvals
  and audit spend reset on restart, and neither is a ceiling if it does.
- **`session_rules.py`**, the five corpus-derived pattern rules, extracted from
  `SessionBroker.authorize` where they were invisible and unswitchable. Same
  predicates and same reason strings: ON in `DeployableStack.from_goal` so every
  published number reproduces, OFF on the raw broker.
- **`SessionBroker` is thread-safe.** Every mutating entry point takes a
  re-entrant session lock. Without it, 20 of 20 concurrent trials produced a
  decision chain that failed its own `verify()`.
- `StepUpRequest.from_dict`, `SessionGrants.snapshot()/load()`.
- `DecisionLog` is bounded in memory (`max_records`, default 10,000) and
  distinguishes eviction from tampering.

### Fixed

- **The package did not import on Python 3.10 or 3.11.** `value_budget.py` put a
  backslash escape inside an f-string expression, a syntax error before 3.12,
  in a module `clayseal/capabilities/__init__.py` imports. `requires-python`
  claimed `>=3.10`. CI never caught it because CI has never run.
- **`issue_commit_token` returned a tuple** instead of a token when
  `action_name` was not a string, a guard copy-pasted from the verifier, which
  produced an `AttributeError` at a trust boundary, the exact failure the guard
  exists to prevent. It raises `ValueError` now.
- **The documented quickstart called an API that does not exist.** README and
  DEV_GUIDE both ended in `verify_commit_token(token, key=...).valid`: no `key=`
  parameter, no `.valid`, and `public_key` is not the hex string
  `trusted_minting_keys` matches. Doc code blocks are now executed by the suite.
- **The library imported the benchmark harness.** `DeployableStack.
  from_benchmark_task` did `from benchmarks.core.detector_eval import _goal_for`,
  which raises `ModuleNotFoundError` in every real install. Moved to
  `benchmarks/core/stack_factory.py`; a test now walks the shipped package for
  any import outside the wheel.
- `confidentiality._decode_layer` used `unicode_escape`, a latin-1 codec that
  mangled non-ASCII and emitted 1,266 deprecation warnings per benchmark run on
  a path Python has announced will become an error. Replaced with a decoder that
  resolves genuine escapes and leaves everything else alone.
- `layer.py` annotated three functions with `CapabilityLayer` without importing
  it; `egress_policy.py` used `Iterable` the same way.
- Dead locals in `monitor/detector.py` and `monitor/entailment.py`; exception
  chaining in `velocity.py`.

### Changed

- CI: the matrix floor is 3.10 rather than 3.11, so `requires-python` is tested
  at both ends. A `wheel` job builds and imports the artifact in a clean
  environment with no source tree on the path. A `lint` job gates the shipped
  package on a pinned ruff rule set. The 14-minute invariant suite moved to a
  nightly job and off the push path.
- `security.yml` pinned `aquasecurity/trivy-action@v0.36.0`; the bare `0.28.0`
  tag does not exist, so every scheduled scan failed at "unable to resolve
  action" rather than on a finding.
- Ruff configuration is pinned in `pyproject.toml` instead of inherited from
  ruff's defaults, so the gate does not change meaning on a ruff release.

### Known limitations

- `SharedPrincipalLedger` is single-host (`fcntl`), has no `fsync`, and rewrites
  its holds sidecar whole.
- `session_state` ships the serialisation, not a distributed store, and does not
  by itself make cross-process access safe.
- In-scope data staging is not contained: against an oracle attacker the escaped
  set is byte-identical to `allow-all`. See
  `benchmarks/results/in_scope_exfiltration.md`.
- Content-defined harm sits at 6.3%. See `benchmarks/results/why_we_fail.md`.

## [0.4.0] - 2026-07-05

### Added

- **Cross-provider identity integration**, layer 2 works with five built-in L1 adapters:
  - `agentauth`, `spiffe_jwt`, `oidc`, `auth0`, `aws_sts`
- Shared authority contract in `clayseal.core`:
  - `AuthorityBinding`, `IdentityProvider`, `IdentitySession`, `CapabilityTokenBackend`, `CapabilityLayer`
- `clayseal.capabilities.identity_adapters` registry with `get_identity_provider(name)`.
- `clayseal.capabilities.integration`, `execution_context_from_session`, `default_biscuit_backend()`.
- `AgentAuthCapabilityLayer` in `clayseal.capabilities.layer`.
- `docs/cross_layer_integration.md` and `examples/04_cross_provider_commit.py`.
- `docs/DEV_GUIDE.md`, comprehensive developer guide.
- GitHub Actions CI (installs identity from sibling repo, runs `python/tests`).
- Eight adapter tests in `python/tests/test_identity_adapters.py`.

### Changed

- Depends on `agentauth-identity @ v0.4.0`.
- Removed duplicate `providers/` tree in favor of `identity_adapters/`.

## [0.3.1] - 2026-07-01

### Changed

- Cleanup after split: namespace layout, `.gitignore`, dependency pin to identity v0.3.1.

## [0.3.0] - 2026-06-30

### Added

- Initial standalone release of the capabilities layer (commit tokens, mandates, leases, value budgets).
