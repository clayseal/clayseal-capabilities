# What it takes to be decisively above SOTA

Written from the measurements this repo produced, including the ones that
refuted our own claims. The question is not "what else could we build" but
"what would make a skeptical reviewer or a CISO conclude we are ahead", and
those two audiences want different evidence.

## Where we already stand

| Axis | Us | Published SOTA | Verdict |
| --- | --- | --- | --- |
| ASR, deployable path | **0.5%** [0.1, 2.6] pooled over 216 runs | ARGUS 3.8%, Progent 4.2% (indep.), CaMeL near-0 | **ahead, and the only pooled figure** |
| Utility cost, strong model | 3 pts (grok-4-1-fast, 81% baseline) | ARGUS 5 pts, CaMeL 7 pts, RTBAS ~2 pts under attack | **ahead of most, n=32** |
| Utility cost, weak model | 29 pts pooled (gpt-4o-mini) | ARGUS 5 pts on gpt-4o-mini | **behind, and this is the gap** |
| Attention cost | 0.83-4.17 interruptions/task, now priced | not reported by anyone | **we are the only ones measuring it** |
| Adaptive attacker | 100% containment at oracle knowledge | rarely evaluated | **ahead on methodology** |
| Long horizon | 100% needle detection, 0 false alarms / 100k actions | benchmarks average 3 calls | **ahead, uncontested** |
| In-surface attacks | ~0% contained | ~0% contained | **level, and the real frontier** |
| Symlink / TOCTOU | open by construction | open | level, and closable |

The honest summary: **we are at or above SOTA on security and on strong-model
utility, and the gap is weak-model utility plus two structural holes nobody has
closed.**

## The five things that would put us decisively ahead

### 1. Solve the in-surface class (the only real frontier)

82% of pooled attack events leave the granted surface and we contain ~100% of
them. The remaining **18% stay inside it**: granted tool, granted resource,
in-scope target, authorized argument shape. Every per-call authorizer on earth
scores ~0% there, ours included, and AgentHarm is 94% this class.

Nobody has solved it, which is exactly why solving it is the move. Three
mechanisms are available and only one is built:

- **aggregate limits** (built): catches fragmented spend and bulk exfiltration
  over an allowed channel;
- **velocity and shape** (not built): an agent that normally reads 10 records
  and reads 10,000 is in-surface on every call and anomalous in aggregate;
- **provenance of the containing object** (not built): distinguishes a value the
  task legitimately derived from one that arrived with untrusted content, which
  is the only way to separate two free-text tokens sharing a source.

**Why it is worth the effort:** an authorization layer that also contains
in-surface attacks is a different product category, not a better version of the
same one. It is also the class real incidents come from, because an attacker who
has to leave the surface has already lost.

### 2. Close weak-model utility, or stop claiming it matters

Our cost is 3 points on grok-4-1-fast and 19-25 on gpt-4o-mini. Two honest
responses, and we should pick one rather than blurring them:

- **Fix it:** most of the loss is the LLM planner failing to enumerate
  legitimate steps, which we proved by removing the plan check and watching
  utility jump (and ASR jump with it, on two suites). A better plan, not a
  weaker gate: plan repair on deviation, or re-clearance mid-session, which the
  broker already supports via `reclear`.
- **Scope it:** state that the system targets models of a given capability and
  publish the ladder. This is defensible and cheap, and the trend is monotone
  enough to support it.

The failure mode to avoid is quoting the 3-point number without the ladder.

### 3. Make the three-axis frontier the standard artifact

We are, as far as the 2026 literature shows, the only ones reporting attention
cost alongside safety and utility. That is not a small methodological detail:
the banking frontier shows `graduated` reaching identical 0% ASR while spending
**5x the human attention for half the utility**. On two axes it looks like a
tie. On three it is strictly dominated.

Publishing this as a reproducible protocol, with the audit budget as the knob
that bounds attention, would set an evaluation standard rather than report a
score. Standards outlive scores.

**One rule to publish with it:** a per-suite frontier is a per-suite
recommendation. `deferallow` sits on the banking frontier and takes ASR to 27.8%
on travel. The deployment decision is the intersection across suites, never the
union.

### 4. Evaluate against an escape-seeking adversary at the syscall boundary

Every published agent-security benchmark evaluates an agent following *injected
instructions*. None evaluates an agent actively trying to **escape its
sandbox**. Our adaptive harness already does defense-aware search; pointing it
at a real kernel boundary through iVisor would produce a category of result that
does not currently exist.

It also closes the two holes we cannot close in userspace: symlink resolution
and TOCTOU. Both are documented in our own code as open, which is the right way
to carry them but not a good place to stay.

### 5. Fix the measurement before adding more mechanism

Everything above is gated on this. Today, at n=8-18 per cell:

- identical configurations produced 50% and 75% clean utility on the same suite;
- **the same configuration produced 27.8% and 0.0% ASR on the same suite**, which
  is wide enough to flip a shipping decision, and which we discovered only
  because a later sweep happened to repeat a cell;
- two claims died to single-suite and single-model artifacts;
- two harness bugs reported perfect scores for defenses that were not running.

The ASR variance is the one that should worry us most, because we had been
treating that axis as solid. **Every 0% ASR in this repository comes from a
single sweep**, and the Wilson upper bound on 0 of 18 is 17.6%. Pooling four
suites brings it to 5.1%; twelve sweeps would bring it to 1.7%. Our headline
security claim is currently supported to about one significant figure, and
saying "0% ASR" without the interval overstates it.

We are measurement-limited, not coverage-limited. Three seeds per cell and
action-level scoring (denials and step-ups, which moved cleanly in every
comparison while task percentages wandered) would resolve differences we
currently cannot see. Adding a sixth mechanism measured this way would produce a
sixth claim we cannot defend.

## Priority

1. **Measurement** (item 5). Cheap, and it gates the credibility of everything else.
2. **Velocity and shape controls** (item 1, second bullet). Attacks the in-surface
   class directly, uses the aggregate machinery already validated, and is the
   loss-of-control signal a CISO already understands.
3. **Three-axis frontier as a published protocol** (item 3). Mostly written.
4. **Plan repair / re-clearance** (item 2). Targets the one rule that causes 100%
   of hard false blocks, without weakening it.
5. **Syscall boundary** (item 4). Highest ceiling, highest cost, uncontested
   territory.

## What would make it undeniable

A single reproducible artifact containing: the three-axis frontier across four
suites and four models; containment against an adaptive, defense-aware attacker
at three knowledge levels; long-horizon detection with false alarms per 1,000
benign actions; the in-surface versus surface-leaving split so nobody has to
guess what the headline number is weighted by; and every negative result we
found, including `deferallow` and the two harness bugs.

The negative results are load-bearing. A submission that reports only wins reads
as marketing to exactly the audience we need to convince, and we now have
unusually good ones to show.
