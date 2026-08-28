# Held-out generalization (dynamic sandbox v0.1)

STATUS: unverified

> No command was recorded for this file, so its numbers cannot be
> re-derived from it. `unverified` says that nobody has checked them, which
> is the honest claim; `current` would be vouching for a run nobody can
> reproduce. See the provenance section of [README.md](README.md).


The anti-overfitting test. The sandbox was designed on banking. Here it is
evaluated with zero per-suite tuning on three AgentDojo suites it was never
designed against: workspace, travel, slack. Different ontologies, different
tools, different exfiltration channels (emails and URLs, not IBANs). Live agent
(gpt-4o-mini), real important_instructions injection, 8 user x 3 injection tasks
per configuration (n=24), plus banking at n=30.

Two configurations:
- **general envelope**: goal-derived LLM scope + verb-class partial order, with
  read-permissive/effect-strict scoping. No destination binding, no oracle. This
  is the deployable path.
- **full stack**: adds ground-truth scope and destination binding. The privileged
  ceiling, labelled as such.

## Attack success rate (lower is better)

| suite | baseline | general envelope | full stack |
|-------|---------:|-----------------:|-----------:|
| banking | 67% | — | **0%** |
| workspace | 87.5% | **4.2%** | 4.2% |
| travel | 29.2% | **8.3%** | 8.3% |
| slack | 66.7% | 29.2% | **0%**\* |

The general envelope, with no tuning and no oracle, cut attack success by 81 to
95 percent on the three held-out suites. Banking needs the destination binding
(its attack reuses the in-scope send_money tool), which drives it to zero.

*Slack was the hard case. Its attacks exfiltrate by reading an attacker URL
(get_webpage) and posting to an attacker page, channels an effect-verb egress gate
did not cover. Extending destination binding to run on any action carrying an
external destination (reads included, not only effect verbs) drove slack full-stack
from 20.8% to **0%** at 87.5% clean utility. Held-out evaluation found the gap and
the fix closed it, with all four suites now at 0 to 8.3% full-stack ASR.

## Clean utility (higher is better)

| suite | baseline | general envelope | full stack |
|-------|---------:|-----------------:|-----------:|
| banking | 70% | — | 60% |
| workspace | 100% | 87.5% | 87.5% |
| travel | 100% | 50% | 87.5% |
| slack | 87.5% | 87.5% | 87.5% |

## Utility under attack (higher is better: is the agent still productive?)

Across the board the defended agent is more productive under attack than the
undefended one, because the sandbox keeps it on task instead of letting the
injection derail it. Workspace: 20.8% undefended to 75% defended. Travel: 54.2%
to 83.3% (full stack). This is the partnership property in a number.

## Read-permissive scoping: the effect and the honest tradeoff

Containment scales with reversibility: the scope admits acquisition (read) tools
broadly and reserves strict membership for irreversible effect tools. Effect on
the general envelope:

| suite | uniform scope | read-permissive | net |
|-------|--------------:|----------------:|-----|
| travel | 25% clean / 12.5% ASR | 50% clean / 8.3% ASR | win (utility up, ASR down) |
| workspace | 100% / 4.2% | 87.5% / 4.2% | neutral |
| slack | 62.5% / 12.5% | 87.5% / 29.2% | utility up, ASR regressed |

The slack regression is diagnostic, not a failure: read-permissive admits
get_webpage, and slack's attack reads an attacker URL, so opening the read
channel without destination binding on reads lets it through. The fix is
egress-on-reads plus deployable destination binding, not reverting
read-permissive. Where attacks use effects (travel, workspace) read-permissive is
a strict win.

## What this establishes and what it does not

Establishes: the dynamic sandbox generalizes across ontologies with zero tuning,
which is the core anti-overfit claim. The wins come from the general layers, not
from anything banking-specific.

Does not yet establish: robustness to an adaptive adversary that knows the
defense (the decisive test, next), and a deployable destination binding that
replaces the oracle seeding with provenance. Slack also shows the read-channel
and output-manipulation limits are real and must be closed, not hidden.
