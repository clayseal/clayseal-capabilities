# Working notes

Internal thinking, kept in the repository because the reasoning behind a design
is worth more than the design alone, and because several of these documents are
what the code's comments cite.

They are **not** user documentation and they are not all current. A roadmap
records what we thought at the time it was written; a frontier map records what
the literature looked like on the day it was surveyed. Where a note and the code
disagree, the code is right and the note is a record of how we got here.

For documentation that is maintained, see [../docs](../docs). For results, see
[../benchmarks/results](../benchmarks/results), where every file carries a
`STATUS:` line saying whether it is current or superseded.

| note | what it is |
| --- | --- |
| `above_sota.md` | a frontier survey, as of its date |
| `improvements.md`, `production_sota_path.md` | where the gaps were and what to do about them |
| `moonshots.md` | larger bets, mostly unbuilt |
| `head_to_head_plan.md` | how the comparison against published systems was set up |

Paper drafts, the fundraising memo and dated positioning surveys are kept
outside this repository. Two audit files in `benchmarks/results/` check their
claims against this code and stand on their own.
