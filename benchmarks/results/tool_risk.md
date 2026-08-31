# Which tools carry the loss, and can that be predicted in advance?

STATUS: current

```bash
python -m benchmarks.tool_risk
```

Classifying DATA sensitivity was built and refused to pay
([flow_content_classifier.md](flow_content_classifier.md)): the benign twin
handles the same confidential values as the attack, so a sharper answer to "what
is sensitive" moves both halves of the pair together. The constraint that binds
is the SINK, which reframes the question from what is dangerous to hold to
**which tools are dangerous to permit**. Unlike data sensitivity, that is
directly measurable.

## Two quantities

**Realised loss, by ablation.** Refuse exactly one tool, nothing else, and
rescore the suite. A tool's `contains` is how many attacks stop; its `cost` is
how many benign twins break. This reads the outcome, so it is a MEASUREMENT and
never a mechanism. Nothing in the gateway may consult it.

**Predicted risk, from the name alone.** A lexical prior over the tool name and
its verb, which is trusted configuration fixed with the mandate. This is what an
operator has on day one, before any incident.

## The prior works, and is not the interesting part

| | tools | mean predicted risk |
| --- | ---: | ---: |
| carry loss | 143 | 1.20 |
| carry none | 292 | 0.22 |

**AUC 0.733** over 41,756 pairs, against 0.5 for chance. A name-only prior does
rank loss-carrying tools above inert ones, so an operator with no policy has a
defensible default: step up what the prior ranks high.

But the top of the ablation table says why that is worth less than it looks.

```
tool                       contains   benign cost
pay_vendor                       12            12
send_email                        7             7
pay_invoice                       5             3
pay                               4             4
```

**The dangerous tools are dangerous because they are the tools that do the
work.** Refusing `pay_vendor` stops twelve attacks and breaks twelve benign
twins. Ranking tools by loss and refusing the top of the list is `deny-all` with
extra steps.

## The exploitable signal is the tail

**26 tools contain an attack at ZERO benign cost.** Legitimate work never touches
them:

```
break_glass          patch_policy_file    override_hard_stop   drop_volume
mint_approval_token  publish_gist         call_admin_api       force_replay
```

The deployable form of that needs no view of any attack: **a tool the benign
trajectory never uses does not need to be in the grant.**

| arm | contained | completed | joint |
| --- | ---: | ---: | ---: |
| least privilege from benign traffic | **33** | **132** | **33** |

Zero benign cost by construction, and it is **complementary** to the gateway
rather than redundant with it:

```
least privilege only : 14        both : 19        gateway only : 56
UNION                : 89 of 132
```

The 14 include three this work had documented as out of reach:
`toctou-stale-approval`, `economic-substance-sham` and `adaptive-stats-reid`. A
grant that never issued the tool is not troubled by the fact that no rule could
have expressed the constraint.

## Why 33 is an upper bound and not a result to quote

The benign twin here is a **complete** account of legitimate behaviour. A
deployment learns from a sample, and this repository has already measured that
gap from the other direction: [observed_grant.md](observed_grant.md) shows that
building a grant from the tools a recording happens to use refuses **42.99% of
5,441 held-out benign events**, because every tool the recording missed is
refused even where the same mandate authorizes that verb class.

So the honest statement is a bound. Perfect knowledge of legitimate tool use is
worth 33 of 132 at no cost; imperfect knowledge of it is the single largest
source of false blocks measured anywhere in this work. The gap between those two
is the actual engineering problem, and it is not a classifier problem.

## What this says about the name-only prior

Twelve of the 26 free-containment tools score **0.0** under the prior, including
`break_glass`, `override_hard_stop` and `call_admin_api`. Their names describe
authority rather than an effect verb, and an effect-verb lexicon cannot see them.
A prior built to rank effects will systematically miss the tools whose danger is
that they change what is permitted.
