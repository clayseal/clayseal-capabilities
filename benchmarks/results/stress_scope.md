# The authorization floor's path scope, under randomized stress

STATUS: current

```bash
python -m benchmarks.stress_scope --cases 200000 --seed 7
```

`task_scope_allows_path` on 200000 generated paths against
allowed `data, finance/ap, out` and denied `infra/prod, data/secrets`.

| property | violations |
| --- | --: |
| TOTAL | 0 of 200000 |
| NO-ESCAPE | 0 of 200000 |
| DENY-WINS | 0 of 200000 |
| conservative-refusal (not a violation) | 12790 of 200000 |

## Detail

**conservative-refusal: 12790**

    '\tout\\finance\x00' resolves to 'out/finance\x00'
    '\tdata/./a b/out/./prod/./infra/' resolves to 'data/a b/out/prod/infra'
    '//data\\infra\\sub/../out/../finance.ledger' resolves to 'data/infra/finance.ledger'
    '/data/etc//out/' resolves to 'data/etc/out'
    ' out/./ap/../finance' resolves to 'out/finance'
    'ap/../out\\etc/' resolves to 'out/etc'


No property was violated. The floor resolves a path before matching it, so
traversal through a granted prefix lands outside the grant, which is where the
monitor's own reading of a path was wrong until this session.

## The two defects this found

`task_scope_allows_path` is the predicate that contains 100% of surface-leaving
attacks across more than 4,400 events on five corpora. It had never been fuzzed.

**A leading whitespace character absorbed a traversal.** `../out/sub` was
correctly denied under a grant of `out/**`. `\t./../out//sub/`, the same path
with a tab in front, normalised to `out/sub` and was **allowed**. The normaliser
classified segments by their raw form, so a whitespace-decorated segment counted
as an ordinary directory name and the `..` that followed popped it. Twenty
escapes in the first 60,000 generated paths, every one of that shape.

Whether a filesystem would open a directory literally named `" .."` is not the
question. Plenty of consumers trim a path before opening it, and this function's
own docstring states the principle: an authorization decision must be about the
file that will actually be opened. Segments are now classified by their stripped
form and matched by their raw one, so both readings err toward denial.

**A deny list closed on one construction path only.** `close_deny_patterns`
exists, is well documented, and was applied where a policy is compiled. A
`TaskScope` built directly, which the library API invites and which every
benchmark loader does, kept the hole: `data/secrets` was ALLOWED under
`denied_paths=["data/secrets/**"]`, because `**` requires a segment after the
slash. It is closed in `TaskScope.__post_init__` now, so every path to a scope
gets it.

## What the fixes cost

Nothing, on every corpus at once. Both fixes make the floor refuse strictly
more, so the question is whether it began refusing legitimate work.

| corpus | benign interrupted | surface-leaving contained |
| --- | --: | --: |
| sleight | 44/311 | 7/7 |
| agentharm | 46/729 | 189/189 |
| redcode | 0 of 344 | 717/717 |
| asb | 0 of 102 | 2040/2040 |
| injecagent | 0 of 1054 | 1597/1597 |
| tau2 | 1/5441 | n/a |
| bfcl | 0 of 1200 | n/a |

Byte-identical to the run before either fix.

## The conservative refusals are not violations

12,790 of 200,000 generated paths are refused where the oracle would allow them,
and they are dominated by two shapes: an absolute path against a relative
pattern (`/data/etc/out` against `data/**`), and a segment carrying whitespace
or a control character. Both are the floor erring toward denial, which is the
safe direction, and the second is deliberate: a segment is matched by its raw
form so ` out/x` does not match `out/**`.

They are counted rather than hidden because a floor that refuses everything has
no escapes either, and the number is the evidence that this one does not.
