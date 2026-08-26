# Surface reading under randomized stress

STATUS: current

```bash
python -m benchmarks.stress_surface --cases 200000 --seed 7
```

200000 generated resource strings, each checked against a randomly chosen goal surface.

| property | violations |
| --- | --: |
| TOTAL | 0 of 200000 |
| NO-SILENT-PASS | 0 of 200000 |
| SEPARATOR | 0 of 200000 |
| MONOTONE | 0 of 200000 |
| FILESYSTEM | 0 of 200000 |

No property was violated. The three defects this file was written for are
closed and the reading holds on inputs no corpus contains.

## What the fixes cost

Nothing, measured rather than assumed. Each fix makes the tier refuse strictly
more, so the question is whether it began refusing legitimate work, and the
answer is on every corpus at once:

| corpus | benign interrupted, before | after | surface-leaving contained |
| --- | --: | --: | --: |
| sleight | 44/311 | 44/311 | 7/7 |
| agentharm | 46/729 | 46/729 | 189/189 |
| redcode | 0 of 344 | 0 of 344 | 717/717 |
| tau2 | 1/5441 | 1/5441 | n/a |
| bfcl | 0 of 1200 | 0 of 1200 | n/a |

Byte-identical in both columns. That is the same fact as the section below read
from the other side: the corpora do not exercise these inputs, so closing the
holes moved nothing they can see.

## The four defects this found, and why no corpus could

Every one was live in code written this session, and every corpus number is
byte-identical before and after all four fixes. That is the argument for the
file: these corpora contain no `.env`, no backslash path and no traversal, so
they can never exercise the reading, and a clean corpus run says nothing about
it.

| defect | what passed | found by |
| --- | --- | --- |
| an unreadable target read as no target | `.env`, a bare `..` | hand probe |
| a backslash was not a separator | `..\..\etc\shadow` | hand probe |
| traversal through a granted prefix | `data/../etc/shadow` classed as `data` | this file, after its own blind spot was fixed |
| a dot split a filename | `data.txt` matched a grant of the directory `data` | this file, `FILESYSTEM` differential |

## The probe had the same blind spot as the code

The first version of `filesystem_differential` **excluded any string containing
`..`**, reasoning that traversal was this library's business rather than the
filesystem's. It then reported five clean properties over 50,000 cases while
`data/../etc/shadow` classed as `data`, passed a surface granting `data`, and
would have opened `/etc/shadow`. Five variants were live.

A probe written by the author of the thing it probes inherits the author's model
of what can go wrong, and an exclusion is where that model is written down. The
lesson is not "fuzz more". It is that an exclusion in a differential deserves the
same scrutiny as a branch in the code, because it is a claim that a whole
population cannot contain a defect.

`normpath` is the authority now, traversal is the population the differential
cares about most, and the exclusions that remain are two: a scheme, which is not
a path, and a leading-dot component, which classes to nothing on purpose with
`names_a_target` stopping that from being a pass.
