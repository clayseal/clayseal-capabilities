"""Randomized differential on the path scope, which IS the authorization floor.

    python -m benchmarks.stress_scope
    python -m benchmarks.stress_scope --cases 200000 --seed 7

`task_scope_allows_path` is the check that contains 100% of surface-leaving
attacks across more than 4,400 events on five corpora. It is the single most
load-bearing predicate in the library, and everything else in this repository
tests it on curated corpora, which find the paths a corpus author thought of.

Three defects in a DIFFERENT path reading were found this session, all by hand,
all invisible to every corpus: an unreadable target treated as no target, a
backslash that was not a separator, and a traversal through a granted prefix.
The floor turned out to be sound on all three when it was finally asked. This
file is the systematic version of asking, because "we checked twelve cases by
hand" is not a claim about a predicate with this much weight on it.

## The oracle

Scopes here are deliberately simple prefix globs, so the correct answer is not a
matter of interpretation: a path is inside `data/**` exactly when the path a
filesystem would resolve begins with `data/`. `posixpath.normpath` is the
authority for that resolution, and a backslash is a separator on the way to it.

Restricting the scope shapes keeps the oracle unarguable. A test whose expected
answer is itself computed by a second glob engine would be comparing two
implementations of the same idea, which is how both come to share a bug.

## The properties

``TOTAL``      the predicate never raises, on any string.
``NO-ESCAPE``  a path resolving OUTSIDE every allowed prefix is never allowed.
               This is the security property: everything else is convenience.
``DENY-WINS``  a path resolving INSIDE a denied prefix is never allowed, whatever
               the allow list says.
``conservative-refusal`` a path the oracle would allow and the floor refuses.
               NOT a violation: erring toward denial is the safe direction, and
               the floor keeps a segment's raw form when matching, so ` out/x`
               does not match `out/**`. Counted because a floor that refuses
               everything has no escapes either.
"""
from __future__ import annotations

import argparse
import posixpath
import random
import string
import sys
from collections import Counter

from clayseal.core.task_scope import TaskScope, task_scope_allows_path

ALLOWED_PREFIXES = ("data", "finance/ap", "out")
DENIED_PREFIXES = ("infra/prod", "data/secrets")

HEADS = ["", "/", "//", "./", "../", "..\\", "\\", "~/", " ", "\t"]
SEGMENTS = ["data", "finance", "ap", "out", "etc", "infra", "prod", "secrets",
            "..", ".", "x", "a b", ".env", "models", "data.txt", "sub"]
JOINS = ["/", "\\", "//", "/./", "/../"]
TAILS = ["", ".txt", ".ledger", "/", "\x00", "%2e%2e"]


def generate(rng: random.Random) -> str:
    if rng.random() < 0.03:
        return "".join(rng.choice(string.printable)
                       for _ in range(rng.randrange(0, 14)))
    depth = rng.randrange(1, 5)
    out = rng.choice(HEADS) + rng.choice(SEGMENTS)
    for _ in range(depth):
        out += rng.choice(JOINS) + rng.choice(SEGMENTS)
    return out + rng.choice(TAILS)


def resolved(path: str) -> str:
    """The most permissive reading a consumer could plausibly take.

    Whitespace is stripped per segment, not just at the ends. That is the point:
    plenty of things that finally open a path trim it, and the bypass this file
    found was a `..` absorbed by a whitespace-decorated segment, so `\t./../out`
    resolved to `out` and passed a grant of `out/**` while `../out` was denied.
    The oracle has to model the consumer that trims, because that consumer is
    who the authorization decision is really about.
    """
    segments = [s.strip() for s in path.replace("\\", "/").split("/")]
    return posixpath.normpath("/".join(segments) or ".").lstrip("/")


def under(prefix: str, path: str) -> bool:
    resolved_path = resolved(path)
    return resolved_path == prefix or resolved_path.startswith(prefix + "/")


def check(path: str, scope: TaskScope) -> list[str]:
    try:
        allowed = task_scope_allows_path(scope, path)
    except Exception as exc:  # noqa: BLE001 - a raise IS the failure here
        return [f"TOTAL({type(exc).__name__}: {exc})"]

    inside_allow = any(under(p, path) for p in ALLOWED_PREFIXES)
    inside_deny = any(under(p, path) for p in DENIED_PREFIXES)

    failures = []
    if allowed and not inside_allow:
        failures.append("NO-ESCAPE")
    if allowed and inside_deny:
        failures.append("DENY-WINS")
    if not allowed and inside_allow and not inside_deny:
        # NOT a violation. Refusing a path the oracle would allow errs toward
        # denial, which is the safe direction, and the floor deliberately keeps
        # a segment's raw form when matching so ` out/x` does not match `out/**`.
        # Counted because a floor that refuses everything has no escapes either.
        failures.append("conservative-refusal")
    return failures


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--cases", type=int, default=200_000)
    p.add_argument("--seed", type=int, default=7)
    p.add_argument("--show", type=int, default=6)
    args = p.parse_args(argv if argv is not None else sys.argv[1:])

    scope = TaskScope(
        allowed_paths=[f"{p}/**" for p in ALLOWED_PREFIXES],
        denied_paths=[f"{p}/**" for p in DENIED_PREFIXES],
    )
    rng = random.Random(args.seed)  # noqa: S311 - reproducible, not secret
    failures: Counter[str] = Counter()
    examples: dict[str, list[str]] = {}

    for _ in range(args.cases):
        path = generate(rng)
        for name in check(path, scope):
            key = name.split("(")[0]
            failures[key] += 1
            examples.setdefault(key, [])
            if len(examples[key]) < args.show:
                examples[key].append(f"{path!r} resolves to {resolved(path)!r}")

    print("# The authorization floor's path scope, under randomized stress\n")
    print("STATUS: current\n")
    print("```bash")
    print(f"python -m benchmarks.stress_scope --cases {args.cases} "
          f"--seed {args.seed}")
    print("```\n")
    print(f"`task_scope_allows_path` on {args.cases} generated paths against")
    print(f"allowed `{', '.join(ALLOWED_PREFIXES)}` and denied "
          f"`{', '.join(DENIED_PREFIXES)}`.\n")
    print("| property | violations |")
    print("| --- | --: |")
    for name in ("TOTAL", "NO-ESCAPE", "DENY-WINS"):
        print(f"| {name} | {failures.get(name, 0)} of {args.cases} |")
    print(f"| conservative-refusal (not a violation) | "
          f"{failures.get('conservative-refusal', 0)} of {args.cases} |")

    unsafe = {k: v for k, v in failures.items()
              if k != "conservative-refusal"}
    if failures:
        print("\n## Detail\n")
        for name, count in failures.most_common():
            print(f"**{name}: {count}**\n")
            for line in examples.get(name, []):
                print(f"    {line}")
            print()
    if unsafe:
        return 1
    print("\nNo property was violated. The floor resolves a path before "
          "matching it, so\ntraversal through a granted prefix lands outside "
          "the grant, which is where the\nmonitor's own reading of a path was "
          "wrong until this session.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
