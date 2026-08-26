"""Randomized stress of the surface reading, which decides membership.

    python -m benchmarks.stress_surface
    python -m benchmarks.stress_surface --cases 200000 --seed 7

`monitor/surface.py` reads an action's target into a class and asks whether that
class is in the goal's surface. Three defects lived in it, and all three were
found by typing candidate strings at a REPL rather than by any corpus:

- `.env` splits on its leading dot, classes to the empty string, and the empty
  reading was treated as "this action names no target", which passed the tier;
- `..\\..\\etc\\shadow` contains no `:` and no `/`, falls through to the `.`
  split, and did the same;
- a backslash was not a separator at all, which is the same bypass class this
  repository already closed once in the path deny-list.

Every corpus number was byte-identical before and after the fix. That is the
whole argument for this file: the corpora do not contain a `.env`, so a corpus
can never find this, and the next reading of a path written here will have the
same blind spot unless something systematically looks for it.

## The properties

``TOTAL``        the reading never raises, for any string at all.
``NO-SILENT-PASS`` an action that names a READABLE target is in-surface only if
                 one of its readings is genuinely in the surface. Readable means
                 a path, a scheme, or something path-shaped; a bare word with no
                 path is abstained on, which is deliberate and measured. The
                 invariant is that `named nothing readable` and `named something
                 readable that does not match` must not collapse.
``SEPARATOR``    a backslash reads as a separator, so a path and its
                 backslash-written twin class identically.
``FILESYSTEM``   for an ordinary relative path, the class agrees with the first
                 component a filesystem would resolve. Differential against
                 `PurePosixPath`, which is the thing that finally opens the file.
``MONOTONE``     widening the surface never turns an allow into a deny.
"""
from __future__ import annotations

import argparse
import posixpath
import random
import string
import sys
from collections import Counter

from agentauth.capabilities.monitor.action import Action
from agentauth.capabilities.monitor.surface import (
    in_surface,
    names_a_readable_target,
    resource_readings,
    surface_class,
)

#: Fragments chosen because each is a way of writing a path that means one thing
#: to a reader and another to whatever finally opens it.
HEADS = ["", "/", "//", "///", "\\", "\\\\", "./", ".\\", "../", "..\\",
         "~/", "~", " ", "\t", "%2e%2e/", "%2f", "C:\\", "\\\\server\\share\\"]
BODIES = ["data", "home", "etc", ".env", ".git", ".ssh", "..", ".", "...",
          "models", "finance", "a b", "a.b", "a:b", "\u00e9t\u00e9", "\u0130",
          "data\u200b", "DATA", "data/", "x" * 200,
          # Traversal through a granted prefix, which is the bypass the first
          # version of this file was written blind to.
          "data/..", "data/../etc", "data/../../etc", "home/../etc",
          "data/./../etc", "data/x/../../etc", "data//../etc"]
TAILS = ["", "/x", "\\x", "/x/y", "\\x\\y", "/..", "/./.", ".txt", "\x00",
         "/*", "?", "#frag", "%00"]
SCHEMES = ["", "net:", "file:", "repo://", "mcp:tool:", "s3://", "https://"]

SURFACES = [
    frozenset({"data", "home"}),
    frozenset({"data"}),
    frozenset(),
    frozenset({"etc", "net", "repo"}),
    frozenset({"data", "home", "etc", "net", "repo", "mcp:tool"}),
]


def generate(rng: random.Random) -> str:
    """One adversarial resource string."""
    if rng.random() < 0.05:
        n = rng.randrange(0, 12)
        return "".join(rng.choice(string.printable) for _ in range(n))
    return (rng.choice(SCHEMES) + rng.choice(HEADS) + rng.choice(BODIES)
            + rng.choice(TAILS))


def _act(resource: str, path: str | None = None) -> Action:
    return Action(step=0, tool="Bash", resource=resource, verb="write",
                  args={}, meta={"path": path} if path is not None else {})


def check(resource: str, path: str | None, surface: frozenset[str]
          ) -> list[str]:
    """Every property, on one case. Returns the names of those that failed."""
    failures: list[str] = []
    try:
        action = _act(resource, path)
        readings = resource_readings(action)
        allowed = in_surface(action, surface)
        # A READABLE target, not merely a non-empty one. A bare word with no
        # path names something and names nothing a path-shaped surface can
        # judge, and the tier abstains on it deliberately: see
        # `names_a_readable_target` and `false_positives.md`, where refusing on
        # exactly that took 46.5% of sleight's benign sessions with it.
        named = names_a_readable_target(action)
    except Exception as exc:  # noqa: BLE001 - a raise IS the failure here
        return [f"TOTAL({type(exc).__name__}: {exc})"]

    # NO-SILENT-PASS: naming a target and passing requires a real match.
    if allowed and named and not any(r in surface for r in readings):
        failures.append("NO-SILENT-PASS")

    # SEPARATOR: a backslash-written twin classes the same.
    if "\\" not in resource and ":" not in resource:
        twin = resource.replace("/", "\\")
        if surface_class(twin) != surface_class(resource):
            failures.append("SEPARATOR")

    # MONOTONE: a wider surface never denies what a narrower one allowed.
    wider = surface | {"data", "home", "etc"}
    if allowed and not in_surface(action, wider):
        failures.append("MONOTONE")

    return failures


def filesystem_differential(resource: str) -> str | None:
    """Does the class agree with the first component a filesystem resolves?

    The authority is `posixpath.normpath`, which is what textually resolves a
    path on the way to being opened.

    **The first version of this excluded any string containing `..`**, on the
    reasoning that traversal was this library's business rather than the
    filesystem's. That is precisely where the bug was: `data/../etc/shadow`
    classed as `data`, passed a surface granting `data`, and opened
    `/etc/shadow`. The probe had been built with the same blind spot as the code
    it was probing, so it reported five clean properties over 50,000 cases while
    the worst defect in the module sat inside the exclusion. Traversal is now
    the population this differential cares about most.
    """
    if (not resource or ":" in resource or "\x00" in resource
            or resource != resource.strip()):
        return None
    normalised = posixpath.normpath(resource.replace("\\", "/")).lstrip("/")
    if not normalised or normalised in (".", ".."):
        return None
    expected = normalised.split("/", 1)[0]
    # A leading-dot component is this library's business: it classes to nothing
    # on purpose, and `names_a_target` is what stops that being a pass.
    if expected.startswith("."):
        return None
    got = surface_class(resource)
    return None if got == expected else f"{resource!r}: {got!r} != {expected!r}"


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--cases", type=int, default=200_000)
    p.add_argument("--seed", type=int, default=7)
    p.add_argument("--show", type=int, default=8)
    args = p.parse_args(argv if argv is not None else sys.argv[1:])

    rng = random.Random(args.seed)  # noqa: S311 - reproducible, not secret
    failures: Counter[str] = Counter()
    examples: dict[str, list[str]] = {}
    fs_mismatch: list[str] = []
    checked = 0

    for _ in range(args.cases):
        resource = generate(rng)
        path = generate(rng) if rng.random() < 0.5 else None
        surface = rng.choice(SURFACES)
        checked += 1
        for name in check(resource, path, surface):
            key = name.split("(")[0]
            failures[key] += 1
            examples.setdefault(key, [])
            if len(examples[key]) < args.show:
                examples[key].append(f"resource={resource!r} path={path!r} "
                                     f"surface={sorted(surface)} [{name}]")
        mismatch = filesystem_differential(resource)
        if mismatch and len(fs_mismatch) < args.show:
            fs_mismatch.append(mismatch)
        if mismatch:
            failures["FILESYSTEM"] += 1

    print("# Surface reading under randomized stress\n")
    print("STATUS: current\n")
    print("```bash")
    print(f"python -m benchmarks.stress_surface --cases {args.cases} "
          f"--seed {args.seed}")
    print("```\n")
    print(f"{checked} generated resource strings, each checked against a "
          f"randomly chosen goal surface.\n")
    print("| property | violations |")
    print("| --- | --: |")
    for name in ("TOTAL", "NO-SILENT-PASS", "SEPARATOR", "MONOTONE",
                 "FILESYSTEM"):
        print(f"| {name} | {failures.get(name, 0)} of {checked} |")

    if not failures:
        print("\nNo property was violated. The three defects this file was "
              "written for are\nclosed and the reading holds on inputs no "
              "corpus contains.")
        return 0

    print("\n## Violations\n")
    for name, count in failures.most_common():
        print(f"**{name}: {count}**\n")
        for line in examples.get(name, fs_mismatch if name == "FILESYSTEM" else []):
            print(f"    {line}")
        print()
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
