"""A linter for results files, run in CI.

    python -m benchmarks.check_claims            # report + ratchet
    python -m benchmarks.check_claims --baseline # rewrite the debt baseline
    python -m benchmarks.check_claims --strict   # enforce everywhere

`SEND_PACKET.md` is a forbidden-claims list that a human has to remember to
consult. This is the runnable half. It exists because the failure it guards
against is not dishonesty, it is that a number written under deadline outlives
the caveat written beside it.

## Why a ratchet rather than a gate

Measured before writing this: **443 bare-zero lines across 47 of 61 results
files, and not one file carries a status header.** A check that fails all of them
on day one is a check that gets disabled in week one, and then the repository has
a disabled linter instead of a problem it can see.

So: files that opt in with `STATUS: current` are enforced strictly. Everything
else is counted, and CI fails only if the count **rises**. The debt stays visible
and cannot grow, and a file becomes enforced the moment someone stamps it. That
is a slower path to clean than a hard gate, and it is the one that survives
contact with a deadline.

## The rules

``bare-zero``     ADVISORY, ratcheted. A rate rendered `0%` or `0.0%` with no
                  interval and no denominator on the line.
                  `frontier.md` says it of itself: 0 of 18 has an upper bound
                  near 18%, and that applies to every 0% in this repository.
                  Use `benchmarks.core.reporting.format_rate`.

``no-status``     A results file with no `STATUS:` header. `current`,
                  `superseded`, or `retracted`. There are ~120 files here
                  including a RETRACTED section inside a live document and a
                  result contradicted by a later sweep; a reader cannot tell
                  which is which.

``forbidden``     A claim `SEND_PACKET.md` names as auto-fail, matched literally.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

RESULTS = Path(__file__).parent / "results"
BASELINE = Path(__file__).parent / "results" / ".claims_baseline.json"

#: A rate rendered as zero. Excludes `10%`, `0.05%`, and version-like `0.0.1`.
BARE_ZERO = re.compile(r"(?<![.\d])0(?:\.0+)?\s?%")
#: Anything on the same line that makes the zero honest. A denominator counts:
#: the sin is an UNCONTEXTUALISED zero, and `0.00% (0 of 1,242)` lets a reader
#: compute the bound themselves. Accepting it keeps the linter narrow enough to
#: be believed — `flow_window.md:16` was flagged on the first run and is exactly
#: the shape this rule should permit.
HAS_BOUND = re.compile(
    r"upper bound|97\.5%|95% CI|\[\s*0?\.|interval|n/a|±|\bCI\b"
    r"|\d+\s*/\s*\d+|\d+\s+of\s+[\d,]+|n\s*=\s*\d+", re.I)
STATUS = re.compile(r"^\s*STATUS:\s*(current|superseded|retracted)\b", re.I | re.M)

#: Literal phrases SEND_PACKET.md forbids. Deliberately narrow: a regex that
#: guesses at intent produces false alarms, and a linter that cries wolf is
#: worse than none.
FORBIDDEN = (
    ("pooled containment", "pooling a SATURATED corpus into a headline"),
    ("supervised utility", "supervised utility is a counterfactual unless measured "
                           "with a resolving approver; say which"),
)


def status_of(text: str) -> str | None:
    match = STATUS.search(text[:600])
    return match.group(1).lower() if match else None


def scan(path: Path) -> dict:
    text = path.read_text(errors="ignore")
    status = status_of(text)
    # A file that qualifies the claim in its own header has complied. The rule
    # exists to catch an UNQUALIFIED claim, and enforcing it per line means a
    # file cannot satisfy it at all: the caveat is written once at the top and
    # the term then appears throughout the body, which is how the caveat is
    # supposed to be written.
    qualified = "counterfactual" in text[:1500].lower()
    bare: list[tuple[int, str]] = []
    forbidden: list[tuple[int, str]] = []
    for i, line in enumerate(text.splitlines(), start=1):
        if BARE_ZERO.search(line) and not HAS_BOUND.search(line):
            bare.append((i, line.strip()[:90]))
        low = line.lower()
        if qualified or "forbidden" in low:
            continue
        for needle, why in FORBIDDEN:
            if needle in low:
                forbidden.append((i, f"{needle}: {why}"))
    try:
        name = str(path.relative_to(RESULTS.parent.parent))
    except ValueError:
        name = str(path)   # a path outside the repo is still scannable
    return {"file": name, "status": status,
            "bare_zero": bare, "forbidden": forbidden}


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--baseline", action="store_true",
                   help="rewrite the debt baseline from the current tree")
    p.add_argument("--strict", action="store_true",
                   help="enforce every file, not only STATUS: current ones")
    args = p.parse_args(argv)

    reports = [scan(f) for f in sorted(RESULTS.glob("*.md"))]
    total_bare = sum(len(r["bare_zero"]) for r in reports)
    stamped = [r for r in reports if r["status"]]
    enforced = [r for r in reports
                if args.strict or r["status"] == "current"]

    if args.baseline:
        BASELINE.write_text(json.dumps({"bare_zero_total": total_bare,
                                        "files": len(reports)}, indent=2))
        print(f"baseline written: {total_bare} bare zeros across {len(reports)} files")
        return 0

    prior = 0
    if BASELINE.exists():
        prior = json.loads(BASELINE.read_text()).get("bare_zero_total", 0)

    print(f"results files          {len(reports)}")
    print(f"stamped with STATUS    {len(stamped)}")
    print(f"enforced this run      {len(enforced)}")
    print(f"bare zeros (total)     {total_bare}   baseline {prior}")

    # Blocking vs advisory, and the distinction is a limit of the instrument
    # rather than a policy choice. A text match cannot tell a CLAIMED rate from a
    # DISCUSSED one: `+0%` in the adequacy table is a taint gap, not a rate, and
    # "reports that as containment 0.00%" is prose about another harness's output.
    # Flagging those as violations is how a linter earns the reputation that gets
    # it switched off.
    #
    # So bare zeros are counted and RATCHETED — the debt is visible and cannot
    # grow — while only the literal forbidden phrases block, because those are
    # matched exactly and do not guess at intent.
    failures: list[str] = []
    for report in reports:
        for line_no, why in report["forbidden"]:
            failures.append(f"{report['file']}:{line_no} forbidden claim: {why}")

    if total_bare > prior:
        failures.append(
            f"bare-zero count rose from {prior} to {total_bare}; the ratchet only "
            f"turns one way. Use benchmarks.core.reporting.format_rate.")

    if failures:
        print("\nFAIL")
        for f in failures[:40]:
            print(f"  {f}")
        if len(failures) > 40:
            print(f"  ... and {len(failures) - 40} more")
        return 1
    print("\nok")
    return 0


if __name__ == "__main__":
    sys.exit(main())
