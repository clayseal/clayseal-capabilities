"""A linter for results files, run in CI.

    python -m benchmarks.check_claims            # report + ratchet
    python -m benchmarks.check_claims --baseline # rewrite the debt baseline
    python -m benchmarks.check_claims --strict   # enforce everywhere

`SEND_PACKET.md` is a forbidden-claims list that a human has to remember to
consult. This is the runnable half. It exists because the failure it guards
against is not dishonesty, it is that a number written under deadline outlives
the caveat written beside it.

## A ratchet turns one way, and it also LOCKS

The first version only refused a rise. That is half a ratchet: fix a file and
the count falls, the baseline stays where it was, and the slack is a free slot
for the next violation. Debt paid down was silently re-borrowable.

So a run that finds a count BELOW its baseline rewrites the baseline down and
says so. Improvement is locked in the moment it happens, which is the property
that makes the number mean something over months rather than over one cleanup.

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

``costless``      ADVISORY, ratcheted. A file that reports CONTAINMENT and never
                  once names what the containment cost. `deny-all` contains
                  everything, so a containment figure with no benign column is
                  not a measurement of anything, and this repository has now
                  found three separate numbers that turned out to be deny-all
                  wearing a reason string: the intent envelope on sleight
                  (82.8% containment, 65.6% of benign events denied), the
                  detector on the same corpus (published 0.0% false-block,
                  actually 72.2%), and the +62.3-point envelope "win" that was
                  the first of these misread as a result. Each was found by
                  running the cost side, and each could have been caught by
                  noticing it was missing.
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


def declares_command(text: str) -> bool:
    """Does this file say what produced it?

    A results file that records neither its command nor its parameters cannot be
    reproduced by anyone, including its author. Measured while adding this:
    `drift.md` reports 2,000 actions against a module default of 10,000, so
    verifying it against the bare command compared two different experiments,
    and thirteen more results failed the same way for the same reason.

    Kept deliberately loose. The question is whether a reader is TOLD how to
    regenerate the numbers, not whether a harness can parse it: a shell script,
    a pytest invocation and a module with flags are all answers.
    """
    from benchmarks.verify_results import _COMMAND, _INLINE

    for block in _COMMAND.findall(text):
        for line in block.splitlines():
            line = line.split("#", 1)[0].strip()
            if line and not line.startswith(("export ", "pip ", "cd ")):
                return True
    return bool(_INLINE.search(text))


#: Words that report containment, and words that report what it cost. A file
#: carrying the first and none of the second is claiming a benefit with no
#: price, and `deny-all` takes that column outright.
_CONTAINMENT = re.compile(
    r"\b(contain(?:ed|ment|s)?|blocked|refus(?:ed|al)|asr|attack success)\b",
    re.IGNORECASE)
_COST = re.compile(
    # `costs` and `costly` are the words a writeup actually uses, and `\bcost\b`
    # matched neither: a section headed "What the extraction costs" read as
    # having no cost column at all. A linter that misses the plural of its own
    # keyword sends people to reword around it instead of answering it.
    r"\b(false[- ]?(?:block|alarm|positive)|benign|interrupt(?:ed|ion|s)?|"
    r"utility|completion|completed|friction|over[- ]?block|costs?|costly|"
    r"step[- ]?up|deny[- ]?all|precision|false positive)\b", re.IGNORECASE)


def reports_containment_without_cost(text: str) -> bool:
    """Does this file claim containment and never say what it cost?

    Deliberately generous about what counts as a cost column: naming
    `deny-all`, a benign rate, a completion rate or a step-up rate all count,
    because the rule is about whether the question was ASKED rather than about
    the shape of the answer. A file that never mentions any of them, while
    reporting containment, is the shape all three of the corrected results had.
    """
    return bool(_CONTAINMENT.search(text)) and not _COST.search(text)


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
    return {"file": name, "status": status, "has_command": declares_command(text),
            "bare_zero": bare, "forbidden": forbidden,
            "costless": reports_containment_without_cost(text)}


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--baseline", action="store_true",
                   help="rewrite the debt baseline from the current tree")
    p.add_argument("--strict", action="store_true",
                   help="enforce every file, not only STATUS: current ones")
    args = p.parse_args(argv)

    reports = [scan(f) for f in sorted(RESULTS.glob("*.md"))]
    total_bare = sum(len(r["bare_zero"]) for r in reports)
    # A file with neither a command nor a status is a number nobody can check and
    # nobody has vouched for. Ratcheted rather than gated, for the reason the
    # whole file is: 38 of them on the day this was written, and a check that
    # fails all 38 is a check somebody deletes.
    unverifiable = [r for r in reports if not r["has_command"] and not r["status"]]
    costless = [r for r in reports if r["costless"]]
    stamped = [r for r in reports if r["status"]]
    enforced = [r for r in reports
                if args.strict or r["status"] == "current"]

    if args.baseline:
        BASELINE.write_text(json.dumps({"bare_zero_total": total_bare,
                                        "unverifiable_total": len(unverifiable),
                                        "costless_total": len(costless),
                                        "files": len(reports)}, indent=2))
        print(f"baseline written: {total_bare} bare zeros, "
              f"{len(unverifiable)} unverifiable, {len(costless)} costless, "
              f"across {len(reports)} files")
        return 0

    prior = 0
    prior_unverifiable = len(unverifiable)
    prior_costless = len(costless)
    if BASELINE.exists():
        saved = json.loads(BASELINE.read_text())
        prior = saved.get("bare_zero_total", 0)
        prior_unverifiable = saved.get("unverifiable_total", len(unverifiable))
        prior_costless = saved.get("costless_total", len(costless))

    print(f"results files          {len(reports)}")
    print(f"stamped with STATUS    {len(stamped)}")
    print(f"enforced this run      {len(enforced)}")
    print(f"bare zeros (total)     {total_bare}   baseline {prior}")
    print(f"neither cmd nor status {len(unverifiable)}   baseline {prior_unverifiable}")
    print(f"containment, no cost   {len(costless)}   baseline {prior_costless}")

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

    if len(unverifiable) > prior_unverifiable:
        added = sorted(r["file"] for r in unverifiable)[-3:]
        failures.append(
            f"results with neither a command nor a STATUS rose from "
            f"{prior_unverifiable} to {len(unverifiable)}; that ratchet only "
            f"turns one way too. Add a ```bash block saying what produced the "
            f"file, WITH its parameters. Recently: {', '.join(added)}")

    if len(costless) > prior_costless:
        added = sorted(r["file"] for r in costless)[-3:]
        failures.append(
            f"results reporting containment with no cost column rose from "
            f"{prior_costless} to {len(costless)}. `deny-all` contains "
            f"everything, so a containment figure alone is not a measurement. "
            f"Report the benign rate from the SAME arm. Recently: "
            f"{', '.join(added)}")

    # A ratchet that never tightens is a ratchet with slack in it. Every count
    # that has fallen below its baseline is recorded at its new value, so paying
    # debt down cannot be undone by the next commit.
    tightened = {k: (was, now) for k, was, now in (
        ("bare_zero_total", prior, total_bare),
        ("unverifiable_total", prior_unverifiable, len(unverifiable)),
        ("costless_total", prior_costless, len(costless)),
    ) if now < was}
    if tightened and not failures:
        saved = json.loads(BASELINE.read_text()) if BASELINE.exists() else {}
        saved.update({k: now for k, (_was, now) in tightened.items()})
        saved["files"] = len(reports)
        BASELINE.write_text(json.dumps(saved, indent=2))
        for key, (was, now) in sorted(tightened.items()):
            print(f"baseline tightened: {key} {was} -> {now}")

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
