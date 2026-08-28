"""Which published results still reproduce?

    python -m benchmarks.verify_results
    python -m benchmarks.verify_results --only structuring
    python -m benchmarks.verify_results --stamp

A results file is a claim about what the code does. `check_claims.py` asks
whether the claim is *rendered* honestly. This asks the prior question: does the
code still produce it.

Forty-two of the results files carried no `STATUS:` header, eighteen of them
cited from the README, the docs or the code. Stamping those by hand would be
guessing, and stamping one `current` is a commitment: `check_claims` enforces
strictly from that moment. So the stamp is earned here instead. A file that
regenerates to the same numbers gets `STATUS: current`; one that does not is
reported and left alone for a person to decide between "superseded" and "the
code regressed", which are very different and cannot be told apart by a diff.

WHAT THIS IS, AND IS NOT

Triage, not a gate. It is advisory on purpose and it is not wired into CI,
because its precision is not good enough to fail a build on:

- A table cell can hold a HISTORICAL figure. `commit_totality.md` reports
  `NEVER_RAISES | 0 *(was 46)*`, and 46 is correctly absent from a current run.
  This reports that as a missing figure.
- A benchmark can take parameters the file does not record, in which case the
  comparison is between two different experiments.

So a FAIL here means "worth a person looking", and only an `ok` is evidence. The
asymmetry is deliberate: the useful output is the queue and the two unambiguous
counts, how many results declare a runnable command at all and how many of those
still produce their own numbers.

WHAT IS COMPARED

Numbers, not prose. A results file is mostly commentary and the commentary is
allowed to be edited; the claim is the figures. Every number in the FILE must
still appear in the regenerated output. The direction is the whole design: the
reverse check fails whenever a benchmark prints a diagnostic the writeup did not
quote, which is most of them, and a verification that red-flags a file
reproducing byte for byte gets switched off within a week.
"""
from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

RESULTS = Path(__file__).resolve().parent / "results"

#: The command is read FROM the results file rather than kept in a table here.
#:
#: A hardcoded table is a second place to keep in step, and it was wrong on its
#: first run: `drift.md` reports 2,000 actions and the module defaults to 10,000,
#: so verifying it against a bare `python -m benchmarks.drift` compared two
#: different experiments and called the difference a regression. The file knows
#: what produced it, or it should, and a file that does not is not verifiable by
#: anyone. Making that visible is more useful than papering over it.
#:
#: A results file declares its command in a fenced bash block:
#:
#:     ```bash
#:     python -m benchmarks.drift --actions 2000
#:     ```
_COMMAND = re.compile(
    r"```(?:bash|sh|console)\n(.*?)```", re.DOTALL)
#: Only the unambiguous form: an interpreter, `-m`, and a dotted module.
#:
#: A looser pattern was tried and was wrong four times in one sitting. It read
#: `benchmarks/live/run_agentdyn.sh` as the module `benchmarks`, reported three
#: results as "declaring a command that does not exist", and the citations were
#: fine; the regex was matching a shell path. Extracting a command from prose is
#: fragile enough without also guessing at what counts as one, so anything that
#: is not exactly this shape is treated as "no command declared" rather than as
#: a command to try.
_PY_MODULE = re.compile(
    r"^(?:[\w./-]*python[\w.]*)\s+-m\s+(benchmarks(?:\.[\w]+)*)\s*(.*)$")

#: Modules that cannot run in a gate: they need a model, a key, a fetched corpus
#: or more than the timeout. Reported as unverifiable rather than as failures,
#: because "we cannot check this here" and "this no longer reproduces" are
#: different facts and merging them makes the check useless.
NOT_IN_GATE = (
    "benchmarks.live", "benchmarks.adaptive", "benchmarks.scoreboard",
    "benchmarks.leaderboard", "benchmarks.opeval", "benchmarks.aml_sequence",
    "benchmarks.mind2web", "benchmarks.agentharm", "benchmarks.agentleak",
    "benchmarks.commit_then_reveal", "benchmarks.fraud_validation",
    "benchmarks.cross_stack",
    "benchmarks.mandate_search", "benchmarks.density", "benchmarks.evade",
)


#: A command written inline in backticks rather than in a fenced block.
#: `flow.md` says "produced by `python -m benchmarks.flow`" and `frontier.md`
#: says "Reproduce with `python -m benchmarks.live.frontier --suite banking`".
#: Both are declarations; only the fencing differs, and a verifier that reads one
#: and not the other invents a distinction the authors never made.
_INLINE = re.compile(r"`([^`\n]*python[^`\n]*-m\s+benchmarks[^`\n]*)`")


def command_in(text: str) -> list[str] | None:
    """The argv a results file declares as having produced it, if it declares one."""
    blocks = list(_COMMAND.findall(text))
    blocks += [m + "\n" for m in _INLINE.findall(text)]
    for block in blocks:
        for line in block.splitlines():
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("export"):
                continue
            if line.endswith("\\"):        # a continued line; too fiddly to trust
                return None
            # Strip a trailing comment: results files annotate their commands
            # (`python -m benchmarks.bpl_sweep   # shipped classifier`) and
            # passing that to argparse produces "unrecognized arguments".
            line = line.split("#", 1)[0].strip()
            if not line:
                continue
            match = _PY_MODULE.match(line)
            if not match:
                continue
            module, rest = match.group(1), match.group(2)
            if any(module.startswith(skip) for skip in NOT_IN_GATE):
                return None
            args = [a for a in rest.split() if not a.startswith(("<", "$"))]
            return ["-m", module, *args]
    return None

#: Figures that legitimately move between runs and are not the claim.
_IGNORE = re.compile(r"\b(?:seed|elapsed|took|ms)\s*[=:]\s*[\d.]+", re.IGNORECASE)
#: ISO dates in prose. `2026-08-09` is three numbers to a naive scanner, and a
#: results file that records when it was produced should not fail verification
#: for having done so.
_DATE = re.compile(r"\b\d{4}-\d{2}-\d{2}\b")
#: Thousands separators. `20,000` is one figure and a naive scanner reads two,
#: which reported `aggregation_residual` as nineteen missing numbers when the
#: only difference was a comma.
_THOUSANDS = re.compile(r"(?<=\d),(?=\d{3}\b)")
_NUMBER = re.compile(r"-?\d+(?:\.\d+)?")


def numbers(text: str, *, tables_only: bool = False) -> list[str]:
    """Every figure in `text`, in order, minus dates and timings.

    `tables_only` restricts to markdown table rows, which is where a results
    file's CLAIM lives. The prose around it is commentary: it rounds, it
    aggregates, it says "roughly a third", and holding it to the same standard
    as a measured cell produces a verifier that fails on rewording. Scanning a
    whole document flagged `flow.md` on 623 figures, of which the first three
    were the digits of the date it recorded itself as being produced on.
    """
    if tables_only:
        text = "\n".join(line for line in text.splitlines()
                          if line.lstrip().startswith("|"))
    text = _THOUSANDS.sub("", _DATE.sub("", text))
    return _NUMBER.findall(_IGNORE.sub("", text))


def verify(stem: str, argv: list[str], *, timeout: int = 600) -> dict:
    path = RESULTS / f"{stem}.md"
    if not path.exists():
        return {"stem": stem, "ok": False, "why": "no results file"}
    try:
        run = subprocess.run([sys.executable, *argv], capture_output=True,
                             text=True, timeout=timeout, check=False)
    except subprocess.TimeoutExpired:
        return {"stem": stem, "ok": False, "why": f"timed out after {timeout}s"}
    if run.returncode != 0:
        tail = (run.stderr.strip().splitlines() or [""])[-1][:80]
        if "No module named" in run.stderr:
            # The file names a module that does not exist. That is a broken
            # citation rather than a failed reproduction, and it is worse: the
            # command was never runnable, so the number was never checkable.
            return {"stem": stem, "ok": False, "broken_command": True,
                    "why": f"declares a command that does not exist: {tail}"}
        return {"stem": stem, "ok": False, "why": f"exited {run.returncode}: {tail}"}

    text = path.read_text()
    published = numbers(text, tables_only=True)
    if not published:
        # Not every results file uses markdown tables; several print a
        # fixed-width table the benchmark emitted verbatim. Falling back to the
        # whole document is right for those and slightly noisier, which is the
        # correct trade for a check that is advisory anyway.
        published = numbers(text)
    produced = set(numbers(run.stdout))
    missing = [n for n in published if n not in produced]
    # DIRECTION MATTERS, and the first version of this had it backwards. The
    # question is whether the PUBLISHED claim is still produced, so every figure
    # in the file must appear in the run. Checking the reverse fails whenever the
    # benchmark prints a diagnostic the writeup did not quote, which is most of
    # them, and it marked a file that reproduces byte for byte as broken.
    return {
        "stem": stem,
        "ok": not missing,
        "why": "" if not missing else
               f"{len(missing)} of {len(published)} published figures are no "
               f"longer produced, first: {missing[:6]}",
        "published": len(published),
    }


def stamp(stem: str) -> bool:
    """Add `STATUS: current` under the title. Returns True if it wrote."""
    path = RESULTS / f"{stem}.md"
    text = path.read_text()
    if re.search(r"^\s*STATUS:", text[:600], re.MULTILINE):
        return False
    lines = text.splitlines()
    at = 1 if lines and lines[0].startswith("#") else 0
    lines.insert(at, "")
    lines.insert(at + 1, "STATUS: current")
    path.write_text("\n".join(lines) + "\n")
    return True


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--only", default=None, help="verify one result stem")
    parser.add_argument("--stamp", action="store_true",
                        help="write `STATUS: current` on the ones that reproduce")
    parser.add_argument("--timeout", type=int, default=600)
    args = parser.parse_args(argv)

    todo: dict[str, list[str]] = {}
    undeclared: list[str] = []
    for path in sorted(RESULTS.glob("*.md")):
        if args.only is not None and path.stem != args.only:
            continue
        argv_ = command_in(path.read_text())
        if argv_ is None:
            undeclared.append(path.stem)
        else:
            todo[path.stem] = argv_
    if not todo and args.only:
        print(f"{args.only!r} declares no runnable command", file=sys.stderr)
        return 2

    rows = [verify(stem, argv_, timeout=args.timeout) for stem, argv_ in todo.items()]
    good = [r for r in rows if r["ok"]]

    print(f"{len(rows)} results with a registered reproducer, "
          f"{len(good)} still reproduce\n")
    for row in rows:
        mark = "ok  " if row["ok"] else "FAIL"
        print(f"  {mark} {row['stem']:16} {row.get('why', '')}")

    if args.stamp:
        print()
        for row in good:
            if stamp(row["stem"]):
                print(f"  stamped {row['stem']}.md STATUS: current")

    unstamped = [
        n for n in undeclared
        if not re.search(r"^\s*STATUS:", (RESULTS / f"{n}.md").read_text()[:600], re.MULTILINE)
    ]
    print(f"\n{len(undeclared)} results declare no command this gate can run, "
          f"{len(unstamped)} of which are also unstamped.")
    print("A file with neither a command nor a status is a number nobody can")
    print("check and nobody has vouched for. That is the queue to work through:")
    for name in sorted(unstamped):
        print(f"  {name}")
    return 0 if len(good) == len(rows) else 1


if __name__ == "__main__":
    raise SystemExit(main())
