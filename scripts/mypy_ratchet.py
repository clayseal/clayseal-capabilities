#!/usr/bin/env python3
"""Type findings may shrink. They may not grow.

    python scripts/mypy_ratchet.py            # check against the baseline
    python scripts/mypy_ratchet.py --update   # record a NEW, LOWER baseline

There are 94 mypy findings in `clayseal/` and none has been triaged. The two
obvious responses are both wrong. Turning the gate on as a hard failure blocks
every change until someone spends a week on a backlog nobody has read. Leaving it
off means the 93% of functions that carry annotations are decoration, and the
number drifts: `pyproject.toml` carried a hand-written "92 findings across 32
files" that had silently become 98 across 35.

So: a ratchet, the same mechanism `benchmarks/check_claims.py` uses for
measurement debt. The count is recorded, CI fails if it goes up, and `--update`
is how it comes down. A change that adds a finding has to either fix it or make
the case for raising the baseline in a commit message somebody reviews.

Per-file counts are recorded as well as the total, so a change that fixes two
findings in one file and adds two in another does not net to zero and pass.
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BASELINE = ROOT / "scripts" / "mypy_baseline.json"

_ERROR = re.compile(r"^(?P<file>[^:]+):\d+: error: .*\[(?P<code>[a-z-]+)\]\s*$")


def run_mypy() -> tuple[Counter, Counter]:
    """(findings per file, findings per error code)."""
    proc = subprocess.run(
        [sys.executable, "-m", "mypy", "--no-error-summary", "--no-color-output"],
        cwd=ROOT, capture_output=True, text=True, check=False)
    if proc.returncode not in (0, 1):
        print(proc.stdout[-2000:], file=sys.stderr)
        print(proc.stderr[-2000:], file=sys.stderr)
        raise SystemExit(f"mypy could not run (exit {proc.returncode})")

    per_file: Counter = Counter()
    per_code: Counter = Counter()
    for line in proc.stdout.splitlines():
        match = _ERROR.match(line.strip())
        if match:
            per_file[match.group("file")] += 1
            per_code[match.group("code")] += 1
    return per_file, per_code


def load_baseline() -> dict:
    if not BASELINE.exists():
        return {"total": None, "per_file": {}}
    return json.loads(BASELINE.read_text())


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--update", action="store_true",
                    help="record the current counts as the new baseline")
    args = ap.parse_args(argv)

    per_file, per_code = run_mypy()
    total = sum(per_file.values())
    baseline = load_baseline()
    prior = baseline["total"]

    print(f"mypy findings   {total}" + (f"   baseline {prior}" if prior is not None else ""))
    print(f"files affected  {len(per_file)}")
    print("by code         " + ", ".join(
        f"{code} {n}" for code, n in per_code.most_common(6)))

    if args.update:
        if prior is not None and total > prior:
            print(f"\nrefusing to raise the baseline from {prior} to {total}.",
                  file=sys.stderr)
            print("--update lowers a ratchet; it does not absorb a regression.",
                  file=sys.stderr)
            return 1
        BASELINE.write_text(json.dumps(
            {"total": total, "per_file": dict(sorted(per_file.items()))}, indent=2) + "\n")
        print(f"\nbaseline recorded at {total}"
              + (f" (was {prior})" if prior is not None else ""))
        return 0

    if prior is None:
        print("\nno baseline recorded yet; run with --update")
        return 0

    failures = []
    if total > prior:
        failures.append(f"total findings rose from {prior} to {total}")
    # Per-file, so two fixed here and two added there does not net to zero.
    was = baseline["per_file"]
    for path, count in sorted(per_file.items()):
        if count > was.get(path, 0):
            failures.append(f"{path}: {was.get(path, 0)} -> {count}")

    for line in failures:
        print(f"FAIL: {line}", file=sys.stderr)
    if failures:
        print("\nFix the finding, or lower another and rerun with --update.",
              file=sys.stderr)
        return 1

    if total < prior:
        print(f"\n{prior - total} fewer than the baseline. Run with --update to "
              "lock the improvement in.")
    print("\nok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
