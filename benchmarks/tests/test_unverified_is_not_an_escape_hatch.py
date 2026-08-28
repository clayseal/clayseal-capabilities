"""`unverified` labels debt. It must not be able to hide it.

The STATUS vocabulary was `current | superseded | retracted`, and none of those
can say the true thing about a file whose numbers were measured once with no
command recorded. Stamping `current` would be vouching for a run nobody can
reproduce, so 22 files carried no status at all and sat in a bucket called
"neither cmd nor status".

`unverified` says the honest thing. The risk it introduces is obvious: a label
that empties a debt counter without anyone checking anything is worse than the
debt, because the debt at least stayed visible.

So three properties, all asserted here:

  1. an `unverified` file is counted, on its own line, so labelling moves it
     between two visible buckets rather than out of sight;
  2. an `unverified` file is never STRICTLY enforced, because nobody vouched
     for it;
  3. the other rules still apply to it, so stamping a file does not exempt its
     contents from the bare-zero or costless checks.
"""
from __future__ import annotations

import pathlib
import tempfile

from benchmarks.check_claims import RESULTS, scan, status_of


def _write(text: str) -> pathlib.Path:
    path = pathlib.Path(tempfile.mkstemp(suffix=".md")[1])
    path.write_text(text)
    return path


def test_unverified_is_a_recognised_status():
    assert status_of("# t\n\nSTATUS: unverified\n") == "unverified"
    assert status_of("# t\n\nSTATUS: current\n") == "current"
    assert status_of("# t\n\nno status here\n") is None


def test_unverified_does_not_exempt_a_file_from_the_other_rules():
    """The property that stops the label being a laundering route."""
    path = _write("# t\n\nSTATUS: unverified\n\n"
                  "The detector reached 0.0% false blocks.\n")
    try:
        assert scan(path)["bare_zero"], (
            "stamping a file unverified silenced the bare-zero rule")
    finally:
        path.unlink()


def test_unverified_is_not_enforced_as_current():
    """`current` is the opt-in to strict enforcement. `unverified` is the
    opposite claim and must not be treated as one."""
    path = _write("# t\n\nSTATUS: unverified\n")
    try:
        assert scan(path)["status"] == "unverified"
        assert scan(path)["status"] != "current"
    finally:
        path.unlink()


def test_the_repository_reports_the_unverified_count_separately():
    """If this set ever stops being counted, the debt is invisible again."""
    stamped = [r for r in (scan(f) for f in sorted(RESULTS.glob("*.md")))
               if r["status"] == "unverified"]
    assert stamped, "no file is stamped unverified; has the label been dropped?"
    # The whole point: these are NOT claiming to be current.
    assert all(r["status"] != "current" for r in stamped)


def test_every_unverified_file_says_why_in_prose():
    """A machine-readable stamp a human never sees is half a fix. Each file has
    to tell a reader, in the file, that its numbers were not re-derived."""
    missing = []
    for path in sorted(RESULTS.glob("*.md")):
        text = path.read_text(errors="ignore")
        if status_of(text) != "unverified":
            continue
        head = text[:900].lower()
        if "re-derive" not in head and "reproduce" not in head:
            missing.append(path.name)
    assert not missing, (
        f"stamped unverified with no explanation for a reader: {missing}")


def test_the_scanner_still_distinguishes_the_states():
    """The control. Every assertion above passes if `status_of` returned the
    same thing for everything."""
    assert status_of("# t\n\nSTATUS: superseded\n") == "superseded"
    assert status_of("# t\n\nSTATUS: retracted\n") == "retracted"
    assert len({status_of(f"# t\n\nSTATUS: {v}\n")
                for v in ("current", "superseded", "retracted", "unverified")}) == 4
