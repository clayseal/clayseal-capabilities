"""Audit evidence and ledger state must not be world-readable.

These files carry principal identity, resource paths, decision outcomes and
spend. Created through a plain ``open("a")`` they inherit the process umask,
which on a typical host yields 0o644, so every local user can read the entire
authorization trail of a security control.
"""
from __future__ import annotations

import stat
from pathlib import Path

import pytest

from clayseal.capabilities.decision_sinks import (
    PRIVATE_DIR_MODE,
    PRIVATE_FILE_MODE,
    JsonlFileSink,
    RotatingJsonlSink,
    make_private_parent,
    open_private_append,
)

RECORD = {"seq": 0, "principal": "alice@example.com", "outcome": "allow",
          "resource": "/finance/ap/inv-001.json"}


def _mode(path: Path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


def test_the_helper_creates_a_file_no_one_else_can_read(tmp_path):
    p = tmp_path / "x.jsonl"
    with open_private_append(p) as fh:
        fh.write("line\n")
    assert _mode(p) == PRIVATE_FILE_MODE
    assert not _mode(p) & (stat.S_IROTH | stat.S_IRGRP)


def test_a_directory_the_sink_creates_is_private(tmp_path):
    target = tmp_path / "made" / "here" / "audit.jsonl"
    make_private_parent(target)
    assert _mode(target.parent) == PRIVATE_DIR_MODE


def test_a_directory_that_already_existed_is_left_alone(tmp_path):
    """Only tighten what this call creates; an operator's own mode is theirs."""
    existing = tmp_path / "operator-owned"
    existing.mkdir(mode=0o755)
    before = _mode(existing)
    make_private_parent(existing / "audit.jsonl")
    assert _mode(existing) == before


@pytest.mark.parametrize("sink_cls", [JsonlFileSink, RotatingJsonlSink])
def test_the_decision_log_is_written_private(tmp_path, sink_cls):
    p = tmp_path / "nested" / "audit.jsonl"
    sink_cls(p)(RECORD)
    assert p.exists()
    assert not _mode(p) & stat.S_IROTH, "audit trail is world-readable"
    assert not _mode(p) & stat.S_IRGRP, "audit trail is group-readable"


def test_appending_to_a_file_that_exists_does_not_widen_it(tmp_path):
    p = tmp_path / "audit.jsonl"
    sink = JsonlFileSink(p)
    sink(RECORD)
    sink(RECORD)
    assert _mode(p) == PRIVATE_FILE_MODE


def test_neither_evidence_writer_still_uses_a_umask_default_open():
    """The two modules that persist evidence, checked at the source."""
    for name in ("decision_sinks", "principal_ledger"):
        src = Path("clayseal/capabilities") / f"{name}.py"
        if not src.exists():          # installed rather than in-tree
            pytest.skip("source tree not available")
        text = src.read_text()
        assert '.open("a"' not in text, f"{name} opens append at umask default"
        assert '.open("a", encoding' not in text


# --- Exposure ----------------------------------------------------------------

def test_a_non_loopback_bind_is_recognised_as_exposed():
    """The gateway authorizes the calls it is handed; it does not authenticate
    whoever hands them over. Binding off loopback puts that authority on the
    network, so the CLI has to be able to tell the difference."""
    from clayseal.capabilities.cli import _is_loopback

    for local in ("127.0.0.1", "127.0.0.53", "::1", "[::1]", "localhost"):
        assert _is_loopback(local), local
    for exposed in ("0.0.0.0", "::", "", "10.0.0.5", "192.168.1.4",
                    "example.com"):
        assert not _is_loopback(exposed), exposed
