"""Every file the documentation tells you to run has to be in the repository.

`examples/02_the_proxy.py`, `examples/refund.yaml` and
`examples/refund_server.py` were present on the author's disk and never added to
git, so the first command the README gives a new reader did not exist in a fresh
clone.
"""
from __future__ import annotations

import re
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
DOCS = ["README.md", "CONTRIBUTING.md", "docs/DEV_GUIDE.md", "docs/README.md"]
#: Paths named inside a command line in the documentation.
REFERENCED = re.compile(r"\b((?:examples|scripts|benchmarks|demo)/[\w./-]+\.\w+)")


def _tracked() -> set[str]:
    out = subprocess.run(["git", "ls-files"], cwd=ROOT,
                         capture_output=True, text=True)
    if out.returncode != 0:
        pytest.skip("not a git checkout")
    return set(out.stdout.split())


@pytest.mark.parametrize("doc", DOCS)
def test_every_path_the_docs_name_is_committed(doc):
    path = ROOT / doc
    if not path.exists():
        pytest.skip(f"{doc} not present")
    tracked = _tracked()
    missing = sorted({
        m.group(1) for m in REFERENCED.finditer(path.read_text())
        if m.group(1) not in tracked
    })
    assert not missing, (
        f"{doc} tells the reader to use files that are not in the repository: "
        f"{missing}")
