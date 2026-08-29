"""Every Python block the README shows must run where the reader is.

The quickstart said `Guardrail.from_policy_file("examples/refund.yaml")`
directly under `pip install clayseal`. That path exists in a checkout and
nowhere else, so the second thing on the page raised `PolicyError` for exactly
the audience the first thing created. Nothing caught it, because every test ran
from the repository root where the file happens to exist.

So these run the blocks in a temporary directory, which is the only place that
can tell the difference.
"""
from __future__ import annotations

import re
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
README = ROOT / "README.md"


def _python_blocks(text: str) -> list[str]:
    return re.findall(r"```python\n(.*?)```", text, re.DOTALL)


@pytest.fixture(scope="module")
def quickstart() -> str:
    """The block under 'Use it in two lines', which is the one people paste."""
    section = re.search(r"## Use it in two lines(.*?)\n## ", README.read_text(), re.DOTALL)
    assert section, "the README no longer has a quickstart section"
    blocks = _python_blocks(section.group(1))
    assert blocks, "the quickstart section no longer contains a python block"
    return blocks[0]


def test_the_quickstart_runs_outside_the_checkout(quickstart) -> None:
    with tempfile.TemporaryDirectory() as work:
        script = Path(work) / "quickstart.py"
        script.write_text(quickstart)
        result = subprocess.run(
            [sys.executable, str(script)], cwd=work,
            capture_output=True, text=True, timeout=120, check=False,
        )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "refunded INV-001" in result.stdout
    assert "refused" in result.stdout


def test_the_quickstart_reads_no_file_from_the_repository(quickstart) -> None:
    """A path into the checkout is the specific bug this file exists for.

    Asserted on the source and not only on the run, so the reason a future
    regression fails is legible instead of being an exit code.
    """
    assert "examples/" not in quickstart, (
        "the quickstart points at a file that only exists in a checkout")


def test_every_other_python_block_at_least_parses() -> None:
    """Weaker on purpose.

    Later blocks are fragments by design: they show one call against a gateway
    the surrounding prose has already built. Running them would need a harness
    that invents the context, and a test that invents context stops testing the
    document. Parsing catches the thing that actually rots, which is a block
    edited into something that is no longer Python.
    """
    blocks = _python_blocks(README.read_text())
    assert len(blocks) >= 3, "the README lost its code samples"
    for i, block in enumerate(blocks):
        try:
            compile(block, f"<readme block {i}>", "exec")
        except SyntaxError as exc:
            pytest.fail(f"README python block {i} does not parse: {exc}\n{block}")
