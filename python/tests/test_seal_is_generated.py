"""The logo is drawn by a script, and the script has to still draw it.

`scripts/render_seal.py` rasterises the seal from geometry. That is only worth
anything while the committed art and the script agree: the moment someone edits
the braille in `onboarding.py` by hand, the script becomes a decorative comment
and the next person to move an eye gets a different seal.
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def test_the_committed_seal_is_what_the_script_draws() -> None:
    result = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "render_seal.py"), "--check"],
        cwd=ROOT, capture_output=True, text=True, timeout=120, check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr


def test_the_seal_is_braille_and_keeps_its_own_blanks() -> None:
    """The gaps inside the art must not be spaces.

    A space is whitespace, so anything that strips or collapses it (a markdown
    renderer, a log formatter, a terminal that trims trailing blanks) eats the
    shape. U+2800 is a printing character that happens to be empty.
    """
    from clayseal.capabilities.onboarding import SEAL

    body = [ln for ln in SEAL.splitlines() if ln.strip()]
    assert body, "the seal is empty"
    for line in body:
        inner = line.strip()
        assert all(0x2800 <= ord(c) <= 0x28FF for c in inner), (
            f"non-braille character in the art: {inner!r}")
