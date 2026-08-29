"""Render a real `clayseal try` run to the SVG the README shows.

    python scripts/render_try_svg.py

The picture has to be the program's actual output, so this runs the command
under a pseudo-terminal to get the colours a real session would print, parses
the escape sequences it emits, and lays the result out as text in an SVG. It
does not accept a transcript and it cannot be hand-edited into saying something
the program does not say.

SVG and not a GIF or an asciinema embed for three reasons. GitHub renders it
inline in the README with no third-party host, the text stays selectable and
searchable, and it is a diffable artefact in the repository, so a change to the
demo shows up as a change to the picture in the same commit.
"""
from __future__ import annotations

import os
import pty
import re
import subprocess
import sys
from pathlib import Path
from xml.sax.saxutils import escape

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "docs" / "assets" / "clayseal-try.svg"

# The palette the terminal would resolve the 256-colour codes to, picked to stay
# legible on the dark window below in both GitHub themes.
XTERM = {
    "173": "#d29a72",   # clay, the brand colour
    "71": "#7cb87c",    # allowed
    "167": "#e07a6a",   # refused
    "179": "#e0b063",   # held
}
FG = "#d8d4cf"
DIM = "#8d8880"
BG = "#1b1a19"
CHROME = "#2a2827"

# Only used to size the canvas, since the text itself flows naturally. Set
# ABOVE the real advance on purpose: too small clips the last column of the
# widest line, and too large is a right margin nobody notices.
CELL_W = 8.5
LINE_H = 20.0
PAD_X = 22.0
PAD_TOP = 52.0         # room for the window chrome
PAD_BOTTOM = 20.0

_ANSI = re.compile(r"\033\[([0-9;]*)m")


def capture() -> str:
    """The command's real output, colours and all.

    A pty pair and not `pty.spawn`: that helper reads the child through a
    callback whose return value it writes onward, and returning an empty
    bytestring from it means EOF, so it stops after the first read. The capture
    came back 304 bytes long and looked like a short demo.
    """
    parent, child = pty.openpty()
    proc = subprocess.Popen(
        [sys.executable, "-m", "clayseal.capabilities.cli", "try", "--fast"],
        stdout=child, stderr=child, stdin=subprocess.DEVNULL, close_fds=True,
    )
    os.close(child)
    chunks: list[bytes] = []
    try:
        while True:
            try:
                data = os.read(parent, 65536)
            except OSError:      # the child closed its end
                break
            if not data:
                break
            chunks.append(data)
    finally:
        os.close(parent)
    if proc.wait() != 0:
        raise SystemExit("clayseal try failed, so there is nothing honest to draw")
    return b"".join(chunks).decode("utf-8", "replace").replace("\r\n", "\n")


def spans(line: str, state: dict):
    """(text, fill, bold) runs for one line, from the escape codes in it.

    `state` carries the active colour ACROSS lines, because a terminal does.
    Parsing each line from a clean slate dropped the colour from every
    continuation line of a multi-line coloured block: the injected ticket in
    act two is one `paint()` call over two lines, and the second line came out
    plain white in the picture while the terminal showed both in amber.
    """
    fill, bold = state["fill"], state["bold"]
    out, pos = [], 0
    for match in _ANSI.finditer(line):
        if match.start() > pos:
            out.append((line[pos:match.start()], fill, bold))
        codes = [c for c in match.group(1).split(";") if c]
        if not codes or codes == ["0"]:
            fill, bold = FG, False
        elif codes[0] == "1":
            bold = True
        elif codes[0] == "2":
            fill = DIM
        elif codes[:2] == ["38", "5"]:
            fill = XTERM.get(codes[2], FG)
        pos = match.end()
    if pos < len(line):
        out.append((line[pos:], fill, bold))
    state["fill"], state["bold"] = fill, bold
    return out


def render(text: str) -> str:
    lines = text.split("\n")
    while lines and not lines[-1].strip():
        lines.pop()
    width = max((len(_ANSI.sub("", ln)) for ln in lines), default=80)
    w = PAD_X * 2 + width * CELL_W
    h = PAD_TOP + len(lines) * LINE_H + PAD_BOTTOM

    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{w:.0f}" height="{h:.0f}" '
        f'viewBox="0 0 {w:.0f} {h:.0f}" font-family="ui-monospace, SFMono-Regular, '
        f'Menlo, Consolas, monospace" font-size="13.4">',
        f'<rect width="{w:.0f}" height="{h:.0f}" rx="10" fill="{BG}"/>',
        f'<rect width="{w:.0f}" height="34" rx="10" fill="{CHROME}"/>',
        f'<rect y="24" width="{w:.0f}" height="10" fill="{CHROME}"/>',
        '<circle cx="21" cy="17" r="5.5" fill="#e07a6a"/>',
        '<circle cx="39" cy="17" r="5.5" fill="#e0b063"/>',
        '<circle cx="57" cy="17" r="5.5" fill="#7cb87c"/>',
        f'<text x="{w / 2:.0f}" y="21.5" fill="{DIM}" font-size="11.5" '
        f'text-anchor="middle">clayseal try</text>',
    ]
    state = {"fill": FG, "bold": False}
    for row, line in enumerate(lines):
        runs = [r for r in spans(line, state) if r[0]]
        if not runs:
            continue
        y = PAD_TOP + row * LINE_H
        # ONE text element per line, with a tspan per colour run, so the font's
        # own advance places every character. Positioning each run at
        # `column * CELL_W` instead made the layout depend on guessing the
        # advance width of whatever monospace font the viewer resolves, and the
        # guess drifted: a bold run mid-line landed on top of the space before
        # it and printed "through.The next".
        body = "".join(
            f'<tspan fill="{fill}"'
            + (' font-weight="600"' if bold else "")
            + f">{escape(text_run)}</tspan>"
            for text_run, fill, bold in runs)
        parts.append(
            f'<text x="{PAD_X:.0f}" y="{y:.1f}" xml:space="preserve">{body}</text>')
    parts.append("</svg>")
    return "\n".join(parts)


def main() -> int:
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(render(capture()))
    print(f"wrote {OUT.relative_to(ROOT)} ({OUT.stat().st_size // 1024} KB)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
