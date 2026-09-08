#!/usr/bin/env python3
"""Draw the seal in `clayseal.capabilities.onboarding.SEAL`.

Hand-drawn ASCII faces come out looking like potatoes because punctuation has
no resolution: `.-''-.` is the same six marks whatever curve you meant. A
braille cell carries a 2x4 grid of dots, and those dots are square at the usual
2:1 terminal cell aspect, so the character grid becomes a bitmap you can draw a
real ellipse on.

So the seal is rasterised rather than typed. Everything below is geometry: the
head is a sampled ellipse widened across the whisker pads, the eyes and nose are
filled shapes, the smile and whiskers are stroked polylines. To move an eye,
move a number.

    python scripts/render_seal.py            # print it
    python scripts/render_seal.py --check    # assert the module still matches
"""
from __future__ import annotations

import argparse
import itertools
import math
import sys
from pathlib import Path

BLANK = "⠀"


class Canvas:
    """A dot grid that renders to braille, 2 dots wide by 4 tall per cell."""

    def __init__(self, w: int, h: int) -> None:
        self.w, self.h = w, h
        self.g = [[0] * w for _ in range(h)]

    def _paint(self, hit) -> None:
        for y in range(self.h):
            for x in range(self.w):
                if hit(x + 0.5, y + 0.5):
                    self.g[y][x] = 1

    def stroke(self, pts, t: float = 1.2) -> None:
        """Every dot within `t` of the polyline. Dense `pts` give a curve."""
        segs = list(itertools.pairwise(pts))

        def hit(px: float, py: float) -> bool:
            for (x1, y1), (x2, y2) in segs:
                dx, dy = x2 - x1, y2 - y1
                span = dx * dx + dy * dy or 1e-9
                s = max(0.0, min(1.0, ((px - x1) * dx + (py - y1) * dy) / span))
                if math.hypot(px - (x1 + s * dx), py - (y1 + s * dy)) <= t:
                    return True
            return False

        self._paint(hit)

    def disc(self, cx: float, cy: float, a: float, b: float | None = None) -> None:
        b = a if b is None else b
        self._paint(lambda x, y: math.hypot((x - cx) / a, (y - cy) / b) <= 1)

    def poly(self, pts) -> None:
        def hit(px: float, py: float) -> bool:
            inside = False
            for i in range(len(pts)):
                x1, y1 = pts[i]
                x2, y2 = pts[(i + 1) % len(pts)]
                if (y1 > py) != (y2 > py) and px < x1 + (py - y1) * (x2 - x1) / (y2 - y1):
                    inside = not inside
            return inside

        self._paint(hit)

    def render(self) -> str:
        rows = []
        for r in range(0, self.h, 4):
            line = ""
            for c in range(0, self.w, 2):
                bits = 0
                for dx, dy, bit in ((0, 0, 1), (0, 1, 2), (0, 2, 4), (1, 0, 8),
                                    (1, 1, 16), (1, 2, 32), (0, 3, 64), (1, 3, 128)):
                    if r + dy < self.h and c + dx < self.w and self.g[r + dy][c + dx]:
                        bits |= bit
                line += chr(0x2800 + bits)
            rows.append(line.rstrip(BLANK))
        while rows and not rows[0]:
            rows.pop(0)
        while rows and not rows[-1]:
            rows.pop()
        return "\n".join(rows)


def ring(cx, cy, rx, ry, a0=0.0, a1=2 * math.pi, n=400, warp=None):
    """An ellipse arc as points. `warp(angle)` scales the radii as it goes."""
    pts = []
    for i in range(n + 1):
        a = a0 + (a1 - a0) * i / n
        sx, sy = warp(a) if warp else (1.0, 1.0)
        pts.append((cx + rx * sx * math.cos(a), cy + ry * sy * math.sin(a)))
    return pts


def draw() -> str:
    c = Canvas(84, 60)
    cx, cy = 42, 25
    rx, ry = 18.5, 20.5

    # Head. The radius grows toward the chin, which is where a seal's whisker
    # pads flare; a plain circle reads as a ball rather than a face.
    outline = ring(cx, cy, rx, ry,
                   warp=lambda a: (1.0 + 0.07 * max(0.0, math.sin(a)), 1.0))
    c.stroke(outline, 1.1)

    for ex in (cx - 8.5, cx + 8.5):
        c.disc(ex, cy - 2.5, 3.4, 3.8)

    nose = cy + 6.5
    c.poly([(cx - 3.2, nose), (cx + 3.2, nose), (cx + 1.7, nose + 3.0),
            (cx, nose + 3.8), (cx - 1.7, nose + 3.0)])
    c.disc(cx, nose + 0.3, 3.2, 1.8)

    smile = nose + 4.4
    c.stroke(ring(cx - 5.0, smile, 6.4, 2.6, -0.4, 1.5), 0.85)
    c.stroke(ring(cx + 5.0, smile, 6.4, 2.6, math.pi - 1.5, math.pi + 0.4), 0.85)

    def edge_at(y: float, sign: int) -> float:
        """Where the outline sits at this height, so whiskers start on the face."""
        best = cx + sign * rx
        for x, yy in outline:
            if abs(yy - y) < 1.2 and (x - cx) * sign > (best - cx) * sign:
                best = x
        return best

    for dy, length, drop in ((4.5, 11, 2.0), (8.0, 10, 3.5)):
        y0 = cy + dy
        for sign in (-1, 1):
            x0 = edge_at(y0, sign) + sign * 3.0
            c.stroke([(x0, y0),
                      (x0 + sign * length * 0.6, y0 + drop * 0.35),
                      (x0 + sign * length, y0 + drop)], 0.75)

    art = c.render().splitlines()
    pad = min(len(ln) - len(ln.lstrip(BLANK)) for ln in art if ln.strip(BLANK))
    return "\n".join("    " + ln[pad:].rstrip() for ln in art)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--check", action="store_true",
                    help="exit non-zero if onboarding.SEAL has drifted from this")
    args = ap.parse_args()

    art = draw()
    if not args.check:
        print(art)
        return 0

    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from clayseal.capabilities.onboarding import SEAL

    if SEAL.strip("\n") != art:
        print("onboarding.SEAL does not match this script's output.", file=sys.stderr)
        print("Paste this in, keeping the surrounding triple quotes:\n", file=sys.stderr)
        print(art, file=sys.stderr)
        return 1
    print("onboarding.SEAL matches.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
