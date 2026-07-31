"""Input hardening: neutralize the delivery tricks of indirect prompt injection.

Hidden-Unicode instructions, homoglyph tool names, zero-width joiners, and
bidirectional-override characters are how untrusted content smuggles
instructions past a human reviewer and a naive allowlist. This module does not
try to judge intent; it detects and strips the *mechanisms*, and reports which
were present so the finding can be fed to the trajectory monitor's taint tracker
(content that needed hardening is content that should not silently justify a
consequential action).

Two entry points: ``scan`` returns the markers found (for taint / audit), and
``sanitize`` returns text with the dangerous characters removed or folded, so
downstream tool-name and argument matching sees the real string.
"""
from __future__ import annotations

import unicodedata
from dataclasses import dataclass

# Zero-width and joiner characters used to hide or splice text.
_ZERO_WIDTH = {"​", "‌", "‍", "⁠", "﻿"}
# Bidirectional overrides used to visually reorder text (Trojan Source).
_BIDI = {"‪", "‫", "‬", "‭", "‮",
         "⁦", "⁧", "⁨", "⁩"}
# Tag-block characters (U+E0000..U+E007F) can encode hidden ASCII instructions.
def _is_tag_char(ch: str) -> bool:
    return 0xE0000 <= ord(ch) <= 0xE007F


# Cross-script confusables (Cyrillic / Greek look-alikes) folded to Latin.
# NFKC does not map these (they are distinct scripts), so a table is required.
_CONFUSABLES = {
    # Cyrillic -> Latin
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x",
    "ѕ": "s", "і": "i", "ј": "j", "к": "k", "м": "m", "н": "h", "т": "t",
    "в": "b", "г": "r", "д": "d", "з": "3", "л": "n", "п": "n",
    "А": "A", "Е": "E", "О": "O", "Р": "P", "С": "C", "У": "Y", "Х": "X",
    "В": "B", "К": "K", "М": "M", "Н": "H", "Т": "T",
    # Greek -> Latin
    "ο": "o", "α": "a", "ν": "v", "μ": "u", "ρ": "p", "τ": "t", "ι": "i",
    "Α": "A", "Β": "B", "Ε": "E", "Ζ": "Z", "Η": "H", "Ι": "I", "Κ": "K",
    "Μ": "M", "Ν": "N", "Ο": "O", "Ρ": "P", "Τ": "T", "Υ": "Y", "Χ": "X",
}


@dataclass(frozen=True)
class HardeningReport:
    markers: tuple[str, ...]
    sanitized: str

    @property
    def suspicious(self) -> bool:
        return bool(self.markers)


def scan(text: str) -> list[str]:
    """Return the injection-delivery markers present in ``text``."""
    markers: set[str] = set()
    for ch in text:
        if ch in _ZERO_WIDTH:
            markers.add("zero-width")
        elif ch in _BIDI:
            markers.add("bidi-override")
        elif _is_tag_char(ch):
            markers.add("unicode-tag")
        elif ch.isascii():
            continue
        elif ch in _CONFUSABLES:
            markers.add("homoglyph")
        else:
            # Fullwidth / compatibility letters fold to a Latin skeleton via NFKC.
            skeleton = unicodedata.normalize("NFKC", ch)
            if skeleton != ch and skeleton.isascii() and skeleton.isalnum():
                markers.add("homoglyph")
            elif unicodedata.category(ch) in {"Cf", "Co", "Cn"}:
                markers.add("hidden-format-char")
    return sorted(markers)


def sanitize(text: str) -> str:
    """Strip zero-width / bidi / tag chars and fold homoglyphs to their skeleton."""
    out: list[str] = []
    for ch in text:
        if ch in _ZERO_WIDTH or ch in _BIDI or _is_tag_char(ch):
            continue
        if ch in _CONFUSABLES:
            out.append(_CONFUSABLES[ch])
        elif not ch.isascii():
            folded = unicodedata.normalize("NFKC", ch)
            out.append(folded if folded.isascii() else ch)
        else:
            out.append(ch)
    return "".join(out)


def harden(text: str) -> HardeningReport:
    return HardeningReport(markers=tuple(scan(text)), sanitized=sanitize(text))
