"""Character-class tables used by the detector and the scrubber.

Categories follow the technique families documented in the reference corpus
(see README): Unicode *tag* characters ("ASCII smuggling"), zero-width and
other invisible characters, bidirectional override characters, C0/C1 control
characters, and mixed-script confusables (homoglyphs).

Every entry is a Python ``str`` constant or a predicate — no dependencies.
"""

from __future__ import annotations

import unicodedata
from typing import Iterable

# --- invisible / zero-width ------------------------------------------------
ZERO_WIDTH: dict[int, str] = {
    0x00AD: "SOFT HYPHEN",
    0x034F: "COMBINING GRAPHEME JOINER",
    0x061C: "ARABIC LETTER MARK",
    0x180E: "MONGOLIAN VOWEL SEPARATOR",
    0x200B: "ZERO WIDTH SPACE",
    0x200C: "ZERO WIDTH NON-JOINER",
    0x200D: "ZERO WIDTH JOINER",
    0x200E: "LEFT-TO-RIGHT MARK",
    0x200F: "RIGHT-TO-LEFT MARK",
    0x2060: "WORD JOINER",
    0x2061: "FUNCTION APPLICATION",
    0x2062: "INVISIBLE TIMES",
    0x2063: "INVISIBLE SEPARATOR",
    0x2064: "INVISIBLE PLUS",
    0xFEFF: "ZERO WIDTH NO-BREAK SPACE (BOM)",
}

# --- emoji variation selectors -------------------------------------------
VARIATION_SELECTORS = range(0xFE00, 0xFE10)  # VS1–VS16
VARIATION_SELECTOR_SUPPLEMENT = range(0xE0100, 0xE01F0)

# --- Unicode tag characters (U+E0000..U+E007F) ---------------------------
TAG_START, TAG_END = 0xE0000, 0xE007F
TAG_NAMES = {0xE0001: "LANGUAGE TAG", 0xE007F: "CANCEL TAG"}

# --- bidirectional override / embedding controls --------------------------
# U+202A..U+202E (LRE, RLE, PDF, LRO, RLO) and U+2066..U+2069 (LRI, RLI,
# FSI, PDI).  These are the "Trojan Source" class of characters.
BIDI_CONTROLS = frozenset(range(0x202A, 0x202F)) | frozenset(range(0x2066, 0x206A))
BIDI_NAMES = {
    0x202A: "LEFT-TO-RIGHT EMBEDDING",
    0x202B: "RIGHT-TO-LEFT EMBEDDING",
    0x202C: "POP DIRECTIONAL FORMATTING",
    0x202D: "LEFT-TO-RIGHT OVERRIDE",
    0x202E: "RIGHT-TO-LEFT OVERRIDE",
    0x2066: "LEFT-TO-RIGHT ISOLATE",
    0x2067: "RIGHT-TO-LEFT ISOLATE",
    0x2068: "FIRST STRONG ISOLATE",
    0x2069: "POP DIRECTIONAL ISOLATE",
}

# LRM/RLM are bidi marks rather than overrides — track them separately with a
# lower severity.
BIDI_MARKS = {0x200E, 0x200F}


def is_tag(cp: int) -> bool:
    return TAG_START <= cp <= TAG_END


def is_variation_selector(cp: int) -> bool:
    return cp in VARIATION_SELECTORS or cp in VARIATION_SELECTOR_SUPPLEMENT


def is_control(cp: int) -> bool:
    """C0/C1 control characters, excluding the whitespace we keep."""
    if cp in (0x09, 0x0A, 0x0D):  # tab, LF, CR
        return False
    return cp < 0x20 or 0x7F <= cp <= 0x9F


def u_name(cp: int) -> str:
    try:
        return unicodedata.name(chr(cp))
    except ValueError:
        return "UNKNOWN"


def char_label(cp: int) -> str:
    if cp in ZERO_WIDTH:
        return ZERO_WIDTH[cp]
    if cp in BIDI_NAMES:
        return BIDI_NAMES[cp]
    if cp in TAG_NAMES:
        return TAG_NAMES[cp]
    return u_name(cp)


# --- confusables (mixed-script homoglyphs) --------------------------------
# A deliberately small, explicit table: characters that look like an ASCII
# letter but come from Cyrillic or Greek blocks.  Mapping target is the
# Latin letter a human sees.
CONFUSABLES: dict[int, str] = {
    0x0430: "a",  # CYRILLIC SMALL LETTER A
    0x0435: "e",
    0x043E: "o",
    0x0440: "p",
    0x0441: "c",
    0x0443: "y",
    0x0445: "x",  # CYRILLIC SMALL LETTER HA
    0x0455: "s",  # CYRILLIC SMALL LETTER DZE
    0x0456: "i",  # CYRILLIC SMALL LETTER BYELORUSSIAN-UKRAINIAN I
    0x0458: "j",  # CYRILLIC SMALL LETTER JE
    0x043A: "k",  # CYRILLIC SMALL LETTER KA
    0x043C: "m",  # CYRILLIC SMALL LETTER EM
    0x0442: "t",  # CYRILLIC SMALL LETTER TE
    0x0434: "A",  # CYRILLIC SMALL LETTER DE
    0x0433: "r",  # CYRILLIC SMALL LETTER GHE
    0x0431: "6",  # CYRILLIC SMALL LETTER BE
    0x0410: "A",  # CYRILLIC CAPITAL LETTER A
    0x0412: "B",  # CYRILLIC CAPITAL LETTER VE
    0x0415: "E",  # CYRILLIC CAPITAL LETTER IE
    0x041A: "K",  # CYRILLIC CAPITAL LETTER KA
    0x041C: "M",  # CYRILLIC CAPITAL LETTER EM
    0x041D: "H",  # CYRILLIC CAPITAL LETTER EN
    0x041E: "O",  # CYRILLIC CAPITAL LETTER O
    0x0420: "P",  # CYRILLIC CAPITAL ER
    0x0421: "C",  # CYRILLIC CAPITAL ES
    0x0422: "T",  # CYRILLIC CAPITAL TE
    0x0425: "X",  # CYRILLIC CAPITAL HA
    0x0432: "B",
    0x03BF: "o",  # GREEK SMALL LETTER OMICRON
    0x03B1: "a",  # GREEK SMALL LETTER ALPHA
    0x03B9: "i",  # GREEK SMALL LETTER IOTA
    0x03BD: "v",  # GREEK SMALL LETTER NU
    0x03C1: "p",  # GREEK SMALL LETTER RHO
    0x03BA: "k",  # GREEK SMALL LETTER KAPPA
    0x03C4: "t",  # GREEK SMALL LETTER TAU
}

# Fullwidth / circled / squared ASCII — visually similar but normalized by NFKC.
FULLWIDTH_ASCII = range(0xFF01, 0xFF5F)

LATIN = set(range(ord("a"), ord("z") + 1)) | set(range(ord("A"), ord("Z") + 1))


def is_latin_letter(ch: str) -> bool:
    return ord(ch) in LATIN


def is_word_char(ch: str) -> bool:
    return ch.isalnum() or ch in {"_", "'"}