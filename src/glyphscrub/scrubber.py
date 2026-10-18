"""The scrubber: remove or neutralize the channels the detector finds.

Order matters and is documented in docs/ARCHITECTURE.md:

1. drop tag characters (they only carry hidden text)
2. drop bidi controls (they only reorder rendering — or, drop the *marks*)
3. drop zero-width and variation selectors
4. drop C0/C1 control characters (keeping tab/LF/CR)
5. optionally transliterate confusables to their ASCII lookalike
6. optionally NFKC-normalize (collapses fullwidth/padded forms)
7. optionally quarantine encoded blobs, replacing them with a placeholder

The scrubber is idempotent: ``scrub(scrub(x)) == scrub(x)``.
"""

from __future__ import annotations

import hashlib
import re
import unicodedata
from dataclasses import dataclass, field
from typing import Any

from . import charset
from .encoded import find_encoded_blobs

QUARANTINE_TEMPLATE = "[glyphscrub:removed-encoded-{kind}-{n}-chars-sha256:{digest}]"


@dataclass
class ScrubResult:
    text: str
    removed: dict[str, int] = field(default_factory=dict)
    quarantined: list[dict[str, Any]] = field(default_factory=list)
    transliterated: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "removed": self.removed,
            "quarantined": self.quarantined,
            "transliterated": self.transliterated,
            "bytes_before": None,
        }


def _bump(removed: dict[str, int], key: str, n: int = 1) -> None:
    removed[key] = removed.get(key, 0) + n


def scrub(
    text: str,
    *,
    quarantine_encoded: bool = False,
    transliterate: bool = False,
    nfkc: bool = False,
) -> ScrubResult:
    removed: dict[str, int] = {}
    chars: list[str] = []

    for ch in text:
        cp = ord(ch)
        if charset.is_tag(cp):
            _bump(removed, "tag-character")
            continue
        if cp in charset.BIDI_CONTROLS:
            _bump(removed, "bidi-control")
            continue
        if cp in charset.ZERO_WIDTH:
            _bump(removed, "zero-width")
            continue
        if charset.is_variation_selector(cp):
            _bump(removed, "variation-selector")
            continue
        if charset.is_control(cp):
            _bump(removed, "control-char")
            continue
        chars.append(ch)
    cleaned = "".join(chars)

    transliterated = 0
    if transliterate:
        out = []
        for ch in cleaned:
            if ord(ch) in charset.CONFUSABLES:
                out.append(charset.CONFUSABLES[ord(ch)])
                transliterated += 1
            elif ord(ch) in charset.FULLWIDTH_ASCII:
                out.append(chr(ord(ch) - 0xFEE0))
                transliterated += 1
            else:
                out.append(ch)
        cleaned = "".join(out)

    quarantined: list[dict[str, Any]] = []
    if quarantine_encoded:
        for blob in reversed(find_encoded_blobs(cleaned)):
            raw = cleaned[blob.start : blob.end]
            digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]
            placeholder = QUARANTINE_TEMPLATE.format(
                kind=blob.kind, n=len(raw), digest=digest
            )
            cleaned = cleaned[: blob.start] + placeholder + cleaned[blob.end :]
            quarantined.append(
                {
                    "kind": blob.kind,
                    "start": blob.start,
                    "chars": len(raw),
                    "sha256_16": digest,
                    "instruction_like": blob.instruction_like,
                }
            )
        quarantined.reverse()

    if nfkc:
        cleaned = unicodedata.normalize("NFKC", cleaned)

    return ScrubResult(
        text=cleaned,
        removed=removed,
        quarantined=quarantined,
        transliterated=transliterated,
    )


def is_idempotent(text: str, **kwargs: Any) -> bool:
    once = scrub(text, **kwargs).text
    return scrub(once, **kwargs).text == once