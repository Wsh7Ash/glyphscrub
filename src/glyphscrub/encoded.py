"""Detection of encoded payload channels (the "encode it so filters miss it"
family): Base64, hex byte sequences and ``\\uXXXX`` escape runs.

Everything here is *defensive*: a blob is decoded only to decide whether it
looks like instruction-like text ("ignore previous instructions" style
skeletons).  Decoded content is never executed, echoed in full, or used to
construct prompts; reports only contain a short, escaped excerpt.
"""

from __future__ import annotations

import base64
import binascii
import re
from dataclasses import dataclass
from typing import Iterable

# Instruction-ish skeleton markers, phrased structurally.  These are outline
# fragments of social-engineering instructions, not usable attack payloads.
INSTRUCTION_MARKERS: tuple[str, ...] = (
    "ignore previous",
    "ignore all previous",
    "ignore the above",
    "disregard prior",
    "disregard the",
    "new instructions",
    "system prompt",
    "developer message",
    "you are now",
    "do not mention",
    "do not tell",
    "without telling",
    "pretend you",
    "act as if",
    "reveal your",
    "your instructions",
    "hidden prompt",
    "previous conversation",
)

BASE64_RE = re.compile(r"(?<![A-Za-z0-9+/=])([A-Za-z0-9+/]{32,}={0,2})(?![A-Za-z0-9+/=])")
HEX_RE = re.compile(r"(?<![0-9a-fA-F])((?:[0-9a-fA-F]{2}){20,})(?![0-9a-fA-F])")
UESCAPE_RE = re.compile(r"(?:\\u[0-9a-fA-F]{4}){6,}")

EXCERPT_LEN = 60


@dataclass(frozen=True)
class EncodedBlob:
    kind: str  # "base64" | "hex" | "unicode-escape"
    start: int
    end: int
    decoded_excerpt: str
    instruction_like: bool
    printable_ratio: float
    error: str | None = None

    @property
    def severity(self) -> str:
        if self.instruction_like:
            return "high"
        if self.error:
            return "info"
        return "low"


def _printable_ratio(text: str) -> float:
    if not text:
        return 0.0
    printable = sum(1 for ch in text if ch.isprintable() or ch in "\n\r\t")
    return printable / len(text)


def _looks_like_text(data: bytes) -> tuple[bool, str, float]:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        try:
            text = data.decode("latin-1")
        except UnicodeDecodeError:  # pragma: no cover - latin-1 never fails
            return False, "", 0.0
    ratio = _printable_ratio(text)
    return ratio >= 0.85, text, ratio


def instruction_markers_in(text: str) -> list[str]:
    lowers = text.lower()
    return [marker for marker in INSTRUCTION_MARKERS if marker in lowers]


def _excerpt(text: str) -> str:
    clean = " ".join(text.split())
    if len(clean) <= EXCERPT_LEN:
        return clean
    return clean[:EXCERPT_LEN] + "…"


def decode_base64(candidate: str) -> bytes | None:
    padded = candidate + "=" * (-len(candidate) % 4)
    if len(padded) % 4:
        return None
    try:
        return base64.b64decode(padded, validate=True)
    except (binascii.Error, ValueError):
        return None


def find_encoded_blobs(text: str) -> list[EncodedBlob]:
    """Return every decodable, human-readable encoded blob in ``text``."""
    blobs: list[EncodedBlob] = []

    for match in BASE64_RE.finditer(text):
        data = decode_base64(match.group(1))
        if not data:
            continue
        ok, decoded, ratio = _looks_like_text(data)
        if not ok:
            continue  # binary noise (images, keys) — not an instruction channel
        markers = instruction_markers_in(decoded)
        blobs.append(
            EncodedBlob(
                kind="base64",
                start=match.start(1),
                end=match.end(1),
                decoded_excerpt=_excerpt(decoded),
                instruction_like=bool(markers),
                printable_ratio=round(ratio, 3),
            )
        )

    for match in HEX_RE.finditer(text):
        try:
            data = bytes.fromhex(match.group(1))
        except ValueError:  # pragma: no cover - regex guarantees pairs
            continue
        ok, decoded, ratio = _looks_like_text(data)
        if not ok:
            continue
        markers = instruction_markers_in(decoded)
        blobs.append(
            EncodedBlob(
                kind="hex",
                start=match.start(1),
                end=match.end(1),
                decoded_excerpt=_excerpt(decoded),
                instruction_like=bool(markers),
                printable_ratio=round(ratio, 3),
            )
        )

    for match in UESCAPE_RE.finditer(text):
        raw = match.group(0)
        try:
            decoded = raw.encode("utf-8").decode("unicode_escape")
        except UnicodeDecodeError:
            continue
        ratio = _printable_ratio(decoded)
        if ratio < 0.85:
            continue
        markers = instruction_markers_in(decoded)
        blobs.append(
            EncodedBlob(
                kind="unicode-escape",
                start=match.start(),
                end=match.end(),
                decoded_excerpt=_excerpt(decoded),
                instruction_like=bool(markers),
                printable_ratio=round(ratio, 3),
            )
        )

    blobs.sort(key=lambda b: b.start)
    return _drop_overlapping(blobs)


def _drop_overlapping(blobs: list[EncodedBlob]) -> list[EncodedBlob]:
    """The same bytes can satisfy several patterns (hex *is* base64 alphabet).

    Keep the first-starting blob of each overlapping cluster so callers can
    splice replacements by offset without corrupting the text.
    """
    kept: list[EncodedBlob] = []
    last_end = -1
    priority = {"hex": 0, "unicode-escape": 1, "base64": 2}
    for blob in sorted(
        blobs, key=lambda b: (b.start, priority.get(b.kind, 9), -(b.end - b.start))
    ):
        if blob.start < last_end:
            continue
        kept.append(blob)
        last_end = blob.end
    return kept


def summarize(blobs: Iterable[EncodedBlob]) -> dict[str, int]:
    counts = {"base64": 0, "hex": 0, "unicode-escape": 0, "instruction_like": 0}
    for blob in blobs:
        counts[blob.kind] = counts.get(blob.kind, 0) + 1
        if blob.instruction_like:
            counts["instruction_like"] += 1
    return counts