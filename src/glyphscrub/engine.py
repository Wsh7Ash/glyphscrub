"""The detection engine: text in, structured findings out."""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field
from typing import Any

from . import charset
from .encoded import find_encoded_blobs

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3}

WORD_RE = re.compile(r"[^\W\d_]+(?:['\-][^\W\d_]+)*", re.UNICODE)


@dataclass(frozen=True)
class Finding:
    category: str
    severity: str
    codepoint: str
    name: str
    index: int
    line: int
    column: int
    detail: str
    context: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ScanResult:
    findings: list[Finding] = field(default_factory=list)

    @property
    def counts_by_category(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for f in self.findings:
            out[f.category] = out.get(f.category, 0) + 1
        return out

    @property
    def max_severity(self) -> str:
        if not self.findings:
            return "clean"
        return max(self.findings, key=lambda f: SEVERITY_ORDER[f.severity]).severity

    @property
    def failed(self) -> bool:
        return bool(self.findings)

    def to_dict(self) -> dict[str, Any]:
        return {
            "findings": [f.to_dict() for f in self.findings],
            "counts_by_category": self.counts_by_category,
            "max_severity": self.max_severity,
            "total": len(self.findings),
        }


def line_col(text: str, index: int) -> tuple[int, int]:
    line = text.count("\n", 0, index) + 1
    last_nl = text.rfind("\n", 0, index)
    column = index - last_nl if last_nl >= 0 else index + 1
    return line, column


def context_window(text: str, index: int, radius: int = 24) -> str:
    start = max(0, index - radius)
    end = min(len(text), index + radius + 1)
    snippet = text[start:end]
    # Make the invisible characters visible in reports without printing them.
    rendered = "".join(_visible(ch) for ch in snippet)
    prefix = "…" if start > 0 else ""
    suffix = "…" if end < len(text) else ""
    return f"{prefix}{rendered}{suffix}"


def _visible(ch: str) -> str:
    cp = ord(ch)
    if ch.isprintable():
        return ch
    if cp in charset.ZERO_WIDTH:
        return f"<ZW:{cp:04X}>"
    if charset.is_tag(cp):
        return "<TAG>"
    if cp in charset.BIDI_NAMES:
        return f"< bidi {cp:04X}>"
    return f"<{cp:04X}>"


def scan(text: str, *, include_encoded: bool = True, detect_homoglyphs: bool = True) -> ScanResult:
    """Scan ``text`` and return every structural smuggling channel found."""
    findings: list[Finding] = []

    def add(category: str, severity: str, cp: int, index: int, detail: str) -> None:
        line, column = line_col(text, index)
        findings.append(
            Finding(
                category=category,
                severity=severity,
                codepoint=f"U+{cp:04X}",
                name=charset.char_label(cp),
                index=index,
                line=line,
                column=column,
                detail=detail,
                context=context_window(text, index),
            )
        )

    for index, ch in enumerate(text):
        cp = ord(ch)
        if charset.is_tag(cp):
            add("tag-character", "high", cp, index, "Unicode tag character — invisible text that tokenizers still see (ASCII smuggling)")
        elif cp in charset.BIDI_CONTROLS:
            add("bidi-control", "high", cp, index, "bidirectional override/embedding — can visually reorder code or instructions (Trojan Source class)")
        elif cp in charset.ZERO_WIDTH:
            sev = "medium"
            add("zero-width", sev, cp, index, "invisible/formatting character can split words or hide text from human review")
        elif charset.is_variation_selector(cp):
            add("variation-selector", "medium", cp, index, "variation selector is invisible next to most glyphs")
        elif charset.is_control(cp):
            add("control-char", "high", cp, index, "unexpected C0/C1 control character in text")

    if detect_homoglyphs:
        findings.extend(_homoglyph_findings(text))

    if include_encoded:
        findings.extend(_encoded_findings(text))

    findings.sort(key=lambda f: (f.index, -SEVERITY_ORDER[f.severity]))
    return ScanResult(findings=findings)


def _homoglyph_findings(text: str) -> list[Finding]:
    out: list[Finding] = []
    for match in WORD_RE.finditer(text):
        word = match.group()
        has_latin = any(charset.is_latin_letter(ch) for ch in word)
        if not has_latin:
            continue
        for offset, ch in enumerate(word):
            cp = ord(ch)
            if cp in charset.CONFUSABLES and charset.is_word_char(ch):
                index = match.start() + offset
                line, column = line_col(text, index)
                out.append(
                    Finding(
                        category="homoglyph",
                        severity="medium",
                        codepoint=f"U+{cp:04X}",
                        name=charset.u_name(cp),
                        index=index,
                        line=line,
                        column=column,
                        detail=(
                            f"mixed-script word: {ch!r} looks like {charset.CONFUSABLES[cp]!r} "
                            "but is not from the same script as its neighbours"
                        ),
                        context=context_window(text, index),
                    )
                )
    return out


def _encoded_findings(text: str) -> list[Finding]:
    out: list[Finding] = []
    for blob in find_encoded_blobs(text):
        line, column = line_col(text, blob.start)
        severity = blob.severity
        if blob.error:
            detail = f"{blob.kind} blob could not be decoded ({blob.error})"
        elif blob.instruction_like:
            detail = (
                f"{blob.kind} blob decodes to instruction-like text: {blob.decoded_excerpt!r}"
            )
        else:
            detail = (
                f"{blob.kind} blob decodes to readable text ({blob.printable_ratio:.0%} printable): "
                f"{blob.decoded_excerpt!r}"
            )
        out.append(
            Finding(
                category="encoded-block",
                severity=severity,
                codepoint="-",
                name=f"{blob.kind} encoded run",
                index=blob.start,
                line=line,
                column=column,
                detail=detail,
                context=context_window(text, blob.start),
            )
        )
    return out
