"""Report renderers: terminal table, markdown and JSON."""

from __future__ import annotations

import json
from typing import Any

from .engine import ScanResult


def render_table(result: ScanResult, source: str = "<text>") -> str:
    if not result.findings:
        return f"{source}: clean — no steganographic channels detected"
    lines = [
        f"{source}: {len(result.findings)} finding(s), max severity {result.max_severity}",
        "",
    ]
    rows = [("#", "SEV", "CATEGORY", "POSITION", "CODEPOINT", "NAME")]
    for i, f in enumerate(result.findings, 1):
        rows.append(
            (
                str(i),
                f.severity.upper(),
                f.category,
                f"line {f.line}, col {f.column}",
                f.codepoint,
                f.name,
            )
        )
    widths = [max(len(r[c]) for r in rows) for c in range(len(rows[0]))]
    for idx, row in enumerate(rows):
        lines.append("  ".join(cell.ljust(widths[c]) for c, cell in enumerate(row)).rstrip())
        if idx == 0:
            lines.append("  ".join("-" * w for w in widths))
    lines.append("")
    for i, f in enumerate(result.findings, 1):
        lines.append(f"{i}. [{f.severity}] {f.category}: {f.detail}")
        if f.context:
            lines.append(f"   context: {f.context}")
    lines.append("")
    lines.append("category totals: " + ", ".join(
        f"{k}={v}" for k, v in sorted(result.counts_by_category.items())
    ))
    return "\n".join(lines)


def render_markdown(result: ScanResult, source: str = "<text>") -> str:
    if not result.findings:
        return f"# glyphscrub report — {source}\n\n**Clean.** No findings.\n"
    lines = [
        f"# glyphscrub report — {source}",
        "",
        f"Findings: **{len(result.findings)}** · max severity: **{result.max_severity}**",
        "",
        "| # | Severity | Category | Line:Col | Codepoint | Name |",
        "|---|---|---|---|---|---|",
    ]
    for i, f in enumerate(result.findings, 1):
        lines.append(
            f"| {i} | {f.severity} | {f.category} | {f.line}:{f.column} | `{f.codepoint}` | {f.name} |"
        )
    lines += ["", "## Details", ""]
    for i, f in enumerate(result.findings, 1):
        lines.append(f"{i}. **{f.category}** ({f.severity}) at line {f.line}, col {f.column} — {f.detail}")
    return "\n".join(lines) + "\n"


def to_json(payload: Any) -> str:
    if isinstance(payload, ScanResult):
        payload = payload.to_dict()
    return json.dumps(payload, indent=2, ensure_ascii=False, sort_keys=True)


CATEGORIES_HELP = {
    "tag-character": (
        "Unicode tag characters U+E0000–U+E007F render as nothing but are still tokenized — "
        "the technique commonly called 'ASCII smuggling'. Defense: delete them (the scrubber does)."
    ),
    "zero-width": (
        "Zero-width and other invisible characters split words so a filter reading the text sees "
        "'ignore previous' as 'i g n o r e' while the model reassembles it. Defense: strip before prompting."
    ),
    "bidi-control": (
        "Bidirectional overrides (U+202A–U+202E, U+2066–U+2069) reorder rendered text — the Trojan "
        "Source class. Defense: strip or reject in code and prompts."
    ),
    "variation-selector": (
        "Variation selectors are invisible codepoints appended to glyphs; they smuggle bytes past "
        "string comparisons. Defense: strip."
    ),
    "control-char": "C0/C1 control characters have no business in natural-language prompts. Defense: strip, keep tab/newline only.",
    "homoglyph": (
        "Mixed-script confusables make a filter's denylist miss a word a human would recognize. "
        "Defense: script-confusion check plus NFKC normalization."
    ),
    "encoded-block": (
        "Base64/hex/\\uXXXX runs that decode to readable instruction-like text are a payload "
        "transport, not data. Defense: decode-and-classify, then quarantine or rewrite with explicit delimiters."
    ),
}