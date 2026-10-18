# Architecture

## Goals

1. **Structural, not semantic.** glyphscrub answers "is this text carrying a
   hidden channel?", never "is this text harmful?" — the two questions need
   different, complementary defenses.
2. **Explainable findings.** Every finding carries a codepoint, a line/column
   position, a plain-language reason, and a context snippet in which the
   invisible characters are made *visible*.
3. **Safe handling.** Decoded blob content is truncated and escaped; the
   repository contains only defanged structural fixtures.
4. **Idempotent repair.** Scrubbing twice must equal scrubbing once.

## Components

```
                 ┌────────────┐  ScanResult  ┌────────────┐
  text ─────────►│ engine.py  │────────────►│ report.py  │──► table / md / json
                 └─────┬──────┘             └────────────┘
                       │ uses
                 ┌─────┴──────┐   ┌──────────────┐
                 │ charset.py │   │ encoded.py   │  decode → classify → dedupe
                 └────────────┘   └──────┬───────┘
                                         │
                 ┌────────────┐          │
  text ─────────►│scrubber.py │◄─────────┘ (quarantine step)
                 └────────────┘
```

### charset.py

Pure data: codepoint → name tables for zero-width characters, bidi controls,
tag characters, variation selectors, predicates `is_tag` / `is_control` /
`is_variation_selector`, and a **small explicit confusables map**
(Latin-looking Cyrillic/Greek codepoints → the ASCII letter they imitate).
Keeping the map explicit beats importing a derived Unicode table we cannot
audit.

### encoded.py

Detects the "encode it so filters miss it" family:

| Pattern | Floor | Decode path |
|---|---|---|
| Base64 run | 32 chars | `base64.b64decode(validate=True)`, padded automatically |
| Hex byte run | 20 bytes | `bytes.fromhex` |
| `\uXXXX` run | 6 escapes | `unicode_escape` |

A blob only counts when the decoded bytes are **≥ 85% printable text** — that
is what separates an instruction channel from an image, a key, or a hash
(a SHA-256 hex digest decodes to random bytes and is correctly ignored).

Overlapping matches are resolved by `_drop_overlapping()`: sort by start
offset, break ties by decoder specificity (hex → unicode-escape → base64) and
by length, then keep the first non-overlapping blob of each cluster. This is
why a pure-hex payload reports as `hex` even though hex is also a valid Base64
alphabet, and why the scrubber can splice replacements by offset without
corrupting the text.

Classification: the decoded text is lowered and matched against a fixed list of
**instruction markers** (`ignore previous`, `system prompt`, …) — structural
skeletons only. Any hit ⇒ severity `high`, excerpt truncated to 60 chars.

### engine.py

`scan(text, include_encoded=True, detect_homoglyphs=True)` walks the string
once per detector family, building `Finding(category, severity, codepoint,
name, index, line, column, detail, context)`.

- Line/column come from `line_col()` (newline counting) — offsets are raw
  Python string indices, so they match what an editor shows for BMP text.
- `context_window()` renders a ±24 char window in which non-printables become
  tokens: `⟨ZW:200B⟩`, `⟨TAG⟩`, `⟨ bidi 202E⟩`. Reports must *show* the hiding,
  not hide it again.
- Homoglyphs: only words that mix ASCII Latin letters with a confusable are
  flagged, so pure-Russian or pure-Greek prose produces zero findings (covered
  by a test).
- Findings sort by index, then by descending severity.

### scrubber.py

Ordered rewrite; each stage can only create text the later stages accept:

1. tag characters → deleted
2. bidi controls (incl. LRM/RLM marks) → deleted
3. zero-width characters → deleted
4. variation selectors → deleted
5. C0/C1 controls → deleted (tab/LF/CR kept)
6. *(optional)* confusables → ASCII lookalikes; fullwidth ASCII → ASCII
7. *(optional)* Base64/hex/escape blobs → `[glyphscrub:removed-encoded-…-sha256:…]`
8. *(optional)* NFKC normalization — last, so normalization cannot resurrect
   a channel the earlier steps removed

The placeholder contains only `[a-z0-9:[]-]`, so re-scrubbing cannot match it
as an encoded blob: idempotence holds by construction (and by test).

Idempotence check available as `scrubber.is_idempotent(text)`.

### report.py / cli.py

Renderers are pure functions. The CLI owns argument parsing and three exit
codes:

| Code | Meaning |
|---|---|
| 0 | clean, or no finding at/above `--fail-on` |
| 1 | gating finding present (severity order: info < low < medium < high) |
| 2 | usage error (missing file, bad decode) |

## Safety properties

- No network access anywhere in the package.
- No execution, printing, or echoing of decoded payload material beyond a
  60-character escaped excerpt.
- `scan` and `scrub` are pure functions of their inputs — easy to audit, easy
  to test (no global state, no caches at module import).

## Testing strategy

| Area | Tests |
|---|---|
| charset predicates | tag range, kept whitespace, flagged controls, names |
| each detector | positive sample + negative control (clean text, pure Cyrillic, SHA-256 hex, binary Base64) |
| positions | line/column across newlines, index ordering |
| encoded | decode validity, offsets exactly slicing the blob, overlap dedupe, summarizer counts |
| scrubber | per-category removal counts, idempotence (incl. quarantine), transliteration, NFKC, post-scrub scan is empty |
| report | table/markdown shape, visible-character rendering, JSON roundtrip |
| CLI | exit codes for clean/dirty/gates, JSON and markdown output, multi-file, missing file, missing-file error, bundled samples all gate high |

All fixtures are defanged structural skeletons; nothing weaponized.