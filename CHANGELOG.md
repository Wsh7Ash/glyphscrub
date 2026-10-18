# Changelog

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
versions follow [Semantic Versioning](https://semver.org/).

## [0.1.0] - 2026-10-18

### Added

- Detector for Unicode **tag characters** (U+E0000–U+E007F, "ASCII
  smuggling"), bidirectional overrides (U+202A–U+202E, U+2066–U+2069),
  zero-width/invisible characters, variation selectors, and stray C0/C1
  control characters.
- **Mixed-script homoglyph** detection over an explicit Cyrillic/Greek
  confusables table (pure non-Latin prose is not flagged).
- **Encoded payload detection**: Base64 (≥32 chars), hex (≥20 bytes) and
  `\uXXXX` runs, decoded only to (a) require ≥85% printable text and (b)
  classify against instruction-skeleton markers → severity `high`/`low`.
  Overlapping matches resolved by decoder specificity.
- `glyphscrub scan` with table/JSON/markdown output, `--fail-on` severity
  gating and line/column plus visible-in-character context snippets.
- `glyphscrub scrub` — ordered removal pipeline with optional confusable
  transliteration, NFKC normalization and encoded-blob **quarantine** to a
  hashed placeholder; idempotent by construction and by test.
- `glyphscrub explain` — per-category defense notes.
- 66 tests, offline demo (`examples/demo.py`), defanged fixtures
  (`examples/defanged-samples/`), CI workflow.