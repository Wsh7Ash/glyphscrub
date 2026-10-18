# glyphscrub

**Detect and remove steganographic and encoded prompt-injection channels — Unicode tag characters, zero-width characters, bidi overrides, mixed-script confusables and encoded blobs — from untrusted text before it reaches a model.**

LLM01 (Prompt Injection) defenses usually focus on *what the text says*.
`glyphscrub` focuses on *how the text is encoded*: the channels that let a
sentence look harmless to a human reviewer (and to a naive keyword filter)
while still being readable to a tokenizer.

## Key features

- **Seven structural detectors**, implemented from the technique taxonomy in
  the [Prompt Injection & Jailbreak Techniques reference](https://gist.github.com/kibotu/c06f54d6fbc4705e886a50fb2e59e6ae):

  | Category | Channel | Default severity |
  |---|---|---|
  | `tag-character` | U+E0000–U+E007F tag runs ("ASCII smuggling") | high |
  | `bidi-control` | U+202A–U+202E, U+2066–U+2069 (Trojan Source class) | high |
  | `control-char` | stray C0/C1 controls | high |
  | `zero-width` | ZWSP/ZWNJ/ZWJ/WJ/BOM/soft hyphen/… | medium |
  | `variation-selector` | VS1–VS16 and the VS supplement | medium |
  | `homoglyph` | mixed-script word (Latin + Cyrillic/Greek lookalikes) | medium |
  | `encoded-block` | Base64 / hex / `\uXXXX` runs that decode to readable text | high if instruction-like, else low |

- **Decode-and-classify for encoded payloads.** A blob is decoded only to
  decide whether it contains instruction-shaped text ("ignore previous…" family
  skeletons). Reports show a short escaped excerpt, never a payload.
- **A real scrubber.** `glyphscrub scrub` strips the channels, optionally
  transliterates confusables, optionally applies NFKC, and optionally
  *quarantines* encoded blobs into a hashed placeholder — and the result is
  idempotent: `scrub(scrub(x)) == scrub(x)`.
- **CI-friendly gating.** `--fail-on high|medium|low|info|none` turns findings
  into exit codes; `--json` and `--markdown` output make it easy to post a
  report.
- **Zero dependencies**, Python 3.10+ standard library only.

## Example session

```shell
$ glyphscrub scan examples/defanged-samples/tag-charset-note.txt
examples/defanged-samples/tag-charset-note.txt: 9 finding(s), max severity high

#  SEV   CATEGORY       POSITION        CODEPOINT  NAME
-  ----  -------------  --------------  ---------  ------------------------
1  HIGH  tag-character  line 7, col 43  U+E0068    TAG LATIN SMALL LETTER H
2  HIGH  tag-character  line 7, col 44  U+E0062    TAG LATIN SMALL LETTER B
...

1. [high] tag-character: Unicode tag character — invisible text that tokenizers still see (ASCII smuggling)
   context: …invisible in brackets): [<TAG><TAG><TAG>…] and [<TAG><TAG>]

category totals: tag-character=9

$ echo $?
1
```

```shell
$ glyphscrub scan examples/clean-note.txt
examples/clean-note.txt: clean — no steganographic channels detected
$ echo $?
0
```

```shell
$ glyphscrub scrub dirty.txt -o clean.txt --transliterate --nfkc --report report.json --before-after
glyphscrub: removed={'zero-width': 2, 'tag-character': 4, 'bidi-control': 1} transliterated=1 quarantined=0 chars 512 -> 501
```

Run the packaged demo (writes `results/`): `python examples/demo.py`.

## Architecture summary

```
text ──► engine.scan ──► ScanResult(findings, severity, line:col, context)
             │
             ▼
        scrubber.scrub ──► cleaned text + removal/quarantine manifest
             │
             ▼
        report.render_table / render_markdown / to_json
```

- `charset.py` — codepoint tables (tag, zero-width, bidi, control, confusables)
- `encoded.py` — Base64/hex/`\uXXXX` extraction with overlap resolution and
  instruction-marker classification
- `engine.py` — detection, positions, context rendering (invisible characters
  are made visible in reports as `<ZW:200B>`, `<TAG>`, `< bidi 202E>`)
- `scrubber.py` — ordered rewrite pipeline, idempotence guaranteed by tests
- `report.py` / `cli.py` — renderers and exit codes (`0` clean, `1` findings
  above the gate, `2` usage error)

Full detail: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Requirements

- Python **3.10+** — standard library only, no runtime dependencies, no
  network access.

## Installation

```shell
git clone https://github.com/Wsh7Ash/glyphscrub
cd glyphscrub
python -m pip install -e .
glyphscrub --version
```

Without installing: `PYTHONPATH=src python -m glyphscrub.cli scan FILE`.

## Quick start

```shell
glyphscrub scan untrusted-document.txt                 # what is hiding in here?
glyphscrub scan *.md --json --fail-on high             # CI gate
glyphscrub scrub untrusted-document.txt -o safe.txt --quarantine-encoded
glyphscrub explain tag-character                       # what did it find?
```

## Testing

```shell
python -m unittest discover -s tests -t . -v
```

66 tests cover every detector (positive + negative cases), the scrub pipeline
and its idempotence, Base64/hex/`\uXXXX` decoding with overlap resolution,
report renderers, and the CLI end-to-end including exit-code gates.

## Project structure

```
glyphscrub/
├─ src/glyphscrub/
│  ├─ charset.py     # codepoint tables and confusables
│  ├─ encoded.py     # Base64 / hex / unicode-escape detection + classification
│  ├─ engine.py      # scan(): findings with positions, context, severity
│  ├─ scrubber.py    # removal + transliteration + NFKC + quarantine
│  ├─ report.py      # table / markdown / JSON renderers, `explain` copy
│  └─ cli.py         # scan, scrub, explain subcommands
├─ tests/            # 66 unittest cases
├─ examples/
│  ├─ defanged-samples/   # structural fixtures (tag, bidi, encoded)
│  ├─ clean-note.txt      # clean control document
│  └─ demo.py             # offline demo → results/
├─ docs/             # ARCHITECTURE.md, USAGE.md
├─ results/          # demo evidence
├─ SECURITY.md       # authorized use + responsible disclosure
└─ .github/workflows/ci.yml
```

## Limitations

- This is a **structural** filter, not a semantic one: it will not catch
  injection attempts written in plain language. Pair it with an
  instruction-hierarchy design and an input/output classifier.
- The confusable table is intentionally small (common Cyrillic/Greek
  lookalikes), not the full Unicode confusables list.
- Encoded-blob detection targets readable text blobs ≥ 32 Base64 chars /
  ≥ 20 hex bytes; deliberately splitting a blob across lines evades it.
- Byte-order marks and line endings survive scrubbing unchanged; NFKC is
  opt-in because it can alter intended formatting.
- The detector reports positions as line/column over Python string indices —
  astral-plane characters count as one index, not two UTF-16 units.

## Roadmap

- Configurable marker lists loaded from a YAML/JSON policy file.
- SARIF output for GitHub code scanning.
- Optional full Unicode confusables table (derived from IDNA/UTS #39).
- Document-level (indirect injection) mode with section-aware delimiting.

## Security notes

glyphscrub is defensive tooling built for reviewing content **you own or are
authorized to analyze**. Decoded blob excerpts are truncated and escaped;
no attack payloads ship in this repository — see `examples/defanged-samples/`
for the structural fixtures. Full policy: [SECURITY.md](SECURITY.md).

### Sources

- [Prompt Injection & Jailbreak Techniques — Comprehensive Reference](https://gist.github.com/kibotu/c06f54d6fbc4705e886a50fb2e59e6ae) (technique taxonomy: Unicode tricks, encoding channels, spotlighting/defenses)
- [OWASP Top 10 for LLM Applications — LLM01:2025 Prompt Injection](https://genai.owasp.org/llmrisk/llm01-prompt-injection/)
- [MITRE ATLAS](https://atlas.mitre.org/) — AML.T0051 (LLM Prompt Injection), AML.T0054 (LLM Jailbreak Injection)

## License

[MIT](LICENSE)