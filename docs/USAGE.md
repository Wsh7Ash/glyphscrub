# Usage

Exit codes: `0` clean / below gate, `1` findings at or above `--fail-on`,
`2` usage error.

## scan

```shell
glyphscrub scan FILE [FILE ...]            # table report per file
glyphscrub scan notes/ -r 2>/dev/null || true   # shell glob works too
cat unknown.txt | glyphscrub scan -        # stdin
glyphscrub scan doc.txt --json             # machine-readable
glyphscrub scan doc.txt --markdown > report.md
glyphscrub scan doc.txt --fail-on high     # only block on high severity
glyphscrub scan doc.txt --fail-on none     # report only, never fail
glyphscrub scan doc.txt --no-encoded       # skip decoding blobs (faster/cheaper)
glyphscrub scan doc.txt --no-homoglyphs    # skip mixed-script checks
```

Reading a report:

- `POSITION` is line/column over Python (0-indexed characters, 1-based column
  as your editor shows it for BMP text).
- `context:` shows a ±24 char window where `⟨ZW:200B⟩`, `⟨TAG⟩`,
  `⟨ bidi 202E⟩` etc. replace invisible characters.
- Severity order: `info < low < medium < high`.

### CI example

```yaml
- name: Prompt-input hygiene gate
  run: |
    pip install -e .
    glyphscrub scan fixtures/untrusted/*.txt --json --fail-on high > glyphscrub.json
```

## scrub

```shell
glyphscrub scrub dirty.txt -o clean.txt
glyphscrub scrub dirty.txt -o clean.txt --before-after
glyphscrub scrub attempts.json -o safe.json --quarantine-encoded --report report.json
glyphscrub scrub - < in.txt > out.txt      # stdin/stdout
glyphscrub scrub page.md -o page.md --transliterate --nfkc   # in place
```

Flags:

| Flag | Effect |
|---|---|
| `--quarantine-encoded` | replace each encoded blob with `[glyphscrub:removed-encoded-…-sha256:…]` |
| `--transliterate` | map confusables and fullwidth characters to ASCII |
| `--nfkc` | apply Unicode NFKC normalization (last step) |
| `--report PATH` | also write the pre-scrub JSON scan report |
| `--before-after` | print removal counts and size delta to stderr |

The idempotence guarantee means you can pipe documents through repeatedly, or
run `scrub` as a pre-commit hook, without accumulating changes.

## explain

```shell
glyphscrub explain                 # list every category
glyphscrub explain tag-character   # one category in depth
```

## Typical workflows

**Review an inbound document (RAG / support ticket / shared file)**

```shell
glyphscrub scan ticket.txt || echo "needs review"
glyphscrub scan ticket.txt --markdown > "ticket-review.md"
```

**Sanitize before prompting**

```shell
glyphscrub scrub ticket.txt -o ticket.safe.txt --quarantine-encoded --nfkc
```

**Repository-wide audit**

```shell
glyphscrub scan $(git ls-files '*.md' '*.txt' '*.json') --fail-on high --json > audit.json
```

## Notes

- glyphscrub does not decide whether text is *malicious*; it removes the
  encoding tricks that keep text from looking the same to humans, filters and
  tokenizers. Keep instruction hierarchy and output filtering in your stack as
  well (see README → Sources).
- Do not commit real untrusted payloads; the bundled samples under
  `examples/defanged-samples/` are defanged structural fixtures.