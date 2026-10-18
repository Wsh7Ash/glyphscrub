# Security Policy

## Authorized use

`glyphscrub` is **defensive tooling for content you own or are authorized to
analyze**: your own prompt pipelines, your RAG corpus, tickets and documents
sent to your service, or datasets you have permission to inspect.

It is a scanner and a sanitizer. It deliberately does **not**:

- generate attack payloads or test them against any model or service,
- contact any network endpoint,
- decode-and-execute anything, or feed decoded content back into a model,
- provide weaponized content of any kind.

The repository ships only **defanged structural fixtures** under
`examples/defanged-samples/`: invisible characters, a bidi override, and one
Base64 blob whose plaintext is a short instruction-shaped skeleton. These are
outlines of a technique class, not working attacks, and they exist so the
detectors are provably exercised.

## Handling of untrusted content

- Blob decoding happens in memory; reports contain a **60-character escaped
  excerpt** of the decoded text, never the full content.
- Encoded blobs can be *quarantined* (replaced by a hashed placeholder)
  instead of reported, so downstream systems never see the original bytes.
- Scanned files are read with `errors="surrogateescape"` — glyphscrub will not
  crash on, or silently rewrite, undecodable bytes in place.
- glyphscrub itself writes only to paths you name on the command line.

## Limitations to be aware of

- A structural filter cannot catch plain-language injection; it is one layer.
- Byte-split blobs (a payload broken across many lines/fields) are out of
  scope for the current patterns.
- The confusable table covers common Cyrillic/Greek lookalikes, not the full
  Unicode confusables set.

## Reporting a vulnerability

Please use GitHub's private security advisory for this repository, or open an
issue without exploit details if private reporting is unavailable. Reports
about false negatives/positives in detectors are welcome and treated as
quality bugs; reports of any use of glyphscrub to *author* attack content will
be rejected — that is outside the tool's purpose.