# Contributing

Thanks for helping improve glyphscrub.

## Setup

```shell
python -m venv .venv && source .venv/bin/activate
pip install -e .
python -m unittest discover -s tests -t . -v
python examples/demo.py
```

Standard library only — please keep it dependency-free.

## Hard rules for this repository

1. **No weaponized content.** New detection examples must be defanged
   structural skeletons: no working attack payloads, no targets, no models to
   attack. If a test needs a sample, build it in code (see `tests/support.py`).
2. **No network.** The package must never make requests.
3. **Excerpts stay bounded.** Decoded material in reports is truncated and
   escaped.
4. **Every detector needs a negative test.** False positives are what makes
   people turn filters off — prove clean text, hashes, binary blobs and
   non-Latin prose stay quiet.

## Adding a detector

- add the codepoint table / pattern to `charset.py` or `encoded.py`
- wire it into `engine.scan` with a category name and default severity
- add an `explain` entry in `report.CATEGORIES_HELP`
- positive + negative tests, and a README row

## Commit style

Any clear imperative message is fine; reference the issue when there is one.