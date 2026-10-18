"""glyphscrub — detect and remove steganographic/encoded prompt-injection channels.

Defensive, educational tooling: it normalizes and reports *structural*
smuggling channels (Unicode tag characters, zero-width characters, bidi
overrides, mixed-script confusables, encoded blobs) in untrusted text before
that text reaches an LLM.  It never generates attack payloads.
"""

__version__ = "0.1.0"