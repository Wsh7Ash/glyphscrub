"""glyphscrub command line interface."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Sequence

from . import __version__
from .engine import SEVERITY_ORDER, scan
from .report import CATEGORIES_HELP, render_markdown, render_table, to_json
from .scrubber import scrub

EXIT_CLEAN = 0
EXIT_FINDINGS = 1
EXIT_USAGE = 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="glyphscrub",
        description="Detect and remove steganographic/encoded prompt-injection channels.",
    )
    parser.add_argument("--version", action="version", version=f"glyphscrub {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    scn = sub.add_parser("scan", help="report smuggling channels in text files or stdin")
    scn.add_argument("paths", nargs="+", help="files to scan; use - for stdin")
    scn.add_argument("--json", action="store_true", help="emit JSON instead of a table")
    scn.add_argument("--markdown", action="store_true", help="emit a markdown report")
    scn.add_argument("--no-encoded", action="store_true", help="skip base64/hex/escape decoding")
    scn.add_argument("--no-homoglyphs", action="store_true", help="skip mixed-script checks")
    scn.add_argument(
        "--fail-on",
        choices=["high", "medium", "low", "info", "none"],
        default="low",
        help="exit 1 when a finding at or above this severity exists (default: low)",
    )

    scb = sub.add_parser("scrub", help="write a cleaned copy of the input")
    scb.add_argument("path", help="input file (or - for stdin)")
    scb.add_argument("-o", "--output", required=True, help="cleaned output file (or - for stdout)")
    scb.add_argument("--quarantine-encoded", action="store_true", help="replace encoded blobs with a placeholder")
    scb.add_argument("--transliterate", action="store_true", help="map confusables/fullwidth characters to ASCII")
    scb.add_argument("--nfkc", action="store_true", help="apply Unicode NFKC normalization")
    scb.add_argument("--report", help="also write a JSON scan report to this path")
    scb.add_argument("--before-after", action="store_true", help="print before/after stats to stderr")

    exp = sub.add_parser("explain", help="explain what a finding category means")
    exp.add_argument("category", nargs="?", choices=sorted(CATEGORIES_HELP), help="category to explain")
    return parser


def _read(path: str) -> str:
    if path == "-":
        return sys.stdin.read()
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(path)
    return p.read_text(encoding="utf-8", errors="surrogateescape")


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(list(argv) if argv is not None else None)
    try:
        if args.command == "scan":
            return _scan(args)
        if args.command == "scrub":
            return _scrub(args)
        if args.command == "explain":
            return _explain(args)
    except FileNotFoundError as exc:
        print(f"error: file not found: {exc}", file=sys.stderr)
        return EXIT_USAGE
    except UnicodeDecodeError as exc:
        print(f"error: cannot decode {exc.object!r} as text", file=sys.stderr)
        return EXIT_USAGE
    return EXIT_USAGE  # pragma: no cover


def _scan(args: argparse.Namespace) -> int:
    worst = 0
    any_findings = False
    render = render_markdown if args.markdown else (lambda r, s: render_table(r, s))
    if args.json:
        import json as _json

        payloads = []
    for path in args.paths:
        text = _read(path)
        result = scan(
            text,
            include_encoded=not args.no_encoded,
            detect_homoglyphs=not args.no_homoglyphs,
        )
        any_findings = any_findings or bool(result.findings)
        if result.findings:
            worst = max(worst, max(SEVERITY_ORDER[f.severity] for f in result.findings))
        if args.json:
            payload = result.to_dict()
            payload["source"] = path
            payloads.append(payload)
        else:
            print(render(result, path))
    if args.json:
        print(to_json(payloads if len(payloads) > 1 else payloads[0]))

    if args.fail_on == "none":
        return EXIT_CLEAN
    threshold = SEVERITY_ORDER[args.fail_on]
    return EXIT_FINDINGS if (any_findings and worst >= threshold) else EXIT_CLEAN


def _scrub(args: argparse.Namespace) -> int:
    text = _read(args.path)
    result = scrub(
        text,
        quarantine_encoded=args.quarantine_encoded,
        transliterate=args.transliterate,
        nfkc=args.nfkc,
    )
    if args.output == "-":
        sys.stdout.write(result.text)
    else:
        Path(args.output).write_text(result.text, encoding="utf-8")

    if args.report:
        report = scan(text)
        Path(args.report).write_text(
            to_json({**report.to_dict(), "source": args.path}), encoding="utf-8"
        )

    if args.before_after:
        print(
            f"glyphscrub: removed={result.removed} transliterated={result.transliterated} "
            f"quarantined={len(result.quarantined)} "
            f"chars {len(text)} -> {len(result.text)}",
            file=sys.stderr,
        )
    return EXIT_CLEAN


def _explain(args: argparse.Namespace) -> int:
    if not args.category:
        for name, text in CATEGORIES_HELP.items():
            print(f"{name}\n  {text}\n")
        return EXIT_CLEAN
    print(CATEGORIES_HELP[args.category])
    return EXIT_CLEAN


def entry() -> None:  # pragma: no cover - console entry point
    raise SystemExit(main())


if __name__ == "__main__":  # pragma: no cover
    entry()