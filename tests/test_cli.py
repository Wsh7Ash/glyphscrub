"""CLI end-to-end tests: scan, scrub, explain, exit codes."""

from __future__ import annotations

import contextlib
import io
import json
import os
import tempfile
import unittest

from glyphscrub.cli import EXIT_CLEAN, EXIT_FINDINGS, EXIT_USAGE, main

from .support import BIDI_RLO, base64_of, with_zero_width

DIR = os.path.join(os.path.dirname(__file__), "..", "examples", "defanged-samples")


def run_cli(*argv: str) -> tuple[int, str]:
    out = io.StringIO()
    err = io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = main(list(argv))
    return code, out.getvalue() + err.getvalue()


class ScanCliTests(unittest.TestCase):
    def setUp(self) -> None:
        self.dir = tempfile.mkdtemp(prefix="glyphscrub-")

    def _write(self, name: str, text: str) -> str:
        path = os.path.join(self.dir, name)
        with open(path, "w", encoding="utf-8", newline="") as fh:
            fh.write(text)
        return path

    def test_clean_file_exits_zero(self) -> None:
        path = self._write("clean.txt", "Nothing suspicious in this document.")
        code, out = run_cli("scan", path)
        self.assertEqual(code, EXIT_CLEAN)
        self.assertIn("clean", out)

    def test_findings_exit_one_by_default(self) -> None:
        path = self._write("dirty.txt", with_zero_width("please ignore previous", at=7))
        code, out = run_cli("scan", path)
        self.assertEqual(code, EXIT_FINDINGS)
        self.assertIn("zero-width", out)
        self.assertIn("line 1", out)

    def test_fail_on_threshold(self) -> None:
        path = self._write("zw.txt", with_zero_width("hello world", at=2))
        code, _ = run_cli("scan", path, "--fail-on", "high")
        self.assertEqual(code, EXIT_CLEAN, "medium-only findings must not trip a high gate")
        code, _ = run_cli("scan", path, "--fail-on", "medium")
        self.assertEqual(code, EXIT_FINDINGS)

    def test_fail_on_none_disables_gating(self) -> None:
        path = self._write("bidi.txt", f"abc {BIDI_RLO} def")
        code, _ = run_cli("scan", path, "--fail-on", "none")
        self.assertEqual(code, EXIT_CLEAN)

    def test_json_output(self) -> None:
        path = self._write("dirty.txt", with_zero_width("hello world", at=2))
        code, out = run_cli("scan", path, "--json")
        payload = json.loads(out)
        self.assertEqual(payload["source"], path)
        self.assertEqual(payload["total"], 1)
        self.assertEqual(payload["findings"][0]["category"], "zero-width")

    def test_markdown_output(self) -> None:
        path = self._write("dirty.txt", with_zero_width("hello world", at=2))
        code, out = run_cli("scan", path, "--markdown")
        self.assertIn("| Severity |", out)
        self.assertIn("zero-width", out)

    def test_multiple_files(self) -> None:
        a = self._write("a.txt", "clean one")
        b = self._write("b.txt", with_zero_width("dirty one", at=5))
        code, out = run_cli("scan", a, b, "--fail-on", "none")
        self.assertEqual(code, EXIT_CLEAN)
        self.assertIn(a, out)
        self.assertIn(b, out)

    def test_missing_file_is_usage_error(self) -> None:
        code, out = run_cli("scan", os.path.join(self.dir, "nope.txt"))
        self.assertEqual(code, EXIT_USAGE)
        self.assertIn("file not found", out)

    def test_bundled_samples_are_detected(self) -> None:
        if not os.path.isdir(DIR):  # pragma: no cover - samples always ship
            self.skipTest("examples not present")
        names = sorted(os.listdir(DIR))
        self.assertGreaterEqual(len(names), 3)
        for name in names:
            code, out = run_cli("scan", os.path.join(DIR, name), "--fail-on", "high")
            self.assertEqual(code, EXIT_FINDINGS, f"{name} should contain a high-severity sample")
            self.assertRegex(out, r"tag-character|bidi-control|encoded-block")


class ScrubCliTests(unittest.TestCase):
    def setUp(self) -> None:
        self.dir = tempfile.mkdtemp(prefix="glyphscrub-")

    def _write(self, name: str, text: str) -> str:
        path = os.path.join(self.dir, name)
        with open(path, "w", encoding="utf-8", newline="") as fh:
            fh.write(text)
        return path

    def test_scrub_writes_clean_output_and_report(self) -> None:
        src = self._write("in.txt", with_zero_width("hello world", at=5))
        out_path = os.path.join(self.dir, "out.txt")
        report = os.path.join(self.dir, "report.json")
        code, msg = run_cli("scrub", src, "-o", out_path, "--report", report, "--before-after")
        self.assertEqual(code, EXIT_CLEAN)
        with open(out_path, encoding="utf-8") as fh:
            self.assertEqual(fh.read(), "hello world")
        with open(report, encoding="utf-8") as fh:
            payload = json.load(fh)
        self.assertEqual(payload["total"], 1)
        self.assertIn("removed", msg)

    def test_scrub_scrub_is_stable(self) -> None:
        src = self._write("in.txt", f"a​b{BIDI_RLO}c")
        once = os.path.join(self.dir, "one.txt")
        twice = os.path.join(self.dir, "two.txt")
        run_cli("scrub", src, "-o", once)
        run_cli("scrub", once, "-o", twice)
        with open(once, encoding="utf-8") as fh:
            first = fh.read()
        with open(twice, encoding="utf-8") as fh:
            second = fh.read()
        self.assertEqual(first, second)

    def test_stdin_to_stdout(self) -> None:
        # Not exercised through stdin here (redirecting sys.stdin is enough
        # elsewhere); -o - writes cleaned text to stdout.
        src = os.path.join(self.dir, "s.txt")
        with open(src, "w", encoding="utf-8") as fh:
            fh.write(with_zero_width("abc", at=1))
        code, out = run_cli("scrub", src, "-o", "-")
        self.assertEqual(code, EXIT_CLEAN)
        self.assertIn("abc", out)


class ExplainCliTests(unittest.TestCase):
    def test_explain_single_category(self) -> None:
        code, out = run_cli("explain", "tag-character")
        self.assertEqual(code, EXIT_CLEAN)
        self.assertIn("U+E0000", out)

    def test_explain_all_categories(self) -> None:
        code, out = run_cli("explain")
        self.assertEqual(code, EXIT_CLEAN)
        for category in ("zero-width", "bidi-control", "homoglyph", "encoded-block"):
            self.assertIn(category, out)


if __name__ == "__main__":
    unittest.main()