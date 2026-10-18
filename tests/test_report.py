"""Renderer tests for tables, markdown and JSON."""

from __future__ import annotations

import json
import unittest

from glyphscrub.engine import scan
from glyphscrub.report import render_markdown, render_table, to_json

from .support import with_zero_width


class ReportTests(unittest.TestCase):
    def test_clean_report(self) -> None:
        result = scan("nothing here")
        table = render_table(result, "clean.txt")
        self.assertIn("clean", table)
        self.assertIn("clean.txt", table)

    def test_table_contains_categories_and_context(self) -> None:
        result = scan(with_zero_width("hello world", at=5), include_encoded=False, detect_homoglyphs=False)
        table = render_table(result, "sample.txt")
        self.assertIn("zero-width", table)
        self.assertIn("U+200B", table)
        self.assertIn("context:", table)
        self.assertIn("<ZW:200B>", table)  # invisible char is rendered visibly

    def test_markdown_report_shape(self) -> None:
        result = scan(with_zero_width("hello world", at=5), include_encoded=False, detect_homoglyphs=False)
        md = render_markdown(result, "sample.txt")
        self.assertTrue(md.startswith("# glyphscrub report — sample.txt"))
        self.assertIn("| Severity |", md)
        self.assertIn("## Details", md)

    def test_clean_markdown(self) -> None:
        md = render_markdown(scan("all good"), "x.txt")
        self.assertIn("**Clean.**", md)

    def test_json_roundtrip(self) -> None:
        result = scan(with_zero_width("hello world", at=5), include_encoded=False, detect_homoglyphs=False)
        payload = json.loads(to_json(result))
        self.assertEqual(payload["total"], 1)
        self.assertEqual(payload["findings"][0]["category"], "zero-width")


if __name__ == "__main__":
    unittest.main()