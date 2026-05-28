from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from watchlog_ai.ai import parse_analysis
from watchlog_ai.log_reader import read_new_logs
from watchlog_ai.severity import Severity
from watchlog_ai.state import State


class AnalysisParsingTest(unittest.TestCase):
    def test_parse_japanese_severity(self) -> None:
        result = parse_analysis(
            """
            {
              "severity": "中",
              "summary": "攻撃らしいアクセスを検知",
              "incidents": [{"severity": "中", "title": "/.git/config", "summary": "探索", "evidence": [], "recommended_actions": []}]
            }
            """
        )

        self.assertEqual(result.severity, Severity.MEDIUM)
        self.assertEqual(result.incidents[0].severity, Severity.MEDIUM)

    def test_medium_and_high_severity_are_notifiable(self) -> None:
        self.assertTrue(Severity.HIGH.should_notify)
        self.assertTrue(Severity.MEDIUM.should_notify)
        self.assertFalse(Severity.LOW.should_notify)
        self.assertFalse(Severity.NONE.should_notify)


class LogReaderTest(unittest.TestCase):
    def test_reads_only_new_bytes_after_first_scan(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            log_dir = Path(temp)
            path = log_dir / "access.log"
            path.write_text("line1\n", encoding="utf-8")
            state = State()

            first = read_new_logs(log_dir, ["access.log"], state, start_at_end=False)
            self.assertEqual(first["access.log"], "line1\n")

            path.write_text("line1\nline2\n", encoding="utf-8")
            second = read_new_logs(log_dir, ["access.log"], state, start_at_end=False)
            self.assertEqual(second["access.log"], "line2\n")

    def test_start_at_end_skips_existing_content(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            log_dir = Path(temp)
            path = log_dir / "error.log"
            path.write_text("old\n", encoding="utf-8")
            state = State()

            first = read_new_logs(log_dir, ["error.log"], state, start_at_end=True)
            self.assertEqual(first, {})

            with path.open("a", encoding="utf-8") as handle:
                handle.write("new\n")
            second = read_new_logs(log_dir, ["error.log"], state, start_at_end=True)
            self.assertEqual(second["error.log"], "new\n")


if __name__ == "__main__":
    unittest.main()
